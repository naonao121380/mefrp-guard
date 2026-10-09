"""状态存储：SQLite。

单文件、WAL 模式、一把全局锁。这个服务的写入量极低（每几十秒几条），
用不上连接池，简单可靠优先。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from .auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from .settings import BOOTSTRAP, DEFAULT_SETTINGS

_LOCK = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnels (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    name                     TEXT NOT NULL UNIQUE,   -- 展示名
    proxy_name               TEXT NOT NULL,          -- mefrp 上的隧道名（唯一标识）
    proxy_type               TEXT NOT NULL DEFAULT 'tcp',
    local_ip                 TEXT NOT NULL DEFAULT '127.0.0.1',
    local_port               INTEGER NOT NULL,
    desired_remote_port      INTEGER,                -- 期望端口，NULL = 随便
    pin_node_id              INTEGER,                -- 手动锁定节点，NULL = 自动
    enabled                  INTEGER NOT NULL DEFAULT 1,
    auto_failover            INTEGER NOT NULL DEFAULT 1,

    -- 这条隧道由哪个 frpc 实例承载。NULL = 还没有挂接。
    -- 解析只有这一级：不兜底、不自动发现（见 engine.frpc_for_tunnel 的说明）。
    frpc_instance_id         INTEGER,

    current_proxy_id         INTEGER,
    current_node_id          INTEGER,
    current_remote_port      INTEGER,

    dns_zone_id              TEXT,
    dns_record_id            TEXT,
    dns_record_name          TEXT,                   -- 如 nas.example.com
    dns_proxied              INTEGER NOT NULL DEFAULT 0,

    needs_downstream_review  INTEGER NOT NULL DEFAULT 0,
    downstream_note          TEXT DEFAULT '',
    last_failover_at         INTEGER NOT NULL DEFAULT 0,
    last_ok_at               INTEGER NOT NULL DEFAULT 0,
    fail_streak              INTEGER NOT NULL DEFAULT 0,
    last_error               TEXT DEFAULT '',
    created_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS node_prefs (
    node_id  INTEGER PRIMARY KEY,
    priority INTEGER NOT NULL DEFAULT 100,   -- 越小越优先
    excluded INTEGER NOT NULL DEFAULT 0,
    note     TEXT DEFAULT ''
);

-- frpc 实例。
--
-- 为什么要支持多个：一个 frpc 进程只能连一个 serverAddr（= 一个 mefrp 节点），
-- 所以「一个 frpc 带全部隧道」会强迫所有受管隧道挤在同一个节点上。
-- 拆成多个实例之后，每个实例各自守着一个节点，互不牵连。
--
-- ⚠️ 因此有一条硬不变式：**同一个实例承载的所有隧道必须落在同一个节点上**。
--    故障转移的单位因此是「实例」而不是「单条隧道」—— 见 engine._failover。
CREATE TABLE IF NOT EXISTS frpc_instances (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,             -- 展示名
    config_path  TEXT NOT NULL,                    -- 该实例 frpc.toml 的绝对路径
    container    TEXT NOT NULL DEFAULT '',         -- 容器名；restart_mode=none 时可为空
    restart_mode TEXT NOT NULL DEFAULT 'docker',   -- docker | none
    enabled      INTEGER NOT NULL DEFAULT 1,
    note         TEXT DEFAULT '',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    level     TEXT NOT NULL,        -- info | warn | error | success
    kind      TEXT NOT NULL,        -- probe / failover / dns / frpc / node / system
    tunnel_id INTEGER,
    message   TEXT NOT NULL,
    detail    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_tunnel ON events(tunnel_id, ts DESC);

-- 登录会话。⚠️ 只存令牌的 SHA-256，绝不存令牌明文：
--    数据库泄露时攻击者拿到的哈希无法反推出可用令牌。
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    user_agent TEXT DEFAULT '',
    ip         TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
"""


def init() -> None:
    global _conn
    BOOTSTRAP.data_dir.mkdir(parents=True, exist_ok=True)
    BOOTSTRAP.frpc_backup_dir.mkdir(parents=True, exist_ok=True)
    BOOTSTRAP.frpc_config_path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        _conn = sqlite3.connect(str(BOOTSTRAP.db_path), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.executescript(SCHEMA)
        _conn.commit()
        _migrate()
        _seed_settings()


def _migrate() -> None:
    """给老库补新增的列。

    `CREATE TABLE IF NOT EXISTS` 对已存在的表**不会**补列，所以新增字段必须
    在这里显式 ALTER。不做这一步的话，老用户升级后 frpc_instance_id 这一列
    根本不存在，所有查询都会炸。
    """
    conn = _db()
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(tunnels)").fetchall()}
    if "frpc_instance_id" not in cols:
        conn.execute("ALTER TABLE tunnels ADD COLUMN frpc_instance_id INTEGER")
        conn.commit()


def _db() -> sqlite3.Connection:
    if _conn is None:
        init()
    assert _conn is not None
    return _conn


def _seed_settings() -> None:
    """把默认值写进去，已存在的不覆盖。"""
    conn = _db()
    for key, value in DEFAULT_SETTINGS.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
    conn.commit()
    _seed_credentials()


def _seed_credentials() -> None:
    """首次启动时播种登录凭据。

    优先级：环境变量 `MG_WEB_PASSWORD` > 内置默认 `admin123`。

    ⚠️ 只在哈希为空时播种。判据是「库里还没有哈希」，不是「有没有这个键」——
    键在 _seed_settings 里已经被写成空串了。
    """
    if get_setting("web_password_hash"):
        return
    password = BOOTSTRAP.web_password or DEFAULT_PASSWORD
    user = BOOTSTRAP.web_user or str(get_setting("web_user") or DEFAULT_USER)
    h, salt, iters = hash_password(password)
    set_settings({
        "web_user": user,
        "web_password_hash": h,
        "web_password_salt": salt,
        "web_password_iter": iters,
    })
    if not BOOTSTRAP.web_password:
        # 用默认密码启动 —— 记一条事件，让用户翻日志时能看到。
        add_event("warn", "system",
                  f"正在使用默认密码登录（用户名 {user}）。"
                  "请到「设置 → 账号安全」修改。")


# ---------------------------------------------------------------------------
# 登录会话
# ---------------------------------------------------------------------------

def create_session(token_hash: str, username: str, ttl_seconds: int,
                   user_agent: str = "", ip: str = "") -> None:
    now = int(time.time())
    with _LOCK:
        _db().execute(
            "INSERT OR REPLACE INTO sessions"
            "(token_hash, username, created_at, expires_at, user_agent, ip) "
            "VALUES (?,?,?,?,?,?)",
            (token_hash, username, now, now + max(60, int(ttl_seconds)),
             (user_agent or "")[:300], (ip or "")[:64]),
        )
        _db().commit()


def get_session(token_hash: str) -> dict[str, Any] | None:
    """取一条**未过期**的会话。过期的顺手删掉。"""
    now = int(time.time())
    with _LOCK:
        row = _db().execute(
            "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return None
        if int(row["expires_at"]) <= now:
            _db().execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            _db().commit()
            return None
    return dict(row)


def delete_session(token_hash: str) -> None:
    with _LOCK:
        _db().execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        _db().commit()


def delete_sessions_for(username: str) -> int:
    """踢掉某个用户的全部会话。改密码后调用 —— 否则旧令牌还能继续用。"""
    with _LOCK:
        cur = _db().execute("DELETE FROM sessions WHERE username = ?", (username,))
        _db().commit()
        return int(cur.rowcount or 0)


def purge_expired_sessions() -> int:
    with _LOCK:
        cur = _db().execute("DELETE FROM sessions WHERE expires_at <= ?",
                            (int(time.time()),))
        _db().commit()
        return int(cur.rowcount or 0)


def count_sessions() -> int:
    with _LOCK:
        row = _db().execute("SELECT COUNT(*) AS n FROM sessions").fetchone()
    return int(row["n"]) if row else 0


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------

def get_setting(key: str, fallback: Any = None) -> Any:
    with _LOCK:
        row = _db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return DEFAULT_SETTINGS.get(key, fallback)
    try:
        return json.loads(row["value"])
    except (TypeError, ValueError):
        return row["value"]


def get_settings(keys: Iterable[str] | None = None) -> dict[str, Any]:
    with _LOCK:
        rows = _db().execute("SELECT key, value FROM settings").fetchall()
    out: dict[str, Any] = {}
    for r in rows:
        try:
            out[r["key"]] = json.loads(r["value"])
        except (TypeError, ValueError):
            out[r["key"]] = r["value"]
    if keys is None:
        return out
    return {k: out.get(k, DEFAULT_SETTINGS.get(k)) for k in keys}


def set_setting(key: str, value: Any) -> None:
    with _LOCK:
        _db().execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
        _db().commit()


def set_settings(items: dict[str, Any]) -> None:
    with _LOCK:
        conn = _db()
        for key, value in items.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )
        conn.commit()


# ---------------------------------------------------------------------------
# tunnels
# ---------------------------------------------------------------------------

TUNNEL_FIELDS = (
    "name", "proxy_name", "proxy_type", "local_ip", "local_port",
    "desired_remote_port", "pin_node_id", "enabled", "auto_failover",
    "frpc_instance_id",
    "current_proxy_id", "current_node_id", "current_remote_port",
    "dns_zone_id", "dns_record_id", "dns_record_name", "dns_proxied",
    "needs_downstream_review", "downstream_note",
    # ⚠️ 以下 4 个是引擎每轮都要写的运行时字段，漏一个都会让自愈逻辑失效：
    #   fail_streak      —— 不写就永远到不了阈值，自动切换永不触发
    #   last_failover_at —— 不写就永远不进入冷却期，会在坏节点间反复横跳
    #   last_ok_at       —— UI 上「上次健康」永远显示 —（只是显示问题）
    #   last_error       —— UI 上看不到失败原因（只是显示问题）
    "last_failover_at", "last_ok_at", "fail_streak", "last_error",
)


def list_tunnels(enabled_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM tunnels"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id"
    with _LOCK:
        rows = _db().execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_tunnel(tunnel_id: int) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute("SELECT * FROM tunnels WHERE id = ?", (tunnel_id,)).fetchone()
    return dict(row) if row else None


def find_tunnel_by_proxy(proxy_name: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute(
            "SELECT * FROM tunnels WHERE proxy_name = ?", (proxy_name,)
        ).fetchone()
    return dict(row) if row else None


def create_tunnel(data: dict[str, Any]) -> int:
    now = int(time.time())
    cols = [f for f in TUNNEL_FIELDS if f in data]
    vals = [data[f] for f in cols]
    cols += ["created_at", "updated_at"]
    vals += [now, now]
    placeholders = ",".join("?" for _ in cols)
    with _LOCK:
        cur = _db().execute(
            f"INSERT INTO tunnels({','.join(cols)}) VALUES ({placeholders})", vals
        )
        _db().commit()
        return int(cur.lastrowid)


def update_tunnel(tunnel_id: int, data: dict[str, Any]) -> None:
    cols = [f for f in TUNNEL_FIELDS if f in data]
    if not cols:
        return
    sets = ",".join(f"{c} = ?" for c in cols)
    vals = [data[c] for c in cols]
    vals.append(int(time.time()))
    with _LOCK:
        _db().execute(
            f"UPDATE tunnels SET {sets}, updated_at = ? WHERE id = ?",
            vals + [tunnel_id],
        )
        _db().commit()


def delete_tunnel(tunnel_id: int) -> None:
    with _LOCK:
        _db().execute("DELETE FROM tunnels WHERE id = ?", (tunnel_id,))
        _db().commit()


# ---------------------------------------------------------------------------
# frpc 实例
# ---------------------------------------------------------------------------

FRPC_FIELDS = ("name", "config_path", "container", "restart_mode",
               "enabled", "note")

RESTART_MODES = ("docker", "none")


def list_frpc_instances(enabled_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM frpc_instances"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id"
    with _LOCK:
        rows = _db().execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_frpc_instance(instance_id: int) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute("SELECT * FROM frpc_instances WHERE id = ?",
                            (int(instance_id),)).fetchone()
    return dict(row) if row else None


def get_frpc_instance_by_name(name: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute("SELECT * FROM frpc_instances WHERE name = ?",
                            (name,)).fetchone()
    return dict(row) if row else None


def create_frpc_instance(data: dict[str, Any]) -> int:
    now = int(time.time())
    cols = [f for f in FRPC_FIELDS if f in data]
    vals = [data[f] for f in cols]
    cols += ["created_at", "updated_at"]
    vals += [now, now]
    placeholders = ",".join("?" for _ in cols)
    with _LOCK:
        cur = _db().execute(
            f"INSERT INTO frpc_instances({','.join(cols)}) VALUES ({placeholders})",
            vals,
        )
        _db().commit()
        return int(cur.lastrowid)


def update_frpc_instance(instance_id: int, data: dict[str, Any]) -> None:
    cols = [f for f in FRPC_FIELDS if f in data]
    if not cols:
        return
    sets = ",".join(f"{c} = ?" for c in cols)
    vals = [data[c] for c in cols]
    vals.append(int(time.time()))
    with _LOCK:
        _db().execute(
            f"UPDATE frpc_instances SET {sets}, updated_at = ? WHERE id = ?",
            vals + [int(instance_id)],
        )
        _db().commit()


def delete_frpc_instance(instance_id: int) -> None:
    """删实例。**不动隧道记录** —— 绑定靠外键值指向一个不存在的 id 自然失效，
    之后会走「未绑定」的解析路径。调用方负责决定要不要先解绑/提醒。
    """
    with _LOCK:
        _db().execute("DELETE FROM frpc_instances WHERE id = ?", (int(instance_id),))
        _db().commit()


def list_tunnels_of_frpc(instance_id: int) -> list[dict[str, Any]]:
    with _LOCK:
        rows = _db().execute(
            "SELECT * FROM tunnels WHERE frpc_instance_id = ? ORDER BY id",
            (int(instance_id),),
        ).fetchall()
    return [dict(r) for r in rows]


def count_tunnels_of_frpc(instance_id: int) -> int:
    with _LOCK:
        row = _db().execute(
            "SELECT COUNT(*) AS n FROM tunnels WHERE frpc_instance_id = ?",
            (int(instance_id),),
        ).fetchone()
    return int(row["n"]) if row else 0


def unbind_tunnels_of_frpc(instance_id: int) -> int:
    """把指向某实例的绑定全部置空。删实例前调用。"""
    with _LOCK:
        cur = _db().execute(
            "UPDATE tunnels SET frpc_instance_id = NULL WHERE frpc_instance_id = ?",
            (int(instance_id),),
        )
        _db().commit()
        return int(cur.rowcount or 0)


# ---------------------------------------------------------------------------
# node prefs
# ---------------------------------------------------------------------------

def list_node_prefs() -> dict[int, dict[str, Any]]:
    with _LOCK:
        rows = _db().execute("SELECT * FROM node_prefs").fetchall()
    return {int(r["node_id"]): dict(r) for r in rows}


def upsert_node_pref(node_id: int, priority: int | None = None,
                     excluded: bool | None = None, note: str | None = None) -> None:
    cur = list_node_prefs().get(node_id, {"priority": 100, "excluded": 0, "note": ""})
    priority = cur["priority"] if priority is None else priority
    excluded = cur["excluded"] if excluded is None else int(bool(excluded))
    note = cur["note"] if note is None else note
    with _LOCK:
        _db().execute(
            "INSERT INTO node_prefs(node_id, priority, excluded, note) VALUES (?,?,?,?) "
            "ON CONFLICT(node_id) DO UPDATE SET "
            "priority = excluded.priority, excluded = excluded.excluded, note = excluded.note",
            (node_id, priority, excluded, note),
        )
        _db().commit()


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------

def add_event(level: str, kind: str, message: str,
              tunnel_id: int | None = None, detail: str = "") -> None:
    with _LOCK:
        _db().execute(
            "INSERT INTO events(ts, level, kind, tunnel_id, message, detail) "
            "VALUES (?,?,?,?,?,?)",
            (int(time.time()), level, kind, tunnel_id, message, detail[:4000]),
        )
        _db().commit()


def list_events(limit: int = 200, tunnel_id: int | None = None) -> list[dict[str, Any]]:
    with _LOCK:
        if tunnel_id is None:
            rows = _db().execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = _db().execute(
                "SELECT * FROM events WHERE tunnel_id = ? ORDER BY id DESC LIMIT ?",
                (tunnel_id, limit),
            ).fetchall()
    return [dict(r) for r in rows]


def prune_events(keep: int = 5000) -> None:
    with _LOCK:
        _db().execute(
            "DELETE FROM events WHERE id NOT IN "
            "(SELECT id FROM events ORDER BY id DESC LIMIT ?)",
            (keep,),
        )
        _db().commit()
