"""状态存储：SQLite。

单文件、WAL 模式、一把全局锁。这个服务的写入量极低（每几十秒几条），
用不上连接池，简单可靠优先。
"""

from __future__ import annotations

import json
import re
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
    -- 展示名。**刻意不加 UNIQUE**：隧道名的唯一性只在「同一台 frps 内」有意义，
    -- 而展示名连那层意义都没有 —— 不同运营商（mefrp / 自建 frps / 别家服务商）
    -- 的命名空间互不相干，重名是完全正常的。加了全局 UNIQUE 会有两个后果：
    --   1. 导入别家的同名隧道时被迫改名成 xxx-7，看不出它原本叫什么；
    --   2. 用户手动把名字改成已存在的那个 → 直接撞约束、接口 500。
    -- 真正需要唯一的是 `proxy_name`，而它的作用域由 find_tunnel_by_proxy 把关。
    name                     TEXT NOT NULL,
    proxy_name               TEXT NOT NULL,          -- 它**在自己那台 frps 上**的隧道名
    -- 自由标签，用来给隧道分组、筛选。空串 = 没打标签。
    -- mefrp 纳管的隧道默认打 'mefrp'（见 _migrate 的回填与 main 里的自动打标），
    -- 外部节点的隧道默认空串，由用户自己设（例如 '公司frps' / '临时'）。
    tag                      TEXT NOT NULL DEFAULT '',
    proxy_type               TEXT NOT NULL DEFAULT 'tcp',
    local_ip                 TEXT NOT NULL DEFAULT '127.0.0.1',
    local_port               INTEGER NOT NULL,
    desired_remote_port      INTEGER,                -- 期望端口，NULL = 随便
    pin_node_id              INTEGER,                -- 手动锁定节点，NULL = 自动
    enabled                  INTEGER NOT NULL DEFAULT 1,
    auto_failover            INTEGER NOT NULL DEFAULT 1,

    -- ---- HTTP/HTTPS 隧道专用（tcp/udp 恒为空）----
    -- 这一组字段存在的理由：http 组**没有远程端口**，它靠「绑定域名」工作 ——
    -- 节点上跑着反代，按请求的 Host 头把流量分到不同隧道。所以它的「身份」
    -- 是域名而不是端口，`desired_remote_port` 对它毫无意义。
    desired_domain           TEXT NOT NULL DEFAULT '',   -- 想在 mefrp 上绑定的域名
    current_domain           TEXT NOT NULL DEFAULT '',   -- mefrp 上实际绑定的（解析后，逗号分隔）
    -- 「隧道类型 × 内网服务协议」的配对，四种合法组合见 mefrp.proxy_create：
    --   http+内网HTTP→空 ｜ http+内网HTTPS→http2https
    --   https+内网HTTP→https2http ｜ https+内网HTTPS→https2https（后两者要证书）
    http_plugin              TEXT NOT NULL DEFAULT '',
    route_locations          TEXT NOT NULL DEFAULT '',   -- 路径路由规则，逗号分隔
    crt_path                 TEXT NOT NULL DEFAULT '',   -- https 隧道：节点侧证书路径
    key_path                 TEXT NOT NULL DEFAULT '',   -- https 隧道：节点侧私钥路径

    -- 这条隧道由哪个 frpc 实例承载。NULL = 还没有挂接。
    -- 解析只有这一级：不兜底、不自动发现（见 engine.frpc_for_tunnel 的说明）。
    frpc_instance_id         INTEGER,

    -- 这条隧道跑在哪个**外部节点**上。NULL = 走 mefrp API 节点（老行为）。
    -- 非 NULL 时引擎完全不碰 mefrp：不比对 proxy、不择优、**永不自动切换** ——
    -- 因为外部节点没有 API，在它上面建不了也删不了隧道，换节点只能靠人点。
    manual_node_id           INTEGER,

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
    -- 这个实例当前接在哪个**外部节点**上。NULL = 走 mefrp API（老行为）。
    -- 非 NULL 时它的配置文件由「手动切换」维护（切换/绑定时改写），
    -- 引擎**不会**自动改写它 —— 手工模式的语义就是手工。
    manual_node_id INTEGER,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

-- 外部节点：由用户粘贴的 frpc 配置导入，**与 mefrp API 节点同级**。
--
-- 为什么需要它：mefrp 有开放 API，节点能查、隧道能建能删，所以引擎可以自动择优、
-- 自动故障转移。但**其它 frp 服务商和自建 frps 根本没有 API**，唯一的真相来源就是
-- 用户手上那份 frpc 配置。导入之后它和 mefrp 节点一样出现在节点列表里，能绑 frpc
-- 实例、能绑域名 —— 唯独**不支持自动切换**：没有 API 就没法在服务端建/删隧道，
-- 换节点只能靠人手动点。
--
-- config_text 存的是**导入时的原文**。手工切换时以它为底改写 server 段，
-- 这样用户的注释和排版不会在来回切换中被磨掉。
CREATE TABLE IF NOT EXISTS manual_nodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    server_addr   TEXT NOT NULL,
    server_port   INTEGER NOT NULL DEFAULT 7000,
    auth_method   TEXT NOT NULL DEFAULT 'none',    -- token | user | none
    auth_token    TEXT DEFAULT '',
    auth_user     TEXT DEFAULT '',
    config_format TEXT NOT NULL DEFAULT 'toml',    -- toml | ini
    config_text   TEXT NOT NULL DEFAULT '',
    note          TEXT DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
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

    ⚠️ 每加一个新列都要往下面这张表里补一行，否则老库升上来会缺列。
       判断「列在不在」用的是 PRAGMA，不是 try/except —— ALTER 失败的原因
       很多（锁、磁盘），不能一律当成「列已存在」吞掉。
    """
    conn = _db()
    wanted = (
        ("tunnels", "frpc_instance_id", "INTEGER"),
        ("tunnels", "manual_node_id", "INTEGER"),
        ("tunnels", "tag", "TEXT NOT NULL DEFAULT ''"),
        ("frpc_instances", "manual_node_id", "INTEGER"),
        # ---- 1.0.2：HTTP/HTTPS 隧道 ----
        ("tunnels", "desired_domain", "TEXT NOT NULL DEFAULT ''"),
        ("tunnels", "current_domain", "TEXT NOT NULL DEFAULT ''"),
        ("tunnels", "http_plugin", "TEXT NOT NULL DEFAULT ''"),
        ("tunnels", "route_locations", "TEXT NOT NULL DEFAULT ''"),
        ("tunnels", "crt_path", "TEXT NOT NULL DEFAULT ''"),
        ("tunnels", "key_path", "TEXT NOT NULL DEFAULT ''"),
    )
    for table, col, decl in wanted:
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            conn.commit()
            # ⚠️ 只在「这一列刚被加出来」的那一次回填。放无条件 UPDATE 的话，
            #    用户手动把某条 mefrp 隧道的标签清空后，下次重启又会被打回
            #    'mefrp' —— 一个静默覆盖用户设置的 bug。
            if (table, col) == ("tunnels", "tag"):
                conn.execute(
                    "UPDATE tunnels SET tag = 'mefrp' "
                    "WHERE manual_node_id IS NULL AND (tag IS NULL OR tag = '')"
                )
                conn.commit()

    _drop_tunnels_scope_uniques(conn)


# 隧道表上**不该有**唯一约束的两列：它们的唯一性范围是「同一台 frps 内」，
# 而不同运营商（mefrp / 自建 frps / 别家服务商）的命名空间互不相干。
#   · name       展示名，连作用域内的唯一性都不需要 —— 它只是个标签。
#   · proxy_name 隧道名，唯一性由 find_tunnel_by_proxy 按作用域把关，
#                不能靠数据库的全局 UNIQUE（那会把别家的同名隧道也挡掉）。
_SCOPE_UNIQUE_COLUMNS = ("name", "proxy_name")


def _tunnels_ddl(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'tunnels'"
    ).fetchone()
    return str(row["sql"] or "") if row else ""


def _sql_code(sql: str) -> str:
    """去掉 SQL 里的 `--` 行尾注释 —— 判断关键字时不能把注释里的字当代码。"""
    return "\n".join(ln.split("--", 1)[0] for ln in sql.splitlines())


def _strip_scope_uniques(ddl: str) -> tuple[str, bool]:
    """把 name / proxy_name 上的 UNIQUE 约束摘掉（列级或表级）。返回 (新 DDL, 有没有改过)。"""
    changed = False
    out: list[str] = []
    for line in ddl.splitlines():
        code, sep, comment = line.partition("--")
        low = code.strip().lower()
        # 表级约束：`UNIQUE (name, proxy_name)` —— 整行丢掉。
        if low.startswith("unique") or (low.startswith("constraint") and "unique" in low):
            changed = True
            continue
        # 列级约束：`name TEXT NOT NULL UNIQUE,` —— 只抠掉 UNIQUE 这个词。
        if any(low.startswith(c + " ") for c in _SCOPE_UNIQUE_COLUMNS) and "unique" in low:
            code = re.sub(r"\s*\bUNIQUE\b", "", code, flags=re.I)
            changed = True
        out.append(code + sep + comment)
    return "\n".join(out), changed


def _drop_tunnels_scope_uniques(conn: sqlite3.Connection) -> None:
    """把 tunnels 上 name / proxy_name 的**全局 UNIQUE** 去掉（整表重建）。

    为什么必须去掉：隧道名的唯一性只在「同一台 frps 内」成立。mefrp 一家时
    proxyName 天然全局唯一，所以这条约束一直没暴露问题；一旦开始纳管**别家
    frps**（命名空间互不相干），它就变成三个实打实的故障：

      · 导入别家的同名隧道被当成「已经纳管过了」，**直接吞掉**，用户导不进来；
      · 展示名被硬改成 `xxx-7`，看不出它原本叫什么；
      · 用户手动改成已存在的名字 → 撞约束、IntegrityError 冒到接口层变成 500。

    SQLite 不支持 DROP CONSTRAINT，只能整表搬一次。⚠️ 新表的 DDL **从现有
    sqlite_master 里读出来再摘 UNIQUE**，不另写一份 —— 这样列集合、可空性、
    默认值都天然对齐，不会出现「新表 NOT NULL 而老数据是 NULL」这种搬不过去的
    情况（另写一份 DDL 就踩过这个坑：老库 last_ok_at 是 NULL）。
    """
    ddl = _tunnels_ddl(conn)
    if not ddl:
        return
    new_ddl, changed = _strip_scope_uniques(ddl)
    if not changed:
        return

    new_ddl, n = re.subn(
        r"^(\s*CREATE\s+TABLE\s+)(?:IF\s+NOT\s+EXISTS\s+)?[\"'`\[]?tunnels[\"'`\]]?",
        r"\1tunnels_rebuild", new_ddl, count=1, flags=re.I | re.M)
    if n != 1:
        raise RuntimeError("重建 tunnels 表失败：没能把表名换成临时名")
    if re.search(r"\bunique\b", _sql_code(new_ddl), re.I):
        raise RuntimeError("重建 tunnels 表失败：DDL 里还残留 UNIQUE 约束")

    old_cols = [r["name"] for r in conn.execute("PRAGMA table_info(tunnels)")]
    conn.execute("DROP TABLE IF EXISTS tunnels_rebuild")   # 上次搬到一半留下的
    conn.execute(new_ddl)
    new_cols = [r["name"] for r in conn.execute("PRAGMA table_info(tunnels_rebuild)")]
    if old_cols != new_cols:
        conn.execute("DROP TABLE tunnels_rebuild")
        conn.commit()
        raise RuntimeError(f"重建 tunnels 表失败：列对不上 {old_cols} != {new_cols}")

    collist = ",".join(f'"{c}"' for c in old_cols)
    conn.execute(f"INSERT INTO tunnels_rebuild ({collist}) SELECT {collist} FROM tunnels")
    conn.execute("DROP TABLE tunnels")
    conn.execute("ALTER TABLE tunnels_rebuild RENAME TO tunnels")
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
    "tag",
    "desired_remote_port", "pin_node_id", "enabled", "auto_failover",
    # HTTP/HTTPS 专用（tcp/udp 恒为空）—— 见 SCHEMA 里那一节的说明。
    #   desired_domain  用户想绑的域名（http 组的「身份」，等价于 port 组的期望端口）
    #   current_domain  从 mefrp 同步回来的实际绑定域名
    #   http_plugin     隧道类型 × 内网服务协议 的配对
    "desired_domain", "current_domain", "http_plugin",
    "route_locations", "crt_path", "key_path",
    "frpc_instance_id", "manual_node_id",
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


def list_tunnels(enabled_only: bool = False,
                 tag: str | None = None) -> list[dict[str, Any]]:
    """列出受管隧道。

    `tag` 给了就只回这个标签的（空串 = 筛「没打标签」的）；`None` = 不过滤。
    ⚠️ 用 `tag is None` 而不是 `if tag` 判断 —— 否则「筛没标签的」这个诉求
       会被当成「不过滤」，永远回全量。
    """
    sql = "SELECT * FROM tunnels"
    where: list[str] = []
    params: list[Any] = []
    if enabled_only:
        where.append("enabled = 1")
    if tag is not None:
        where.append("tag = ?")
        params.append(tag)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id"
    with _LOCK:
        rows = _db().execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def list_tags() -> list[dict[str, Any]]:
    """所有用到的标签 + 各自的隧道条数，按条数降序。

    空标签（没打标签）**不返回** —— 它不是一个标签，前端用「全部」来表达。
    """
    with _LOCK:
        rows = _db().execute(
            "SELECT tag, COUNT(*) AS n FROM tunnels "
            "WHERE tag IS NOT NULL AND tag != '' "
            "GROUP BY tag ORDER BY n DESC, tag"
        ).fetchall()
    return [{"tag": str(r["tag"]), "count": int(r["n"])} for r in rows]


def get_tunnel(tunnel_id: int) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute("SELECT * FROM tunnels WHERE id = ?", (tunnel_id,)).fetchone()
    return dict(row) if row else None


def find_tunnel_by_proxy(proxy_name: str, *,
                         manual_node_id: int | None = None) -> dict[str, Any] | None:
    """在**同一台 frps 的作用域内**按隧道名找。

    ⚠️ 隧道名的唯一性范围是「一台 frps 内」，**不是全局**：

      · mefrp 的「一台 frps」= 整个 mefrp 账号 —— 运营商自己就要求 proxyName 唯一；
      · 外部节点的「一台 frps」= 那个 manual_node。

    不同运营商之间重名完全合法（各家的命名空间互不相干），所以**不能拿全局查** ——
    否则「别家 frps 上恰好同名的隧道」会被误判成「已经纳管过了」，导入时直接被吞掉。

    `manual_node_id=None` 表示 **mefrp 作用域**（外部隧道的这一列非空）。
    刻意做成 keyword-only：调用点必须写出 `manual_node_id=...`，
    免得有人顺手传个位置参数、把作用域搞错还不自知。
    """
    if manual_node_id is None:
        sql = "SELECT * FROM tunnels WHERE proxy_name = ? AND manual_node_id IS NULL"
        params: tuple[Any, ...] = (proxy_name,)
    else:
        sql = "SELECT * FROM tunnels WHERE proxy_name = ? AND manual_node_id = ?"
        params = (proxy_name, int(manual_node_id))
    with _LOCK:
        row = _db().execute(sql, params).fetchone()
    return dict(row) if row else None


def find_tunnel_by_dns_name(record_name: str, *,
                            exclude_id: int | None = None) -> dict[str, Any] | None:
    """按 DNS 记录名找**别的**隧道。

    ⚠️ 和隧道名不一样，DNS 记录名必须**全局唯一**。隧道名的唯一性范围是
    「一台 frps 内」（见 find_tunnel_by_proxy），但 DNS 记录名不是谁的命名
    空间，它是 Cloudflare 上一个实实在在的资源 —— 两条隧道填同一个名字会
    发生这种事：

        两边都在健康路径上每轮同步一次（默认 20 秒）
        → 一个把记录改成节点 A 的地址，另一个改成节点 B 的地址
        → 互相覆盖、无限抖动；日志里只有一行行「DNS 已更新」，
          完全看不出是在打架，而解析结果每 20 秒翻一次面。

    所以这个冲突要**硬拒绝**，没有 overwrite 开关 —— 它不像「同一台 frps 上
    同名」，那种情况还能说谁先谁后，这种情况没有任何合理的语义。

    比对时大小写/首尾空格都归一（DNS 记录名不区分大小写）。
    `exclude_id` 用于「编辑自己」的场景，否则会把自己判成冲突。
    """
    name = (record_name or "").strip().lower()
    if not name:
        return None
    sql = ("SELECT * FROM tunnels"
           " WHERE dns_record_name IS NOT NULL"
           "   AND lower(trim(dns_record_name)) = ?")
    params: list[Any] = [name]
    if exclude_id is not None:
        sql += " AND id <> ?"
        params.append(int(exclude_id))
    with _LOCK:
        row = _db().execute(sql, tuple(params)).fetchone()
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
               "enabled", "note", "manual_node_id")

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
# 外部节点
# ---------------------------------------------------------------------------

MANUAL_NODE_FIELDS = ("name", "server_addr", "server_port", "auth_method",
                      "auth_token", "auth_user", "config_format", "config_text",
                      "note", "enabled")

AUTH_METHODS = ("token", "user", "none")


def list_manual_nodes(enabled_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM manual_nodes"
    if enabled_only:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id"
    with _LOCK:
        rows = _db().execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_manual_node(node_id: int) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute("SELECT * FROM manual_nodes WHERE id = ?",
                            (int(node_id),)).fetchone()
    return dict(row) if row else None


def get_manual_node_by_name(name: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _db().execute("SELECT * FROM manual_nodes WHERE name = ?",
                            (name,)).fetchone()
    return dict(row) if row else None


def find_manual_node_by_addr(addr: str, port: int) -> dict[str, Any] | None:
    """按地址+端口找。导入时用它提示「这个节点已经导过了」。"""
    with _LOCK:
        row = _db().execute(
            "SELECT * FROM manual_nodes WHERE server_addr = ? AND server_port = ?",
            (str(addr), int(port)),
        ).fetchone()
    return dict(row) if row else None


def create_manual_node(data: dict[str, Any]) -> int:
    now = int(time.time())
    cols = [f for f in MANUAL_NODE_FIELDS if f in data]
    vals = [data[f] for f in cols]
    cols += ["created_at", "updated_at"]
    vals += [now, now]
    placeholders = ",".join("?" for _ in cols)
    with _LOCK:
        cur = _db().execute(
            f"INSERT INTO manual_nodes({','.join(cols)}) VALUES ({placeholders})", vals
        )
        _db().commit()
        return int(cur.lastrowid)


def update_manual_node(node_id: int, data: dict[str, Any]) -> None:
    cols = [f for f in MANUAL_NODE_FIELDS if f in data]
    if not cols:
        return
    sets = ",".join(f"{c} = ?" for c in cols)
    vals = [data[c] for c in cols]
    vals.append(int(time.time()))
    with _LOCK:
        _db().execute(
            f"UPDATE manual_nodes SET {sets}, updated_at = ? WHERE id = ?",
            vals + [int(node_id)],
        )
        _db().commit()


def delete_manual_node(node_id: int) -> None:
    """删节点。**不动隧道和实例记录** —— 解绑由调用方决定，见 unbind_* 两个函数。"""
    with _LOCK:
        _db().execute("DELETE FROM manual_nodes WHERE id = ?", (int(node_id),))
        _db().commit()


def list_tunnels_of_manual_node(node_id: int) -> list[dict[str, Any]]:
    with _LOCK:
        rows = _db().execute(
            "SELECT * FROM tunnels WHERE manual_node_id = ? ORDER BY id",
            (int(node_id),),
        ).fetchall()
    return [dict(r) for r in rows]


def count_tunnels_of_manual_node(node_id: int) -> int:
    with _LOCK:
        row = _db().execute(
            "SELECT COUNT(*) AS n FROM tunnels WHERE manual_node_id = ?",
            (int(node_id),),
        ).fetchone()
    return int(row["n"]) if row else 0


def list_instances_of_manual_node(node_id: int) -> list[dict[str, Any]]:
    with _LOCK:
        rows = _db().execute(
            "SELECT * FROM frpc_instances WHERE manual_node_id = ? ORDER BY id",
            (int(node_id),),
        ).fetchall()
    return [dict(r) for r in rows]


def unbind_tunnels_of_manual_node(node_id: int) -> int:
    """把挂在某外部节点上的隧道全部解绑（同时关掉它们的自动切换标记）。

    ⚠️ 删节点前必须调用。留着 manual_node_id 指向一个不存在的节点，下一轮
       引擎就会拿着一份空节点去探测，把健康隧道判成故障。
    """
    with _LOCK:
        cur = _db().execute(
            "UPDATE tunnels SET manual_node_id = NULL WHERE manual_node_id = ?",
            (int(node_id),),
        )
        _db().commit()
        return int(cur.rowcount or 0)


def unbind_instances_of_manual_node(node_id: int) -> int:
    """把指向某外部节点的 frpc 实例解绑（回到 mefrp API 模式）。"""
    with _LOCK:
        cur = _db().execute(
            "UPDATE frpc_instances SET manual_node_id = NULL WHERE manual_node_id = ?",
            (int(node_id),),
        )
        _db().commit()
        return int(cur.rowcount or 0)


# ---------------------------------------------------------------------------
# node prefs
# ---------------------------------------------------------------------------

def list_node_prefs() -> dict[int, dict[str, Any]]:
    # 用显式列名而不是 `SELECT *`：`_migrate` 只加列不删列，老库里可能还留着已经
    # 废弃的列（比如 1.0.2 中途撤掉的 `http_entry`），`SELECT *` 会把它们一并漏给
    # API，前端就拿到一堆没人认识的键。
    with _LOCK:
        rows = _db().execute(
            "SELECT node_id, priority, excluded, note FROM node_prefs").fetchall()
    return {int(r["node_id"]): dict(r) for r in rows}


def upsert_node_pref(node_id: int, priority: int | None = None,
                     excluded: bool | None = None, note: str | None = None) -> None:
    """写某个节点的偏好。`None` = 这一项不动（**不是**清空）。

    ⚠️ 这个「None 表示不改」的约定是必须的：设置页只提交用户真正改过的那几项，
    要是把 None 当成清空，改个优先级就会顺手把排除标记抹掉。
    """
    cur = list_node_prefs().get(
        node_id, {"priority": 100, "excluded": 0, "note": ""})
    priority = cur["priority"] if priority is None else priority
    excluded = cur["excluded"] if excluded is None else int(bool(excluded))
    note = cur["note"] if note is None else note
    with _LOCK:
        _db().execute(
            "INSERT INTO node_prefs(node_id, priority, excluded, note) "
            "VALUES (?,?,?,?) "
            "ON CONFLICT(node_id) DO UPDATE SET "
            "priority = excluded.priority, excluded = excluded.excluded, "
            "note = excluded.note",
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
