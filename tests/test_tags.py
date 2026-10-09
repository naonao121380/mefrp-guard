# -*- coding: utf-8 -*-
"""隧道标签（1.0.1）HTTP 端点测试：读写 / 归一化 / 筛选 / 默认打标 / 老库回填。

独立文件 + 独立数据目录 —— store 是模块级单例，和别的测试放同一进程会互相污染。

标签本身不参与任何自愈逻辑，它只是隧道上的一个自由字段。但有两处**容易写错**
且后果隐蔽的地方，这里专门盯住：

  · `?tag=`（空串）必须能筛出「没打标签的隧道」，不能被当成「不过滤」；
  · 老库升上来时 mefrp 隧道要自动补 'mefrp'，而且**只补一次** ——
    无条件 UPDATE 的话，用户手动清掉的标签每次重启都会被打回来。
"""

from __future__ import annotations

import base64
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="mg-tags-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
    MG_WEB_USER="admin",
    MG_WEB_PASSWORD="s3cret-pass",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient          # noqa: E402
from app.main import app                            # noqa: E402

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret-pass").decode()}
PASS = FAIL = 0


def check(name: str, cond: bool, extra: object = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  ->  {extra}")


def mk(c, name: str, tag=None) -> int:
    body = {"name": name, "proxy_name": name, "local_port": 8000}
    if tag is not None:
        body["tag"] = tag
    r = c.post("/api/tunnels", headers=AUTH, json=body)
    assert r.status_code == 200, r.text
    return int(r.json()["id"])


with TestClient(app) as c:
    print("[1] 鉴权")
    check("未登录 /api/tags -> 401", c.get("/api/tags").status_code == 401)
    check("登录后 200", c.get("/api/tags", headers=AUTH).status_code == 200)

    print("[2] 空库")
    check("空库时没有标签", c.get("/api/tags", headers=AUTH).json() == [],
          c.get("/api/tags", headers=AUTH).json())

    print("[3] 建隧道：默认打 mefrp")
    t1 = mk(c, "tun-a")           # 不带 tag
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t1][0]
    check("★ 不传 tag 时默认 'mefrp'", row["tag"] == "mefrp", row.get("tag"))

    print("[4] 建隧道：自定义标签原样保留")
    t2 = mk(c, "tun-b", tag="公司frps")
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t2][0]
    check("自定义标签保留", row["tag"] == "公司frps", row.get("tag"))

    print("[5] 归一化：首尾空白 / 内部连续空白 / 超长")
    t3 = mk(c, "tun-c", tag="  mefrp  ")
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t3][0]
    check("★ '  mefrp  ' 归一到 'mefrp'", row["tag"] == "mefrp", row.get("tag"))
    t4 = mk(c, "tun-d", tag="a   b")
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t4][0]
    check("内部连续空白折成一个", row["tag"] == "a b", row.get("tag"))
    t5 = mk(c, "tun-e", tag="x" * 80)
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t5][0]
    check("超长截到 32 字符", len(row["tag"]) == 32, len(row.get("tag") or ""))

    print("[6] /api/tags：计数与排序")
    tags = {x["tag"]: x["count"] for x in c.get("/api/tags", headers=AUTH).json()}
    check("mefrp 计到 2 条", tags.get("mefrp") == 2, tags)
    check("公司frps 计到 1 条", tags.get("公司frps") == 1, tags)
    check("a b 计到 1 条", tags.get("a b") == 1, tags)
    check("★ 空标签不出现在标签列表里", "" not in tags, tags)
    raw = c.get("/api/tags", headers=AUTH).json()
    check("按条数降序（mefrp 在最前）", raw and raw[0]["tag"] == "mefrp", raw)

    print("[7] 按标签筛选")
    r = c.get("/api/tunnels", headers=AUTH, params={"tag": "mefrp"})
    got = {t["id"] for t in r.json()}
    check("tag=mefrp 命中 2 条", got == {t1, t3}, got)
    r = c.get("/api/tunnels", headers=AUTH, params={"tag": "公司frps"})
    check("tag=中文 命中 1 条", {t["id"] for t in r.json()} == {t2}, r.json())
    r = c.get("/api/tunnels", headers=AUTH, params={"tag": "  mefrp  "})
    check("★ 筛选值也归一化（'  mefrp  ' 能命中）",
          {t["id"] for t in r.json()} == {t1, t3}, r.json())
    r = c.get("/api/tunnels", headers=AUTH, params={"tag": "不存在的标签"})
    check("不存在的标签 -> 空列表", r.json() == [], r.json())

    print("[8] 显式清空标签 + 用空串筛「没打标签的」")
    r = c.patch(f"/api/tunnels/{t2}", headers=AUTH, json={"tag": ""})
    check("PATCH tag='' 成功", r.status_code == 200, r.text[:200])
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t2][0]
    check("★ 标签被清空（不是被忽略）", row["tag"] == "", row.get("tag"))
    r = c.get("/api/tunnels", headers=AUTH, params={"tag": ""})
    check("★ ?tag= 筛出「没打标签的」而不是全量",
          {t["id"] for t in r.json()} == {t2}, r.json())
    check("★ 不带 ?tag= 时才是全量",
          len(c.get("/api/tunnels", headers=AUTH).json()) == 5)

    print("[9] PATCH 改标签 / 传 null 等价于清空")
    c.patch(f"/api/tunnels/{t1}", headers=AUTH, json={"tag": "临时"})
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t1][0]
    check("改成新标签", row["tag"] == "临时", row.get("tag"))
    c.patch(f"/api/tunnels/{t1}", headers=AUTH, json={"tag": None})
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t1][0]
    check("传 null 也清空", row["tag"] == "", row.get("tag"))
    # 反例：PATCH 里完全不提 tag，不该把它清掉
    c.patch(f"/api/tunnels/{t1}", headers=AUTH, json={"tag": "保留我"})
    c.patch(f"/api/tunnels/{t1}", headers=AUTH, json={"local_port": 8001})
    row = [t for t in c.get("/api/tunnels", headers=AUTH).json() if t["id"] == t1][0]
    check("★ 不传 tag 字段时标签不受影响", row["tag"] == "保留我", row.get("tag"))

    print("[10] overview 里也带标签")
    ov = c.get("/api/overview", headers=AUTH).json()
    ovrow = [t for t in ov["tunnels"] if t["id"] == t1][0]
    check("overview 隧道项带 tag", ovrow.get("tag") == "保留我", ovrow.get("tag"))

# ===========================================================================
# 十一、老库迁移：加列 + 一次性回填
# ===========================================================================

print("[11] 老库迁移：补 tag 列并只回填一次")

MIG_DIR = tempfile.mkdtemp(prefix="mg-tag-mig-")
MIG_DB = os.path.join(MIG_DIR, "guard.db")

# 1.0.1 的 schema —— 有 manual_node_id，但**没有 tag**。
# 这正是这次升级要面对的真实起点：老库里已经有一条 mefrp 隧道（manual_node_id
# 为 NULL）和一条外部节点隧道（manual_node_id 非 NULL）。
_OLD_SCHEMA = """
CREATE TABLE tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, proxy_name TEXT NOT NULL UNIQUE,
    proxy_type TEXT NOT NULL DEFAULT 'tcp',
    local_ip TEXT NOT NULL DEFAULT '127.0.0.1', local_port INTEGER NOT NULL,
    desired_remote_port INTEGER, current_remote_port INTEGER,
    current_node_id INTEGER, current_proxy_id INTEGER,
    pin_node_id INTEGER, frpc_instance_id INTEGER, manual_node_id INTEGER,
    dns_record_name TEXT DEFAULT '', dns_proxied INTEGER NOT NULL DEFAULT 0,
    downstream_note TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
    auto_failover INTEGER NOT NULL DEFAULT 1,
    fail_streak INTEGER NOT NULL DEFAULT 0, last_error TEXT DEFAULT '',
    last_ok_at INTEGER, needs_downstream_review INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE frpc_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, config_path TEXT NOT NULL UNIQUE,
    container TEXT DEFAULT '', restart_mode TEXT NOT NULL DEFAULT 'docker',
    note TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
    manual_node_id INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
    level TEXT NOT NULL, kind TEXT NOT NULL, tunnel_id INTEGER,
    message TEXT NOT NULL, detail TEXT DEFAULT ''
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    user_agent TEXT DEFAULT '', ip TEXT DEFAULT ''
);
INSERT INTO tunnels (name,proxy_name,local_port,manual_node_id,created_at,updated_at)
    VALUES ('老mefrp隧道','old-mefrp',1234,NULL,1,1);
INSERT INTO tunnels (name,proxy_name,local_port,manual_node_id,created_at,updated_at)
    VALUES ('老外部隧道','old-manual',1234,7,1,1);
"""

_conn0 = sqlite3.connect(MIG_DB)
_conn0.executescript(_OLD_SCHEMA)
_conn0.commit()
_conn0.close()

_PROBE = f'''
import os, sys, sqlite3
os.environ["MG_DATA_DIR"] = {MIG_DIR!r}
sys.path.insert(0, {str(ROOT)!r})
from app import store
store.init()
conn = sqlite3.connect({MIG_DB!r}); conn.row_factory = sqlite3.Row
cols = {{r["name"] for r in conn.execute("PRAGMA table_info(tunnels)")}}
print("HAS_TAG", "tag" in cols)
for r in conn.execute("SELECT proxy_name, tag FROM tunnels ORDER BY id"):
    print("TAG", r["proxy_name"], repr(r["tag"]))
'''


def run_probe() -> dict:
    p = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr[-600:]
    out: dict = {"TAG": {}}
    for ln in p.stdout.strip().splitlines():
        if ln.startswith("HAS_TAG "):
            out["HAS_TAG"] = ln.split(" ", 1)[1].strip()
        elif ln.startswith("TAG "):
            _, name, val = ln.split(" ", 2)
            out["TAG"][name] = val
    return out


a = run_probe()
check("★ tunnels 补上了 tag 列", a["HAS_TAG"] == "True", a)
check("★ mefrp 隧道被回填 'mefrp'", a["TAG"].get("old-mefrp") == "'mefrp'", a["TAG"])
check("★ 外部节点隧道不回填（留空）", a["TAG"].get("old-manual") == "''", a["TAG"])

# 模拟用户手动清掉标签，再跑一次 init —— 不能被回填打回来。
_c = sqlite3.connect(MIG_DB)
_c.execute("UPDATE tunnels SET tag = '' WHERE proxy_name = 'old-mefrp'")
_c.commit()
_c.close()

b = run_probe()
check("★ 手动清空后重启不会被重新打标", b["TAG"].get("old-mefrp") == "''", b["TAG"])
check("列还在（重复迁移不报错）", b["HAS_TAG"] == "True", b)

print()
print(f"==> PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
