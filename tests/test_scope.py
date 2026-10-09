# -*- coding: utf-8 -*-
"""隧道名的唯一性作用域（1.0.1 修 bug）。

**这个 bug 的根因**：`proxy_name`（以及展示名 `name`）被当成了**全局唯一**。
但隧道名的唯一性只在「同一台 frps 内」成立：

  · mefrp 的「一台 frps」= 整个 mefrp 账号 —— 运营商自己就要求 proxyName 唯一；
  · 外部节点的「一台 frps」= 那个 manual_node。

不同运营商之间重名完全合法（命名空间互不相干）。原来的全局查重导致：
导入一份含 `nas-ssh` 的外部配置时，只要 mefrp 上已经有 `nas-ssh`，
这条隧道就会被当成「已经纳管过了」**直接吞掉**，用户根本导不进来。

独立文件 + 独立数据目录（store 是模块级单例）。

⚠️ 所有探测目标都指向 127.0.0.1 上没人监听的端口，连接立刻被拒，不碰外网。
"""

from __future__ import annotations

import base64
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="mg-scope-")
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
from app.engine import engine                       # noqa: E402
from app.mefrp import Proxy                         # noqa: E402
from app import store                               # noqa: E402

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


# 外部节点的配置：隧道名故意叫 nas-ssh —— 和下面那条 mefrp 隧道**同名**。
EXT_CONF = '''serverAddr = "198.51.100.7"
serverPort = 7000

[[proxies]]
name = "nas-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 16022
'''

with TestClient(app) as c:
    print("[1] 先建一条 mefrp 隧道 nas-ssh（走 /api/tunnels）")
    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "nas-ssh", "proxy_name": "nas-ssh", "local_port": 22})
    check("建 mefrp 隧道 200", r.status_code == 200, r.text[:200])
    mefrp_tid = r.json()["id"]

    print("[2] ★ 导入一份含**同名**隧道的外部配置")
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": EXT_CONF,
        "proxies": [{"name": "nas-ssh", "adopt": True, "dns_record_name": ""}]})
    check("导入 200", r.status_code == 200, r.text[:300])
    d = r.json()
    nid = d["id"]
    check("★ 同名隧道**没有被跳过**", d["adopted"] == ["nas-ssh"], d)
    check("★ 也没有被跳过理由", d["skipped"] == [], d["skipped"])

    rows = c.get("/api/tunnels", headers=AUTH).json()
    same = [t for t in rows if t["proxy_name"] == "nas-ssh"]
    check("★ 两条同名隧道并存", len(same) == 2, same)
    check("★ 外部那条的展示名就是本名（没被改成 xxx-数字）",
          all(t["name"] == "nas-ssh" for t in same), [t["name"] for t in same])
    check("★ 两条分属不同作用域",
          {t["manual_node_id"] for t in same} == {None, nid},
          [t["manual_node_id"] for t in same])

    print("[3] ★ 展示名重名不再触发 UNIQUE（以前会 500）")
    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "nas-ssh", "proxy_name": "another-one", "local_port": 23})
    check("★ 再建一条同名展示名 -> 200（不是 500）", r.status_code == 200, r.text[:200])
    dup_tid = r.json()["id"]
    r = c.patch(f"/api/tunnels/{dup_tid}", headers=AUTH, json={"name": "nas-ssh"})
    check("★ 改名成已存在的展示名 -> 200（不是 500）", r.status_code == 200, r.text[:200])

    print("[4] mefrp 作用域内 proxy_name 仍然唯一")
    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "又一条", "proxy_name": "nas-ssh", "local_port": 24})
    check("mefrp 内重名 proxy_name -> 400", r.status_code == 400, r.text[:200])

    print("[5] 作用域查重：两个作用域各查各的")
    hit_me = store.find_tunnel_by_proxy("nas-ssh")
    hit_ext = store.find_tunnel_by_proxy("nas-ssh", manual_node_id=nid)
    check("mefrp 作用域查到的是 mefrp 那条",
          hit_me is not None and hit_me["id"] == mefrp_tid, hit_me)
    check("★ 外部作用域查到的是外部那条",
          hit_ext is not None and hit_ext["manual_node_id"] == nid, hit_ext)
    check("★ 两个作用域查到的不是同一条", hit_me["id"] != hit_ext["id"], (hit_me, hit_ext))
    check("★ 另一个外部节点上查不到（作用域隔离）",
          store.find_tunnel_by_proxy("nas-ssh", manual_node_id=nid + 999) is None)

    print("[6] ★ /api/orphans 不被同名的外部隧道干扰")
    # 造一条 mefrp 上真实存在、但本地**没纳管**的 proxy，名字故意和一条外部隧道重名。
    # 这就是原来那个 bug 的第二个面相：managed 集合原来是把所有隧道的 proxy_name
    # 都算进去的，于是这条真·未纳管的 mefrp 隧道会被「同名的那条外部隧道」藏掉，
    # 用户在「未纳管」列表里永远看不到它。
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": EXT_CONF.replace('serverAddr = "198.51.100.7"',
                                 'serverAddr = "203.0.113.9"')
                         .replace('name = "nas-ssh"', 'name = "orphan-panel"'),
        "proxies": [{"name": "orphan-panel", "adopt": True, "dns_record_name": ""}]})
    check("第二条外部配置导入 200", r.status_code == 200, r.text[:300])
    engine.proxies = {
        "orphan-panel": Proxy(proxy_id=4242, proxy_name="orphan-panel",
                              proxy_type="tcp", node_id=9, local_ip="127.0.0.1",
                              local_port=8080, remote_port=18080, is_online=True),
    }
    try:
        orph = c.get("/api/orphans", headers=AUTH).json()
        check("★ 真·未纳管的 mefrp 隧道仍然列得出来（没被同名外部隧道藏掉）",
              any(p["proxy_name"] == "orphan-panel" for p in orph), orph)
    finally:
        engine.proxies = {}

    print("[6b] ★ 立即探测也按作用域分流（不能拿 proxy_name 去 mefrp 的列表里找）")
    # 再导入一份配置，地址用 127.0.0.1（探测会立刻被拒，不占测试时间）。
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": EXT_CONF.replace('serverAddr = "198.51.100.7"',
                                 'serverAddr = "127.0.0.1"')
                         .replace('name = "nas-ssh"', 'name = "probe-me"')
                         .replace("remotePort = 16022", "remotePort = 16099"),
        "proxies": [{"name": "probe-me", "adopt": True, "dns_record_name": ""}]})
    check("第三条外部配置导入 200", r.status_code == 200, r.text[:300])
    nid3 = r.json()["id"]
    ext3 = [t for t in c.get("/api/tunnels", headers=AUTH).json()
            if t["manual_node_id"] == nid3][0]

    # 造一条**同名**的 mefrp proxy，指向一个本地根本不存在的节点。
    # 探测端点要是还按名字去 mefrp 的列表里查，就会拿它的 node/端口去探 ——
    # 探的是一条完全不相干的隧道，而且「节点不在列表里」这种报错也解释不通。
    engine.proxies = {
        "probe-me": Proxy(proxy_id=777, proxy_name="probe-me", proxy_type="tcp",
                          node_id=9, local_ip="127.0.0.1", local_port=22,
                          remote_port=16099, is_online=True),
        # 顺手把那条同名的 mefrp proxy 也放进来，好反证两条路走的是不同分支。
        "nas-ssh": Proxy(proxy_id=778, proxy_name="nas-ssh", proxy_type="tcp",
                         node_id=9, local_ip="127.0.0.1", local_port=22,
                         remote_port=16022, is_online=True),
    }
    try:
        r = c.post(f"/api/tunnels/{ext3['id']}/probe", headers=AUTH)
        check("外部隧道探测 200", r.status_code == 200, r.text[:200])
        d = r.json()
        check("★ 探测目标是外部节点的地址（不是 mefrp 那条）",
              d["target"] == "127.0.0.1:16099", d)
        check("★ 报的节点名是外部节点（不是 mefrp 节点）",
              d["node"] == "127.0.0.1:7000", d)

        # 反证：同名的 mefrp 隧道走的是**另一条**分支（去查 mefrp 的节点表）。
        r = c.post(f"/api/tunnels/{mefrp_tid}/probe", headers=AUTH)
        check("★ 同名 mefrp 隧道走的是 mefrp 分支（节点 9 不在列表 -> 404）",
              r.status_code == 404 and "9" in r.text, (r.status_code, r.text[:200]))
    finally:
        engine.proxies = {}

    print("[6c] ★ 解析预览的「已纳管」判定也要按作用域")
    # 同一份含 nas-ssh 的外部配置：mefrp 上确实有一条受管的 nas-ssh，
    # 但那是**另一个命名空间**里的事，不该把这条标成「不可勾选」。
    # （这就是用户报的那个 bug 在预览层的样子：隧道明明能导，勾选框却是灰的。）
    p = c.post("/api/manual-nodes/parse", headers=AUTH,
               json={"text": EXT_CONF}).json()
    check("★ 新建时 taken_names 为空（新节点 = 新命名空间，里面什么都没有）",
          p["taken_names"] == [], p["taken_names"])
    # 反过来：在**已经纳管了 nas-ssh 的那个节点**的语境下解析，就该报「已纳管」。
    p = c.post("/api/manual-nodes/parse", headers=AUTH,
               json={"text": EXT_CONF, "node_id": nid}).json()
    check("★ 在正确的作用域里解析 -> 报已纳管",
          p["taken_names"] == ["nas-ssh"], p["taken_names"])

print()
print("=" * 70)
print("[7] 老库迁移：tunnels.name 的全局 UNIQUE 要被去掉（整表重建）")

MIG_DIR = tempfile.mkdtemp(prefix="mg-scope-mig-")
MIG_DB = os.path.join(MIG_DIR, "guard.db")

# 老库的结构：name 和 proxy_name 上都挂着全局 UNIQUE（就是这次要去掉的那两条）。
_OLD_SCHEMA = """
CREATE TABLE tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    proxy_name TEXT NOT NULL UNIQUE,
    tag TEXT NOT NULL DEFAULT '',
    proxy_type TEXT NOT NULL DEFAULT 'tcp',
    local_ip TEXT NOT NULL DEFAULT '127.0.0.1', local_port INTEGER NOT NULL,
    desired_remote_port INTEGER, current_remote_port INTEGER,
    current_node_id INTEGER, current_proxy_id INTEGER,
    pin_node_id INTEGER, frpc_instance_id INTEGER, manual_node_id INTEGER,
    dns_record_name TEXT DEFAULT '', dns_proxied INTEGER NOT NULL DEFAULT 0,
    downstream_note TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
    auto_failover INTEGER NOT NULL DEFAULT 1,
    fail_streak INTEGER NOT NULL DEFAULT 0, last_error TEXT DEFAULT '',
    last_ok_at INTEGER NOT NULL DEFAULT 0, last_failover_at INTEGER NOT NULL DEFAULT 0,
    needs_downstream_review INTEGER NOT NULL DEFAULT 0,
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
INSERT INTO tunnels (id,name,proxy_name,local_port,tag,created_at,updated_at)
    VALUES (7,'老隧道','old-a',1234,'mefrp',1,1);
INSERT INTO tunnels (id,name,proxy_name,local_port,tag,created_at,updated_at)
    VALUES (8,'老隧道二','old-b',1235,'',1,1);
"""

_conn0 = sqlite3.connect(MIG_DB)
_conn0.executescript(_OLD_SCHEMA)
_conn0.commit()
_conn0.close()

_MIG_CODE = f'''
import os, sys, sqlite3
os.environ["MG_DATA_DIR"] = {MIG_DIR!r}
sys.path.insert(0, {str(ROOT)!r})
from app import store
store.init()
conn = sqlite3.connect({MIG_DB!r}); conn.row_factory = sqlite3.Row
ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='tunnels'").fetchone()["sql"]
code = "\\n".join(l.split("--",1)[0] for l in ddl.splitlines())
print("NO_UNIQUE_AT_ALL", "unique" not in code.lower())
rows = [dict(r) for r in conn.execute("SELECT id,name,proxy_name,tag FROM tunnels ORDER BY id")]
print("N_ROWS", len(rows))
print("ROW7", rows[0]["id"], rows[0]["name"], rows[0]["proxy_name"], rows[0]["tag"])
print("ROW8", rows[1]["id"], rows[1]["name"], rows[1]["proxy_name"], repr(rows[1]["tag"]))
# 重建之后必须能插两条同名 —— 这正是这次要修的东西
conn.execute("INSERT INTO tunnels (name,proxy_name,local_port,created_at,updated_at)"
             " VALUES ('老隧道','old-c',1236,1,1)")
conn.commit()
n = conn.execute("SELECT COUNT(*) AS n FROM tunnels WHERE name='老隧道'").fetchone()["n"]
print("DUP_OK", n)
# 同名 proxy_name 也要能插（跨作用域重名，数据库层不该拦）
conn.execute("INSERT INTO tunnels (name,proxy_name,local_port,created_at,updated_at)"
             " VALUES ('另取一名','old-a',1237,1,1)")
conn.commit()
m = conn.execute("SELECT COUNT(*) AS n FROM tunnels WHERE proxy_name='old-a'").fetchone()["n"]
print("DUP_PROXY_OK", m)
# 列一个都不能少
cols = {{r["name"] for r in conn.execute("PRAGMA table_info(tunnels)")}}
print("HAS_TAG", "tag" in cols)
print("HAS_MANUAL", "manual_node_id" in cols)
print("HAS_FRPC", "frpc_instance_id" in cols)
'''

p = subprocess.run([sys.executable, "-c", _MIG_CODE], capture_output=True, text=True)
out: dict = {}
for ln in p.stdout.strip().splitlines():
    if " " in ln:
        k, v = ln.split(" ", 1)
        out[k] = v
check("迁移子进程正常退出", p.returncode == 0, p.stderr[-600:])
check("★ name / proxy_name 上的 UNIQUE 都已去掉",
      out.get("NO_UNIQUE_AT_ALL") == "True", out)
check("★ 老数据没丢（还是 2 条）", out.get("N_ROWS") == "2", out)
check("★ 主键 id 原样保留", out.get("ROW7", "").startswith("7 "), out)
check("★ 标签原样保留（mefrp）", out.get("ROW7", "").endswith("mefrp"), out)
check("★ 空标签原样保留", out.get("ROW8", "").endswith("''"), out)
check("★ 重建后可以插入同名展示名", out.get("DUP_OK") == "2", out)
check("★ 重建后可以插入同名 proxy_name", out.get("DUP_PROXY_OK") == "2", out)
check("列没丢：tag", out.get("HAS_TAG") == "True", out)
check("列没丢：manual_node_id", out.get("HAS_MANUAL") == "True", out)
check("列没丢：frpc_instance_id", out.get("HAS_FRPC") == "True", out)

# ---------------------------------------------------------------------------
# [7b] ★ 真正的 1.0.0 库：**既要补列、又要摘 UNIQUE**，两件事同一次 init() 里做对
#
# [7] 用的 schema 是「1.0.1 中途」的状态 —— 已经有 tag / manual_node_id 了，
# 只考验整表重建。而用户手上真正的是 **1.0.0**：tunnels.name 和 proxy_name 上
# 都挂着全局 UNIQUE、没有 tag、没有 manual_node_id、连 manual_nodes 表都不存在。
#
# 顺序是有讲究的：必须**先 ALTER 补列、再从补完列之后的 DDL 派生新表**。
# 反过来的话重建出来的表会缺列，整个升级直接炸。这个用例就是钉住这个顺序。
# ---------------------------------------------------------------------------
print()
print("[7b] ★ 真正的 1.0.0 老库：补列 + 摘 UNIQUE 两件事一起来")

MIG2_DIR = tempfile.mkdtemp(prefix="mg-scope-mig100-")
MIG2_DB = os.path.join(MIG2_DIR, "guard.db")

# 1.0.0 的 schema：name / proxy_name 都有全局 UNIQUE，没有 tag / manual_node_id，
# 没有 manual_nodes 表。行数据刻意造两条**不同名**的隧道（老库里本来就撞不了名，
# 否则 UNIQUE 早就拦住了），外加一个 frpc 实例。
_OLD100 = """
CREATE TABLE tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    proxy_name TEXT NOT NULL UNIQUE,
    proxy_type TEXT NOT NULL DEFAULT 'tcp',
    local_ip TEXT NOT NULL DEFAULT '127.0.0.1', local_port INTEGER NOT NULL,
    desired_remote_port INTEGER, current_remote_port INTEGER,
    current_node_id INTEGER, current_proxy_id INTEGER,
    pin_node_id INTEGER, frpc_instance_id INTEGER,
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
INSERT INTO tunnels (id,name,proxy_name,local_port,current_remote_port,
                     created_at,updated_at)
    VALUES (2,'ikuai_ovpn','ikuai_ovpn',58002,48518,1,1);
INSERT INTO tunnels (id,name,proxy_name,local_port,created_at,updated_at)
    VALUES (3,'39KTO11_rdp','39KTO11_rdp',57111,1,1);
INSERT INTO frpc_instances (id,name,config_path,created_at,updated_at)
    VALUES (1,'默认','/frpc/a/frpc.toml',1,1);
"""

_c = sqlite3.connect(MIG2_DB)
_c.executescript(_OLD100)
_c.commit()
_c.close()

_MIG2_CODE = f'''
import os, sys, sqlite3
os.environ["MG_DATA_DIR"] = {MIG2_DIR!r}
sys.path.insert(0, {str(ROOT)!r})
from app import store
store.init()
conn = sqlite3.connect({MIG2_DB!r}); conn.row_factory = sqlite3.Row
ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='tunnels'").fetchone()["sql"]
code = "\\n".join(l.split("--",1)[0] for l in ddl.splitlines())
print("NO_UNIQUE", "unique" not in code.lower())
cols = {{r["name"] for r in conn.execute("PRAGMA table_info(tunnels)")}}
print("HAS_TAG", "tag" in cols)
print("HAS_MANUAL", "manual_node_id" in cols)
inst = {{r["name"] for r in conn.execute("PRAGMA table_info(frpc_instances)")}}
print("INST_MANUAL", "manual_node_id" in inst)
mn = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manual_nodes'").fetchone()
print("MANUAL_TABLE", bool(mn))
rows = [dict(r) for r in conn.execute(
    "SELECT id,name,proxy_name,local_port,current_remote_port,tag,manual_node_id"
    " FROM tunnels ORDER BY id")]
print("N_ROWS", len(rows))
print("ROW2", rows[0]["id"], rows[0]["name"], rows[0]["proxy_name"],
      rows[0]["local_port"], rows[0]["current_remote_port"], rows[0]["tag"])
print("ROW3", rows[1]["id"], rows[1]["name"], rows[1]["tag"])
print("ROW2_MANUAL", rows[0]["manual_node_id"])
# 补列之后 tag 要按「老库里的隧道都是 mefrp 的」回填一次
print("BACKFILL", sum(1 for r in rows if r["tag"] == "mefrp"))
# 摘掉 UNIQUE 之后，两条同名都能插
conn.execute("INSERT INTO tunnels (name,proxy_name,local_port,created_at,updated_at)"
             " VALUES ('ikuai_ovpn','ikuai_ovpn',58002,1,1)")
conn.commit()
print("DUP_OK", conn.execute(
    "SELECT COUNT(*) AS n FROM tunnels WHERE name='ikuai_ovpn'").fetchone()["n"])
# 主键序列不能被重建搞坏（否则下一条新隧道会撞 id）
cur = conn.execute("INSERT INTO tunnels (name,proxy_name,local_port,created_at,updated_at)"
                   " VALUES ('新的','brand-new',1234,1,1)")
conn.commit()
print("NEW_ID_GT_3", cur.lastrowid > 3)
print("INST_OK", conn.execute(
    "SELECT name FROM frpc_instances WHERE id=1").fetchone()["name"])
'''

p2 = subprocess.run([sys.executable, "-c", _MIG2_CODE], capture_output=True, text=True)
o2: dict = {}
for ln in p2.stdout.strip().splitlines():
    if " " in ln:
        k, v = ln.split(" ", 1)
        o2[k] = v
check("1.0.0 升级子进程正常退出", p2.returncode == 0, p2.stderr[-800:])
check("★ 1.0.0 的库升上来后 UNIQUE 都没了",
      o2.get("NO_UNIQUE") == "True", o2)
check("★ 补上了 tag 列", o2.get("HAS_TAG") == "True", o2)
check("★ 补上了 tunnels.manual_node_id", o2.get("HAS_MANUAL") == "True", o2)
check("★ 补上了 frpc_instances.manual_node_id", o2.get("INST_MANUAL") == "True", o2)
check("★ manual_nodes 表被建出来", o2.get("MANUAL_TABLE") == "True", o2)
check("★ 两条老隧道都在", o2.get("N_ROWS") == "2", o2)
check("★ 老行逐字段原样保留",
      o2.get("ROW2", "") == "2 ikuai_ovpn ikuai_ovpn 58002 48518 mefrp", o2)
check("★ 老库里的隧道被回填成 mefrp 标签", o2.get("BACKFILL") == "2", o2)
check("★ 老行的 manual_node_id 保持 NULL", o2.get("ROW2_MANUAL") == "None", o2)
check("★ 升级后能插同名（原来会 IntegrityError）", o2.get("DUP_OK") == "2", o2)
check("★ 自增序列没被重建搞坏", o2.get("NEW_ID_GT_3") == "True", o2)
check("★ frpc 实例老数据没丢", o2.get("INST_OK") == "默认", o2)

print()
print(f"==> PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
