# -*- coding: utf-8 -*-
"""外部节点（1.0.1）纯逻辑测试：配置解析 / 改写保真 / 数据层 / 老库迁移 / 引擎分支。

不碰网络、不依赖第三方库，可以直接跑：

    python tests/test_manual_node.py

这里钉的是这个功能里**最容易出错**的几处：

* **解析**：frpc 配置格式跨版本差别极大（TOML/INI、键名写法、老式插件段）。
  解析错一份配置，用户就会拿一份错的去改自己线上跑的 frpc.toml。
* **改写**：patch_server 是文本级替换，最容易产出**非法文本** ——
  TOML 重复键、顶层键插错位置。这两种都会让整份配置直接解析不了。
* **不自动切换**：外部节点没有 API，切不了。任何「误切」都要被拦住。
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp(prefix="mg-manual-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
)

from app import frpcparse, store                      # noqa: E402
from app.engine import GuardEngine, probe_plan        # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, extra: object = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  ->  {extra}")


class FakeCF:
    """假的 Cloudflare 客户端。

    只记「问过什么、写了什么」，够验证**有没有走到 DNS 同步**这件事 ——
    这里要钉的是分支有没有被跳过，不是 CF 接口本身（那是 cloudflare.py 的事）。
    两个列表分开记：`zone_queries` 空但 `upserts` 非空说明 zone 是从库里读的。
    """

    def __init__(self) -> None:
        # ⚠️ `_sync_dns` 会先看「有没有配 token」再决定要不要往下走，所以假客户端
        #    也得有这个属性 —— 少一个属性会以 AttributeError 炸，而不是「跳过 DNS」。
        self.token = "fake-cf-token"
        self.upserts: list[dict] = []
        self.zone_queries: list[str] = []

    async def resolve_zone(self, name: str):
        from app.cloudflare import Zone
        self.zone_queries.append(name)
        return Zone(zone_id="ZTEST", name="example.com")

    async def list_records(self, zone_id: str, name: str | None = None):
        return []

    async def upsert(self, **kw):
        from app.cloudflare import DnsRecord
        self.upserts.append(kw)
        return DnsRecord(kw.get("record_id") or "R1", kw["zone_id"], kw["name"],
                         kw["record_type"], kw["content"], kw.get("proxied", False))


# ===========================================================================
# 一、解析：TOML（frpc >= 0.52）
# ===========================================================================

TOML_STD = '''# 我的 frpc 配置
serverAddr = "1.2.3.4"
serverPort = 7000

auth.method = "token"
auth.token = "abc123"

[[proxies]]
name = "nas-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 16022

[[proxies]]
name = "nas-web"
type = "tcp"
localIP = "127.0.0.1"
localPort = 5000
remotePort = 16080
'''

# 老式写法：token 直接写顶层（frpc 0.4x 的写法，很多人一直没改）。
# 隧道仍然是 [[proxies]] 数组 —— TOML 时代从来就是这样。
TOML_LEGACY = '''server_addr = "5.6.7.8"
server_port = 7100
token = "legacy-tok"
user = "demo"

[[proxies]]
name = "git"
type = "tcp"
local_ip = "10.0.0.5"
local_port = 3000
remote_port = 13000
'''

# ★ 把 [[proxies]] 写成 [proxies]（少一对方括号）—— 用户很容易写错，
#   而 frpc 那边会直接不生效。解析器必须报警告，不能静默当成 0 条隧道。
TOML_WRONG_PROXIES = '''serverAddr = "1.2.3.4"
serverPort = 7000

[proxies]
name = "写错了"
type = "tcp"
localPort = 22
remotePort = 16022
'''

# 有人写成 [auth] 表
TOML_AUTH_TABLE = '''serverAddr = "9.9.9.9"
serverPort = 7000

[auth]
method = "token"
token = "table-tok"

[[proxies]]
name = "p1"
type = "tcp"
localPort = 80
remotePort = 8080
'''

INI_STD = '''[common]
server_addr = 1.2.3.4
server_port = 7000
token = ini-token

[nas-ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 16022

[nas-web]
type = tcp
local_ip = 127.0.0.1
local_port = 5000
remote_port = 16080
'''

# ⚠️ 老 frpc 的插件段**照样带 `type = tcp`**。用「有没有 type」判断插件段
#    会全部漏判，所以判据必须是「有没有 plugin 键」或「段名以 plugin_ 开头」。
INI_PLUGIN = '''[common]
server_addr = 1.2.3.4
server_port = 7000

[ssh-via-plugin]
type = tcp
remote_port = 16022
plugin = socks5

[plugin_https2http]
type = tcp
remote_port = 16080
plugin = https2http
plugin_local_addr = 127.0.0.1:5000

[normal]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = 18080
'''

print("[1] 解析：TOML")
p = frpcparse.parse(TOML_STD)
check("格式识别为 toml", p.fmt == "toml", p.fmt)
check("serverAddr 取到", p.server_addr == "1.2.3.4", p.server_addr)
check("serverPort 取到", p.server_port == 7000, p.server_port)
check("点号写法 auth.token 取到", p.auth_token == "abc123", p.auth_token)
check("鉴权方式 token", p.auth_method == "token", p.auth_method)
check("两条隧道", len(p.proxies) == 2, [x.name for x in p.proxies])
check("隧道名正确", [x.name for x in p.proxies] == ["nas-ssh", "nas-web"], [x.name for x in p.proxies])
check("隧道端口正确", [x.remote_port for x in p.proxies] == [16022, 16080],
      [x.remote_port for x in p.proxies])
check("本地地址/端口正确",
      p.proxies[0].local_ip == "127.0.0.1" and p.proxies[0].local_port == 22,
      p.proxies[0].as_dict())
check("label = 地址:端口", p.label == "1.2.3.4:7000", p.label)

print("  --- 老式顶层 token / 下划线键名 ---")
p = frpcparse.parse(TOML_LEGACY)
check("下划线键名 server_addr 能识别", p.server_addr == "5.6.7.8", p.server_addr)
check("server_port 能识别", p.server_port == 7100, p.server_port)
check("顶层 token 能识别", p.auth_token == "legacy-tok", p.auth_token)
check("顶层 user 能识别", p.auth_user == "demo", p.auth_user)
check("单条隧道解析出来", len(p.proxies) == 1, [x.name for x in p.proxies])

print("  --- ★ 把 [[proxies]] 写成 [proxies]（少一对方括号）---")
p = frpcparse.parse(TOML_WRONG_PROXIES)
check("★ 单表写法解析出 0 条隧道（不是静默成功）", len(p.proxies) == 0,
      [x.name for x in p.proxies])
check("★ 给出了明确的警告", any("[[proxies]]" in w for w in p.warnings), p.warnings)
check("服务端要素仍能读出来", p.server_addr == "1.2.3.4", p.server_addr)

print("  --- [auth] 表写法 ---")
p = frpcparse.parse(TOML_AUTH_TABLE)
check("表写法 token 取到", p.auth_token == "table-tok", p.auth_token)
check("表写法 method 取到", p.auth_method == "token", p.auth_method)

print("[2] 解析：INI（frpc < 0.52）")
p = frpcparse.parse(INI_STD)
check("格式识别为 ini", p.fmt == "ini", p.fmt)
check("server_addr 取到", p.server_addr == "1.2.3.4", p.server_addr)
check("token 取到", p.auth_token == "ini-token", p.auth_token)
check("两条隧道", [x.name for x in p.proxies] == ["nas-ssh", "nas-web"], [x.name for x in p.proxies])
check("[common] 没被当成隧道", all(x.name != "common" for x in p.proxies),
      [x.name for x in p.proxies])

print("  --- 插件段识别 ---")
p = frpcparse.parse(INI_PLUGIN)
names = {x.name: x for x in p.proxies}
check("三条段都列出来", len(p.proxies) == 3, [x.name for x in p.proxies])
check("★ 带 type=tcp 的 plugin 段也判成插件", names["ssh-via-plugin"].plugin is True,
      names["ssh-via-plugin"].as_dict())
check("★ 段名 plugin_ 开头的判成插件", names["plugin_https2http"].plugin is True,
      names["plugin_https2http"].as_dict())
check("普通段不判成插件", names["normal"].plugin is False, names["normal"].as_dict())

print("[3] 格式识别与显式覆盖")
check("★ 含 [common] 判成 ini（不是 toml）", frpcparse.detect_format(INI_STD) == "ini",
      frpcparse.detect_format(INI_STD))
check("纯 TOML 判成 toml", frpcparse.detect_format(TOML_STD) == "toml",
      frpcparse.detect_format(TOML_STD))
check("显式指定 ini 生效", frpcparse.parse(INI_STD, "ini").fmt == "ini")
try:
    frpcparse.parse("这不是配置", "toml")
    check("坏配置抛 FrpcParseError", False, "没抛")
except frpcparse.FrpcParseError as exc:
    check("坏配置抛 FrpcParseError", True)
    check("报错信息非空", bool(str(exc)), str(exc))

# ===========================================================================
# 四、patch_server：改写服务端段（最容易产出非法文本的地方）
# ===========================================================================

print("[4] patch_server：TOML 保真与合法性")

out = frpcparse.patch_server(TOML_STD, addr="203.0.113.9", port=7000,
                             auth_method="token", auth_token="newtok")
check("新地址写进去了", 'serverAddr = "203.0.113.9"' in out, out[:200])
check("★ 没有产生重复的 serverAddr 键", out.count("serverAddr") == 1, out.count("serverAddr"))
check("★ 顶层键在第一个表头之前（不会掉进 [auth] 里）",
      out.index("serverAddr") < out.index("[[proxies]]"), out[:200])
check("原注释保留", "# 我的 frpc 配置" in out, out[:120])
check("两条 [[proxies]] 原样保留", out.count("[[proxies]]") == 2, out.count("[[proxies]]"))
check("隧道名没被动过", "nas-ssh" in out and "nas-web" in out)
check("隧道端口没被动过", "remotePort = 16022" in out and "remotePort = 16080" in out)
check("token 被换成新的",
      'auth.token = "newtok"' in out or 'token = "newtok"' in out, out[:300])
# 自证：改写结果必须还能被解析回来
reparsed = frpcparse.parse(out, "toml")
check("★ 改写后的配置仍是合法 TOML（能解析回来）",
      reparsed.server_addr == "203.0.113.9" and len(reparsed.proxies) == 2, reparsed.as_dict())

print("  --- 已经写过 serverAddr 的配置（★ 曾经会产出重复键） ---")
again = frpcparse.patch_server(out, addr="198.51.100.7", port=7200)
check("★ 再改一次不产生重复键", again.count("serverAddr") == 1, again.count("serverAddr"))
check("★ 再改一次仍是合法 TOML",
      frpcparse.parse(again, "toml").server_addr == "198.51.100.7")

print("  --- 原配置有 [auth] 表（★ 曾经会产出非法 TOML） ---")
out2 = frpcparse.patch_server(TOML_AUTH_TABLE, addr="203.0.113.9", port=7000,
                              auth_method="token", auth_token="x")
check("★ [auth] 表写法下不硬塞顶层 auth.*",
      not any(ln.strip().startswith("auth.") for ln in out2.splitlines()), out2)
check("★ 结果仍是合法 TOML",
      frpcparse.parse(out2, "toml").auth_token in ("x", "table-tok"),
      frpcparse.parse(out2, "toml").as_dict())
check("★ 没有重复的 auth 定义", out2.count("[auth]") <= 1, out2.count("[auth]"))

print("  --- 老式顶层 token 写法 ---")
out3 = frpcparse.patch_server(TOML_LEGACY, addr="203.0.113.9", port=7000,
                              auth_method="token", auth_token="zzz")
check("★ 老写法仍是合法 TOML",
      frpcparse.parse(out3, "toml").server_addr == "203.0.113.9", out3)
check("★ 老写法下不重复定义 token",
      out3.count("legacy-tok") + out3.count('"zzz"') <= 2, out3)

print("  --- 只改地址、不动鉴权 ---")
out4 = frpcparse.patch_server(TOML_STD, addr="203.0.113.9", port=7000)
check("没传 token 时原 token 不动", "abc123" in out4, out4[:200])

print("[5] patch_server：INI")
out5 = frpcparse.patch_server(INI_STD, addr="203.0.113.9", port=7100,
                              auth_method="token", auth_token="newtok")
check("server_addr 改写", "server_addr = 203.0.113.9" in out5, out5[:200])
check("server_port 改写", "server_port = 7100" in out5, out5[:200])
check("token 改写", "token = newtok" in out5, out5[:200])
check("两条隧道段原样保留",
      out5.count("[nas-ssh]") == 1 and out5.count("[nas-web]") == 1, out5)
check("★ 改写后的 INI 仍是合法配置",
      frpcparse.parse(out5, "ini").server_addr == "203.0.113.9",
      frpcparse.parse(out5, "ini").as_dict())

# ===========================================================================
# 六、数据层
# ===========================================================================

print("[6] 数据层：manual_nodes CRUD 与绑定")
store.init()
nid = store.create_manual_node({
    "name": "自建-香港", "server_addr": "203.0.113.9", "server_port": 7000,
    "auth_method": "token", "auth_token": "tk", "auth_user": "",
    "config_format": "toml", "config_text": TOML_STD, "note": "测试", "enabled": 1,
})
check("创建返回 id", isinstance(nid, int) and nid > 0, nid)
n = store.get_manual_node(nid)
check("读回来名字对", n and n["name"] == "自建-香港", n)
check("读回来端口是 int", isinstance(n["server_port"], int), type(n["server_port"]))
check("按名字查得到", (store.get_manual_node_by_name("自建-香港") or {}).get("id") == nid)
check("按地址查得到", (store.find_manual_node_by_addr("203.0.113.9", 7000) or {}).get("id") == nid)
check("地址对但端口不对查不到", store.find_manual_node_by_addr("203.0.113.9", 7100) is None)
store.update_manual_node(nid, {"note": "改过了", "enabled": 0})
n = store.get_manual_node(nid)
check("更新生效", n["note"] == "改过了" and n["enabled"] == 0, n)
check("enabled_only 过滤掉停用的", store.list_manual_nodes(enabled_only=True) == [],
      store.list_manual_nodes(enabled_only=True))
store.update_manual_node(nid, {"enabled": 1})

tid = store.create_tunnel({
    "name": "nas-ssh", "proxy_name": "nas-ssh", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22, "current_remote_port": 16022,
    "manual_node_id": nid, "enabled": 1, "auto_failover": 0,
})
check("隧道绑到外部节点", len(store.list_tunnels_of_manual_node(nid)) == 1,
      store.list_tunnels_of_manual_node(nid))
check("计数一致", store.count_tunnels_of_manual_node(nid) == 1)

iid = store.create_frpc_instance({
    "name": "inst-hk", "config_path": os.path.join(TMP, "frpc-hk.toml"),
    "container": "", "restart_mode": "none", "note": "", "enabled": 1,
})
store.update_frpc_instance(iid, {"manual_node_id": nid})
check("实例绑到外部节点", len(store.list_instances_of_manual_node(nid)) == 1,
      store.list_instances_of_manual_node(nid))

print("  --- 解绑 ---")
check("解绑实例返回条数", store.unbind_instances_of_manual_node(nid) == 1)
check("实例已解绑", store.get_frpc_instance(iid)["manual_node_id"] is None,
      store.get_frpc_instance(iid))
store.update_frpc_instance(iid, {"manual_node_id": nid})
check("解绑隧道返回条数", store.unbind_tunnels_of_manual_node(nid) == 1)
check("隧道已解绑", store.get_tunnel(tid)["manual_node_id"] is None, store.get_tunnel(tid))
store.update_tunnel(tid, {"manual_node_id": nid})

print("  --- 删除节点 ---")
store.delete_manual_node(nid)
check("节点已删", store.get_manual_node(nid) is None)
check("删除不级联删隧道（级联由上层决定）", store.get_tunnel(tid) is not None)

# ===========================================================================
# 七、老库迁移
# ===========================================================================

print("[7] 老库迁移：1.0.0 的库升上来要自动补列")

MIG_DIR = tempfile.mkdtemp(prefix="mg-mig-")
MIG_DB = os.path.join(MIG_DIR, "guard.db")

# 1.0.0 的 schema：tunnels 没有 manual_node_id、frpc_instances 没有 manual_node_id、
# 也没有 manual_nodes 表。
_OLD_SCHEMA = """
CREATE TABLE tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, proxy_name TEXT NOT NULL UNIQUE,
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
INSERT INTO tunnels (name,proxy_name,local_port,created_at,updated_at)
    VALUES ('老隧道','old-tunnel',1234,1,1);
INSERT INTO frpc_instances (name,config_path,created_at,updated_at)
    VALUES ('老实例','/etc/frpc/frpc.toml',1,1);
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
conn = sqlite3.connect({MIG_DB!r})
conn.row_factory = sqlite3.Row
t = {{r["name"] for r in conn.execute("PRAGMA table_info(tunnels)")}}
f = {{r["name"] for r in conn.execute("PRAGMA table_info(frpc_instances)")}}
mn = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='manual_nodes'").fetchone()
old = conn.execute("SELECT proxy_name FROM tunnels").fetchone()
oldi = conn.execute("SELECT name FROM frpc_instances").fetchone()
print("TUNNEL_MANUAL", "manual_node_id" in t)
print("INSTANCE_MANUAL", "manual_node_id" in f)
print("MANUAL_TABLE", bool(mn))
print("OLD_DATA", old["proxy_name"] if old else "")
print("OLD_INST", oldi["name"] if oldi else "")
print("OLD_FRPC_COL", "frpc_instance_id" in t)
'''
_proc = subprocess.run([sys.executable, "-c", _MIG_CODE], capture_output=True, text=True)
_out = dict(ln.split(" ", 1) for ln in _proc.stdout.strip().splitlines() if " " in ln)
check("迁移子进程正常退出", _proc.returncode == 0, _proc.stderr[-400:])
check("★ tunnels 补上了 manual_node_id", _out.get("TUNNEL_MANUAL") == "True", _out)
check("★ frpc_instances 补上了 manual_node_id", _out.get("INSTANCE_MANUAL") == "True", _out)
check("★ manual_nodes 表被建出来", _out.get("MANUAL_TABLE") == "True", _out)
check("★ 老数据没丢（隧道还在）", _out.get("OLD_DATA") == "old-tunnel", _out)
check("★ 老数据没丢（实例还在）", _out.get("OLD_INST") == "老实例", _out)
check("1.0.0 就有的列仍在", _out.get("OLD_FRPC_COL") == "True", _out)

# ===========================================================================
# 八、引擎：手工隧道永不自动切换
# ===========================================================================

print("[8] 引擎：手工隧道判定与不自动切换")

eng = GuardEngine()

mid = store.create_manual_node({
    "name": "引擎测试节点", "server_addr": "127.0.0.1", "server_port": 1,
    "auth_method": "none", "auth_token": "", "auth_user": "",
    "config_format": "toml", "config_text": TOML_STD, "note": "", "enabled": 1,
})
t_manual = store.create_tunnel({
    "name": "手工隧道", "proxy_name": "manual-tun", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22, "current_remote_port": 1,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
})
check("★ 隧道自己标了 manual_node_id -> 判成手工",
      eng.tunnel_is_manual(store.get_tunnel(t_manual)) is True)

# 另一条：隧道没标，但它挂接的实例绑了外部节点 —— 也必须判成手工。
# 这是「用户先把实例指到外部节点、再挂隧道」的中间态，只看隧道自己会漏掉。
i2 = store.create_frpc_instance({
    "name": "引擎测试实例", "config_path": os.path.join(TMP, "eng.toml"),
    "container": "", "restart_mode": "none", "note": "", "enabled": 1,
})
store.update_frpc_instance(i2, {"manual_node_id": mid})
t_via = store.create_tunnel({
    "name": "间接手工隧道", "proxy_name": "via-inst", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22, "current_remote_port": 1,
    "frpc_instance_id": i2, "enabled": 1, "auto_failover": 0,
})
check("★ 隧道没标、但实例绑了外部节点 -> 也判成手工（中间态）",
      eng.tunnel_is_manual(store.get_tunnel(t_via)) is True)

t_plain = store.create_tunnel({
    "name": "普通隧道", "proxy_name": "plain-tun", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22, "enabled": 1, "auto_failover": 1,
})
check("普通隧道不判成手工", eng.tunnel_is_manual(store.get_tunnel(t_plain)) is False)

# manual_node_for 必须和 tunnel_is_manual 判据一致 —— 前者用来取节点、后者
# 用来分支，两者不一致的话会出现「判定是外部节点、却取不到节点」的组合，
# 然后在 _reconcile_manual 里被当成「节点已不存在」，记一条假错误。
check("★ manual_node_for 在「隧道自己标了」时取得到",
      (eng.manual_node_for(store.get_tunnel(t_manual)) or {}).get("id") == mid,
      eng.manual_node_for(store.get_tunnel(t_manual)))
check("★ manual_node_for 在「只有实例绑了」的中间态也取得到",
      (eng.manual_node_for(store.get_tunnel(t_via)) or {}).get("id") == mid,
      eng.manual_node_for(store.get_tunnel(t_via)))
# 真跑一次，确认中间态不会被误判成「节点已不存在」——不跑的话 last_error 是空的，
# 断言会假通过。
asyncio.run(eng._reconcile_manual(store.get_tunnel(t_via)))
check("★ 中间态下 _reconcile_manual 不报「节点已不存在」",
      "已不存在" not in (store.get_tunnel(t_via)["last_error"] or ""),
      store.get_tunnel(t_via)["last_error"])
check("manual_node_for 对纯 mefrp 隧道返回 None",
      eng.manual_node_for(store.get_tunnel(t_plain)) is None)

print("  --- _failover 的防御闸门 ---")
res = asyncio.run(eng._failover(store.get_tunnel(t_manual), "测试触发"))
check("★ 手工隧道 _failover 被拒", res.get("ok") is False, res)
check("★ 拒绝理由点明「外部节点」", "外部节点" in str(res.get("error", "")), res)
check("★ 拒绝理由给出人工路径", "手动切换" in str(res.get("error", "")), res)

print("  --- _reconcile_manual：UDP 不涨 fail_streak、也不写红色 last_error ---")
# UDP 隧道探不了，而外部节点上**没有**第二层判据 —— mefrp 那套「proxy 是否
# 在线」是 API 给的。所以只能如实说「没探」：**既不算失败，也不算健康**。
#   · 不能涨 fail_streak（那会把健康隧道判成故障，一路涨到阈值去切它）；
#   · 不能写 last_error —— 前端把它画成红色「异常」，而这里只是「探不了」。
#     原因进 probe_cache，页面上以 ⓘ 中性提示显示。
udp_t = store.create_tunnel({
    "name": "手工UDP", "proxy_name": "manual-udp", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5000,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
})
probe_kind, _why = probe_plan("udp", "auto")
check("udp 在 auto 模式下不探测", probe_kind == "none")
asyncio.run(eng._reconcile_manual(store.get_tunnel(udp_t)))
after = store.get_tunnel(udp_t)
check("★ UDP 不涨 fail_streak", after["fail_streak"] == 0, after["fail_streak"])
check("★ UDP 不写 last_error（红色「异常」是误导）", after["last_error"] == "",
      after["last_error"])
_cached = eng.probe_cache.get(udp_t)
check("★ 「不适用」的原因进了 probe_cache（三态里的 None）",
      bool(_cached) and _cached[1] is None and "UDP" in _cached[2], _cached)

# 老代码会在 last_error 里留下「无法探测：…」，前端把它画成红色故障，
# 而那条隧道其实是健康的。新代码要能在下一轮把它清掉，否则用户升级后
# 那条红字会永远挂在页面上。
store.update_tunnel(udp_t, {"last_error":
    "无法探测：UDP 隧道不做 TCP 端到端探测（协议不匹配，探测必然失败）"})
asyncio.run(eng._reconcile_manual(store.get_tunnel(udp_t)))
check("★ 老代码留下的「无法探测」被清掉",
      store.get_tunnel(udp_t)["last_error"] == "",
      store.get_tunnel(udp_t)["last_error"])


print("  --- ★ UDP + 填了 DNS 记录名：必须照常同步 DNS ---")
# 用户报的那个 bug：地址对不对，跟「能不能用 TCP 去探它」**没有任何关系**。
# 原来 ok is None 分支直接 return，于是 udp 的外部隧道**永远同步不了 DNS**
# —— 而 udp 恰恰是外部节点上最常见的一类（VPN / 游戏服 / DNS）。
udp_dns = store.create_tunnel({
    "name": "手工UDP带域名", "proxy_name": "manual-udp-dns", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5001,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "udp.example.com",
})
_cf = FakeCF()
eng.cf = _cf
store.set_setting("auto_dns_sync", True)
asyncio.run(eng._reconcile_manual(store.get_tunnel(udp_dns)))
check("★ UDP 隧道也走到了 DNS 同步（不是直接 return）",
      len(_cf.upserts) == 1, _cf.upserts)
check("★ 记录名用的是隧道上填的那个",
      bool(_cf.upserts) and _cf.upserts[0]["name"] == "udp.example.com",
      _cf.upserts)
check("★ 目标地址用的是外部节点的 serverAddr（没有 proxy 可用）",
      bool(_cf.upserts) and _cf.upserts[0]["content"] == "127.0.0.1",
      _cf.upserts)
check("★ 是 IP 所以建 A 记录",
      bool(_cf.upserts) and _cf.upserts[0]["record_type"] == "A", _cf.upserts)
check("★ 解析出来的 zone 落了库",
      store.get_tunnel(udp_dns)["dns_zone_id"] == "ZTEST",
      store.get_tunnel(udp_dns)["dns_zone_id"])
check("★ 建出来的记录 id 落了库",
      store.get_tunnel(udp_dns)["dns_record_id"] == "R1",
      store.get_tunnel(udp_dns)["dns_record_id"])
check("★ 同步成功记了 dns 事件",
      any(e["kind"] == "dns" for e in store.list_events(limit=5)),
      store.list_events(limit=5))

# 没填记录名 = 用户明确不管这条的 DNS，一次都不该去问 Cloudflare。
_nodns = store.create_tunnel({
    "name": "手工UDP无域名", "proxy_name": "manual-udp-nodns", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5002,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
})
_cf2 = FakeCF()
eng.cf = _cf2
asyncio.run(eng._reconcile_manual(store.get_tunnel(_nodns)))
check("★ 没填记录名 -> 完全不碰 Cloudflare",
      _cf2.upserts == [] and _cf2.zone_queries == [], _cf2.upserts)

# 关掉自动同步（且不是用户刚下达的指令）时不该动 DNS。
_udp2 = store.create_tunnel({
    "name": "手工UDP关同步", "proxy_name": "manual-udp-off", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5003,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "off.example.com",
})
_cf3 = FakeCF()
eng.cf = _cf3
store.set_setting("auto_dns_sync", False)
asyncio.run(eng._reconcile_manual(store.get_tunnel(_udp2)))
check("★ 自动同步关闭时巡检不动 DNS", _cf3.upserts == [], _cf3.upserts)
store.set_setting("auto_dns_sync", True)


print("  --- ★ mefrp 侧不可用时，外部节点的隧道仍要被对账 ---")
# mefrp 拉取失败（或压根没配 token）时，原来 tick() 直接 return —— 于是用户
# 自建节点上的隧道跟着一起瞎掉：探测不更新、DNS 不解析，页面上一点线索都没有。
# 可它们根本不用 mefrp API，地址就在库里。
# 反过来也要防住：这种时候**不能**去对账 mefrp 隧道 —— proxy 列表是陈旧的，
# 拿陈旧数据判故障会一路涨 fail_streak，最后触发一次不该发生的切换。
store.update_tunnel(t_plain, {"fail_streak": 5, "last_error": "陈旧数据留下的假故障"})
tick_dns = store.create_tunnel({
    "name": "巡检域名隧道", "proxy_name": "tick-dns", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5009,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "tick.example.com",
})
_cft = FakeCF()
# ⚠️ eng.client 先设成非 None：tick() 里 `if self.client is None:
#    self.reload_clients()` 会把 cf 换成真的（测试库里没配 token，一换就炸）。
eng.client = object()
eng.cf = _cft
check("测试前提：库里确实没有 mefrp token",
      not store.get_setting("mefrp_token", ""), store.get_setting("mefrp_token", ""))
asyncio.run(eng.tick())
check("★ mefrp 没配时，外部节点的隧道照样被对账（DNS 同步了）",
      "tick.example.com" in {u["name"] for u in _cft.upserts},
      [u["name"] for u in _cft.upserts])
check("★ 而 mefrp 隧道没被拿陈旧数据判故障（fail_streak 原样）",
      store.get_tunnel(t_plain)["fail_streak"] == 5,
      store.get_tunnel(t_plain)["fail_streak"])
check("★ 引擎如实说清了 mefrp 侧为什么不可用",
      "Token" in (eng.last_error or ""), eng.last_error)


print("  --- ★ mefrp 拉取失败：满 alert_after_seconds 才告警 ---")
# 移动宽带抖两三分钟就自愈。原来每轮（20 秒）记一条 error —— 实测三天 122 条，
# **没有一条是源站真挂了**。现在：刚开始失败只留**一条** warn，中间完全安静，
# 连续满 30 分钟才升 error；恢复时（真告过警的）记一条 success。
from app.engine import ALERT_AFTER_SECONDS           # noqa: E402
from app.mefrp import MefrpError                     # noqa: E402


class DeadMefrp:
    """所有接口都拉不通的假客户端。`fail=False` 时返回空数据（= 恢复正常）。"""

    def __init__(self) -> None:
        self.fail = True

    def _boom(self):
        raise MefrpError("请求 mefrp 失败：All connection attempts failed")

    async def node_list(self):
        return self._boom() if self.fail else []

    async def node_status(self):
        return self._boom() if self.fail else {}

    async def proxy_list(self):
        return self._boom() if self.fail else ([], {})

    async def user_info(self):
        # 成败都抛 —— `_refresh_remote` 本来就 catch 它（当作「用户组暂不可知」），
        # 不影响这一轮的成功/失败判定。
        raise MefrpError("用户组暂不可用")


def _sys() -> list[dict]:
    return [e for e in store.list_events(limit=500) if e["kind"] == "system"]


store.set_setting("mefrp_token", "fake-token-for-alert-test")
_dm = DeadMefrp()
eng.client = _dm
eng.mefrp_fail_since = None
eng.mefrp_alert_count = 0
_n0 = len(_sys())

asyncio.run(eng.tick())
_e = _sys()[0]
check("★ mefrp 刚开始失败只记一条 warn（不告警）", _e["level"] == "warn", _e)
check("★ warn 文案说清了「满多久才告警、中途自愈不记录」",
      "才告警" in _e["message"] and "自愈" in _e["message"], _e["message"])

for _i in range(10):
    asyncio.run(eng.tick())
check("★ 未满阈值期间完全静默（再跑 10 轮一条都不记）",
      len(_sys()) == _n0 + 1, (len(_sys()), _n0))

eng.mefrp_fail_since = time.time() - (ALERT_AFTER_SECONDS + 1)
asyncio.run(eng.tick())
_e = _sys()[0]
check("★ 连续满 30 分钟才升 error", _e["level"] == "error", _e)
check("★ error 文案带上已断时长", "30 分" in _e["message"], _e["message"])

_dm.fail = False
asyncio.run(eng.tick())
_e = _sys()[0]
check("★ 告过警的恢复记一条 success",
      _e["level"] == "success" and "恢复" in _e["message"], _e)
check("★ 恢复后连续失败状态清零",
      eng.mefrp_fail_since is None and eng.mefrp_alert_count == 0,
      (eng.mefrp_fail_since, eng.mefrp_alert_count))

store.set_setting("mefrp_token", "")
eng.client = object()


print("  --- ★ 没配 CF token：不能每轮记一条错误事件 ---")
# 没配 token 是**静态配置问题**，不是「这条隧道此刻解析失败了」。照常往下走的话
# `CloudflareAuthError` 会被 except 抓住、每轮巡检记一条 error 事件 ——
# 20 秒一条 × 每条填了记录名的隧道，很快把事件日志刷满，真正的问题反而被淹掉。
from app.cloudflare import CloudflareClient          # noqa: E402

_notok = store.create_tunnel({
    "name": "没配token的隧道", "proxy_name": "no-token", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5010,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "notok.example.com",
})
eng.cf = CloudflareClient(token="")        # 真的客户端，只是没 token
_n0 = len([e for e in store.list_events(limit=200) if e["kind"] == "dns"])
asyncio.run(eng._reconcile_manual(store.get_tunnel(_notok)))
_n1 = len([e for e in store.list_events(limit=200) if e["kind"] == "dns"])
check("★ 巡检时不为「没配 token」刷事件", _n1 == _n0, (_n0, _n1))
check("★ 但如实说明原因（force 时会回给用户）",
      "Token" in asyncio.run(eng._sync_dns(store.get_tunnel(_notok), None,
                                           host="127.0.0.1")),
      asyncio.run(eng._sync_dns(store.get_tunnel(_notok), None, host="127.0.0.1")))
_n2 = len([e for e in store.list_events(limit=200) if e["kind"] == "dns"])
asyncio.run(eng._sync_dns(store.get_tunnel(_notok), None, force=True,
                          host="127.0.0.1"))
_n3 = len([e for e in store.list_events(limit=200) if e["kind"] == "dns"])
check("★ 用户明确要求时（force）才记事件", _n3 == _n2 + 1, (_n2, _n3))
eng.cf = _cft                              # 还原成能用的假客户端

print("  --- ★ 瞬时 DNS 失败：满 alert_after_seconds 才升 error ---")
# 巡检每 20 秒一轮，每轮都顺手同步一次 DNS。网络抖一下（移动宽带的间歇性抽风，
# 或者本机挂着 `http_proxy=127.0.0.1:51140` 这种本地代理时）就会失败一次，下一轮
# 立刻又好了。原来失败**一律记 error**；后来改成「连续 3 次」—— 但 3 次只有 1
# 分钟，照样刷屏。实测三天：mefrp 122 条 + Cloudflare 64 条 error，全是 2~9 分钟
# 的短窗口，**没有一条是源站真挂了**。
# 现在按**时间**：满 30 分钟才告警，之前只留一条 warn，中途自愈不再记。
from app.cloudflare import CloudflareError                        # noqa: E402
from app.engine import ALERT_AFTER_SECONDS, alert_after_seconds   # noqa: E402
from app.settings import DNS_RECOVER_GRACE_SECONDS                # noqa: E402

check("★ 默认告警门槛是 30 分钟", ALERT_AFTER_SECONDS == 1800, ALERT_AFTER_SECONDS)
store.set_setting("alert_after_seconds", 1800)
check("设置项可读，且默认值与常量一致",
      alert_after_seconds() == 1800.0, alert_after_seconds())
store.set_setting("alert_after_seconds", 0)
check("★ 设 0 = 立刻告警（关掉这层缓冲）", alert_after_seconds() == 0.0,
      alert_after_seconds())
store.set_setting("alert_after_seconds", 1800)


class FlakyCF:
    """按开关抛**传输层瞬时**错的假 CF。

    `fail=False` 时正常走完 —— 用来验「成功一次就把连续计数清零」。
    抛出来的形状和 cloudflare.py 重试耗尽后抛的那条一致（带 transient=True）。
    """

    def __init__(self) -> None:
        self.token = "fake-cf-token"
        self.fail = True
        self.upserts: list[dict] = []

    async def resolve_zone(self, name: str):
        from app.cloudflare import Zone
        return Zone(zone_id="ZFL", name="example.com")

    async def list_records(self, zone_id: str, name: str | None = None):
        if self.fail:
            raise CloudflareError(
                "请求 Cloudflare 失败（已重试 2 次）：ConnectTimeout: ",
                transient=True)
        return []

    async def upsert(self, **kw):
        from app.cloudflare import DnsRecord
        self.upserts.append(kw)
        return DnsRecord("RFL", kw["zone_id"], kw["name"], kw["record_type"],
                         kw["content"], False)


store.set_setting("auto_dns_sync", True)
_fl = store.create_tunnel({
    "name": "会抖的隧道", "proxy_name": "flaky-dns", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 5000, "current_remote_port": 5020,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "flaky.example.com",
})
_cffl = FlakyCF()
eng.cf = _cffl
_fid = int(store.get_tunnel(_fl)["id"])


def _newest_dns() -> dict:
    """最新一条 dns 事件（list_events 是 id DESC，所以 [0] 就是最新的）。"""
    return [e for e in store.list_events(limit=50) if e["kind"] == "dns"][0]


def _sync_flaky():
    """跑「一轮」：同步 + 轮末聚合。

    ⚠️ 必须带上 `_flush_dns_alerts()` —— DNS 的 warn / error 事件是在**轮末**
    按站点聚合出来的，`_sync_dns` 自己只负责把失败登记进 `dns_fail_round`。
    """
    r = asyncio.run(eng._sync_dns(store.get_tunnel(_fl), None,
                                  host="127.0.0.1"))
    eng._flush_dns_alerts()
    return r


_sync_flaky()
_e = _newest_dns()
check("★ 刚开始失败只记一条 warn（不告警）", _e["level"] == "warn", _e)
check("★ warn 文案说清了「满多久才告警、恢复要多久」",
      "才告警" in _e["message"] and "恢复需连续正常" in _e["message"],
      _e["message"])

# ★ 关键：没满阈值期间**一条都不记** —— 这就是「别吵」的本体。
#   原来每轮一条 warn，90 轮就是 90 条。
_n_before = len(store.list_events(limit=200))
for _i in range(20):
    _sync_flaky()
check("★ 未满阈值期间完全静默（连跑 20 轮一条都不记）",
      len(store.list_events(limit=200)) == _n_before,
      (len(store.list_events(limit=200)), _n_before))

# 把「连续失败起点」往前拨 30 分钟 —— 等价于真的断了半小时（比 sleep 靠谱，
# 也不依赖真实时钟流逝）。⚠️ 状态是**站点级**的（不分隧道），所以直接赋值。
eng.dns_fail_since = time.time() - (ALERT_AFTER_SECONDS + 1)
_sync_flaky()
_e = _newest_dns()
check("★ 连续满 30 分钟才升 error", _e["level"] == "error", _e)
check("★ error 文案带上已断时长", "30 分" in _e["message"], _e["message"])

# 再满一个阈值 → 补一条（断一整天也只有 48 条，既不漏报也不刷屏）
eng.dns_fail_since = time.time() - (ALERT_AFTER_SECONDS * 2 + 1)
_sync_flaky()
check("★ 再满一个阈值补一条 error（长时间断网不漏报）",
      _newest_dns()["level"] == "error", _newest_dns())

# ★ 恢复要有**迟滞**：一次干净只是「这次碰巧通了」，不算恢复。
#   实测 2026-10-13：CF API 打三次挂两次，每一次偶然成功都把 episode 切断，
#   四小时刷出 62 条 warn、0 条 error（30 分钟的告警永远攒不满）。
_cffl.fail = False
_sync_flaky()
check("恢复后记录同步成功（走了 upsert）", len(_cffl.upserts) == 1, _cffl.upserts)
check("★ 一次干净**不算**恢复（episode 保持、不记 success）",
      eng.dns_fail_since is not None
      and "DNS 同步已恢复" not in _newest_dns()["message"],
      (eng.dns_fail_since, _newest_dns()["message"]))
check("★ 但「干净起点」已开始计时", eng.dns_ok_since is not None, eng.dns_ok_since)

# 把「干净起点」往前拨过宽限期 → 这才算「连续干净满窗口」
eng.dns_ok_since = time.time() - (DNS_RECOVER_GRACE_SECONDS + 1)
_sync_flaky()
check("★ 连续干净满宽限期才判恢复", eng.dns_fail_since is None,
      eng.dns_fail_since)
check("★ 告过警的恢复记一条 success",
      "DNS 同步已恢复" in _newest_dns()["message"], _newest_dns()["message"])
check("★ 恢复后连续失败状态清零",
      eng.dns_fail_since is None and eng.dns_alert_count == 0
      and eng.dns_ok_since is None,
      (eng.dns_fail_since, eng.dns_alert_count, eng.dns_ok_since))

# 恢复后再挂 → 又是全新的一段，从 warn 重新开始
_cffl.fail = True
_sync_flaky()
check("★ 恢复后再失败又从 warn 开始（短抖不会攒成 error）",
      _newest_dns()["level"] == "warn", _newest_dns())
# 短抖自愈**不**记「已恢复」 —— 前面那条 warn 已经留过痕了，再来一条纯属噪音
_cffl.fail = False
_sync_flaky()
check("★ 没告过警的短抖自愈不额外记「已恢复」（保持安静）",
      "DNS 同步已恢复" not in _newest_dns()["message"], _newest_dns()["message"])

# force = 用户明确点的动作，不看阈值，第一次就如实记 error。
# ⚠️ 此时站点可能已经处于「异常中」（迟滞没过完）—— 那也不影响：force 这条路
#    压根不看聚合状态，用户正站在页面前等结果，必须如实报。
_cffl.fail = True
_sync_flaky()
asyncio.run(eng._sync_dns(store.get_tunnel(_fl), None, force=True,
                          host="127.0.0.1"))
check("★ force（导入 / 立即探测）时第一次就如实记 error",
      _newest_dns()["level"] == "error", _newest_dns())


# ★ 站点级聚合：DNS 同步打的是同一个 Cloudflare API，一轮里几条隧道都撞上同一个
#   超时，也只该报**一条** —— 而不是每条各报一次。按隧道各记一份的话，那几份的
#   「已连续失败」起点还相差几十秒（巡检是串行的，每条失败要耗掉一个 connect
#   timeout），事件列表里看着就像时长在反复横跳。
print("  --- DNS 告警按站点聚合（不按隧道）---")
_agg1 = store.create_tunnel({
    "name": "聚合 A", "proxy_name": "agg-a", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 5100, "current_remote_port": 5110,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "agg-a.example.com",
})
_agg2 = store.create_tunnel({
    "name": "聚合 B", "proxy_name": "agg-b", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 5101, "current_remote_port": 5111,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "agg-b.example.com",
})


def _reset_dns_state() -> None:
    eng.dns_fail_since = None
    eng.dns_alert_count = 0
    eng.dns_ok_since = None
    eng.dns_fail_tunnels.clear()
    eng.dns_fail_round.clear()
    eng.dns_ok_round = 0


def _run_round(*tids) -> None:
    """模拟一轮巡检：逐条同步，最后聚合一次（和 `tick()` 里的顺序一致）。"""
    for _tid in tids:
        asyncio.run(eng._sync_dns(store.get_tunnel(_tid), None,
                                  host="127.0.0.1"))
    eng._flush_dns_alerts()


def _n_events() -> int:
    return len(store.list_events(limit=1000))


def _n_dns_alerts() -> int:
    """只数 warn / error 级的 dns 事件。

    ⚠️ 不能直接数事件总数：干净轮里记录名底下是空的，`_sync_dns` 会走 upsert
    并记一条 **success**「DNS 已更新」—— 那跟告警没关系。
    """
    return len([e for e in store.list_events(limit=1000)
                if e["kind"] == "dns" and e["level"] in ("warn", "error")])


eng.cf = _cffl
_reset_dns_state()
_cffl.fail = True

_n0 = _n_events()
_run_round(_agg1, _agg2)
check("★ 一轮里两条隧道都失败 → 只记**一条**事件（按站点聚合，不是按隧道）",
      _n_events() - _n0 == 1, _n_events() - _n0)
_e = _newest_dns()
check("★ 聚合出来的那条是 warn，且说明「满多久才告警」",
      _e["level"] == "warn" and "才告警" in _e["message"], _e["message"])
check("★ 聚合事件不带隧道（它是站点级事件）", _e["tunnel_id"] is None,
      _e["tunnel_id"])

# 未满阈值期间照旧一条都不记
_n0 = _n_events()
for _i in range(10):
    _run_round(_agg1, _agg2)
check("★ 聚合之后未满阈值仍然完全静默（连跑 10 轮一条都不记）",
      _n_events() == _n0, _n_events() - _n0)

# 拨到满 30 分 → 告警，且文案报出影响面
eng.dns_fail_since = time.time() - (ALERT_AFTER_SECONDS + 1)
_n0 = _n_events()
_run_round(_agg1, _agg2)
check("★ 聚合告警也仍然只有一条", _n_events() - _n0 == 1, _n_events() - _n0)
check("★ 告警文案报出受影响的隧道条数",
      "2 条隧道受影响" in _newest_dns()["message"], _newest_dns()["message"])

# ★ 关键：本轮**有**失败就不清状态 —— 否则「一条老是超时、另一条正常」时，
#   那条超时的会被另一条的成功反复清零，永远攒不满 30 分钟（漏报）。
_reset_dns_state()
eng.dns_fail_round[_agg1] = "x"
eng._flush_dns_alerts()
check("★ 本轮有失败 → 连续失败状态保持", eng.dns_fail_since is not None,
      eng.dns_fail_since)

# ★ 「本轮没人失败」不等于「站点好了」：隧道被判故障时 `_reconcile` 根本不会调
#   `_sync_dns`，三条隧道同时故障就一个 CF 请求都发不出去。拿「没问」当「通了」
#   会在隧道长期故障时把 DNS 的 episode 悄悄判成恢复。
eng._flush_dns_alerts()
check("★ 本轮没发任何 CF 请求 → 不算干净（无证据，状态保持）",
      eng.dns_fail_since is not None and eng.dns_ok_since is None,
      (eng.dns_fail_since, eng.dns_ok_since))

# 真去问了、且没失败 → 干净。但**一次干净不算恢复**，要连续满宽限期。
eng.dns_ok_round = 1
eng._flush_dns_alerts()
check("★ 干净但未满宽限期 → 仍不恢复（只是开始计时）",
      eng.dns_fail_since is not None and eng.dns_ok_since is not None,
      (eng.dns_fail_since, eng.dns_ok_since))

eng.dns_ok_round = 1
eng.dns_ok_since = time.time() - (DNS_RECOVER_GRACE_SECONDS + 1)
eng._flush_dns_alerts()
check("★ 连续干净满宽限期 → 才恢复、清状态",
      eng.dns_fail_since is None and eng.dns_ok_since is None,
      (eng.dns_fail_since, eng.dns_ok_since))

# 恢复事件只在**告过警**时才记
eng.dns_fail_since = time.time()
eng.dns_alert_count = 0
eng.dns_ok_round = 1
eng.dns_ok_since = time.time() - (DNS_RECOVER_GRACE_SECONDS + 1)
_n0 = _n_events()
eng._flush_dns_alerts()
check("★ 没告过警的站点恢复不记 success（保持安静）",
      _n_events() == _n0, _n_events() - _n0)

eng.dns_fail_since = time.time() - 100
eng.dns_alert_count = 1
eng.dns_ok_round = 1
eng.dns_ok_since = time.time() - (DNS_RECOVER_GRACE_SECONDS + 1)
_n0 = _n_events()
eng._flush_dns_alerts()
check("★ 告过警的站点恢复记一条 success", _n_events() - _n0 == 1,
      _n_events() - _n0)
check("★ 恢复文案带上此前异常的时长",
      "DNS 同步已恢复" in _newest_dns()["message"]
      and "此前持续异常" in _newest_dns()["message"],
      _newest_dns()["message"])

# ★★ 回归：抖动型故障源（打三次挂两次）不再被切成几十条 warn。
#   这就是 2026-10-13 那天「4 小时 62 条 warn、0 条 error」的最小复现。
print("  --- ★ 抖动型故障：一段故障只能有一条 warn ---")
_reset_dns_state()
_cffl.fail = True
_run_round(_agg1, _agg2)
check("★ 抖动开始：记一条 warn，episode 起表",
      eng.dns_fail_since is not None and _newest_dns()["level"] == "warn",
      (eng.dns_fail_since, _newest_dns()))
_n_a = _n_dns_alerts()
# 干净一轮 → 又挂一轮，反复 6 个来回（模拟 CF 时通时不通）
for _i in range(6):
    _cffl.fail = False
    _run_round(_agg1, _agg2)
    _cffl.fail = True
    _run_round(_agg1, _agg2)
check("★ 反复抖动 6 个来回：**一条新告警都不记**（episode 不被切断）",
      _n_dns_alerts() == _n_a, _n_dns_alerts() - _n_a)
check("★ 抖动期间 episode 起点没被清零（计时连续）",
      eng.dns_fail_since is not None and eng.dns_alert_count == 0,
      (eng.dns_fail_since, eng.dns_alert_count))
# 拨满 30 分 → 该告警了，而且**只有一条**（不是每个来回一条）
eng.dns_fail_since = time.time() - (ALERT_AFTER_SECONDS + 1)
_n_a = _n_dns_alerts()
_run_round(_agg1, _agg2)
check("★ 抖动攒满 30 分 → 记一条 error（不是 62 条 warn）",
      _n_dns_alerts() - _n_a == 1 and _newest_dns()["level"] == "error",
      (_n_dns_alerts() - _n_a, _newest_dns()))
check("★ error 文案说的是「持续异常」而不是「连续失败」"
      "（中途确实通了几次，说「连续失败」是假的）",
      "已持续异常" in _newest_dns()["message"], _newest_dns()["message"])

_reset_dns_state()
_cffl.fail = False


# 静态问题（token 没权限这种，重试一万次也不会好）不套「等半小时」，立刻报。
class StaticFailCF(FlakyCF):
    async def list_records(self, zone_id: str, name: str | None = None):
        raise CloudflareError("[10000] Authentication error", transient=False)


eng.cf = StaticFailCF()
_fl2 = store.create_tunnel({
    "name": "静态错的隧道", "proxy_name": "staticfail-dns", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 5002, "current_remote_port": 5022,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
    "dns_record_name": "staticfail.example.net",
})
asyncio.run(eng._sync_dns(store.get_tunnel(_fl2), None, host="127.0.0.1"))
check("★ 静态问题（重试不会好）第一次就记 error，不等半小时",
      _newest_dns()["level"] == "error", _newest_dns())
eng.cf = _cft

print("  --- 节点不存在 / 没有远程端口时如实报错 ---")
ghost = store.create_tunnel({
    "name": "孤儿隧道", "proxy_name": "orphan-tun", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22, "current_remote_port": 1,
    "manual_node_id": 99999, "enabled": 1, "auto_failover": 0,
})
asyncio.run(eng._reconcile_manual(store.get_tunnel(ghost)))
check("指向已删除节点的隧道如实报错",
      "已不存在" in (store.get_tunnel(ghost)["last_error"] or ""),
      store.get_tunnel(ghost)["last_error"])

noport = store.create_tunnel({
    "name": "没端口隧道", "proxy_name": "noport-tun", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22,
    "manual_node_id": mid, "enabled": 1, "auto_failover": 0,
})
asyncio.run(eng._reconcile_manual(store.get_tunnel(noport)))
check("没远程端口时说明原因而不是静默",
      "没有远程端口" in (store.get_tunnel(noport)["last_error"] or ""),
      store.get_tunnel(noport)["last_error"])

print("  --- 停用的节点 ---")
store.update_manual_node(mid, {"enabled": 0})
asyncio.run(eng._reconcile_manual(store.get_tunnel(t_manual)))
check("停用节点上的隧道如实报错",
      "已停用" in (store.get_tunnel(t_manual)["last_error"] or ""),
      store.get_tunnel(t_manual)["last_error"])
store.update_manual_node(mid, {"enabled": 1})

print()
print(f"==> PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
