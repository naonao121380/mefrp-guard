# -*- coding: utf-8 -*-
"""1.0.2：HTTP/HTTPS 隧道支持。

独立文件 + 独立数据目录 —— `store` 是模块级单例，和别的测试放同一个进程里
会互相污染数据库。

分三段：
  [A] 纯逻辑：domain 字段的解析 / 序列化（mefrp 的坑最多的一段）
  [B] 探测分流：HTTP 探测的 URL 构造与三态判定
  [C] API 与引擎：按类型校验、偏好分组、冷却复合键、DNS 走节点 IP

⚠️ 全程不碰外网：httpx 是桩，节点地址是 127.0.0.1。
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import tempfile

import asyncio

TMP = tempfile.mkdtemp(prefix="mg-http-tunnel-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
    MG_WEB_USER="admin",
    MG_WEB_PASSWORD="s3cret-pass",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# httpx 桩。
#
# ⚠️ **不能替换 sys.modules["httpx"]** —— FastAPI 的 TestClient 依赖真实的
#    httpx.Response 等类型，整个换掉会在 import 阶段就炸。正确做法是拿到真模块、
#    只把 AsyncClient 换成假的：engine.http_probe 在函数内部 `import httpx`，
#    拿到的就是同一个（已被打过补丁的）模块对象。
# ---------------------------------------------------------------------------
import httpx as _httpx                                  # noqa: E402

_HTTP = {"code": 200, "exc": None, "urls": []}


class _Resp:
    def __init__(self, code): self.status_code = code
    def __bool__(self): return True


class _AsyncClient:
    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **k):
        _HTTP["urls"].append(url)
        if _HTTP["exc"] is not None:
            raise _HTTP["exc"]
        return _Resp(_HTTP["code"])


_httpx.AsyncClient = _AsyncClient
# 异常类型用真实的那几个（engine 的 except Exception 能接住，但类型名要真的）
_TRANSPORT_ERR = _httpx.TransportError

from fastapi.testclient import TestClient               # noqa: E402
from app.main import app                                # noqa: E402
from app import store                                   # noqa: E402
from app.mefrp import (MefrpClient, Proxy, is_http_type,  # noqa: E402
                       join_domains, kind_of, parse_domains)
import app.engine as E                                  # noqa: E402

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


# ===========================================================================
# [A] domain 字段：mefrp 用「文本化的 JSON 数组」表达它，最容易写错的一段
# ===========================================================================
print("[A] mefrp domain 字段的解析与序列化")

# --- parse_domains：宽容解析 ---
check("parse: 官方形态（文本化 JSON 数组）",
      parse_domains('["a.example.com"]') == ["a.example.com"],
      parse_domains('["a.example.com"]'))
check("parse: 多个域名的 JSON 数组",
      parse_domains('["a.com","b.com"]') == ["a.com", "b.com"])
check("parse: 裸域名也认",
      parse_domains("a.example.com") == ["a.example.com"])
check("parse: 逗号分隔的裸串也认",
      parse_domains("a.com,b.com") == ["a.com", "b.com"])
check("parse: 分号 / 空格分隔也认",
      parse_domains("a;b c") == ["a", "b", "c"])
check("parse: 空串 -> []", parse_domains("") == [])
check("parse: None -> []", parse_domains(None) == [])
check("parse: 已经是 list 直接过",
      parse_domains(["a.com", " b.com "]) == ["a.com", "b.com"])
check("parse: JSON 数组里的空白被清掉",
      parse_domains('[" a.com ", ""]') == ["a.com"])
check("parse: 畸形 JSON 不抛异常（宽容兜底）",
      isinstance(parse_domains('["a"'), list))

# --- join_domains：严格照官方示例序列化 ---
check("join: 单个域名",
      join_domains("a.example.com") == '["a.example.com"]', join_domains("a.example.com"))
check("join: 多个域名",
      join_domains(["y.com", "z.com"]) == '["y.com", "z.com"]', join_domains(["y.com", "z.com"]))
check("join: 已经是 JSON 数组文本 -> 归一化（不双重编码）",
      join_domains('["x.example.com"]') == '["x.example.com"]',
      join_domains('["x.example.com"]'))
check("join: 空 -> 空串（TCP/UDP 的 domain 就是这个值）", join_domains("") == "")
check("join: None -> 空串", join_domains(None) == "")
check("join: 结果一定是合法 JSON", json.loads(join_domains("a.com,b.com")) == ["a.com", "b.com"])

# --- 类型判定 ---
check("is_http_type: http/https 是", is_http_type("http") and is_http_type("HTTPS"))
check("is_http_type: tcp/udp 不是", not is_http_type("tcp") and not is_http_type("udp"))
check("is_http_type: 带空格也认", is_http_type(" http "))
check("is_http_type: 空 -> 不是", not is_http_type(""))
check("kind_of: http/https -> http",
      kind_of("http") == "http" and kind_of("HTTPS") == "http")
check("kind_of: tcp/udp/空/怪值 -> port（保守一侧）",
      kind_of("tcp") == "port" and kind_of("udp") == "port"
      and kind_of("") == "port" and kind_of("weird") == "port")

# --- Proxy 上的便利属性 ---
p_http = Proxy(proxy_id=1, proxy_name="w", proxy_type="http", node_id=5,
               local_ip="127.0.0.1", local_port=8080, remote_port=None,
               domain='["w.example.com"]', is_online=True)
check("Proxy.domains 解析出域名列表", p_http.domains == ["w.example.com"], p_http.domains)
check("Proxy.is_http 为真", p_http.is_http is True)
p_tcp = Proxy(proxy_id=2, proxy_name="t", proxy_type="tcp", node_id=5,
              local_ip="127.0.0.1", local_port=22, remote_port=40022,
              domain="", is_online=True)
check("TCP Proxy.domains 为空", p_tcp.domains == [])
check("TCP Proxy.is_http 为假", p_tcp.is_http is False)

# --- proxy_create 的请求体：两类隧道只差两个字段 ---
print("  --- proxy_create 按类型分流 ---")


class _Capture(MefrpClient):
    def __init__(self):
        super().__init__(token="tk", base="http://127.0.0.1:1")
        self.bodies: list[dict] = []

    async def _request(self, method, path, json_body=None):
        self.bodies.append({"path": path, "body": json_body})
        return {}


cap = _Capture()
asyncio.run(cap.proxy_create(node_id=9, proxy_name="web", local_ip="127.0.0.1",
                             local_port=8080, proxy_type="http",
                             domain="nas.example.com", locations="/api"))
b = cap.bodies[-1]["body"]
check("HTTP: remotePort 显式传 None（不是省略）", b["remotePort"] is None, b["remotePort"])
check("HTTP: domain 是文本化 JSON 数组",
      b["domain"] == '["nas.example.com"]', b["domain"])
check("HTTP: locations 透传", b["locations"] == "/api", b["locations"])
check("HTTP: proxyType=http", b["proxyType"] == "http", b["proxyType"])

asyncio.run(cap.proxy_create(node_id=9, proxy_name="ssh", local_ip="127.0.0.1",
                             local_port=22, proxy_type="tcp",
                             remote_port=40022, domain="ignored.example.com"))
b = cap.bodies[-1]["body"]
check("TCP: remotePort 用传入值", b["remotePort"] == 40022, b["remotePort"])
check("★ TCP: domain 被强制清空（传了也不发）", b["domain"] == "", b["domain"])
check("TCP: locations 被强制清空", b["locations"] == "", b["locations"])

asyncio.run(cap.proxy_create(node_id=9, proxy_name="auto", local_ip="127.0.0.1",
                             local_port=22, proxy_type="tcp"))
check("TCP: 不给端口时 remotePort 为 None（让服务端分配）",
      cap.bodies[-1]["body"]["remotePort"] is None)

asyncio.run(cap.proxy_create(node_id=9, proxy_name="h2", local_ip="127.0.0.1",
                             local_port=8443, proxy_type="http",
                             domain="a.com,b.com", http_plugin="http2https"))
b = cap.bodies[-1]["body"]
check("HTTP: 多个域名序列化成 JSON 数组",
      json.loads(b["domain"]) == ["a.com", "b.com"], b["domain"])
check("HTTP: httpPlugin 透传", b["httpPlugin"] == "http2https", b["httpPlugin"])


# ===========================================================================
# [B] 探测分流
# ===========================================================================
print("[B] HTTP 探测的 URL 构造与三态判定")

check("url: http 隧道 -> http://",
      E.http_probe_url("http", "a.example.com") == "http://a.example.com/",
      E.http_probe_url("http", "a.example.com"))
check("url: https 隧道 -> https://",
      E.http_probe_url("https", '["b.example.com"]') == "https://b.example.com/",
      E.http_probe_url("https", '["b.example.com"]'))
check("url: 多域名取第一个",
      E.http_probe_url("http", "a.com,b.com") == "http://a.com/")
check("url: 自定义路径",
      E.http_probe_url("http", "a.com", "/health") == "http://a.com/health")
check("url: 路径不带斜杠自动补",
      E.http_probe_url("http", "a.com", "health") == "http://a.com/health")
check("url: 空域名 -> 空串（调用方据此报「没有绑定域名」）",
      E.http_probe_url("http", "") == "")

# http_probe 的返回码判定
_HTTP["exc"] = None
for code, want in ((200, True), (204, True), (301, True), (302, True), (399, True),
                   (400, False), (403, False), (404, False), (500, False), (502, False)):
    _HTTP["code"] = code
    okv, why = asyncio.run(E.http_probe("http://a.example.com/"))
    check(f"http_probe: {code} -> {'通' if want else '不通'}", okv is want, (okv, why))

_HTTP["code"] = 404
_okv, _why = asyncio.run(E.http_probe("http://a.example.com/"))
check("http_probe: 4xx 的说明里点明「链路通但服务返回了码」", "链路是通的" in _why, _why)
_HTTP["code"] = 200
_okv, _why = asyncio.run(E.http_probe("http://a.example.com/"))
check("http_probe: 2xx 的说明是 HTTP 200", _why == "HTTP 200", _why)

_HTTP["exc"] = _TRANSPORT_ERR("connect failed")
_okv, _why = asyncio.run(E.http_probe("http://a.example.com/"))
check("http_probe: 异常 -> 不通", _okv is False)
check("★ http_probe: 异常说明里带异常类型名（超时类 str() 常为空）",
      "TransportError" in _why, _why)
_HTTP["exc"] = None

_okv, _why = asyncio.run(E.http_probe(""))
check("http_probe: 空 URL -> 不通且说明原因", _okv is False and "域名" in _why, _why)

check("http_probe 不跟随重定向（3xx 也算通，靠的是 follow_redirects=False）",
      E.http_probe.__doc__ is not None and "不跟随" in E.http_probe.__doc__)


# ===========================================================================
# [C] API 与引擎：按类型校验 + 偏好分组 + 冷却复合键 + DNS 入口域名
# ===========================================================================
print("[C] API 按类型校验")

with TestClient(app) as c:
    # --- 建 HTTP 隧道 ---
    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "站点", "proxy_name": "web-1", "proxy_type": "http",
        "local_port": 8080, "desired_domain": "nas.example.com"})
    check("HTTP 隧道（带域名）-> 200", r.status_code == 200, r.text[:200])
    http_tid = r.json()["id"]

    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "没域名", "proxy_name": "web-2", "proxy_type": "http",
        "local_port": 8080})
    check("★ HTTP 隧道缺域名 -> 400", r.status_code == 400, r.status_code)
    check("  且说明「必须填写绑定域名」", "绑定域名" in r.text, r.text[:200])

    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "又给端口", "proxy_name": "web-3", "proxy_type": "http",
        "local_port": 8080, "desired_domain": "x.com", "desired_remote_port": 40001})
    check("★ HTTP 隧道填了端口 -> 400（端口对它无意义）", r.status_code == 400, r.status_code)

    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "TCP 绑域名", "proxy_name": "tcp-1", "proxy_type": "tcp",
        "local_port": 22, "desired_domain": "nope.com"})
    check("★ TCP 隧道绑域名 -> 400", r.status_code == 400, r.status_code)

    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "TCP 正常", "proxy_name": "tcp-2", "proxy_type": "tcp",
        "local_port": 22, "desired_remote_port": 40022})
    check("TCP 隧道（带端口）-> 200", r.status_code == 200, r.text[:200])
    tcp_tid = r.json()["id"]

    rows = {t["id"]: t for t in c.get("/api/tunnels", headers=AUTH).json()}
    check("HTTP 隧道的 desired_domain 落库成文本化 JSON 数组",
          rows[http_tid]["desired_domain"] == '["nas.example.com"]',
          rows[http_tid]["desired_domain"])
    check("HTTP 隧道的端口被清空", rows[http_tid]["desired_remote_port"] is None,
          rows[http_tid]["desired_remote_port"])
    check("TCP 隧道的 desired_domain 为空", rows[tcp_tid]["desired_domain"] == "")

    # --- overview 的对外入口按类型给 ---
    ov = c.get("/api/overview", headers=AUTH).json()
    o = {t["id"]: t for t in ov["tunnels"]}
    check("overview: HTTP 隧道 is_http=True", o[http_tid]["is_http"] is True)
    check("overview: HTTP 隧道 domains 解析成列表",
          o[http_tid]["domains"] == ["nas.example.com"], o[http_tid]["domains"])
    check("overview: HTTP 隧道 public_endpoint 是 http://域名",
          o[http_tid]["public_endpoint"] == "http://nas.example.com",
          o[http_tid]["public_endpoint"])
    check("overview: TCP 隧道 is_http=False", o[tcp_tid]["is_http"] is False)
    check("overview: TCP 隧道 public_endpoint 不是 URL 形式",
          not str(o[tcp_tid]["public_endpoint"]).startswith("http"),
          o[tcp_tid]["public_endpoint"])

    # --- PATCH 改类型/域名 ---
    r = c.patch(f"/api/tunnels/{http_tid}", headers=AUTH,
                json={"desired_domain": "a.com,b.com"})
    check("PATCH desired_domain -> 200", r.status_code == 200, r.text[:200])
    t = {x["id"]: x for x in c.get("/api/tunnels", headers=AUTH).json()}[http_tid]
    check("PATCH 后归一化成 JSON 数组",
          json.loads(t["desired_domain"]) == ["a.com", "b.com"], t["desired_domain"])

    # --- 设置：http_* 组可读写 ---
    r = c.put("/api/settings", headers=AUTH, json={
        "http_allow_regions": "cnos,oversea",
        "http_min_bandwidth_mbps": 30,
        "http_probe_path": "/health",
        "http_node_cooldown": 900,
        "probe_mode": "http",
    })
    check("PUT http_* 设置 -> 200", r.status_code == 200, r.text[:200])
    s = c.get("/api/settings", headers=AUTH).json()
    check("http_allow_regions 读回", s["settings"]["http_allow_regions"] == "cnos,oversea",
          s["settings"]["http_allow_regions"])
    check("http_probe_path 读回", s["settings"]["http_probe_path"] == "/health")
    check("probe_mode=http 被接受（枚举里有它）",
          s["settings"]["probe_mode"] == "http", s["settings"]["probe_mode"])
    check("默认值里有 http_allow_regions（且默认避开大陆）",
          s["defaults"].get("http_allow_regions") == "cnos,oversea",
          s["defaults"].get("http_allow_regions"))
    check("默认值里有 http_probe_path", s["defaults"].get("http_probe_path") == "/")
    r = c.put("/api/settings", headers=AUTH, json={"probe_mode": "bogus"})
    check("probe_mode 非法值 -> 400", r.status_code == 400, r.status_code)

    # --- 「HTTP 入口」已移除：节点偏好只剩 priority / excluded / note ---
    r = c.post("/api/nodes/91/pref", headers=AUTH,
               json={"http_entry": "node91.example.net"})
    check("提交已废弃的 http_entry -> 仍 200（未知字段被忽略，不报错）",
          r.status_code == 200, r.text[:200])
    prefs = c.get("/api/settings", headers=AUTH).json()["node_prefs"]
    check("★ 已废弃的 http_entry 不会落库",
          prefs.get("91", {}).get("http_entry") in (None, ""), prefs.get("91"))

print("[C] 引擎：偏好分组 / 冷却复合键 / DNS 入口域名")

# ---- 偏好按类型分组：同一个节点在两组口径下可以有不同的可用性 ----
from app.mefrp import Node      # noqa: E402
from app.settings import pref_key   # noqa: E402

check("pref_key: port 组映射到旧键",
      pref_key("port", "regions") == "allow_regions"
      and pref_key("port", "keywords") == "prefer_keywords"
      and pref_key("port", "node_cooldown") == "node_cooldown")
check("pref_key: http 组映射到 http_* 键",
      pref_key("http", "regions") == "http_allow_regions"
      and pref_key("http", "keywords") == "http_prefer_keywords"
      and pref_key("http", "node_cooldown") == "http_node_cooldown")
check("pref_key: 认不出的 kind 一律退回 port（保守）",
      pref_key("weird", "regions") == "allow_regions")

store.set_setting("allow_regions", "cn")
store.set_setting("http_allow_regions", "cnos,oversea")
store.set_setting("min_bandwidth_mbps", 25)
store.set_setting("http_min_bandwidth_mbps", 25)
store.set_setting("max_load_percent", 90)
store.set_setting("http_max_load_percent", 90)
store.set_setting("prefer_keywords", "")
store.set_setting("http_prefer_keywords", "")

eng = E.GuardEngine()
eng.nodes = {
    91: Node(node_id=91, name="北京①", hostname="", region="cn",
             bandwidth="100Mbps", is_online=True, allow_type="tcp;udp;http;https"),
    237: Node(node_id=237, name="纽约②", hostname="", region="oversea",
             bandwidth="100Mbps", is_online=True, allow_type="tcp;udp;http"),
}
n_port, _ = eng.pick_node(proxy_type="tcp")
check("TCP 口径（allow_regions=cn）只挑大陆节点",
      n_port is not None and n_port.node_id == 91, n_port)
n_http, _ = eng.pick_node(proxy_type="http")
check("★ HTTP 口径（http_allow_regions=cnos,oversea）只挑海外节点",
      n_http is not None and n_http.node_id == 237, n_http)
check("★ 同一批节点在两套口径下选出不同结果（证明偏好真的分开了）",
      n_port.node_id != n_http.node_id)

# rank_nodes 按类型给 warning
rows_port = {r["node_id"]: r for r in eng.rank_nodes("tcp")}
rows_http = {r["node_id"]: r for r in eng.rank_nodes("http")}
# ⚠️ 区域不符是**软偏好**：节点仍然 selectable（可以手动指定），只是不 eligible。
check("rank_nodes(tcp): 纽约节点区域不符 -> 不合格（但仍可手动指定）",
      rows_port[237]["eligible"] is False and rows_port[237]["selectable"] is True,
      rows_port[237])
check("rank_nodes(tcp): 区域不符的原因进 warnings",
      any("区域" in w for w in rows_port[237]["warnings"]), rows_port[237]["warnings"])
check("rank_nodes(http): 纽约节点合格",
      rows_http[237]["eligible"] is True, rows_http[237])
check("★ rank_nodes(http): 大陆节点带「需报备」警告",
      any("报备" in w for w in rows_http[91]["warnings"]), rows_http[91]["warnings"])
check("rank_nodes(tcp): 大陆节点没有报备警告（那只对 http 组有意义）",
      not any("报备" in w for w in rows_port[91]["warnings"]), rows_port[91]["warnings"])
check("★ rank_nodes 不再透传已废弃的 http_entry",
      "http_entry" not in rows_http[91], list(rows_http[91]))

# ---- 冷却表是 (类型组, 节点) 复合键 ----
eng.node_cooldown = {("port", 91): 9e9}
check("port 组冷却：tcp 挑不到 91", eng.pick_node(proxy_type="tcp")[0] is None)
check("★ port 组冷却不影响 http 组（键不同）",
      eng.pick_node(proxy_type="http")[0] is not None)
eng.node_cooldown = {("http", 237): 9e9}
check("http 组冷却：http 挑不到 237",
      eng.pick_node(proxy_type="http")[0] is None)
check("★ http 组冷却不影响 port 组", eng.pick_node(proxy_type="tcp")[0] is not None)
eng.node_cooldown = {}

# ---- DNS 目标：两类隧道都走节点 IP 的 A 记录 ----
# （1.0.2 中途曾有过一个「HTTP 入口域名」让 HTTP 隧道走 CNAME，后来去掉了 ——
#  官方要求 CNAME 到的那个「节点域名」对非管理员账号根本拿不到，用户无从填写。）
print("  --- DNS 目标 ---")


class _FakeCF:
    def __init__(self):
        self.token = "tk"
        self.upserts = []

    async def resolve_zone(self, name):
        from app.cloudflare import Zone
        return Zone(zone_id="Z1", name="example.com")

    async def list_records(self, zone_id, name=None):
        return []

    async def upsert(self, **kw):
        from app.cloudflare import DnsRecord
        self.upserts.append(kw)
        return DnsRecord(kw.get("record_id") or "R1", kw["zone_id"], kw["name"],
                         kw["record_type"], kw["content"], kw.get("proxied", False))


store.set_setting("auto_dns_sync", True)
eng.cf = _FakeCF()
eng.nodes = {91: Node(node_id=91, name="北京①", hostname="", region="cn",
                      bandwidth="100Mbps", is_online=True,
                      allow_type="tcp;udp;http;https")}
# 让 node_address 直接返回 IP，避免走「从官方配置反推」那条路
eng.node_hostname_cache = {91: "203.0.113.10"}

h_http = store.create_tunnel({
    "name": "站点A", "proxy_name": "site-a", "proxy_type": "http",
    "local_ip": "127.0.0.1", "local_port": 8080,
    "desired_domain": '["site-a.example.com"]', "current_domain": "site-a.example.com",
    "current_node_id": 91, "dns_record_name": "site-a.example.com", "enabled": 1,
})
proxy_a = Proxy(proxy_id=501, proxy_name="site-a", proxy_type="http", node_id=91,
                local_ip="127.0.0.1", local_port=8080, remote_port=None,
                domain='["site-a.example.com"]', is_online=True)

# HTTP 隧道：DNS 目标是**节点 IP**，于是走 A 记录。
asyncio.run(eng._sync_dns(store.get_tunnel(h_http), proxy_a, force=True))
rec = eng.cf.upserts[-1]
check("★ HTTP 隧道的 DNS 走节点 IP 的 A 记录",
      rec["record_type"] == "A" and rec["content"] == "203.0.113.10",
      (rec["record_type"], rec["content"]))

# TCP 隧道：口径完全一致（两类隧道在 DNS 目标上不再有分叉）
h_tcp = store.create_tunnel({
    "name": "SSH", "proxy_name": "ssh-a", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22, "current_remote_port": 40022,
    "current_node_id": 91, "dns_record_name": "ssh-a.example.com", "enabled": 1,
})
proxy_t = Proxy(proxy_id=502, proxy_name="ssh-a", proxy_type="tcp", node_id=91,
                local_ip="127.0.0.1", local_port=22, remote_port=40022,
                domain="", is_online=True)
asyncio.run(eng._sync_dns(store.get_tunnel(h_tcp), proxy_t, force=True))
rec = eng.cf.upserts[-1]
check("TCP 隧道也是节点 IP 的 A 记录（两类口径一致）",
      rec["record_type"] == "A" and rec["content"] == "203.0.113.10",
      (rec["record_type"], rec["content"]))

# ---- probe_plan 在 http 模式下的分流 ----
print("  --- probe_plan 三种模式 ---")
check("auto: http 隧道跳过（TCP 层是假阳性）",
      E.probe_plan("http", "auto")[0] == "none")
check("auto: tcp 隧道照常 TCP 探测", E.probe_plan("tcp", "auto")[0] == "tcp")
check("http 模式: http 隧道走 HTTP 探测", E.probe_plan("http", "http")[0] == "http")
check("http 模式: https 隧道走 HTTP 探测", E.probe_plan("https", "http")[0] == "http")
check("http 模式: tcp 隧道仍是 TCP 探测", E.probe_plan("tcp", "http")[0] == "tcp")
check("http 模式: udp 隧道仍不探", E.probe_plan("udp", "http")[0] == "none")
check("none 模式: 全关", all(E.probe_plan(t, "none")[0] == "none"
                          for t in ("tcp", "udp", "http", "https")))

# ---- _probe_cached 在 http 模式下真的去请求域名 ----
_HTTP["code"] = 200
_HTTP["urls"].clear()
store.set_setting("probe_mode", "http")
store.set_setting("http_probe_path", "/health")
eng.probe_cache.clear()
okv, why = asyncio.run(eng._probe_cached(h_http, "", 0, "http",
                                         domain="site-a.example.com"))
check("★ probe_mode=http 时引擎真的请求了绑定域名",
      _HTTP["urls"] and _HTTP["urls"][-1] == "http://site-a.example.com/health",
      _HTTP["urls"])
check("探测通过时返回 True", okv is True, (okv, why))

_HTTP["code"] = 502
eng.probe_cache.clear()
okv, why = asyncio.run(eng._probe_cached(h_http, "", 0, "http",
                                         domain="site-a.example.com"))
check("502 -> False（真故障，会涨 fail_streak）", okv is False, (okv, why))

store.set_setting("probe_mode", "auto")
eng.probe_cache.clear()
okv, why = asyncio.run(eng._probe_cached(h_http, "", 0, "http",
                                         domain="site-a.example.com"))
check("★ auto 模式下 http 隧道返回 None（不是 False，不能涨 fail_streak）",
      okv is None, (okv, why))
check("  auto 模式下给出的原因是「假阳性」",
      "假阳性" in why, why)

# 没有绑定域名时也是 None（不适用），不是 False。用 http 模式才会走到这一支。
store.set_setting("probe_mode", "http")
eng.probe_cache.clear()
okv, why = asyncio.run(eng._probe_cached(h_http, "", 0, "http", domain=""))
check("没有绑定域名 -> None 且说明原因", okv is None and "域名" in why, (okv, why))
store.set_setting("probe_mode", "auto")

print(f"\n==> PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
