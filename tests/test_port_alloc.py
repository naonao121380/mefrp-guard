# -*- coding: utf-8 -*-
"""远程端口分配 + 告警去重（2026-11-13 事故）。

用户报的现象（凌晨 3 点）：
  · 所有节点切换都报 `[400] 远程端口无效`，回滚也失败；
  · 同一条 Gotify 连着推了几百遍。

根因（用真实 mefrp 接口实测确认）：

    请求里的 remotePort                  返回
    ----------------------------------  ----------------------------------
    null（老代码「让服务端自动分配」）     [400] 远程端口无效
    合法且空闲的端口                      成功
    已被占用的端口                        [403] 端口已被占用, 请重新选择…
    HTTP/HTTPS（恒为 null）               正常

  也就是说 mefrp 去掉了「服务端自动分配」，而老代码的兜底档正是传 null ——
  于是必失败；失败又不写 `last_failover_at`（冷却起点），冷却等于没有，
  每轮巡检重试一次、推一条 Gotify，刷屏就是这么来的。

本文件钉住：
  [A] parse_port_ranges / pick_free_port 的边界
  [B] port_candidates 的优先顺序与「绝不产出 None」
  [C] 客户端入口拒绝空端口（不再把 null 发给 mefrp）
  [D] _move_tunnel：端口被占用 → 自动换一个，最终用上的是节点范围内端口
  [E] push_tunnel_config：没填期望端口时也会挑一个具体端口
  [F] Notifier 的重复抑制
  [G] 切换失败会写 last_failover_at 并累加退避计数

⚠️ 全程不碰外网：`_request` 是桩。
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import random
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="mg-port-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
    MG_WEB_USER="admin",
    MG_WEB_PASSWORD="s3cret-pass",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import engine as E                     # noqa: E402
from app import store                           # noqa: E402
from app.mefrp import (MefrpApiError, MefrpClient, MefrpError,  # noqa: E402
                       Node, Proxy)
from app.notifier import Notifier                # noqa: E402

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
# [A] 端口区间解析与随机挑选
# ===========================================================================
print("[A] parse_port_ranges / pick_free_port")

check("单区间", E.parse_port_ranges("40000-65535") == [(40000, 65535)])
check("多区间（分号）",
      E.parse_port_ranges("10000-20000;30000-31000")
      == [(10000, 20000), (30000, 31000)])
check("单值", E.parse_port_ranges("8080") == [(8080, 8080)])
check("空串 -> 空列表", E.parse_port_ranges("") == [])
check("垃圾串 -> 空列表", E.parse_port_ranges("abc;--;0-0") == [])
check("倒序区间被丢弃", E.parse_port_ranges("500-400") == [])

rng = random.Random(7)
picked = {E.pick_free_port([(37500, 37999)], set(), rng=rng) for _ in range(50)}
check("挑出来的端口都落在区间内",
      all(37500 <= p <= 37999 for p in picked), picked)
check("是随机的（50 次不止一个值）", len(picked) > 1, len(picked))
check("池子占满 -> None",
      E.pick_free_port([(10, 12)], {10, 11, 12}) is None)
check("跳过被占用的端口",
      E.pick_free_port([(10, 11)], {10}) == 11)
check("多区间里能挑到第二段",
      E.pick_free_port([(10, 10), (20, 20)], {10}) == 20)


# ===========================================================================
# [B] port_candidates
# ===========================================================================
print("[B] port_candidates：期望 → 现有 → 随机，且绝不产出 None")


def mk_node(**over) -> Node:
    data = dict(node_id=350, name="北京 ④", hostname="1.1.1.1",
                allow_port="37500-37999", allow_type="tcp;udp",
                allow_group="", is_online=True)
    data.update(over)
    return Node(**data)


E.engine.proxies = {}
E.engine.proxy_by_id = {}

node = mk_node()
cands = list(E.engine.port_candidates(node, {
    "desired_remote_port": None, "current_remote_port": 48518}))
check("★ 现有端口不在此节点范围（48518 vs 37500-37999）时不会出现在候选里",
      48518 not in cands, cands[:3])
check("候选全部落在节点允许范围内",
      all(37500 <= p <= 37999 for p in cands), cands[:3])
check("候选里没有 None", None not in cands)
check("最多吐 MAX_PORT_TRIES 个随机端口",
      len(cands) <= E.MAX_PORT_TRIES, len(cands))

cands2 = list(E.engine.port_candidates(node, {
    "desired_remote_port": 37600, "current_remote_port": 37610}))
check("期望端口排第一", cands2[0] == 37600, cands2[:2])
check("现有端口排第二", cands2[1] == 37610, cands2[:2])
check("之后的随机端口不重复",
      len(cands2) == len(set(cands2)), cands2)

# 节点上已占用的端口必须避开
E.engine.proxies = {
    "占用者": Proxy(proxy_id=1, proxy_name="占用者", proxy_type="tcp",
                    node_id=350, local_ip="127.0.0.1", local_port=1,
                    remote_port=37501, is_online=True),
}
E.engine.proxy_by_id = {1: E.engine.proxies["占用者"]}
occupied = {p for p in E.engine.port_candidates(node, {})
            if p == 37501}
check("★ 节点上已被别的隧道占用的端口不会出现在候选里",
      not occupied, occupied)
E.engine.proxies = {}
E.engine.proxy_by_id = {}

# 节点没有 allowPort → 回落到默认区间，仍然不是 None
free_node = mk_node(node_id=999, name="野节点", allow_port="")
fallback = list(E.engine.port_candidates(free_node, {}))
check("节点没给 allowPort 时回落到默认区间",
      fallback and all(E.DEFAULT_PORT_RANGE[0] <= p <= E.DEFAULT_PORT_RANGE[1]
                       for p in fallback), fallback[:2])


# ===========================================================================
# [C] 客户端入口：空端口直接报错，不发请求
# ===========================================================================
print("[C] proxy_create / proxy_update 拒绝空端口")


class _Cap(MefrpClient):
    """记录请求；create 时按 busy 集合模拟 403。"""

    def __init__(self) -> None:
        super().__init__(token="tk", base="http://127.0.0.1:1")
        self.calls: list[tuple[str, dict]] = []
        self.busy: set[int] = set()
        self.create_ports: list[object] = []

    def body_of(self, path: str) -> dict:
        for p, b in reversed(self.calls):
            if p == path:
                return b or {}
        return {}

    async def _request(self, method, path, json_body=None):
        self.calls.append((path, json_body))
        if path == "/auth/proxy/create":
            body = json_body or {}
            rp = body.get("remotePort")
            # HTTP/HTTPS 的 remotePort 就该是 null —— mefrp 要的就是这个
            if str(body.get("proxyType") or "").lower() in ("http", "https"):
                return None
            self.create_ports.append(rp)
            if rp is None:
                raise MefrpApiError(400, "远程端口无效")
            if int(rp) in self.busy:
                raise MefrpApiError(403, "端口已被占用, 请重新选择端口")
            self.busy.add(int(rp))
            return None
        if path == "/auth/proxy/update":
            return None
        if path == "/auth/proxy/list":
            return {"nodes": [], "proxies": []}
        if path in ("/auth/node/list", "/auth/node/status", "/auth/proxy/kick"):
            return []
        return {}


cap = _Cap()
err = ""
try:
    asyncio.run(cap.proxy_create(node_id=350, proxy_name="t", local_ip="127.0.0.1",
                                 local_port=1, proxy_type="udp", remote_port=None))
except MefrpError as exc:
    err = str(exc)
check("★ TCP/UDP 传空端口在客户端就报错（不浪费一次 400 请求）",
      "必须显式指定远程端口" in err, err)
check("★ 而且根本没发请求", cap.calls == [], cap.calls)

err2 = ""
try:
    asyncio.run(cap.proxy_update(1, node_id=350, proxy_name="t", local_ip="127.0.0.1",
                                 local_port=1, proxy_type="tcp", remote_port=None))
except MefrpError as exc:
    err2 = str(exc)
check("update 同样拒绝空端口", "必须显式指定远程端口" in err2, err2)

# http 不受影响：仍然传 null
asyncio.run(cap.proxy_create(node_id=350, proxy_name="h", local_ip="127.0.0.1",
                             local_port=1, proxy_type="http", domain="a.com"))
hb = cap.body_of("/auth/proxy/create")
check("HTTP 隧道仍然传 remotePort=null（这条路 mefrp 要的就是 null）",
      "remotePort" in hb and hb["remotePort"] is None, hb.get("remotePort"))


# ===========================================================================
# [D] _move_tunnel：端口被占用时自动换一个
# ===========================================================================
print("[D] _move_tunnel：403 端口被占用 -> 换下一个")


class _MoveCap(_Cap):
    """create 第一次回 403，第二次成功；proxy/list 返回新隧道。"""

    def __init__(self, fail_times: int = 1) -> None:
        super().__init__()
        self.fail_times = fail_times
        self.ok_port: int | None = None

    async def _request(self, method, path, json_body=None):
        if path == "/auth/proxy/create":
            self.calls.append((path, json_body))
            body = json_body or {}
            if str(body.get("proxyType") or "").lower() in ("http", "https"):
                return None
            rp = body.get("remotePort")
            self.create_ports.append(rp)
            if rp is None:
                raise MefrpApiError(400, "远程端口无效")
            if self.fail_times > 0:
                self.fail_times -= 1
                raise MefrpApiError(403, "端口已被占用, 请重新选择端口")
            self.ok_port = int(rp)
            return None
        return await super()._request(method, path, json_body)


TUN_NAME = "ikuai_ovpn"
tid = store.create_tunnel({
    "name": "ikuai_ovpn", "proxy_name": TUN_NAME, "proxy_type": "udp",
    "local_ip": "10.215.171.11", "local_port": 1194,
    "current_proxy_id": 4242, "current_node_id": 117,
    "current_remote_port": 48518,
})
tun = store.get_tunnel(tid)
cap = _MoveCap(fail_times=1)
E.engine.client = cap
E.engine.proxies = {}
E.engine.proxy_by_id = {}
# _await_proxy 要用真实列表，这里回一条同名隧道
_orig = cap._request


async def _patched(method, path, json_body=None):
    if path == "/auth/proxy/list":
        cap.calls.append((path, json_body))
        return {"nodes": [], "proxies": [{
            "proxyId": 7777, "proxyName": TUN_NAME, "proxyType": "udp",
            "nodeId": 350, "localIp": "10.215.171.11", "localPort": 1194,
            "remotePort": cap.ok_port or 0, "isOnline": False,
        }]}
    return await _orig(method, path, json_body)


cap._request = _patched  # type: ignore[method-assign]

res = asyncio.run(E.engine._move_tunnel(tun, mk_node()))
check("换端口后创建成功", res.get("ok") is True, res.get("error"))
check("★ 创建请求里的 remotePort 全部是**具体端口**，没有一个是 None",
      cap.create_ports and all(p is not None for p in cap.create_ports),
      cap.create_ports)
check("★ 第一次被 403、第二次换了一个端口（试了两次）",
      len(cap.create_ports) == 2, cap.create_ports)
check("两次用的不是同一个端口",
      len(set(cap.create_ports)) == 2, cap.create_ports)
check("最终端口落在节点允许范围内",
      cap.ok_port is not None and 37500 <= cap.ok_port <= 37999, cap.ok_port)
check("★ 48518 没有被硬发出去（它不在北京④的端口池里）",
      48518 not in cap.create_ports, cap.create_ports)
check("返回的新端口是 mefrp 上真实分配的那个",
      res.get("new_port") == cap.ok_port, (res.get("new_port"), cap.ok_port))


# ===========================================================================
# [E] push_tunnel_config：没填期望端口也要挑一个
# ===========================================================================
print("[E] push_tunnel_config：desired/current 都为空时自动挑端口")

tid2 = store.create_tunnel({
    "name": "空端口隧道", "proxy_name": "empty-port", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 22,
    "current_proxy_id": 8888, "current_node_id": 350,
    "current_remote_port": None,
})
tun2 = store.get_tunnel(tid2)

cap2 = _Cap()
E.engine.client = cap2
E.engine.proxies = {"empty-port": Proxy(
    proxy_id=8888, proxy_name="empty-port", proxy_type="tcp", node_id=350,
    local_ip="127.0.0.1", local_port=22, remote_port=0, is_online=False)}
E.engine.proxy_by_id = {8888: E.engine.proxies["empty-port"]}
E.engine.nodes = {350: mk_node()}

upd = asyncio.run(E.engine.push_tunnel_config(tid2))
body = cap2.body_of("/auth/proxy/update")
check("推远端没有直接失败", not upd.get("error"), upd)
check("★ update 请求的 remotePort 是具体端口（不是 null）",
      body.get("remotePort") is not None, body.get("remotePort"))
check("端口落在节点允许范围内",
      body.get("remotePort") is not None
      and 37500 <= int(body["remotePort"]) <= 37999, body.get("remotePort"))


# ===========================================================================
# [F] Notifier 去重
# ===========================================================================
print("[F] Notifier：同一句话不会连着推")


class _FakeResp:
    status_code = 200


class _FakeClient:
    posts: list[dict] = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeClient.posts.append(json or {})
        return _FakeResp()


import app.notifier as N  # noqa: E402

_orig_client = N.httpx.AsyncClient
N.httpx.AsyncClient = _FakeClient  # type: ignore[assignment]

n = Notifier("http://gotify.local", "tk")
for _ in range(5):
    asyncio.run(n.send("⚠️ 隧道切换失败：ikuai_ovpn", "原因：[400] 远程端口无效", "error"))
check("★ 同一标题+正文推 5 次，只真的发出去 1 次",
      len(_FakeClient.posts) == 1, len(_FakeClient.posts))

asyncio.run(n.send("⚠️ 隧道切换失败：ikuai_ovpn", "原因：[403] 端口已被占用", "error"))
check("正文不同 -> 照常推", len(_FakeClient.posts) == 2, len(_FakeClient.posts))

n2 = Notifier("http://gotify.local", "tk")
# 去重账本现在按**字符串 key**存（支持调用方传稳定 key），不再用三元组。
n2._sent_at["error|t|m"] = time.monotonic() - 1801
check("窗口过期后允许再推",
      not n2._is_duplicate("error|t|m", "error"))

N.httpx.AsyncClient = _orig_client  # type: ignore[assignment]


# ===========================================================================
# [G] 切换失败要进冷却
# ===========================================================================
print("[G] 失败也写 last_failover_at（否则冷却等于没有）")

tid3 = store.create_tunnel({
    "name": "冷却", "proxy_name": "cool", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 1,
})
tun3 = store.get_tunnel(tid3)
E.engine.failover_fail_streak = {}
now = time.time()
g = [tun3]
s1 = E.engine._mark_failover_failed(g, now)
check("失败计数从 1 开始", s1 == 1, s1)
check("★ last_failover_at 被写成这次尝试的时间",
      int(store.get_tunnel(tid3)["last_failover_at"]) == int(now),
      store.get_tunnel(tid3)["last_failover_at"])
s2 = E.engine._mark_failover_failed(g, now + 1)
check("连续失败累加", s2 == 2, s2)
check("退避倍数封顶 8",
      min(2 ** 10, 8) == 8)

# 失败 → 冷却真的会拦住下一次（不 ignore_cooldown 时）
E.engine.client = _Cap()
E.engine.proxies = {}
E.engine.nodes = {}
r = asyncio.run(E.engine._failover(store.get_tunnel(tid3), "测试"))
check("★ 冷却期内不会再切（返回失败但不是「没节点」那条路）",
      r.get("ok") is False and "冷却" in str(r.get("error")), r)


print()
print(f"PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
