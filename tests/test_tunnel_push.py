# -*- coding: utf-8 -*-
"""编辑隧道必须**真的**落到 mefrp（2026-10-17 修，版本号仍为 1.0.3）。

用户报的问题：改完隧道信息、保存成功，实际一点没变。

根因是两层叠加：
  1. `PATCH /api/tunnels/{id}` 只 `store.update_tunnel()` —— **从不调 mefrp**；
  2. frpc 配置是 mefrp 按**远端 proxy** 生成的（`/auth/proxy/config`），
     远端不动 → 配置不动 → 行为不变。页面上的数字只是本地库。

本文件钉住：
  [A] `_field_equal` 的归一化比较（域名是文本化 JSON、端口有 None/0 两种空）
  [B] `proxy_update` / `proxy_kick` 的请求体（update 必须带 proxyId）
  [C] `push_tunnel_config` 的四条「推不了」分支 + 正常路径（kick → update → rebuild）
  [D] `PATCH /api/tunnels` 的接线：改远端字段才推、改标签不推、改类型 400

⚠️ 全程不碰外网：`_request` 是桩。
"""

from __future__ import annotations

import asyncio
import base64
import os
import pathlib
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="mg-tunnel-push-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
    MG_WEB_USER="admin",
    MG_WEB_PASSWORD="s3cret-pass",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient               # noqa: E402
from app.main import app                                # noqa: E402
from app import store                                   # noqa: E402
import app.engine as E                                  # noqa: E402
from app.mefrp import MefrpApiError, MefrpClient, Proxy  # noqa: E402

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


class _Cap(MefrpClient):
    """把 `_request` 换成记录器；按路径返回 mefrp 形状的假数据。"""

    def __init__(self) -> None:
        super().__init__(token="tk", base="http://127.0.0.1:1")
        self.calls: list[tuple[str, dict]] = []
        self.kick_offline = False        # kick 时回「隧道不在线」
        self.online_fail_times = 0       # update 前 N 次回「隧道在线」
        self.update_error: MefrpApiError | None = None

    def paths(self) -> list[str]:
        return [p for p, _ in self.calls]

    def body_of(self, path: str) -> dict:
        for p, b in reversed(self.calls):
            if p == path:
                return b or {}
        return {}

    async def _request(self, method, path, json_body=None):
        self.calls.append((path, json_body))
        if path == "/auth/proxy/list":
            return {"nodes": [], "proxies": [{
                "proxyId": 555, "proxyName": "web-1", "proxyType": "http",
                "nodeId": 9, "localIp": "127.0.0.1", "localPort": 8080,
                "remotePort": 0, "domain": '["new.example.com"]',
                "isOnline": True,
            }]}
        if path in ("/auth/node/list", "/auth/node/status"):
            return []
        if path == "/auth/user/info":
            return {}
        if path == "/auth/proxy/update":
            if self.online_fail_times > 0:
                self.online_fail_times -= 1
                raise MefrpApiError(403, "隧道在线，请先强制下线隧道")
            if self.update_error is not None:
                raise self.update_error
            return None
        if path == "/auth/proxy/kick":
            if self.kick_offline:
                raise MefrpApiError(400, "隧道不在线")
            return None
        return {}


def new_tunnel(**over) -> int:
    data = {
        "name": "站点", "proxy_name": "web-1", "proxy_type": "http",
        "local_ip": "127.0.0.1", "local_port": 8080,
        "desired_domain": '["new.example.com"]',
        "current_proxy_id": 555, "current_node_id": 9,
        "current_domain": '["old.example.com"]',
    }
    data.update(over)
    return store.create_tunnel(data)


def engine_ready(cap: _Cap) -> None:
    E.engine.client = cap
    E.engine.proxies = {"web-1": Proxy(
        proxy_id=555, proxy_name="web-1", proxy_type="http", node_id=9,
        local_ip="127.0.0.1", local_port=8080, remote_port=0,
        domain='["new.example.com"]', is_online=True)}
    E.engine.proxy_by_id = {555: E.engine.proxies["web-1"]}


def _cap_create_fields() -> dict:
    """拿一次 create 的 body 作为「字段全集」的基准（update 应与它一致）。"""
    c = _Cap()
    asyncio.run(c.proxy_create(node_id=9, proxy_name="web-1",
                               local_ip="127.0.0.1", local_port=8080,
                               proxy_type="http", domain="a.com"))
    return c.body_of("/auth/proxy/create")


# ===========================================================================
# [A] 归一化比较 —— 「改没改」判断错了，后面全白做
# ===========================================================================
print("[A] _field_equal：什么才算「真的改了」")

from app.main import PUSH_TO_REMOTE_FIELDS, _field_equal   # noqa: E402

check("域名：JSON 文本化与裸串等价",
      _field_equal("desired_domain", '["a.com"]', "a.com"))
# ★ 顺序**刻意**算「变了」：mefrp 的 domain 是个有序数组，第一个是主域名。
#   判成等价就会漏推 —— 宁可多重启一次容器，也不能让用户的顺序调整静默失效。
check("域名：顺序不同算「变了」（有序数组，第一个是主域名）",
      not _field_equal("desired_domain", '["a.com", "b.com"]', "b.com,a.com"))
check("域名：多一个就是变了",
      not _field_equal("desired_domain", '["a.com"]', '["a.com", "b.com"]'))
check("端口：None 与 0 都算「空」",
      _field_equal("desired_remote_port", None, 0))
check("端口：8080 与 '8080' 等价",
      _field_equal("local_port", 8080, "8080"))
check("端口：8080 与 8081 不等价",
      not _field_equal("local_port", 8080, 8081))
check("普通字段：None 与 '' 等价", _field_equal("http_plugin", None, ""))
check("★ 需要推远端的字段里包含 local_port 与 desired_domain",
      "local_port" in PUSH_TO_REMOTE_FIELDS
      and "desired_domain" in PUSH_TO_REMOTE_FIELDS)
check("★ 纯本地字段不在推送清单里（改标签不该重启容器）",
      not any(k in PUSH_TO_REMOTE_FIELDS
              for k in ("name", "tag", "enabled", "dns_record_name",
                        "auto_failover", "frpc_instance_id")))

# ===========================================================================
# [B] 两个新端点的请求体
# ===========================================================================
print("[B] proxy_update / proxy_kick 的请求体")

cap = _Cap()
asyncio.run(cap.proxy_update(
    555, node_id=9, proxy_name="web-1", local_ip="10.0.0.2", local_port=9090,
    proxy_type="http", domain="new.example.com", locations="/api"))
b = cap.body_of("/auth/proxy/update")
check("update 走 /auth/proxy/update", "/auth/proxy/update" in cap.paths(), cap.paths())
check("update 带 proxyId", b.get("proxyId") == 555, b.get("proxyId"))
check("update 的 localPort 是新值", b.get("localPort") == 9090, b.get("localPort"))
check("update 的 localIp 是新值", b.get("localIp") == "10.0.0.2", b.get("localIp"))
check("update 的 domain 是文本化 JSON 数组",
      b.get("domain") == '["new.example.com"]', b.get("domain"))
check("update 的 remotePort 对 http 显式 None",
      b.get("remotePort") is None, b.get("remotePort"))
check("update 与 create 的字段集合一致",
      set(b) - {"proxyId"} == set(_cap_create_fields()), sorted(set(b)))

cap2 = _Cap()
asyncio.run(cap2.proxy_kick(555))
b2 = cap2.body_of("/auth/proxy/kick")
check("kick 走 /auth/proxy/kick", "/auth/proxy/kick" in cap2.paths())
check("kick 的 body 只有 proxyId", b2 == {"proxyId": 555}, b2)


# ===========================================================================
# [C] push_tunnel_config：四条「推不了」+ 正常路径
# ===========================================================================
print("[C] push_tunnel_config")

out = asyncio.run(E.engine.push_tunnel_config(999999))
check("隧道不存在 -> not_found",
      out.get("applicable") is False and out.get("reason") == "not_found", out)

tid_manual = new_tunnel(name="外部", proxy_name="ext-1", manual_node_id=1)
out = asyncio.run(E.engine.push_tunnel_config(tid_manual))
check("外部节点 -> external_node（没有 API 可推）",
      out.get("applicable") is False and out.get("reason") == "external_node", out)

tid_local = new_tunnel(name="未纳管", proxy_name="local-1", current_proxy_id=None)
out = asyncio.run(E.engine.push_tunnel_config(tid_local))
check("没有 current_proxy_id -> not_adopted",
      out.get("applicable") is False and out.get("reason") == "not_adopted", out)

# --- 正常路径 ---
tid = new_tunnel(name="正常", proxy_name="web-1")
cap = _Cap()
engine_ready(cap)
out = asyncio.run(E.engine.push_tunnel_config(tid))
check("正常路径 applicable=True", out.get("applicable") is True, out)
check("正常路径 updated=True", out.get("updated") is True, out)
check("正常路径 kicked=True", out.get("kicked") is True, out)
ps = cap.paths()
check("★ 顺序：kick 在 update 之前",
      ps.index("/auth/proxy/kick") < ps.index("/auth/proxy/update"), ps)
check("update 之后刷新了远端快照（拉了 proxy/list）",
      "/auth/proxy/list" in ps, ps)
cur = store.get_tunnel(tid) or {}
check("current_domain 同步成远端实际值",
      cur.get("current_domain") == '["new.example.com"]', cur.get("current_domain"))
check("current_proxy_id 保持 555", int(cur.get("current_proxy_id") or 0) == 555,
      cur.get("current_proxy_id"))

# --- kick 说「不在线」不是错误 ---
cap = _Cap()
cap.kick_offline = True
engine_ready(cap)
out = asyncio.run(E.engine.push_tunnel_config(tid))
check("★ kick 回「隧道不在线」当成功处理（不是失败）",
      out.get("updated") is True and not out.get("error"), out)

# --- update 撞「隧道在线」要重试 ---
cap = _Cap()
cap.online_fail_times = 2
engine_ready(cap)
out = asyncio.run(E.engine.push_tunnel_config(tid))
kicks = cap.paths().count("/auth/proxy/kick")
check("★ update 撞 403「在线」会重新 kick 并重试",
      out.get("updated") is True and kicks >= 2, f"kicks={kicks} out={out}")

# --- update 真失败：如实回传，但 frpc 那边仍要处理（隧道已被踢下线）---
cap = _Cap()
cap.update_error = MefrpApiError(400, "绑定域名列表不能为空")
engine_ready(cap)
out = asyncio.run(E.engine.push_tunnel_config(tid))
check("update 失败 -> updated=False 且带 error",
      out.get("updated") is False and "绑定域名" in str(out.get("error")), out)
check("★ update 失败也走完了 frpc 那一步（把隧道拉回来）",
      isinstance(out.get("frpc"), dict), out.get("frpc"))

# ===========================================================================
# [D] PATCH /api/tunnels 的接线
# ===========================================================================
print("[D] PATCH /api/tunnels/{id}")

with TestClient(app) as c:
    r = c.post("/api/tunnels", headers=AUTH, json={
        "name": "接线", "proxy_name": "wire-1", "proxy_type": "http",
        "local_port": 8080, "desired_domain": "wire.example.com"})
    check("建隧道 -> 200", r.status_code == 200, r.text[:200])
    wid = r.json()["id"]
    store.update_tunnel(wid, {"current_proxy_id": 555, "current_node_id": 9,
                              "current_domain": '["wire.example.com"]'})

    cap = _Cap()
    engine_ready(cap)
    E.engine.proxies = {"wire-1": Proxy(
        proxy_id=555, proxy_name="wire-1", proxy_type="http", node_id=9,
        local_ip="127.0.0.1", local_port=8080, remote_port=0,
        domain='["wire.example.com"]', is_online=True)}
    E.engine.proxy_by_id = {555: E.engine.proxies["wire-1"]}

    # 1) 改本地端口 -> 必须推远端
    r = c.patch(f"/api/tunnels/{wid}", headers=AUTH, json={"local_port": 9091})
    check("改 local_port -> 200", r.status_code == 200, r.text[:200])
    push = (r.json() or {}).get("push") or {}
    check("★ 改 local_port 会推远端（push.applicable=True）",
          push.get("applicable") is True, push)
    check("★ 推送时真的调了 update",
          "/auth/proxy/update" in cap.paths(), cap.paths())

    # 2) 只改标签 -> 不该推远端（不该重启容器）
    before = len(cap.calls)
    r = c.patch(f"/api/tunnels/{wid}", headers=AUTH, json={"tag": "临时"})
    check("改 tag -> 200", r.status_code == 200, r.text[:200])
    check("★ 改 tag 不推远端（push 为 null）",
          (r.json() or {}).get("push") is None, r.json())
    check("★ 改 tag 没有产生任何 mefrp 请求",
          len(cap.calls) == before, cap.paths()[before:])

    # 3) 改类型 -> 400（mefrp 的隧道不能原地改类型）
    r = c.patch(f"/api/tunnels/{wid}", headers=AUTH, json={"proxy_type": "tcp"})
    check("★ 改 proxy_type -> 400", r.status_code == 400, r.text[:200])
    check("400 的文案说清了「不能原地改」",
          "不能原地修改" in r.text, r.text[:200])

    # 4) 原样回写（没变化）-> 不该推远端
    before = len(cap.calls)
    r = c.patch(f"/api/tunnels/{wid}", headers=AUTH,
                json={"local_port": 9091, "desired_domain": "wire.example.com"})
    check("原样回写 -> 200", r.status_code == 200, r.text[:200])
    check("★ 值没变就不推远端（不白重启容器）",
          (r.json() or {}).get("push") is None and len(cap.calls) == before,
          (r.json(), cap.paths()[before:]))

# ===========================================================================
# [E] force_restart：kick 之后「配置没变也得重启」—— 否则隧道永久离线
# ===========================================================================
print("[E] _rebuild_and_restart 的 force_restart")


class _FakeDocker:
    def __init__(self) -> None:
        self.restarts = 0

    def restart(self, timeout: int = 15) -> dict:
        self.restarts += 1
        return {"ok": True, "status": "running"}


def _wire_instance(tid: int) -> _FakeDocker:
    """给隧道挂一个 frpc 实例，并把 Docker / 重建都换成桩。"""
    _wire_instance.n += 1
    iid = store.create_frpc_instance({
        "name": f"测试实例-{_wire_instance.n}",
        "config_path": os.path.join(TMP, f"inst-{_wire_instance.n}.toml"),
        "container": f"frpc-test-{_wire_instance.n}",
        "restart_mode": "docker", "enabled": 1,
    })
    store.update_tunnel(tid, {"frpc_instance_id": iid})
    dk = _FakeDocker()
    # ⚠️ 必须放进 dockers[iid]：docker_for 只在**单实例**时才兜底 self.docker，
    #    本文件会建好几个实例，靠兜底拿不到控制器。
    E.engine.dockers = {iid: dk}
    E.engine.docker = dk

    async def _fake_rebuild(instance_id=None):
        return False, {"proxy_count": 1}     # ★ 配置「没变化」

    E.engine.rebuild_frpc = _fake_rebuild
    return dk


_wire_instance.n = 0


tid_f = new_tunnel(name="强制重启", proxy_name="force-1")
dk = _wire_instance(tid_f)
rr = asyncio.run(E.engine._rebuild_and_restart(store.get_tunnel(tid_f) or {}))
check("配置无变化 + 不强制 -> 不重启", dk.restarts == 0, dk.restarts)
check("配置无变化 + 不强制 -> restart_ok=True（跳过不算失败）",
      rr.get("restart_ok") is True and rr.get("changed") is False, rr)

dk = _wire_instance(tid_f)
rr = asyncio.run(E.engine._rebuild_and_restart(
    store.get_tunnel(tid_f) or {}, force_restart=True))
check("★ 配置无变化 + force_restart -> 仍然重启了容器",
      dk.restarts == 1, f"restarts={dk.restarts} rr={rr}")
check("★ 强制重启后 restart_ok=True", rr.get("restart_ok") is True, rr)

# 端到端：push 走完后必须落到「强制重启」这条路上
cap = _Cap()
engine_ready(cap)
tid_p = new_tunnel(name="推送后重启", proxy_name="force-2")
dk = _wire_instance(tid_p)
out = asyncio.run(E.engine.push_tunnel_config(tid_p))
check("★ push_tunnel_config 会强制重启 frpc 容器（kick 之后必须拉回来）",
      dk.restarts == 1, f"restarts={dk.restarts} out={out}")

print()
print(f"断言 {PASS + FAIL} 条，通过 {PASS}，失败 {FAIL}")
sys.exit(1 if FAIL else 0)
