# -*- coding: utf-8 -*-
"""故障转移全流程验证：mefrp / Cloudflare / Gotify / Docker 全部用假实现，
只有引擎和配置生成是真的。目的是验证「一整条自愈链路」串得起来。"""
import sys, types, os, tempfile, pathlib, asyncio, time

stub = types.ModuleType("httpx")
class _D:
    def __init__(self,*a,**k): pass
    async def __aenter__(self): return self
    async def __aexit__(self,*a): return False
stub.AsyncClient=_D; stub.HTTPError=type("HTTPError",(Exception,),{})
# cloudflare.py 模块级就要 `httpx.TransportError`，桩里没有会直接 import 失败。
stub.TransportError=type("TransportError",(stub.HTTPError,),{}); sys.modules["httpx"]=stub

tmp = tempfile.mkdtemp(prefix="mg-e2e-")
cfg = os.path.join(tmp, "frpc.toml")
os.environ.update(MG_DATA_DIR=tmp, MG_FRPC_CONFIG=cfg, MG_FRPC_CONTAINER="frpc")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import store, frpc
from app.mefrp import Node, Proxy
import app.engine as E
from app.engine import GuardEngine

PROBE = {"ok": True, "why": ""}
async def _fake_probe(host, port, timeout=4.0):
    return PROBE["ok"], PROBE["why"]
E.tcp_probe = _fake_probe          # 引擎内部是按模块全局名调用的

store.init()
store.set_setting("prefer_keywords", "北京")
store.set_setting("min_bandwidth_mbps", 25)
store.set_setting("auto_dns_sync", True)

ok=bad=0
def check(n,c,e=""):
    global ok,bad
    if c: ok+=1; print(f"  PASS  {n}")
    else: bad+=1; print(f"  FAIL  {n}  ->  {e}")

# ---------------- 假 mefrp ----------------
# 节点公网地址。**故意不放在 Node.hostname 里** —— 真实 API 对非管理员账号
# 会把 /auth/node/list 的 hostname 脱敏成空串，地址只出现在 /auth/proxy/list
# 的 nodes 子数组里。测试必须还原这个行为，否则测不到真正的取址路径。
NODE_ADDR = {5: "10.0.0.5", 9: "10.0.0.9", 7: "10.0.0.7"}

class FakeMefrp:
    def __init__(self):
        self.created = []       # 成功创建的 (node_id, proxy_name, remote_port)
        self.attempts = []      # 全部尝试（含失败的）的 (node_id, remote_port)
        self.deleted = []
        self._proxies = [Proxy(proxy_id=111, proxy_name="nas-panel", proxy_type="tcp",
                               node_id=5, local_ip="127.0.0.1", local_port=5000,
                               remote_port=41234, is_online=True)]
        self.fail_first_port = False
        # ★ 新建出来的 proxy 默认「在线」（= 有 frpc 连上来了）。想模拟「没挂接
        #   frpc、新 proxy 必然离线」的场景，把它置成 False —— 见 [19]。
        self.created_online = True
    async def node_list(self):
        # hostname 一律空串 = 非管理员视图（真实行为）
        return [
            Node(node_id=5, name="上海-旧节点", hostname="", region="cn",
                 bandwidth="100Mbps", is_online=False),          # 挂了的旧节点
            Node(node_id=9, name="北京-联通", hostname="", region="cn",
                 bandwidth="1Gbps", is_online=True, allow_port="40000-65535"),
            Node(node_id=7, name="广州-移动", hostname="", region="cn",
                 bandwidth="200Mbps", is_online=True, allow_port="40000-65535"),
        ]
    async def node_status(self): return {}
    async def proxy_list(self):
        # nodes 子数组只覆盖「已经有隧道」的节点 —— 和真实 API 一致。
        # 这是非管理员唯一能拿到节点公网地址的地方。
        brief = {p.node_id: {"nodeId": p.node_id, "name": f"node-{p.node_id}",
                             "hostname": NODE_ADDR.get(p.node_id, ""),
                             "allowGroup": ""}
                 for p in self._proxies}
        return (list(self._proxies), brief)
    async def user_info(self):
        from app.mefrp import UserInfo
        return UserInfo(username="demo-user", group="default",
                        friendly_group="正式用户", max_proxies=10, used_proxies=2)
    async def proxy_create(self, *, node_id, proxy_name, local_ip, local_port,
                           proxy_type="tcp", remote_port=None, **kw):
        self.attempts.append((node_id, remote_port))
        if remote_port == 41234 and self.fail_first_port:
            from app.mefrp import MefrpApiError
            self.fail_first_port = False
            raise MefrpApiError(400, "端口 41234 已被占用")
        self.created.append((node_id, proxy_name, remote_port))
        self._proxies = [p for p in self._proxies if p.proxy_name != proxy_name]
        self._proxies.append(Proxy(proxy_id=222, proxy_name=proxy_name, proxy_type=proxy_type,
                                   node_id=node_id, local_ip=local_ip, local_port=local_port,
                                   remote_port=remote_port or 41234,
                                   is_online=self.created_online))
    async def proxy_delete(self, pid): self.deleted.append(pid)
    async def proxy_config(self, pid, fmt="toml"):
        # ★ 故意用 TOML **单引号字面量** —— mefrp 官方生成的配置就是这个风格，
        #   原正则只认双引号，会把引号一起吃进捕获组，导致同一地址被误判为跨节点。
        node = {111: NODE_ADDR[5], 222: NODE_ADDR[9]}.get(pid, NODE_ADDR[9])
        return (f"serverAddr = '{node}'\nserverPort = 7000\nauth.method = 'token'\n"
                f"auth.token = 'tk'\nuser = 'demo'\n\n[[proxies]]\nname = 'nas-panel'\n"
                f"type = 'tcp'\nlocalIP = '127.0.0.1'\nlocalPort = 5000\nremotePort = 41234\n")

# ---------------- 假 Cloudflare ----------------
class FakeCF:
    def __init__(self):
        self.token = "fake-cf-token"   # _sync_dns 会先看「有没有配 token」
        self.upserts = []
    async def resolve_zone(self, name):
        from app.cloudflare import Zone
        return Zone(zone_id="Z1", name="example.com")
    async def list_records(self, zone_id, name=None): return []
    async def upsert(self, **kw):
        from app.cloudflare import DnsRecord
        self.upserts.append(kw)
        return DnsRecord(kw.get("record_id") or "R1", kw["zone_id"], kw["name"],
                         kw["record_type"], kw["content"], kw.get("proxied", False))

# ---------------- 假 Gotify ----------------
class FakeNotifier:
    def __init__(self): self.sent = []
    def configure(self, *a): pass
    async def send(self, title, message, level="info"):
        self.sent.append((level, title, message)); return True

# ---------------- 假 Docker ----------------
class FakeDocker:
    def __init__(self): self.restarts = 0
    def state(self): return {"available": True, "name": "frpc", "status": "running"}
    def restart(self, timeout=15): self.restarts += 1; return {"ok": True, "status": "running"}

# ---------------- 组装 ----------------
tid = store.create_tunnel({
    "name":"NAS 面板","proxy_name":"nas-panel","proxy_type":"tcp",
    "local_ip":"127.0.0.1","local_port":5000,"desired_remote_port":41234,
    "enabled":1,"auto_failover":1,"dns_proxied":0,
    "dns_record_name":"nas.example.com","downstream_note":"改 Lucky 反代后端",
    "current_proxy_id":111,"current_node_id":5,"current_remote_port":41234,
})
eng = GuardEngine()
fake = FakeMefrp(); cf = FakeCF(); nf = FakeNotifier(); dk = FakeDocker()
eng.client = fake; eng.cf = cf; eng.notifier = nf; eng.docker = dk

# ⚠️ 实例不再自动播种，隧道也不再自动兜底 —— 必须手工建容器 + 显式挂接。
# 这正是新的模型（一条隧道 : 一个 frpc 容器），测试里也要如实走一遍。
A_ID = store.create_frpc_instance({
    "name": "默认", "config_path": cfg, "container": "frpc",
    "restart_mode": "docker", "enabled": 1, "note": ""})
store.update_tunnel(tid, {"frpc_instance_id": A_ID})
# 把容器控制器换成假的 —— 否则 eng.dockers 里会是真 DockerControl，
# 一重启就真的去连 docker.sock 了
eng.dockers = {A_ID: dk}

eng.user_group = "free"
eng.nodes = {n.node_id: n for n in asyncio.run(fake.node_list())}

async def run(ignore_cooldown=True):
    t = store.get_tunnel(tid)
    return await eng._failover(t, "节点离线（测试）", ignore_cooldown=ignore_cooldown)

res = asyncio.run(run())

print("[1] 节点选择：跳过挂掉的旧节点，选带宽最大的北京节点")
check("选中的是 9（北京-联通 1Gbps）", res.get("node_id") == 9, res)
check("排除了旧节点 5", all(c[0] != 5 for c in fake.created), fake.created)

print("[2] 端口优先策略：期望端口 41234 落在新节点的 allowPort 内，应当沿用")
check("请求了 41234 而不是自动分配", fake.created and fake.created[0][2] == 41234, fake.created)

print("[3] 新隧道建立 + 旧隧道清理")
check("proxy_create 被调用", len(fake.created) == 1, fake.created)
check("旧隧道 111 被删除", fake.deleted == [111], fake.deleted)
check("新 proxyId 已落库", store.get_tunnel(tid)["current_proxy_id"] == 222)
check("新 node_id 已落库", store.get_tunnel(tid)["current_node_id"] == 9)

print("[4] frpc 配置真的写到了磁盘")
written = pathlib.Path(cfg).read_text(encoding="utf-8")
check("配置文件已生成", bool(written.strip()), repr(written[:60]))
# 断言要引号无关：mefrp 官方配置用 TOML 单引号字面量，合并后原样保留，
# 用 `'serverAddr = "..."' in text` 去比会误报失败。直接按 TOML 解析最稳。
import tomllib as _tl
_parsed = _tl.loads(written)
check("serverAddr 指向新节点", _parsed.get("serverAddr") == "10.0.0.9", _parsed.get("serverAddr"))
sm = frpc.config_summary(written)
check("TOML 合法且含 1 个隧道", sm.get("valid") and sm.get("proxy_count") == 1, sm)
check("备份目录已产生备份？(首次写入无旧文件，应为 0)", len(frpc.list_backups()) == 0)

print("[5] frpc 容器被重启")
check("restart 被调用 1 次", dk.restarts == 1, dk.restarts)
check("结果里 restart_ok=True", res.get("restart_ok") is True, res)

print("[6] DNS 同步：节点是 IP -> A 记录")
check("upsert 被调用", len(cf.upserts) == 1, cf.upserts)
if cf.upserts:
    u = cf.upserts[0]
    check("记录名正确", u["name"] == "nas.example.com", u)
    check("类型是 A（节点是 IP）", u["record_type"] == "A", u)
    check("内容是节点 IP", u["content"] == "10.0.0.9", u)
check("record_id 已回写", store.get_tunnel(tid)["dns_record_id"] == "R1")

print("[7] 端口没变 -> 不该触发下游待办")
check("needs_downstream_review = 0", store.get_tunnel(tid)["needs_downstream_review"] == 0)
check("port_changed = False", res.get("port_changed") is False, res)

print("[8] 通知与事件")
check("Gotify 收到 1 条", len(nf.sent) == 1, nf.sent)
if nf.sent:
    lvl, title, msg = nf.sent[0]
    check("标题含隧道名", "NAS 面板" in title, title)
    check("正文含新节点与端口", "10.0.0.9" in msg and "41234" in msg, msg[:200])
evs = store.list_events(tunnel_id=tid)
check("写了 failover 事件", any(e["kind"] == "failover" for e in evs), [e["kind"] for e in evs])
check("写了 dns 事件", any(e["kind"] == "dns" for e in evs), [e["kind"] for e in evs])
check("写了 frpc 事件", any(e["kind"] == "frpc" for e in evs), [e["kind"] for e in evs])

print("[9] 冷却期与节点冷却已生效")
# ⚠️ 1.0.2 起冷却表键是 (隧道类型组, node_id)：port / http 两套偏好各自记。
check("新节点进了冷却", ("port", 9) in eng.node_cooldown, list(eng.node_cooldown))
check("last_failover_at 已写", store.get_tunnel(tid)["last_failover_at"] > 0)
check("fail_streak 已清零", store.get_tunnel(tid)["fail_streak"] == 0)

print("[10] ★ 端口被占用时自动降级为「服务端分配」并提示下游")
store.update_tunnel(tid, {"current_node_id": 9, "current_remote_port": 41234})
fake.fail_first_port = True
fake.created.clear(); fake.attempts.clear(); fake.deleted.clear(); cf.upserts.clear(); nf.sent.clear()
eng.nodes = {n.node_id: n for n in asyncio.run(fake.node_list())}
eng.node_cooldown = {}
res2 = asyncio.run(run())
check("先试 41234（被占用失败），再退回自动分配", [a[1] for a in fake.attempts] == [41234, None], fake.attempts)
check("端口未变（服务端恰好又给了 41234）", res2.get("port_changed") is False, res2)

print("[11] ★ 端口真的变了 -> 必须提示检查下游")
store.update_tunnel(tid, {"current_remote_port": 40000})
eng.node_cooldown = {}
fake.created.clear(); fake.attempts.clear(); fake.deleted.clear(); cf.upserts.clear(); nf.sent.clear()
fake._proxies = [Proxy(proxy_id=111, proxy_name="nas-panel", proxy_type="tcp",
                       node_id=5, local_ip="127.0.0.1", local_port=5000,
                       remote_port=40000, is_online=True)]
res3 = asyncio.run(run())
check("port_changed = True", res3.get("port_changed") is True, res3)
check("needs_downstream_review 被置 1", store.get_tunnel(tid)["needs_downstream_review"] == 1)
check("通知里带下游提醒", nf.sent and "下游" in nf.sent[0][2], (nf.sent[0][2][:300] if nf.sent else None))
check("通知里带下游备忘原文", nf.sent and "Lucky" in nf.sent[0][2], (nf.sent[0][2][:300] if nf.sent else None))

print("[12] ★ 一个可用节点都没有 -> 必须失败并通知，不能假装成功")
eng.nodes = {5: Node(node_id=5, name="上海-旧节点", hostname="10.0.0.5",
                     region="cn", bandwidth="100Mbps", is_online=False)}
store.update_tunnel(tid, {"needs_downstream_review": 0})   # 先清干净，才能验证「失败不会置它」
nf.sent.clear()
res4 = asyncio.run(run())
check("返回 ok=False", res4.get("ok") is False, res4)
check("错误信息说明没有可用节点", "没有满足条件的节点" in res4.get("error",""), res4.get("error"))
check("发了失败告警", nf.sent and nf.sent[0][0] == "error", nf.sent)
check("提示去页面手动指定节点", nf.sent and "手动指定" in nf.sent[0][2], nf.sent)
check("★ 切换失败不该置「下游待办」（什么都没变，置了就是误报）",
      store.get_tunnel(tid)["needs_downstream_review"] == 0,
      store.get_tunnel(tid)["needs_downstream_review"])
check("失败原因写进了 last_error",
      "没有满足条件的节点" in (store.get_tunnel(tid)["last_error"] or ""),
      store.get_tunnel(tid)["last_error"])

print("[13] ★ 冷却期内不重复切换")
store.set_setting("failover_cooldown", 300)
store.update_tunnel(tid, {"last_failover_at": int(time.time())})
eng.nodes = {n.node_id: n for n in asyncio.run(fake.node_list())}
fake.created.clear(); fake.attempts.clear()
res5 = asyncio.run(run(ignore_cooldown=False))
check("冷却期拦截", res5.get("ok") is False and "冷却期" in res5.get("error",""), res5)
check("没有真的创建隧道", fake.created == [], fake.created)

print("[14] ★ 端到端探测失败时，不该去改 DNS（改了就是指向一个不通的地址）")
store.update_tunnel(tid, {"current_node_id": 5, "current_remote_port": 41234,
                          "dns_record_id": None, "dns_zone_id": None})
eng.node_cooldown = {}
fake.created.clear(); fake.attempts.clear(); fake.deleted.clear(); cf.upserts.clear(); nf.sent.clear()
fake._proxies = [Proxy(proxy_id=111, proxy_name="nas-panel", proxy_type="tcp",
                       node_id=5, local_ip="127.0.0.1", local_port=5000,
                       remote_port=41234, is_online=True)]
PROBE["ok"] = False; PROBE["why"] = "连接 10.0.0.9:41234 超时"
res6 = asyncio.run(run())
check("隧道上线了但探测没过", res6.get("online") is True and res6.get("probe_ok") is False, res6)
check("healthy = False", res6.get("healthy") is False, res6)
check("DNS 没有被改动", cf.upserts == [], cf.upserts)
check("发了 error 级告警", nf.sent and nf.sent[0][0] == "error", nf.sent)
PROBE["ok"] = True; PROBE["why"] = ""

print("[15] ★ 回归：节点地址来自 /auth/proxy/list 的 nodes 子数组")
# 背景：mefrp 对**非管理员**账号把 /auth/node/list 的 hostname 脱敏成空串，
# 真实地址只出现在 /auth/proxy/list 返回的 nodes 子数组里。原代码把
# proxy_list() 的第二个返回值直接丢弃了，于是「节点地址」永远是空的。
fake._proxies = [Proxy(proxy_id=111, proxy_name="nas-panel", proxy_type="tcp",
                       node_id=9, local_ip="127.0.0.1", local_port=5000,
                       remote_port=41234, is_online=True)]
eng.node_hostname_cache.clear()
_raw_nodes = asyncio.run(fake.node_list())
check("假 node_list 的 hostname 确实是空串（还原非管理员视图）",
      all(not n.hostname for n in _raw_nodes), [n.hostname for n in _raw_nodes])
asyncio.run(eng._refresh_remote())
check("★ 缓存里拿到了节点 9 的地址", eng.node_hostname_cache.get(9) == "10.0.0.9",
      eng.node_hostname_cache)
check("node_address_cached(9) 同步可取", eng.node_address_cached(9) == "10.0.0.9")
check("node_address(9) 异步也一致", asyncio.run(eng.node_address(9)) == "10.0.0.9")
check("Node.hostname 被顺带回填", eng.nodes[9].hostname == "10.0.0.9", eng.nodes[9].hostname)
check("★ 节点 7 上没隧道 -> 地址拿不到（mefrp 对非管理员的真实限制，不是 bug）",
      asyncio.run(eng.node_address(7)) == "", repr(asyncio.run(eng.node_address(7))))

print("[16] ★ 回归：用户组来自 /auth/user/info 的 group 字段")
# 背景：/auth/user/group 这个端点**根本不存在**（HTTP 404，message 还是
# 服务器通用 banner「ME Frp 5.21 API Server is OK!」，看起来像服务正常）。
# 正确来源是 /auth/user/info：group="default"（机器名）+ friendlyGroup="正式用户"。
check("user_group 取到机器名 default", eng.user_group == "default", eng.user_group)
check("user_group_friendly 取到展示名", eng.user_group_friendly == "正式用户",
      eng.user_group_friendly)
check("没有报错", eng.user_group_error == "", eng.user_group_error)
_info = asyncio.run(eng.client.user_info())
check("user_info 暴露 maxProxies/usedProxies",
      _info.max_proxies == 10 and _info.used_proxies == 2,
      (_info.max_proxies, _info.used_proxies))
check("节点 allowGroup 匹配用的是 group（机器名）而非展示名",
      Node(node_id=1, name="x", allow_group="default;vip").allows_group("default")
      and not Node(node_id=1, name="x", allow_group="default;vip").allows_group("正式用户"))

print("[17] ★ 回归：TOML 单引号字面量的 serverAddr 解析")
# 背景：mefrp 官方生成的配置用单引号字面量 serverAddr = '203.0.113.10'。
# 原正则 `"?([^"\n]+)"?` 对单引号会把引号一起吞进捕获组，于是同一地址
# 只因引号风格不同就被判成「跨节点」，merge_configs 直接拒绝生成配置。
check("单引号能解析", frpc.server_addr_of("serverAddr = '1.2.3.4'\nserverPort = 7000\n") == "1.2.3.4")
check("双引号能解析", frpc.server_addr_of('serverAddr = "1.2.3.4"\nserverPort = 7000\n') == "1.2.3.4")
check("无引号能解析", frpc.server_addr_of("serverAddr = 1.2.3.4\nserverPort = 7000\n") == "1.2.3.4")
check("两种引号的同一地址视为一致（不误报跨节点）",
      frpc.server_addr_of("serverAddr = '9.9.9.9'\n") == frpc.server_addr_of('serverAddr = "9.9.9.9"\n'))
try:
    _m, _g = frpc.merge_configs([
        "serverAddr = '1.2.3.4'\nserverPort = 7000\n\n[[proxies]]\nname='a'\ntype='tcp'\nlocalIP='127.0.0.1'\nlocalPort=1\nremotePort=10001\n",
        'serverAddr = "1.2.3.4"\nserverPort = 7000\n\n[[proxies]]\nname="b"\ntype="tcp"\nlocalIP="127.0.0.1"\nlocalPort=2\nremotePort=10002\n',
    ])
    check("★ 引号风格不同但地址相同 -> 合并成功（修复前会抛跨节点错误）", True)
    check("合并结果 serverAddr 正确", _g.get("serverAddr") == "1.2.3.4", _g)
except Exception as _e:
    check("★ 引号风格不同但地址相同 -> 合并成功（修复前会抛跨节点错误）", False, repr(_e))

print("[18] ★ 回归：UDP 隧道不做 TCP 端到端探测")
# 背景：udp 隧道在节点上监听的是 UDP 端口，没有 TCP 监听，用 TCP 去探必然失败。
# 若不区分，健康的 udp 隧道会被永久判成「异常」，fail_streak 涨到阈值后
# 触发故障转移 —— 搬走之后依然是 udp、依然探不通，形成无限切换循环。
store.set_setting("probe_mode", "auto")
udp_id = store.create_tunnel({
    "name": "测试 UDP 隧道", "proxy_name": "test_udp", "proxy_type": "udp",
    "local_ip": "127.0.0.1", "local_port": 51820,
    "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
    "current_proxy_id": 901, "current_node_id": 9, "current_remote_port": 41235,
})
fake._proxies = [Proxy(proxy_id=901, proxy_name="test_udp", proxy_type="udp",
                       node_id=9, local_ip="127.0.0.1", local_port=51820,
                       remote_port=41235, is_online=True)]
asyncio.run(eng._refresh_remote())
fake.created.clear(); fake.attempts.clear()
eng.probe_cache.clear()
PROBE["ok"] = False; PROBE["why"] = "TCP 探 UDP 端口必然失败"
asyncio.run(eng._reconcile(store.get_tunnel(udp_id)))
_t = store.get_tunnel(udp_id)
check("★ fail_streak 保持 0（没被误判成故障）", _t["fail_streak"] == 0, _t["fail_streak"])
_c = eng.probe_cache.get(udp_id)
check("★ probe_cache 第二项是 None（「不适用」而非「失败」）", bool(_c) and _c[1] is None, _c)
check("probe_cache 里写明了跳过原因", bool(_c) and "UDP" in _c[2], _c)
check("★ 没有触发任何切换", fake.created == [], fake.created)
check("last_error 没被写入", not _t["last_error"], _t["last_error"])

# 反过来验证「逃生口」确实生效：probe_mode=tcp 时强制探测，应如实记为失败
store.set_setting("probe_mode", "tcp")
store.update_tunnel(udp_id, {"fail_streak": 0})
eng.probe_cache.clear()
asyncio.run(eng._reconcile(store.get_tunnel(udp_id)))
check("probe_mode=tcp 时强制探测，如实记为失败",
      store.get_tunnel(udp_id)["fail_streak"] == 1, store.get_tunnel(udp_id)["fail_streak"])

# probe_mode=none 时连 tcp 隧道都不探
store.set_setting("probe_mode", "none")
eng.probe_cache.clear()
check("probe_mode=none -> tcp 隧道也跳过", E.probe_plan("tcp", "none")[0] == "none")
check("probe_mode=tcp -> tcp 隧道强制探测", E.probe_plan("tcp", "tcp")[0] == "tcp")
check("probe_mode=auto -> tcp 探、udp 不探",
      E.probe_plan("tcp", "auto")[0] == "tcp" and E.probe_plan("udp", "auto")[0] == "none")
# ★ 1.0.2：http 隧道在 auto 下不探（TCP 层是假阳性），改 probe_mode=http 才走 HTTP 探测
check("probe_mode=auto -> http 隧道不探（假阳性）",
      E.probe_plan("http", "auto")[0] == "none")
check("probe_mode=http -> http 隧道走 HTTP 探测",
      E.probe_plan("http", "http")[0] == "http")
store.set_setting("probe_mode", "auto")
PROBE["ok"] = True; PROBE["why"] = ""

print("[19] ★★ 未挂接 frpc 的隧道也能切换节点（1.0.3）")
# 背景：以前「没挂接 frpc 容器」直接被拒（前端按钮变灰、后端也拦）。理由写的是
# 「切换要改写承载它的 frpc 配置并重启容器，没有承载者就无从下手」—— 但那是把
# 本地那半截当成了全部。切换节点本质是 **mefrp 侧的业务**：删掉旧节点上的同名
# proxy、在新节点建一个。这条隧道在 mefrp 上一直存在、一直占着节点和端口，跟本地
# 有没有容器毫无关系；而且用户想换节点的场景里，「先挂一个 frpc 容器」本身往往
# 正是他接下来要做的事 —— 他需要先落到一个能用的节点上。
#
# 现在：me frp 那半截照做，本地那半截（写配置 / 重启容器 / 等上线 / 端到端探测）
# 如实跳过，并且**不能因此判成失败**。
un_id = store.create_tunnel({
    "name": "未挂接的隧道", "proxy_name": "unbound-demo", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 6000, "desired_remote_port": 41300,
    "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
    "dns_record_name": "unbound.example.com",
    "current_proxy_id": 555, "current_node_id": 5, "current_remote_port": 41300,
})
# 没有 frpc 去连 frps → 新建出来的 proxy 必然是离线的。桩要还原这一点，
# 否则「跳过上线等待」这个分支测不出来（proxy 永远在线，怎么都算成功）。
fake.created_online = False
fake.created.clear(); fake.attempts.clear(); fake.deleted.clear()
cf.upserts.clear(); nf.sent.clear()
eng.node_cooldown = {}; eng.dns_checked.clear()
_restarts_before = dk.restarts
_cfg_before = pathlib.Path(cfg).read_text(encoding="utf-8")

_un = asyncio.run(eng._failover(store.get_tunnel(un_id), "手动触发（未挂接 frpc）",
                                prefer_node_id=9, ignore_cooldown=True))

check("★ 不再被「没挂接 frpc」挡住，切换真的走完了", _un.get("ok") is True, _un)
check("结果里带了 unbound 标记（前端靠它区分文案）", _un.get("unbound") is True, _un)
check("★ 没挂接时 healthy 恒为 False（确实没有任何东西在跑）",
      _un.get("healthy") is False, _un.get("healthy"))
check("★ 但没把它当失败：probe_ok 是 None（不适用）而不是 False",
      _un.get("probe_ok") is None, _un.get("probe_ok"))
check("★ 跳过上线等待（新 proxy 离线，也不去白等 45 秒）",
      _un.get("online") is False, _un.get("online"))
check("mefrp 上真的搬了：新节点建了同名 proxy",
      any(c[1] == "unbound-demo" for c in fake.created), fake.created)
check("旧节点上的 proxy 555 被删掉", 555 in fake.deleted, fake.deleted)
check("新节点已落库", store.get_tunnel(un_id)["current_node_id"] == 9,
      store.get_tunnel(un_id)["current_node_id"])
check("新 proxyId 已落库", store.get_tunnel(un_id)["current_proxy_id"] == 222,
      store.get_tunnel(un_id)["current_proxy_id"])
check("★ 没写 frpc 配置（没有承载者，一个字都不该动）",
      pathlib.Path(cfg).read_text(encoding="utf-8") == _cfg_before)
check("★ 没重启容器", dk.restarts == _restarts_before, (dk.restarts, _restarts_before))
check("★ DNS 仍然同步到新节点地址（域名不能一直指着老节点）",
      bool(cf.upserts) and cf.upserts[0]["content"] == "10.0.0.9", cf.upserts)
_un_evs = store.list_events(tunnel_id=un_id)
check("★ 事件级别是 success，不是 error",
      any(e["level"] == "success" and e["kind"] == "failover" for e in _un_evs),
      [(e["level"], e["kind"]) for e in _un_evs])
check("★ 通知里不出现「frpc 重启：失败」这种误导文案",
      bool(nf.sent) and "frpc 重启：失败" not in nf.sent[0][2],
      (nf.sent[0][2][:400] if nf.sent else None))
check("★ 通知里说清「只搬了 mefrp 上的隧道」",
      bool(nf.sent) and "只搬了 mefrp 上的隧道" in nf.sent[0][2],
      (nf.sent[0][2][:400] if nf.sent else None))

# 反过来：**自动**切换仍然挡住未挂接的隧道 —— 没有 frpc 时探测必然一直失败，
# 放行只会让它在节点之间来回搬（每过一个冷却期一次），永远搬不好。
eng.nodes = {n.node_id: n for n in asyncio.run(fake.node_list())}
asyncio.run(eng._refresh_remote())          # 让 eng.proxies 里出现刚建的那条
store.update_tunnel(un_id, {"fail_streak": 0})
fake.created.clear(); fake.attempts.clear(); fake.deleted.clear()
store.set_setting("fail_threshold", 1)
store.set_setting("auto_failover", True)
eng.probe_cache.clear()
PROBE["ok"] = False; PROBE["why"] = "没有 frpc 连上来"
asyncio.run(eng._reconcile(store.get_tunnel(un_id)))
check("★ 自动路径仍然不搬未挂接的隧道（避免无限来回切换）",
      fake.created == [], fake.created)
check("★ 但事件里明确告诉用户「手动切换」是可用的",
      any("手动切换" in (e["detail"] or "")
          for e in store.list_events(tunnel_id=un_id)),
      [e["message"] for e in store.list_events(tunnel_id=un_id)][:3])
PROBE["ok"] = True; PROBE["why"] = ""
fake.created_online = True

print(f"\n==> PASS {ok} / FAIL {bad}")
sys.exit(1 if bad else 0)
