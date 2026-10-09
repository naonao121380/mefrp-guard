# -*- coding: utf-8 -*-
"""多 frpc 实例：绑定解析 / 按实例重建 / 成组故障转移 / 跨实例隔离 / 失败回滚。

核心不变式（这组测试就是为了守住它）：
    一个 frpc 进程只能连一个 serverAddr，
    所以同一个实例承载的所有隧道必须落在同一个节点上，
    因此故障转移的单位是「实例」而不是「单条隧道」。

mefrp / Cloudflare / Gotify / Docker 全是假实现，只有引擎和配置生成是真的。
"""
import sys, types, os, tempfile, pathlib, asyncio, tomllib

stub = types.ModuleType("httpx")
class _D:
    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
stub.AsyncClient = _D
stub.HTTPError = type("HTTPError", (Exception,), {})
sys.modules["httpx"] = stub

TMP = tempfile.mkdtemp(prefix="mg-multi-")
CFG_A = os.path.join(TMP, "frpcA.toml")
CFG_B = os.path.join(TMP, "frpcB.toml")
os.environ.update(MG_DATA_DIR=TMP, MG_FRPC_CONFIG=CFG_A, MG_FRPC_CONTAINER="frpcA")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import store, frpc                       # noqa: E402
from app.mefrp import Node, Proxy, UserInfo, MefrpApiError   # noqa: E402
import app.engine as E                            # noqa: E402
from app.engine import GuardEngine                # noqa: E402

PROBE = {"ok": True, "why": ""}
async def _fake_probe(host, port, timeout=4.0):
    return PROBE["ok"], PROBE["why"]
E.tcp_probe = _fake_probe        # 引擎内部按模块全局名调用

store.init()

ok = bad = 0
def check(n, c, e=""):
    global ok, bad
    if c:
        ok += 1; print(f"  PASS  {n}")
    else:
        bad += 1; print(f"  FAIL  {n}  ->  {e}")


# ---------------------------------------------------------------- 假 mefrp
# 节点公网地址故意不放进 Node.hostname —— 真实 API 对非管理员会脱敏成空串，
# 地址只出现在 proxy_list 的 nodes 子数组里。
NODE_ADDR = {5: "10.0.0.5", 9: "10.0.0.9", 7: "10.0.0.7"}


class FakeMefrp:
    def __init__(self):
        self.proxies: dict[int, Proxy] = {}
        self.next_pid = 1000
        self.created: list[tuple] = []
        self.deleted: list[int] = []
        # 操作序列，用来断言「先删旧、再建新」—— 顺序反了就会撞名。
        self.ops: list[tuple[str, object]] = []
        self.fail_names: set[str] = set()
        # 指定「(隧道名, 节点) 建不出来」：用来测「切换失败 -> 回滚」。
        # 为什么不用 fail_names：fail_names 是一律失败，回滚时也建不出来，
        # 就测不到「回滚真的把隧道建回原节点」这条路径了。
        self.fail_on_node: set[tuple[str, int]] = set()

    def add(self, name, node_id, remote_port, local_port=5000, ptype="tcp") -> int:
        pid = self.next_pid
        self.next_pid += 1
        self.proxies[pid] = Proxy(
            proxy_id=pid, proxy_name=name, proxy_type=ptype, node_id=node_id,
            local_ip="127.0.0.1", local_port=local_port,
            remote_port=remote_port, is_online=True)
        return pid

    async def node_list(self):
        return [
            Node(node_id=5, name="上海-旧节点", hostname="", region="cn",
                 bandwidth="100Mbps", is_online=False),
            Node(node_id=9, name="北京-联通", hostname="", region="cn",
                 bandwidth="1Gbps", is_online=True, allow_port="40000-65535"),
            Node(node_id=7, name="广州-移动", hostname="", region="cn",
                 bandwidth="200Mbps", is_online=True, allow_port="40000-65535"),
        ]

    async def node_status(self): return {}

    async def proxy_list(self):
        ps = list(self.proxies.values())
        brief = {p.node_id: {"nodeId": p.node_id, "name": f"node-{p.node_id}",
                             "hostname": NODE_ADDR.get(p.node_id, ""),
                             "allowGroup": ""}
                 for p in ps}
        return ps, brief

    async def user_info(self):
        return UserInfo(username="naonao", group="default",
                        friendly_group="正式用户", max_proxies=10,
                        used_proxies=len(self.proxies))

    async def proxy_create(self, *, node_id, proxy_name, local_ip, local_port,
                           proxy_type="tcp", remote_port=None, **kw):
        if proxy_name in self.fail_names:
            raise MefrpApiError(400, f"隧道名「{proxy_name}」被拒绝")
        if (proxy_name, int(node_id)) in self.fail_on_node:
            raise MefrpApiError(400, f"节点 {node_id} 上无法创建「{proxy_name}」")
        # ★ 还原真实 mefrp 的语义：proxyName 在账号内唯一，**同名已存在就直接拒绝**。
        #   这条把「必须先删旧、再建新」钉死 —— 顺序反了这里就红。
        #   （原来的 fake 会「自动顶掉同名」，那种宽容行为掩盖了这个约束。）
        if any(p.proxy_name == proxy_name for p in self.proxies.values()):
            raise MefrpApiError(400, f"隧道名「{proxy_name}」已存在")
        self.created.append((node_id, proxy_name, remote_port))
        self.ops.append(("create", proxy_name))
        self.add(proxy_name, node_id, remote_port or 41234, local_port, proxy_type)

    async def proxy_delete(self, pid):
        self.deleted.append(int(pid))
        self.ops.append(("delete", int(pid)))
        self.proxies.pop(int(pid), None)

    async def proxy_config(self, pid, fmt="toml"):
        p = self.proxies.get(int(pid))
        node = NODE_ADDR.get(p.node_id if p else 9, NODE_ADDR[9])
        name = p.proxy_name if p else "?"
        port = p.remote_port if p else 0
        lp = p.local_port if p else 0
        # 官方配置用 TOML 单引号字面量，这里保持一致
        return (f"serverAddr = '{node}'\nserverPort = 7000\nauth.method = 'token'\n"
                f"auth.token = 'tk'\nuser = 'naonao'\n\n[[proxies]]\nname = '{name}'\n"
                f"type = 'tcp'\nlocalIP = '127.0.0.1'\nlocalPort = {lp}\n"
                f"remotePort = {port}\n")


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


class FakeNotifier:
    def __init__(self): self.sent = []
    def configure(self, *a): pass
    async def send(self, title, message, level="info"):
        self.sent.append((level, title, message)); return True


class FakeDocker:
    """按实例独立的假容器控制器 —— restarts 计数分开，才能证明「只重启了该重启的」。"""
    def __init__(self, name): self.name = name; self.restarts = 0
    def state(self): return {"available": True, "name": self.name, "status": "running"}
    def restart(self, timeout=15): self.restarts += 1; return {"ok": True, "status": "running"}


# ================================================================ [1] 迁移与手工建实例
print("[1] 首次运行：不播种任何实例（挂接全靠手动）")
insts = store.list_frpc_instances()
check("★ 一条实例都不播种", len(insts) == 0, insts)

cols = {r["name"] for r in
        store._db().execute("PRAGMA table_info(tunnels)").fetchall()}
check("tunnels 有 frpc_instance_id 列", "frpc_instance_id" in cols, sorted(cols))

# 实例现在只能手工建 —— 这就是「挂接」的第一步
A_ID = store.create_frpc_instance({
    "name": "默认", "config_path": CFG_A, "container": "frpcA",
    "restart_mode": "docker", "enabled": 1, "note": ""})
A = store.get_frpc_instance(A_ID)
check("手工建出实例 A", A is not None and A["name"] == "默认", A)
check("配置路径 = 建的时候填的", A.get("config_path") == CFG_A, A)
check("容器名 = 建的时候填的", A.get("container") == "frpcA", A)
check("restart_mode 就是建的时候填的", A.get("restart_mode") == "docker", A)

print("[2] 新增第二个实例")
B_ID = store.create_frpc_instance({
    "name": "备用线路", "config_path": CFG_B, "container": "frpcB",
    "restart_mode": "docker", "enabled": 1, "note": ""})
B = store.get_frpc_instance(B_ID)
check("实例 B 已建", B is not None and B["name"] == "备用线路", B)
check("两个实例并存", len(store.list_frpc_instances()) == 2)

print("[3] proxy_names 解析（自动发现的基础）")
check("能读出隧道名",
      frpc.proxy_names("[[proxies]]\nname = 'x'\ntype='tcp'\n") == ["x"],
      frpc.proxy_names("[[proxies]]\nname = 'x'\ntype='tcp'\n"))
check("多个隧道都读出来",
      frpc.proxy_names("[[proxies]]\nname='a'\n[[proxies]]\nname='b'\n") == ["a", "b"])
check("空配置返回空列表", frpc.proxy_names("") == [])
check("坏 TOML 不抛异常", frpc.proxy_names("this is = = not toml") == [])
check("无 proxies 段返回空", frpc.proxy_names("serverAddr = '1.2.3.4'\n") == [])

# ---------------------------------------------------------------- 建隧道
tA1 = store.create_tunnel({
    "name": "NAS 面板", "proxy_name": "nas-panel", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 5000, "desired_remote_port": 41234,
    "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
    "current_proxy_id": 0, "current_node_id": 5, "current_remote_port": 41234,
    "frpc_instance_id": A_ID})
tA2 = store.create_tunnel({
    "name": "Web 面板", "proxy_name": "web-panel", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 5001, "desired_remote_port": 41235,
    "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
    "current_proxy_id": 0, "current_node_id": 5, "current_remote_port": 41235,
    "frpc_instance_id": A_ID})
tB1 = store.create_tunnel({
    "name": "Git 面板", "proxy_name": "git-panel", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 3000, "desired_remote_port": 41236,
    "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
    "current_proxy_id": 0, "current_node_id": 5, "current_remote_port": 41236,
    "frpc_instance_id": B_ID})
# 故意不绑定 —— 用来测「配置发现」
tD = store.create_tunnel({
    "name": "发现出来的", "proxy_name": "disc-panel", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 6000, "desired_remote_port": 41237,
    "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
    "current_proxy_id": 0, "current_node_id": 5, "current_remote_port": 41237})

fake = FakeMefrp()
pid_a1 = fake.add("nas-panel", 5, 41234, 5000)
pid_a2 = fake.add("web-panel", 5, 41235, 5001)
pid_b1 = fake.add("git-panel", 5, 41236, 3000)
pid_d = fake.add("disc-panel", 5, 41237, 6000)
store.update_tunnel(tA1, {"current_proxy_id": pid_a1})
store.update_tunnel(tA2, {"current_proxy_id": pid_a2})
store.update_tunnel(tB1, {"current_proxy_id": pid_b1})
store.update_tunnel(tD, {"current_proxy_id": pid_d})

# 模拟「用户手上本来就有一份能跑的 frpcB.toml」，里面写着 disc-panel
pathlib.Path(CFG_B).write_text(
    "serverAddr = '10.0.0.5'\nserverPort = 7000\nuser = 'naonao'\n\n"
    "[[proxies]]\nname = 'disc-panel'\ntype = 'tcp'\n"
    "localIP = '127.0.0.1'\nlocalPort = 6000\nremotePort = 41237\n",
    encoding="utf-8")

eng = GuardEngine()
eng.client = fake
eng.cf = FakeCF()
eng.notifier = FakeNotifier()
eng.user_group = "default"
eng.nodes = {n.node_id: n for n in asyncio.run(fake.node_list())}
dk_a, dk_b = FakeDocker("frpcA"), FakeDocker("frpcB")
eng.dockers = {A_ID: dk_a, B_ID: dk_b}

# ================================================================ [4] 绑定解析
print("[4] 绑定解析：显式优先，其次唯一实例兜底")
check("显式绑定的隧道 -> A",
      int(eng.frpc_for_tunnel(store.get_tunnel(tA1))["id"]) == A_ID)
check("显式绑定的隧道 -> B",
      int(eng.frpc_for_tunnel(store.get_tunnel(tB1))["id"]) == B_ID)
check("★ 未绑定 + 多实例 -> 未绑定（绝不靠猜）",
      eng.frpc_for_tunnel(store.get_tunnel(tD)) is None,
      eng.frpc_for_tunnel(store.get_tunnel(tD)))

tX = store.create_tunnel({
    "name": "谁的都不是", "proxy_name": "nobody-panel", "proxy_type": "tcp",
    "local_ip": "127.0.0.1", "local_port": 7000, "enabled": 1,
    "auto_failover": 1, "dns_proxied": 0})
check("两个实例且哪儿都找不到 -> 未绑定",
      eng.frpc_for_tunnel(store.get_tunnel(tX)) is None,
      eng.frpc_for_tunnel(store.get_tunnel(tX)))

store.update_tunnel(tX, {"frpc_instance_id": 9999})
check("绑定指向已删除的实例 -> 退回未绑定（不是崩溃）",
      eng.frpc_for_tunnel(store.get_tunnel(tX)) is None)
store.update_tunnel(tX, {"frpc_instance_id": None})

m = eng.resolve_map()
check("resolve_map 有 2 个实例", len(m["instances"]) == 2, m)
check("resolve_map 列出未绑定的隧道",
      {u["id"] for u in m["unassigned"]} >= {tX, tD}, m["unassigned"])

print("[4b] 自动发现：一次性把推断结果写成**显式绑定**")
preview = eng.discover_bindings(apply=False)
check("预览不改库", store.get_tunnel(tD)["frpc_instance_id"] is None)
check("预览建议 tD -> B",
      any(p["tunnel_id"] == tD and p["instance_id"] == B_ID
          for p in preview["proposals"]),
      preview["proposals"])
check("列出各实例现有配置里的隧道名",
      any("disc-panel" in i["proxy_names"] for i in preview["instances"]),
      preview["instances"])
check("找不到归属的进了 unmatched",
      any(u["tunnel_id"] == tX for u in preview["unmatched"]),
      preview["unmatched"])

applied = eng.discover_bindings(apply=True)
check("应用后写入显式绑定", store.get_tunnel(tD)["frpc_instance_id"] == B_ID)
check("应用计数正确", applied["applied"] >= 1, applied["applied"])
check("★ 应用后 tD 解析到 B",
      int(eng.frpc_for_tunnel(store.get_tunnel(tD))["id"]) == B_ID)

print("[4c] ★ 显式解绑不会被启发式规则绑回去")
store.update_tunnel(tD, {"frpc_instance_id": None})
check("解绑后就是未绑定（B 的配置里虽然还留着 disc-panel 也不认）",
      eng.frpc_for_tunnel(store.get_tunnel(tD)) is None,
      eng.frpc_for_tunnel(store.get_tunnel(tD)))
store.update_tunnel(tD, {"frpc_instance_id": B_ID})     # 还原，后面要用

# ================================================================ [5] 按实例重建
print("[5] 按实例重建：各写各的文件，互不串味")

changed_a, sum_a = asyncio.run(eng.rebuild_frpc(A_ID))
text_a = pathlib.Path(CFG_A).read_text(encoding="utf-8")
names_a = set(frpc.proxy_names(text_a))
check("A 的配置写到了 CFG_A", pathlib.Path(CFG_A).exists() and bool(text_a))
check("A 的配置含 nas-panel", "nas-panel" in names_a, sorted(names_a))
check("A 的配置含 web-panel", "web-panel" in names_a, sorted(names_a))
check("★ A 的配置**不含** B 的隧道", "git-panel" not in names_a, sorted(names_a))
check("A 的配置不含 disc-panel", "disc-panel" not in names_a, sorted(names_a))
check("A 的 serverAddr = 旧节点 10.0.0.5",
      tomllib.loads(text_a).get("serverAddr") == "10.0.0.5",
      tomllib.loads(text_a).get("serverAddr"))
check("A 的摘要里有 proxy_names", "proxy_names" in sum_a, sum_a)

changed_b, sum_b = asyncio.run(eng.rebuild_frpc(B_ID))
text_b = pathlib.Path(CFG_B).read_text(encoding="utf-8")
names_b = set(frpc.proxy_names(text_b))
check("B 的配置含 git-panel", "git-panel" in names_b, sorted(names_b))
check("B 的配置含 disc-panel", "disc-panel" in names_b, sorted(names_b))
check("★ B 的配置**不含** A 的隧道", "nas-panel" not in names_b, sorted(names_b))
check("B 的配置不含 web-panel", "web-panel" not in names_b, sorted(names_b))

print("[6] 备份按实例子目录隔离")
backups_a = frpc.list_backups(A_ID)
backups_b = frpc.list_backups(B_ID)
check("A/B 是不同的备份目录",
      frpc.instance_backup_dir(A_ID) != frpc.instance_backup_dir(B_ID))
# A 是首次写入，之前根本没有文件 -> 不该凭空造一份备份
check("★ A 首次写入无旧文件 -> 0 份备份（这是对的）", len(backups_a) == 0,
      backups_a)
# B 覆盖的是「用户手写的那份」-> 必须留底
check("★ B 覆盖了手写配置 -> 留下了备份", len(backups_b) >= 1, backups_b)

# ================================================================ [7] 成组切换
print("[7] 成组故障转移：A 的 2 条隧道一起搬，只重启 A 一次")
fake.created.clear(); fake.deleted.clear(); fake.ops.clear()
res = asyncio.run(eng._failover(store.get_tunnel(tA1), "节点离线（测试）",
                                ignore_cooldown=True))
check("切换成功", res.get("ok") is True, res)
check("落到节点 9（北京-联通）", res.get("node_id") == 9, res)
check("★ 成组大小 = 2", res.get("group_size") == 2, res)
check("★ 组里含 nas-panel 与 web-panel",
      set(res.get("group_tunnels") or []) == {"NAS 面板", "Web 面板"},
      res.get("group_tunnels"))
# ★ 顺序断言：mefrp 上 proxyName 唯一，同名不能共存 —— 必须先删旧的腾位。
#   这个 fake 的 proxy_create 遇到同名会直接报错，所以一旦顺序反了，
#   上面那条「切换成功」自己就会红。这里再显式盯一次调用序列。
check("★ 操作序列是「删旧 → 建新」交替（不是先建后删）",
      bool(fake.ops) and fake.ops[0][0] == "delete"
      and all(fake.ops[i][0] == "delete" and fake.ops[i + 1][0] == "create"
              for i in range(0, len(fake.ops) - 1, 2)),
      fake.ops)
check("两条隧道都在节点 9 上建了",
      {c[1] for c in fake.created if c[0] == 9} == {"nas-panel", "web-panel"},
      fake.created)
check("★ 只重启了 A 一次", dk_a.restarts == 1, dk_a.restarts)
check("★ 完全没重启 B", dk_b.restarts == 0, dk_b.restarts)
check("★ 只重建了 A 的文件，B 的文件没被动",
      pathlib.Path(CFG_B).read_text(encoding="utf-8") == text_b)

check("tA1 已落库到节点 9",
      store.get_tunnel(tA1)["current_node_id"] == 9, store.get_tunnel(tA1))
check("tA2 也落库到节点 9",
      store.get_tunnel(tA2)["current_node_id"] == 9, store.get_tunnel(tA2))
check("tA2 的 fail_streak 也清零", store.get_tunnel(tA2)["fail_streak"] == 0)
check("tB1 完全没被牵连",
      store.get_tunnel(tB1)["current_node_id"] == 5, store.get_tunnel(tB1))

text_a2 = pathlib.Path(CFG_A).read_text(encoding="utf-8")
check("★ 重建后 A 的 serverAddr 跟到了新节点",
      tomllib.loads(text_a2).get("serverAddr") == "10.0.0.9",
      tomllib.loads(text_a2).get("serverAddr"))
check("A 仍含两条隧道",
      set(frpc.proxy_names(text_a2)) == {"nas-panel", "web-panel"},
      frpc.proxy_names(text_a2))

backups_a = frpc.list_backups(A_ID)
backups_b = frpc.list_backups(B_ID)
check("★ 切换后 A 产生了备份（覆盖了上一版配置）", len(backups_a) >= 1, backups_a)
check("★ A/B 备份文件名不冲突（各自独立目录）",
      not ({b["name"] for b in backups_a} & {b["name"] for b in backups_b}),
      ([b["name"] for b in backups_a], [b["name"] for b in backups_b]))

print("[8] 成组切换后，组内其它隧道在冷却期内不会被重复切换")
res2 = asyncio.run(eng._failover(store.get_tunnel(tA2), "重复触发"))
check("第二条被冷却期拦住", res2.get("ok") is False and "冷却" in res2.get("error", ""),
      res2)

print("[9] 组内其它隧道各自的端口也单独判定")
check("两条都拿到了自己的端口",
      store.get_tunnel(tA1)["current_remote_port"] == 41234
      and store.get_tunnel(tA2)["current_remote_port"] == 41235,
      (store.get_tunnel(tA1)["current_remote_port"],
       store.get_tunnel(tA2)["current_remote_port"]))
check("端口没变 -> 不置下游待办",
      store.get_tunnel(tA1)["needs_downstream_review"] == 0
      and store.get_tunnel(tA2)["needs_downstream_review"] == 0)

# ================================================================ [10] 回滚
print("[10] 组内任一失败 -> 整体回滚（绝不留下半搬状态）")
before_a1 = store.get_tunnel(tA1)
before_a2 = store.get_tunnel(tA2)
fake.created.clear(); fake.deleted.clear()
# 让 web-panel 在「除原节点外」的任何节点上都建不出来 —— 切换必失败，
# 而回滚（建回原节点 9）必成功。不写死目标节点号，免得择优策略一改就误伤。
fake.fail_on_node = {("web-panel", nid) for nid in (5, 7)}
res3 = asyncio.run(eng._failover(store.get_tunnel(tA1), "测试回滚",
                                 ignore_cooldown=True))
check("整体报失败", res3.get("ok") is False, res3)
check("错误里点了名", "web-panel" in res3.get("error", ""), res3)
check("★ 报的是「已回滚」而不是「回滚未完全成功」",
      "回滚未完全成功" not in res3.get("error", ""), res3.get("error"))
check("★ 旧 proxy 确实发过删除请求（先删后建）",
      before_a1["current_proxy_id"] in fake.deleted, fake.deleted)
after_a1 = store.get_tunnel(tA1)
after_a2 = store.get_tunnel(tA2)
check("★ tA1 回到了原节点",
      after_a1["current_node_id"] == before_a1["current_node_id"],
      (before_a1["current_node_id"], after_a1["current_node_id"]))
# ⚠️ 回滚同样是「先删后建」，所以 proxyId 必然换了一个新的。
#    关键不是 id 相等，而是库里存的那个 id **真的存在于原节点上** ——
#    否则下一轮 _reconcile 会拿着一个不存在的 proxyId 去比对。
check("★ 库里记的 tA1 proxyId 在原节点上真实存在",
      after_a1["current_proxy_id"] in fake.proxies
      and fake.proxies[after_a1["current_proxy_id"]].node_id
          == before_a1["current_node_id"],
      (after_a1["current_proxy_id"], sorted(fake.proxies)))
check("★ 被删掉的旧 proxyId 确实不在 mefrp 上了",
      before_a1["current_proxy_id"] not in fake.proxies,
      (before_a1["current_proxy_id"], sorted(fake.proxies)))
check("★ tA2 也被建回了原节点（回滚不只管成功的那条）",
      after_a2["current_proxy_id"] in fake.proxies
      and fake.proxies[after_a2["current_proxy_id"]].node_id
          == before_a2["current_node_id"],
      (after_a2["current_proxy_id"], sorted(fake.proxies)))
check("回滚时没有重启任何容器", dk_a.restarts == 1 and dk_b.restarts == 0,
      (dk_a.restarts, dk_b.restarts))
fake.fail_on_node = set()

# ================================================================ [11] 未绑定
print("[11] 未挂接容器的隧道：不写配置 + 明确告警 + 拒绝切换")
eng.docker = None
res4 = asyncio.run(eng._rebuild_and_restart(store.get_tunnel(tX)))
check("如实返回「跳过了」", res4.get("skipped") is True, res4)
check("明确说明原因", "挂接" in (res4.get("note") or ""), res4)
evs = store.list_events(limit=50)
check("写了告警事件",
      any(e["kind"] == "frpc" and e["level"] == "warn" and "没有挂接" in e["message"]
          for e in evs),
      [(e["level"], e["kind"], e["message"][:40]) for e in evs[:8]])
# 没挂接也不能切换：换了节点本地没人接，比不切更糟（用户会以为自愈成功了）
fake.created.clear(); fake.deleted.clear()
res4b = asyncio.run(eng._failover(store.get_tunnel(tX), "测试未挂接",
                                  ignore_cooldown=True))
check("★ 未挂接 -> 拒绝切换", res4b.get("ok") is False, res4b)
check("★ 拒绝理由讲清要挂接", "挂接" in (res4b.get("error") or ""),
      res4b.get("error"))
check("★ 拒绝时没在 mefrp 上动过任何 proxy",
      not fake.created and not fake.deleted, (fake.created, fake.deleted))

print("[12] 空实例重建 -> 报错而不是写空配置")
# 把 tB1/tD 解绑，让 B 变成空实例；同时记下 B 的文件内容
before_b = pathlib.Path(CFG_B).read_text(encoding="utf-8")
store.update_tunnel(tB1, {"frpc_instance_id": None})
store.update_tunnel(tD, {"frpc_instance_id": None})
try:
    asyncio.run(eng.rebuild_frpc(B_ID))
    check("空实例重建抛 FrpcError", False, "没有抛异常")
except frpc.FrpcError as exc:
    check("空实例重建抛 FrpcError", True)
    check("报错说明了原因", "没有任何隧道挂接" in str(exc), str(exc))
check("★ 没有把 B 的配置文件清空",
      pathlib.Path(CFG_B).read_text(encoding="utf-8") == before_b)

print("[13] 多实例一致性：同一实例内跨节点必须报错")
bad_cfg = ("serverAddr = '1.1.1.1'\nserverPort = 7000\n\n"
           "[[proxies]]\nname = 'x'\ntype = 'tcp'\n")
good_cfg = ("serverAddr = '2.2.2.2'\nserverPort = 7000\n\n"
            "[[proxies]]\nname = 'y'\ntype = 'tcp'\n")
try:
    frpc.merge_configs([good_cfg, bad_cfg], label="备用线路")
    check("跨节点合并被拒绝", False, "没有抛异常")
except frpc.FrpcError as exc:
    check("跨节点合并被拒绝", True)
    check("报错带上实例名（便于定位）", "备用线路" in str(exc), str(exc))
check("同节点合并正常",
      frpc.merge_configs([good_cfg, good_cfg.replace("y", "z")], label="A")[0]
      .count("[[proxies]]") == 2)

# ================================================================ [14] 删除实例
print("[14] 删除实例：有绑定要拦，unbind 才放行")
store.update_tunnel(tB1, {"frpc_instance_id": B_ID})
check("计数正确", store.count_tunnels_of_frpc(B_ID) == 1,
      store.count_tunnels_of_frpc(B_ID))
check("解绑生效", store.unbind_tunnels_of_frpc(B_ID) == 1)
check("解绑后计数归零", store.count_tunnels_of_frpc(B_ID) == 0)
store.delete_frpc_instance(B_ID)
check("实例已删除", store.get_frpc_instance(B_ID) is None)
check("只剩 1 个实例", len(store.list_frpc_instances()) == 1)

print("[15] 不再兜底：只剩一个实例时，没挂接的隧道依然没有归属")
store.update_tunnel(tB1, {"frpc_instance_id": None})
store.update_tunnel(tD, {"frpc_instance_id": None})
check("★ 未挂接 -> None（不再自动归到那个唯一的实例）",
      eng.frpc_for_tunnel(store.get_tunnel(tB1)) is None,
      eng.frpc_for_tunnel(store.get_tunnel(tB1)))
grp = eng.frpc_group(store.get_tunnel(tB1), eng.frpc_for_tunnel(store.get_tunnel(tB1)))
check("★ 未挂接时整组只有它自己（不会顺手把别人的配置也写了）",
      len(grp) == 1 and int(grp[0]["id"]) == int(tB1),
      [g["name"] for g in grp])
store.update_tunnel(tB1, {"frpc_instance_id": A_ID})
check("挂接之后才解析得出来",
      int(eng.frpc_for_tunnel(store.get_tunnel(tB1))["id"]) == A_ID)
store.update_tunnel(tB1, {"frpc_instance_id": None})

print("[16] reload_dockers：按实例建控制器")
eng.dockers = {}
eng.docker = None
eng.reload_dockers()
check("A 有控制器", A_ID in eng.dockers, list(eng.dockers))
check("单实例时 self.docker 也对齐了", eng.docker is not None)

print()
print(f"==> PASS {ok} / FAIL {bad}")
sys.exit(1 if bad else 0)
