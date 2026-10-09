# -*- coding: utf-8 -*-
"""纯逻辑测试：frpc 配置合并 / store 持久化 / 数据模型 / 节点择优。

不依赖任何第三方库（httpx 用桩替掉），可以直接跑：

    python tests/test_logic.py
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---- 用桩替掉 httpx，让 mefrp / engine 能被 import（本项目只有这两个模块用到它）----
_stub = types.ModuleType("httpx")


class _DummyClient:
    def __init__(self, *a, **k): ...
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False


_stub.AsyncClient = _DummyClient
_stub.HTTPError = type("HTTPError", (Exception,), {})
# ⚠️ cloudflare.py 在**模块级**就取了 `httpx.TransportError` 去拼「值得重试的
#    异常」那个元组 —— 桩里少这个属性的话，import 就炸，而报的是一句跟本文件
#    毫无关系的 AttributeError。
_stub.TransportError = type("TransportError", (_stub.HTTPError,), {})
sys.modules.setdefault("httpx", _stub)

_TMP = tempfile.mkdtemp(prefix="mg-logic-")
os.environ.update(
    MG_DATA_DIR=_TMP,
    MG_FRPC_CONFIG=os.path.join(_TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
)

from app import frpc, store                       # noqa: E402
from app.engine import GuardEngine, keyword_rank, normalize_keywords  # noqa: E402
from app.mefrp import Node, Proxy                 # noqa: E402

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
# frpc：TOML 合并（风险最高的逻辑）
# ===========================================================================

CONF_A = '''serverAddr = "1.2.3.4"
serverPort = 7000
auth.method = "token"
auth.token = "abcdef"
user = "demo"

[[proxies]]
name = "nas-panel"
type = "tcp"
localIP = "127.0.0.1"
localPort = 5000
remotePort = 41234
'''

CONF_B = CONF_A.replace("nas-panel", "lucky").replace("5000", "16601").replace("41234", "41235")
CONF_OTHER_NODE = CONF_B.replace('"1.2.3.4"', '"5.6.7.8"')


def test_frpc() -> None:
    print("[frpc] TOML 合并与校验")

    merged, glob = frpc.merge_configs([CONF_A, CONF_B])
    check("合并后 proxies 数为 2", merged.count("[[proxies]]") == 2)
    check("全局段来自第一份", 'serverAddr = "1.2.3.4"' in merged and "serverPort = 7000" in merged)
    check("两条隧道都在", "nas-panel" in merged and "lucky" in merged)
    check("全局摘要正确", glob.get("serverAddr") == "1.2.3.4" and glob.get("serverPort") == "7000", glob)

    sm = frpc.config_summary(merged)
    check("回读 TOML 合法", sm.get("valid") is True, sm)
    check("回读 proxy_count=2", sm.get("proxy_count") == 2, sm.get("proxy_count"))
    check("回读 server_port=7000", str(sm.get("server_port")) == "7000", sm.get("server_port"))

    # 一个 frpc 只能连一个节点 —— 不一致必须报错，而不是写出错配置
    try:
        frpc.merge_configs([CONF_A, CONF_OTHER_NODE])
        check("跨节点配置必须抛错", False, "没有抛")
    except frpc.FrpcError as exc:
        check("跨节点配置必须抛错", "serverAddr" in str(exc), exc)

    for bad in ([], ["", "   "]):
        try:
            frpc.merge_configs(bad)
            check(f"空输入 {bad!r} 必须抛错", False)
        except frpc.FrpcError:
            check(f"空输入 {bad!r} 必须抛错", True)

    try:
        frpc.merge_configs([CONF_A.split("[[proxies]]")[0]])
        check("没有 [[proxies]] 必须抛错", False)
    except frpc.FrpcError:
        check("没有 [[proxies]] 必须抛错", True)

    check("单份配置也能合并", frpc.merge_configs([CONF_A])[0].count("[[proxies]]") == 1)
    check("坏 TOML 的 summary 返回 valid=False",
          frpc.config_summary("not = = toml").get("valid") is False)

    # ---- 回归：mefrp 官方配置用 TOML **单引号字面量** ----
    # 原正则 `"?([^"\n]+)"?` 对单引号会把引号一起吞进捕获组，
    # 于是 serverAddr 变成 "'1.2.3.4'"，同一地址只因引号风格不同
    # 就被判成「跨节点」，merge_configs 直接拒绝生成配置。
    check("server_addr_of 认单引号字面量",
          frpc.server_addr_of("serverAddr = '203.0.113.10'\nserverPort = 7000\n")
          == "203.0.113.10")
    check("server_addr_of 认双引号",
          frpc.server_addr_of('serverAddr = "203.0.113.10"\nserverPort = 7000\n')
          == "203.0.113.10")
    check("server_addr_of 认无引号裸值",
          frpc.server_addr_of("serverAddr = 203.0.113.10\nserverPort = 7000\n")
          == "203.0.113.10")
    check("捕获组不会把引号带进去",
          "'" not in frpc.server_addr_of("serverAddr = '1.2.3.4'\n")
          and '"' not in frpc.server_addr_of('serverAddr = "1.2.3.4"\n'))
    check("取不到时返回空串（而不是抛异常）",
          frpc.server_addr_of("serverPort = 7000\n") == "")
    # 单引号版和双引号版是同一个节点 -> 必须合并成功，不能报「跨节点」
    SQ_A = CONF_A.replace('"1.2.3.4"', "'1.2.3.4'").replace('"7000"', "'7000'")
    SQ_A = SQ_A.replace("serverPort = 7000", "serverPort = 7000")
    try:
        _m, _g = frpc.merge_configs([SQ_A, CONF_B])
        check("单引号 + 双引号但地址相同 -> 合并成功", _m.count("[[proxies]]") == 2, _m[:80])
        check("合并后的全局摘要已剥引号", _g.get("serverAddr") == "1.2.3.4", _g)
    except frpc.FrpcError as exc:
        check("单引号 + 双引号但地址相同 -> 合并成功", False, exc)

    # 配置读写 + 备份轮转 + 路径穿越防护
    frpc.write_config(CONF_A)
    check("写入后能读回", frpc.read_current() == CONF_A)
    frpc.write_config(CONF_B)
    backups = frpc.list_backups()
    check("覆盖前产生了备份", len(backups) == 1, backups)
    frpc.restore_backup(backups[0]["name"])
    check("恢复备份成功", frpc.read_current() == CONF_A)
    try:
        frpc.restore_backup("../../etc/passwd")
        check("路径穿越必须被挡住", False, "居然成功了")
    except frpc.FrpcError:
        check("路径穿越必须被挡住", True)


# ===========================================================================
# store + 数据模型
# ===========================================================================

def test_store() -> None:
    print("[store] 持久化与字段白名单")
    store.init()

    check("默认带宽阈值 25", store.get_setting("min_bandwidth_mbps") == 25)
    check("默认优先关键词「北京」", store.get_setting("prefer_keywords") == "北京")
    check("布尔默认值类型正确", store.get_setting("auto_failover") is True)

    tid = store.create_tunnel({
        "name": "NAS 面板", "proxy_name": "nas-panel", "proxy_type": "tcp",
        "local_ip": "127.0.0.1", "local_port": 5000,
        "enabled": 1, "auto_failover": 1, "dns_proxied": 0,
        "dns_record_name": "nas.example.com", "downstream_note": "改 Lucky 后端",
    })
    t = store.get_tunnel(tid)
    check("创建后能读回", t is not None and t["name"] == "NAS 面板", t)
    check("created_at 已填", t["created_at"] > 0)
    check("find_tunnel_by_proxy 命中", store.find_tunnel_by_proxy("nas-panel")["id"] == tid)
    check("find 不存在的返回 None", store.find_tunnel_by_proxy("nope") is None)

    # ★ 这 4 个字段是引擎每轮都要写的，漏一个自愈逻辑就整个失效
    print("  --- 引擎依赖的运行时字段（曾经漏配过，导致自动切换永不触发）---")
    for i in (1, 2, 3):
        store.update_tunnel(tid, {"fail_streak": i, "last_error": f"err{i}"})
        check(f"fail_streak 能累加到 {i}", store.get_tunnel(tid)["fail_streak"] == i,
              store.get_tunnel(tid)["fail_streak"])
    check("last_error 能写入", store.get_tunnel(tid)["last_error"] == "err3")
    store.update_tunnel(tid, {"last_ok_at": 1700000000, "last_failover_at": 1700000999})
    t = store.get_tunnel(tid)
    check("last_ok_at 能写入", t["last_ok_at"] == 1700000000, t["last_ok_at"])
    check("last_failover_at 能写入（冷却期的依据）", t["last_failover_at"] == 1700000999, t["last_failover_at"])

    print("  --- 白名单不能放行不该改的列 ---")
    store.update_tunnel(tid, {"id": 999, "created_at": 1, "updated_at": 1, "bogus": 1})
    t = store.get_tunnel(tid)
    check("id 未被篡改", t["id"] == tid)
    check("created_at 未被篡改", t["created_at"] > 1)

    store.update_tunnel(tid, {"enabled": 0})
    check("enabled_only 过滤生效", store.list_tunnels(enabled_only=True) == [])
    store.update_tunnel(tid, {"enabled": 1})

    store.upsert_node_pref(7, priority=5, excluded=True, note="北京联通")
    store.upsert_node_pref(7, priority=None, excluded=None, note=None)
    p = store.list_node_prefs()[7]
    check("节点偏好局部更新保留其余字段",
          p["priority"] == 5 and p["excluded"] == 1 and p["note"] == "北京联通", p)

    store.add_event("warn", "probe", "测试事件", tunnel_id=tid)
    check("事件写入", store.list_events(limit=1)[0]["message"] == "测试事件")
    check("按隧道过滤", len(store.list_events(tunnel_id=tid)) >= 1)
    check("不存在的隧道 id 返回空", store.list_events(tunnel_id=99999) == [])
    store.add_event("error", "system", "y" * 9999)
    check("detail 有截断保护", len(store.list_events(limit=1)[0]["detail"]) <= 4000)

    store.delete_tunnel(tid)
    check("删除后读不到", store.get_tunnel(tid) is None)
    check("删除后 proxy 名被释放", store.find_tunnel_by_proxy("nas-panel") is None)


def test_models() -> None:
    print("[models] Node / Proxy 字段解析")

    n = Node(node_id=1, name="北京-联通-01", hostname="1.2.3.4",
             allow_group="admin;sponsor;vip", allow_port="40000-65535",
             allow_type="tcp;udp", region="cn", bandwidth="200Mbps", is_online=True)
    check("200Mbps -> 200", n.bandwidth_mbps == 200.0, n.bandwidth_mbps)
    check("1Gbps -> 1000", Node(1, "x", bandwidth="1Gbps").bandwidth_mbps == 1000.0)
    check("空带宽 -> 0", Node(1, "x", bandwidth="").bandwidth_mbps == 0.0)
    check("「不限」-> 很大", Node(1, "x", bandwidth="不限").bandwidth_mbps > 9999)
    check("usable", n.usable is True)
    check("离线不可用", Node(1, "x", is_online=False).usable is False)

    check("vip 有权限", n.allows_group("vip") is True)
    check("free 无权限", n.allows_group("free") is False)
    check("组名大小写不敏感", n.allows_group("VIP") is True)
    check("空 allowGroup 视为不限", Node(1, "x", allow_group="").allows_group("free") is True)

    check("tcp 允许", n.allows_type("tcp") is True)
    check("http 不允许", n.allows_type("http") is False)

    check("端口 41234 在区间内", n.port_allowed(41234) is True)
    check("端口 80 不在区间内", n.port_allowed(80) is False)
    check("多段 allowPort", Node(1, "x", allow_port="10000-20000;30000-31000").port_allowed(30500) is True)
    check("单值 allowPort", Node(1, "x", allow_port="8080").port_allowed(8080) is True)
    check("空 allowPort 视为不限", Node(1, "x", allow_port="").port_allowed(1) is True)

    check("Proxy 健康", Proxy(1, "a", is_online=True).healthy_flags is True)
    check("Proxy 被封禁不健康", Proxy(1, "a", is_online=True, is_banned=True).healthy_flags is False)
    check("Proxy 被禁用不健康", Proxy(1, "a", is_online=True, is_disabled=True).healthy_flags is False)


# ===========================================================================
# pick_node：择优调度
# ===========================================================================

def test_pick_node() -> None:
    print("[pick_node] 自动择优 / 硬约束 / 软偏好")
    eng = GuardEngine()
    eng.user_group = "free"

    def N(nid: int, name: str, **kw) -> Node:
        base = dict(node_id=nid, name=name, hostname=f"10.0.0.{nid}",
                    allow_group="", allow_port="40000-65535", allow_type="tcp",
                    region="cn", bandwidth="100Mbps", is_online=True, is_disabled=False)
        base.update(kw)
        return Node(**base)

    store.set_setting("prefer_keywords", "北京")
    store.set_setting("min_bandwidth_mbps", 25)
    store.set_setting("max_load_percent", 90)
    store.set_setting("allow_regions", "cn")

    eng.nodes = {1: N(1, "上海-电信", bandwidth="500Mbps"),
                 2: N(2, "北京-联通", bandwidth="200Mbps"),
                 3: N(3, "广州-移动", bandwidth="1Gbps")}
    node, _ = eng.pick_node()
    check("优先关键词「北京」压过带宽", node and node.node_id == 2, node.name if node else "")

    store.set_setting("prefer_keywords", "")
    node, _ = eng.pick_node()
    check("无关键词时按带宽降序", node and node.node_id == 3, node.name if node else "")

    # ---- 节点偏好：有序 + 包含匹配 ----
    # 老实现是「命中任意关键词 = 排前面」的布尔判断，多填几个词没有顺序之分。
    # 现在改成「命中第几个词就排第几档」，所以「北京,上海」和「上海,北京」结果不同。
    print("  --- 节点偏好（有序多选）---")
    eng.nodes = {1: N(1, "上海-电信", bandwidth="1Gbps"),
                 2: N(2, "北京-联通", bandwidth="100Mbps"),
                 3: N(3, "广州-移动", bandwidth="500Mbps")}

    store.set_setting("prefer_keywords", "北京,上海")
    node, _ = eng.pick_node()
    check("偏好「北京,上海」-> 北京压过带宽高得多的上海",
          node and node.node_id == 2, node.name if node else "")

    store.set_setting("prefer_keywords", "上海,北京")
    node, _ = eng.pick_node()
    check("★ 顺序反过来 -> 上海优先（顺序真的生效）",
          node and node.node_id == 1, node.name if node else "")

    store.set_setting("prefer_keywords", "上海")
    node, _ = eng.pick_node()
    check("只填上海 -> 上海胜出，哪怕它带宽最高",
          node and node.node_id == 1, node.name if node else "")

    store.set_setting("prefer_keywords", "查无此名")
    node, _ = eng.pick_node()
    check("★ 一个都没命中 -> 不筛掉，退回按带宽排（偏好是排序不是筛选）",
          node and node.node_id == 1, node.name if node else "")

    check("包含匹配：节点名「北京BGP-1」命中「北京」",
          keyword_rank(N(9, "北京BGP-1"), ["北京"]) == 0)
    check("命中第二个关键词 -> 顺位 1",
          keyword_rank(N(9, "上海-电信"), ["北京", "上海"]) == 1)
    check("未命中 -> len(keywords)，排在所有命中项之后",
          keyword_rank(N(9, "广州-移动"), ["北京", "上海"]) == 2)
    check("空偏好 -> 恒 0（同权，不影响原有排序）",
          keyword_rank(N(9, "广州-移动"), []) == 0)
    check("匹配范围含描述",
          keyword_rank(N(9, "node-1", description="北京机房"), ["北京"]) == 0)
    check("匹配范围含区域",
          keyword_rank(N(9, "node-1", region="beijing"), ["beijing"]) == 0)

    check("关键词去重且保留首次出现的顺序",
          normalize_keywords("上海, 北京 ,上海") == ["上海", "北京"],
          normalize_keywords("上海, 北京 ,上海"))
    check("★ 中文全角逗号也认（中文输入法下打出来的就是它）",
          normalize_keywords("北京，上海") == ["北京", "上海"])
    check("空串 / None -> 空表",
          normalize_keywords("") == [] and normalize_keywords(None) == [])
    check("也接受数组（前端直接传）",
          normalize_keywords([" 北京 ", "", "北京"]) == ["北京"])
    check("★ 数组元素里的逗号照样拆（传 ['北京，上海'] 等于传 '北京,上海'）",
          normalize_keywords(["北京，上海"]) == ["北京", "上海"],
          normalize_keywords(["北京，上海"]))

    store.set_setting("prefer_keywords", "北京,上海")
    rows = {r["node_id"]: r for r in eng.rank_nodes()}
    check("rank_nodes 带 keyword_rank",
          rows[2]["keyword_rank"] == 0 and rows[1]["keyword_rank"] == 1, rows[2])
    check("keyword_hit 与顺位一致",
          rows[2]["keyword_hit"] is True and rows[3]["keyword_hit"] is False, rows[3])
    order = [r["node_id"] for r in eng.rank_nodes()]
    check("★ rank_nodes 也按偏好顺位排（否则页面上看到的顺序会骗人）",
          order.index(2) < order.index(1) < order.index(3), order)

    pv = eng.preview_pref(["北京", "上海"])
    check("preview：每个关键词各自命中 1 个",
          [len(g["nodes"]) for g in pv["groups"]] == [1, 1], pv)
    check("preview：未命中的单独统计", len(pv["unmatched"]) == 1, pv)
    check("preview：总数对得上", pv["total"] == 3, pv)
    check("★ preview 只读，不动库里的设置",
          store.get_setting("prefer_keywords") == "北京,上海")
    check("preview 逗号串也认",
          eng.preview_pref("北京")["keywords"] == ["北京"])

    store.set_setting("prefer_keywords", "")

    eng.nodes = {1: N(1, "北京-A", bandwidth="10Mbps")}
    node, why = eng.pick_node()
    check("全部低于带宽阈值 -> None", node is None)
    check("拒因说明带宽原因", "带宽" in why, why)

    eng.nodes = {1: N(1, "北京-VIP", allow_group="vip")}
    node, why = eng.pick_node()
    check("用户组无权限 -> None", node is None)
    check("拒因说明用户组原因", "无权限" in why, why)

    eng.nodes = {1: N(1, "北京-A", allow_type="udp")}
    check("类型不符 -> None", eng.pick_node(proxy_type="tcp")[0] is None)

    eng.nodes = {1: N(1, "北京-A", is_online=False), 2: N(2, "北京-B", is_disabled=True)}
    node, why = eng.pick_node()
    check("离线+禁用全跳过", node is None)
    check("拒因含离线与被禁用", "离线" in why and "被禁用" in why, why)

    eng.nodes = {1: N(1, "北京-A", region="oversea")}
    check("区域不符被筛", eng.pick_node()[0] is None)

    eng.nodes = {1: N(1, "北京-A", load_percent=99), 2: N(2, "北京-B", load_percent=10)}
    check("高负载被筛", eng.pick_node()[0].node_id == 2)

    eng.nodes = {1: N(1, "北京-A"), 2: N(2, "北京-B")}
    check("exclude 生效", eng.pick_node(exclude={1})[0].node_id == 2)
    eng.node_cooldown = {2: time.time() + 9999}
    check("冷却期节点被跳过", eng.pick_node()[0].node_id == 1)
    eng.node_cooldown = {}

    # ★ 手动指定 = 只受硬约束限制。否则「没有合格节点时让用户手动选」这条兜底路径走不通
    print("  --- 手动指定可以突破软偏好 ---")
    eng.nodes = {1: N(1, "北京-A", bandwidth="10Mbps")}
    check("手动选中低带宽节点", eng.pick_node(prefer_node_id=1)[0] is not None)
    eng.nodes = {1: N(1, "北京-A", load_percent=99)}
    check("手动选中高负载节点", eng.pick_node(prefer_node_id=1)[0] is not None)
    eng.nodes = {1: N(1, "北京-A", region="oversea")}
    check("手动选中区域外节点", eng.pick_node(prefer_node_id=1)[0] is not None)
    eng.nodes = {1: N(1, "北京-A")}
    eng.node_cooldown = {1: time.time() + 9999}
    check("手动选中冷却期节点", eng.pick_node(prefer_node_id=1)[0] is not None)
    eng.node_cooldown = {}
    store.upsert_node_pref(1, excluded=True)
    check("手动选中被排除的节点", eng.pick_node(prefer_node_id=1)[0] is not None)
    store.upsert_node_pref(1, excluded=False)

    print("  --- 手动指定仍受硬约束限制 ---")
    eng.nodes = {1: N(1, "北京-A", is_online=False)}
    node, why = eng.pick_node(prefer_node_id=1)
    check("离线节点手动也选不了", node is None and "离线" in why, why)
    eng.nodes = {1: N(1, "北京-A", is_disabled=True)}
    node, why = eng.pick_node(prefer_node_id=1)
    check("禁用节点手动也选不了", node is None and "被禁用" in why, why)
    eng.nodes = {1: N(1, "北京-VIP", allow_group="vip")}
    node, why = eng.pick_node(prefer_node_id=1)
    check("无权限节点手动也选不了", node is None and "无权限" in why, why)
    eng.nodes = {1: N(1, "北京-A", allow_type="udp")}
    node, why = eng.pick_node(prefer_node_id=1)
    check("类型不符手动也选不了", node is None and "不支持" in why, why)
    eng.nodes = {}
    node, why = eng.pick_node(prefer_node_id=99)
    check("不存在的节点", node is None and "不在列表中" in why, why)

    print("  --- 软指定（隧道里的「锁定节点」）---")
    eng.nodes = {1: N(1, "北京-A", bandwidth="1Gbps"), 2: N(2, "北京-B", bandwidth="10Mbps")}
    check("软指定可突破带宽阈值", eng.pick_node(prefer_node_id=2, soft_prefer=True)[0].node_id == 2)
    eng.nodes = {1: N(1, "北京-A", bandwidth="1Gbps"), 2: N(2, "北京-B", is_online=False)}
    check("软指定遇硬约束回退到自动候选",
          eng.pick_node(prefer_node_id=2, soft_prefer=True)[0].node_id == 1)
    check("硬指定遇硬约束则报错", eng.pick_node(prefer_node_id=2)[0] is None)

    print("  --- rank_nodes 给 UI 的两类标记 ---")
    eng.nodes = {1: N(1, "北京-好", bandwidth="200Mbps"),
                 2: N(2, "北京-慢", bandwidth="10Mbps"),
                 3: N(3, "北京-挂", is_online=False)}
    rows = {r["node_id"]: r for r in eng.rank_nodes()}
    check("合格节点 eligible", rows[1]["eligible"] is True and rows[1]["blockers"] == [])
    check("低带宽节点 selectable 但不 eligible",
          rows[2]["selectable"] is True and rows[2]["eligible"] is False, rows[2])
    check("低带宽原因进 warnings 而非 blockers",
          rows[2]["blockers"] == [] and "带宽" in rows[2]["warnings"][0], rows[2])
    check("离线节点不可 selectable", rows[3]["selectable"] is False, rows[3])
    check("离线原因进 blockers", "离线" in rows[3]["blockers"], rows[3])
    order = [r["node_id"] for r in eng.rank_nodes()]
    check("排序：合格的最前、不可用的最后", order[0] == 1 and order[-1] == 3, order)

    eng.nodes = {1: N(1, "北京-A", allow_type="tcp;udp")}
    check("proxy_type=tcp 可选", eng.rank_nodes("tcp")[0]["selectable"] is True)
    check("proxy_type=http 不可选", eng.rank_nodes("http")[0]["selectable"] is False)


def test_probe_plan() -> None:
    """端到端探测的适用性判定。

    这是防「健康的 UDP 隧道被反复误判成故障、进而被无意义地反复切换」的闸门。
    udp 隧道在节点上只有 UDP 监听，TCP 握手必然失败 —— 所以 auto 模式必须跳过。
    """
    from app.engine import probe_plan, PROBE_MODES

    print("[probe_plan] 端到端探测适用性")
    check("PROBE_MODES 只含 auto/tcp/none", set(PROBE_MODES) == {"auto", "tcp", "none"},
          PROBE_MODES)

    # auto：按协议分流
    check("auto + tcp -> 探测", probe_plan("tcp", "auto")[0] is True)
    check("auto + http -> 探测", probe_plan("http", "auto")[0] is True)
    check("auto + https -> 探测", probe_plan("https", "auto")[0] is True)
    check("★ auto + udp -> 不探测", probe_plan("udp", "auto")[0] is False)
    check("不探测时必须给出原因", bool(probe_plan("udp", "auto")[1]),
          probe_plan("udp", "auto"))
    check("原因里点明是协议不匹配",
          "UDP" in probe_plan("udp", "auto")[1], probe_plan("udp", "auto")[1])

    # 大小写与空白容错
    check("UDP 大写也认", probe_plan("UDP", "auto")[0] is False)
    check("类型带空格也认", probe_plan(" udp ", "auto")[0] is False)
    check("模式大写也认", probe_plan("udp", "AUTO")[0] is False)
    check("类型为空按 tcp 处理（默认探测）", probe_plan("", "auto")[0] is True)
    check("模式为空按 auto 处理", probe_plan("udp", "")[0] is False)

    # 逃生口与总开关
    check("tcp 模式强制探测 udp（逃生口）", probe_plan("udp", "tcp")[0] is True)
    check("tcp 模式强制探测 tcp", probe_plan("tcp", "tcp")[0] is True)
    check("none 模式关闭 tcp 探测", probe_plan("tcp", "none")[0] is False)
    check("none 模式关闭 udp 探测", probe_plan("udp", "none")[0] is False)
    check("none 模式也给出原因", "关闭" in probe_plan("tcp", "none")[1],
          probe_plan("tcp", "none")[1])


if __name__ == "__main__":
    test_frpc()
    test_store()
    test_models()
    test_pick_node()
    test_probe_plan()
    print(f"\n==> PASS {PASS} / FAIL {FAIL}")
    sys.exit(1 if FAIL else 0)
