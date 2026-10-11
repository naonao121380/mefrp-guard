"""自愈引擎。

一轮循环做四件事：
  1. 从 mefrp 拉全量状态（节点列表 / 节点状态 / 隧道列表 / 我的用户组）
  2. 对每个受管隧道做**三层健康判定**
  3. 健康 → 顺便纠正漂移的 DNS；不健康 → 累计失败次数，够了就故障转移
  4. 故障转移：选新节点 → 删旧隧道 → 建新隧道 → 重建 frpc 配置 → 重启 → 验证 → 改 DNS → 通知

为什么必须做第三层「端到端 TCP 探测」：
  mefrp 的节点列表有 5 分钟 Redis 缓存，`isOnline` 也可能滞后。
  只有真的去 connect 一次 `节点地址:远程端口`，才知道隧道是不是真的通。
  这是唯一不会骗人的判据。

防抖设计：
  * fail_threshold —— 连续失败 N 次才判定故障，避免网络抖动误切
  * failover_cooldown —— 一次切换后冷却一段时间，避免在多个坏节点间反复横跳
  * node_cooldown —— 刚被切走的节点一段时间内不再选它
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import frpc, frpcparse, store
from .cloudflare import CloudflareClient, CloudflareError
from .mefrp import (MefrpApiError, MefrpClient, MefrpError, Node, Proxy,
                    is_http_type, join_domains, kind_of, parse_domains)
from .notifier import Notifier
from .settings import BOOTSTRAP, pref_key


# 哨兵：区分「调用方没传 current_proxy_id」与「明确要求不删任何 proxy」。
# 不能用 None 当默认值 —— None 在这里是有意义的值（表示「当前没有 proxy」）。
_UNSET = object()


# ---------------------------------------------------------------------------
# 节点偏好（「优先北京，其次上海」这类有序偏好）
# ---------------------------------------------------------------------------

def normalize_keywords(items: str | list[str] | None) -> list[str]:
    """归一化节点偏好关键词表。

    接受两种输入：设置里存的逗号分隔串，或前端直接传的数组。
    数组会先拼回串再拆 —— 这样无论调用方传 `"北京,上海"` 还是 `["北京，上海"]`，
    结果都一样，不会因为「逗号在数组元素里面」就少拆一个。
    去空、去重（保留首次出现的顺序），并**同时认中英文逗号** ——
    中文输入法下打出来的「，」跟在英文键盘上打的「,」肉眼几乎没区别，
    让用户为这个差异买单没有道理。
    """
    if isinstance(items, str):
        raw = items
    else:
        raw = ",".join(str(x) for x in (items or []))
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.replace("，", ",").split(","):
        k = part.strip()
        if not k or k.lower() in seen:
            continue
        seen.add(k.lower())
        out.append(k)
    return out


def node_haystack(node: Node) -> str:
    """参与偏好匹配的「节点字符串」。

    名称 + 描述 + 区域。**用包含匹配而不是相等**：mefrp 的节点名形如
    「北京BGP-1」「上海-电信」，用户只会想填「北京」这两个字。
    """
    return f"{node.name} {node.description} {node.region}"


def keyword_rank(node: Node, keywords: list[str]) -> int:
    """节点在偏好表里的顺位：命中第几个关键词就返回几（0 = 最优先）。

    一个都没命中返回 `len(keywords)` —— 比任何命中项都靠后，但仍然可被选中
    （偏好是**排序**，不是筛选：没命中只是排在后面，不会把节点排除掉）。

    没配偏好（空表）时恒返回 0：所有节点同权，排序退回带宽/负载。
    """
    if not keywords:
        return 0
    low = node_haystack(node).lower()
    for i, k in enumerate(keywords):
        if k.lower() in low:
            return i
    return len(keywords)


@dataclass
class Verdict:
    ok: bool
    reason: str = ""
    layer: str = ""


@dataclass
class Snapshot:
    ts: int = 0
    running: bool = False
    configured: bool = False
    user_group: str = ""
    user_group_friendly: str = ""
    user_group_error: str = ""
    nodes: list[dict] = field(default_factory=list)
    proxies: list[dict] = field(default_factory=list)
    last_error: str = ""
    tick_count: int = 0
    next_tick_in: int = 0


async def tcp_probe(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str]:
    """对 节点地址:远程端口 做一次真实 TCP 连接。返回 (是否可达, 说明)。"""
    if not host or not port:
        return False, "节点地址或端口为空"
    try:
        fut = asyncio.open_connection(host, int(port))
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        del reader
        return True, ""
    except asyncio.TimeoutError:
        return False, f"连接 {host}:{port} 超时（{timeout}s）"
    except OSError as exc:
        return False, f"连接 {host}:{port} 失败：{exc}"


async def http_probe(url: str, timeout: float = 6.0) -> tuple[bool, str]:
    """HTTP 层端到端探测：GET 一个 URL，**2xx/3xx 算通**。

    这是 http/https 隧道唯一有意义的 L3 判据 —— 原因见 `probe_plan` 里那段
    「为什么 http 不能做 TCP 探测」。

    判定为什么这么定：
      · **3xx 也算通** —— 本地服务在根路径上 302 跳登录页是极常见的，判成故障
        会造成「健康隧道被反复切换」，而这是这套代码里最怕的事。
      · **4xx/5xx 算不通** —— 多半意味着节点反代没匹配到这条隧道（返回了它自己
        的 404 页），或者本地服务真的挂了。⚠️ 但「本地服务在探测路径上本来就
        返回 4xx」的情况也存在（纯 API 服务、带鉴权的后台），所以文案里必须
        带上状态码，并把「改探测路径」这条出路写出来 —— 否则用户只会看到一片红
        却不知道是自己配的路径不对。

    **不跟随重定向**：跟了之后最终状态码会变成目标页的，反而看不出中间那层是
    不是通的，而且会平白多打好几个请求。

    ⚠️ `import httpx` 放在函数里而不是模块顶层：engine 模块被「纯逻辑测试」导入
    时是塞了假 httpx 的（见 tests 里 sys.modules 那套注入），顶层导入会把
    `httpx.AsyncClient` 这类属性需求提前压到桩上。真跑 http 探测时拿到的才是真货。
    """
    if not url:
        return False, "没有可用的绑定域名，无法做 HTTP 探测"
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as c:
            r = await c.get(url)
    except Exception as exc:                      # noqa: BLE001 —— 探测必须吞掉一切异常
        # ⚠️ 必须带**异常类型名**：httpx 的超时类异常 `str()` 经常是空串，
        #    只打 `{exc}` 会得到一条没有任何信息的事件（CF 客户端里踩过这个坑）。
        return False, f"HTTP 探测失败（{type(exc).__name__}）：{exc or '无详情'}"
    code = int(r.status_code)
    if 200 <= code < 400:
        return True, f"HTTP {code}"
    return False, (f"HTTP {code} —— 链路是通的但服务返回了 {code}。"
                   "若你的服务在这个路径上本来就返回 4xx/5xx，"
                   "请到设置里把「HTTP 探测路径」改成能返回 2xx 的路径")


def http_probe_url(proxy_type: str, domain: str, path: str = "/") -> str:
    """拼出 HTTP 探测的 URL。

    ⚠️ 用**绑定域名**而不是节点地址：这条隧道的身份就是域名，节点上的反代也是
    按请求的 Host 头分流的。拿节点 IP 去请求只会拿到反代的默认页，探不出任何
    有用的东西 —— 那还不如不探。

    scheme 按**隧道类型**定，不是按本地服务：
      · `http` 隧道对外就是明文，哪怕本地服务是 HTTPS（那是 `http2https`
        插件在节点侧做的一次转换）；
      · `https` 隧道对外是 TLS（节点侧拿你给的证书终结）。
    """
    host = parse_domains(domain)
    if not host:
        return ""
    scheme = "https" if str(proxy_type or "").strip().lower() == "https" else "http"
    p = (path or "/").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    return f"{scheme}://{host[0]}{p}"


# 端到端探测模式，与 settings.DEFAULT_SETTINGS["probe_mode"] 的取值一致。
#   auto —— tcp 走 TCP 探测；udp 与 http/https 都**跳过**（各有各的理由，见 probe_plan）
#   tcp  —— 一律 TCP 探测（逃生口；对 http 隧道是假阳性）
#   http —— 按类型各用各的：tcp 走 TCP，http/https 走真实 HTTP 请求
#   none —— 全关
PROBE_MODES = ("auto", "tcp", "http", "none")

# 探测种类。`probe_plan` 返回这三个值之一，调用方按它分流。
PROBE_NONE = "none"
PROBE_TCP = "tcp"
PROBE_HTTP = "http"

# ★ 连续失败**多久**才升级成 error 告警（秒）。默认 30 分钟。
#
# ⚠️ 为什么按**时间**、不按次数：巡检每 20 秒一轮。原来的口径是「连续 N 次」，
#    3 次 = 1 分钟 —— 移动宽带那种「抖两三分钟就自愈」的间歇性抽风，会一路
#    记满一屏红字。实测 10-08~10-10 三天：mefrp 报了 122 条 error、Cloudflare
#    64 条，全是这种 2~9 分钟的短窗口，**没有一条是源站真挂了**。用户明确要求：
#    **连续半小时连不上才告警**；mefrp 的状态本来就不要求时效性，DNS 也一样。
#
# 现在的规则（mefrp 与 DNS 完全一致）：
#   · 刚开始失败 → 记**一条** warn 留痕（不告警），之后保持安静
#   · 连续失败满 `alert_after_seconds` → 记一条 error（这才是告警）
#   · 之后每再满一个 `alert_after_seconds` → 补一条（长时间断网不漏报）
#   · 恢复 → 状态清零；**告过警**的才记一条 success（短抖自愈不再记，免得吵）
#   · 静态问题（zone 找不到这种，重试不会好）不套这套，立刻记 error
#
# 可在「设置」页改（`alert_after_seconds`）。刻意**不复用** `fail_threshold`：
# 那个管的是「连续探测失败几次才触发切换」，捆在一起以后调一个必然误伤另一个。
ALERT_AFTER_SECONDS = 1800


def alert_after_seconds() -> float:
    """读「连续失败多久才告警」。设置页可改；脏值/缺值一律回落到默认。

    ⚠️ 每次现读、不缓存：改设置不用重启（`PUT /api/settings` 之后下一轮巡检
    就该按新口径走）。设成 0 或负数视为「立刻告警」，等价于关掉这层缓冲。
    """
    try:
        v = float(store.get_setting("alert_after_seconds", ALERT_AFTER_SECONDS))
    except (TypeError, ValueError):
        return float(ALERT_AFTER_SECONDS)
    return max(0.0, v)


def _fmt_span(seconds: float) -> str:
    """把秒数写成「X 分 Y 秒」/「X 小时 Y 分」，给事件文案用。"""
    s = int(max(0.0, seconds))
    if s >= 3600:
        h, m = divmod(s // 60, 60)
        return f"{h} 小时 {m} 分" if m else f"{h} 小时"
    if s >= 60:
        m, r = divmod(s, 60)
        return f"{m} 分 {r} 秒" if r else f"{m} 分"
    return f"{s} 秒"


def probe_plan(proxy_type: str, mode: str) -> tuple[str, str]:
    """决定这条隧道这一轮该做哪种端到端探测。返回 (探测种类, 不做探测的原因)。

    探测种类是 `"tcp"` / `"http"` / `"none"` 三者之一，调用方（`_probe_cached`）
    按它分流。

    ⚠️ 这里每一条「跳过」都是踩出来的，不是洁癖：

    **udp 不能做 TCP 探测** —— mefrp 的 udp 隧道在节点上监听的是 **UDP** 端口，
    没有 TCP 监听。对它做 `asyncio.open_connection`（三次握手）**必然失败**，
    于是这条完全健康的隧道会被永久判成「异常」：

        fail_streak 一路涨 → 到阈值 → 自动切换被触发
        → 隧道被搬到另一个节点 → 地址变了、DNS 要改、下游要改
        → 新节点上依然是 udp，依然探不通 → 再切换 …… 无限循环。

    **http/https 也不能做 TCP 探测**，但原因跟 udp 正好相反 —— 不是「探不到」，
    而是「**探了也白探，而且是假阳性**」：

        节点上跑着反代，它对**任何** Host 都会接受 TCP 连接并回一个页面。
        所以 `connect(节点:80)` 永远成功 —— 哪怕这条隧道根本没建起来、
        哪怕绑定域名还解析在别的节点上。拿它当健康判据等于没判。

    那 http 隧道怎么探？用**真的 HTTP 请求**（`mode="http"` 时）：GET 绑定域名，
    看能不能拿到 2xx/3xx。这是唯一能验到「域名解析对不对、链路通不通」的办法。
    ⚠️ 但它有个前提：域名必须**已经**解析到当前节点，而 DNS 生效是异步的，
    所以刚切换完的那一小段时间会误报 —— 这是默认不启用它的原因。
    """
    pt = (proxy_type or "tcp").strip().lower()
    m = (mode or "auto").strip().lower()
    if m == "none":
        return PROBE_NONE, "已按设置关闭端到端探测（probe_mode = none）"
    if m == "tcp":
        # 逃生口：所有隧道一律 TCP 探。⚠️ 对 http 隧道来说这是**假阳性**，
        # 页面上要提示，别让用户以为「探通了就没事」。
        return PROBE_TCP, ""
    if m == "http":
        # 按类型各用各的：http 组走真 HTTP 请求，tcp 照旧，udp 仍然跳过
        # （udp 那层协议不匹配跟探测方式无关，换什么方式都探不到）。
        if pt == "udp":
            return PROBE_NONE, "UDP 隧道不做端到端探测（协议不匹配，任何 TCP/HTTP 探测都不适用）"
        return (PROBE_HTTP, "") if pt in ("http", "https") else (PROBE_TCP, "")
    # auto（默认）
    if pt == "udp":
        return PROBE_NONE, "UDP 隧道不做 TCP 端到端探测（协议不匹配，探测必然失败）"
    if pt in ("http", "https"):
        return PROBE_NONE, ("HTTP 隧道不做 TCP 探测：节点反代对任何 Host 都会握手成功，"
                            "探出来永远是「通」（假阳性）。"
                            "要真探请在设置里把探测模式改成「按类型（http）」")
    return PROBE_TCP, ""


def scope_key(manual_node_id: Any) -> int | None:
    """把「这台东西跑在哪台 frps 上」归一成一个可比较的值。

    None = mefrp（走 API 的那一家），int = 某个外部节点。
    隧道和 frpc 实例都用它 —— **隧道名只在同一台 frps 内唯一**，
    跨作用域比较是没有意义的（各运营商命名空间互不相干）。
    """
    return int(manual_node_id) if manual_node_id else None


def _close_client_soon(client: Any) -> None:
    """把被替换掉的 CF 客户端的连接池关掉。

    `reload_clients` 是**同步**方法（启动、保存设置、切节点等多处调用），
    没法 await，所以把关闭动作丢给当前事件循环去跑。

    · 没有运行中的循环（启动早期、纯同步的测试）→ 直接返回，连接池随对象
      一起被回收，不值得为它引入一次同步阻塞；
    · 客户端没有 `aclose`（测试里注入的假客户端）→ 跳过。
    """
    if client is None or not hasattr(client, "aclose"):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(client.aclose())


class GuardEngine:
    def __init__(self):
        self.client: MefrpClient | None = None
        self.cf: CloudflareClient | None = None
        self.notifier = Notifier()

        # 「默认实例」的容器控制器。保留这个字段是因为外部（测试、旧调用方）
        # 会直接注入它。多实例场景下真正的来源是 self.dockers。
        self.docker: frpc.DockerControl | None = None
        # frpc_instance_id -> DockerControl
        self.dockers: dict[int, frpc.DockerControl] = {}

        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()

        self.nodes: dict[int, Node] = {}
        self.node_status: dict[int, dict] = {}
        self.proxies: dict[str, Proxy] = {}
        self.proxy_by_id: dict[int, Proxy] = {}
        self.user_group: str = ""
        self.user_group_friendly: str = ""
        self.user_group_error: str = ""

        # 节点公网地址缓存。nodeId -> hostname
        #
        # 为什么需要缓存：/auth/node/list 对非管理员把 hostname 脱敏成空串，
        # 唯一的来源是「该节点上已有隧道的官方配置里的 serverAddr」，
        # 而取一次要多打一个 API，所以缓存起来。
        self.node_hostname_cache: dict[int, str] = {}

        # (时间戳, 是否可达, 说明)。第二个元素是**三态**：True/False/None，
        # None 表示「协议不适用探测，已跳过」—— 和「探测失败」是两回事。
        self.probe_cache: dict[int, tuple[float, bool | None, str]] = {}

        # 刚被切走的节点在冷却期内不再选它。★ 键是 **`(隧道类型组, node_id)`**，
        # 不是单纯的 node_id —— 「port」和「http」是两套独立的偏好体系
        # （见 settings.PREF_KEYS），同一台节点上，一条 TCP 隧道刚失败不代表
        # 一条 HTTP 隧道也要躲开它（两者用到的能力根本不同：HTTP 靠节点反代 +
        # 域名，TCP 靠裸端口）。所以冷却也要按类型分开记。
        self.node_cooldown: dict[tuple[str, int], float] = {}

        # 外部节点的可达性缓存：node_id -> (时间戳, 是否可达, 说明)。
        # 探的是 frps 的**控制端口**（serverAddr:serverPort），和隧道的
        # 端到端探测是两件事：这个说明「节点本身还在不在」。
        self.manual_probe: dict[int, tuple[float, bool, str]] = {}

        # ★ 连续失败的**起点时间戳**（None / 缺键 = 当前没在失败）与**已发过几次
        #   告警**。只用来决定这条失败该记 warn 还是 error，成功一次就清零。
        #   内存态即可 —— 重启之后从头计时没有副作用（最多多记一条 warn）。
        #   口径见 `ALERT_AFTER_SECONDS`：满 30 分钟才告警，之前只留一条 warn。
        self.dns_fail_since: dict[int, float] = {}
        self.dns_alert_count: dict[int, int] = {}
        self.mefrp_fail_since: float | None = None
        self.mefrp_alert_count: int = 0

        self.last_error: str = ""
        self.tick_count: int = 0
        self.last_tick_at: float = 0.0

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def reload_clients(self) -> None:
        s = store.get_settings()
        self.client = MefrpClient(
            token=str(s.get("mefrp_token") or ""),
            base=str(s.get("mefrp_base") or ""),
            user_agent=str(s.get("user_agent") or ""),
        )
        # ⚠️ 换掉 CF 客户端之前先把旧的连接池关掉。CloudflareClient 现在会**复用**
        #    一个 httpx.AsyncClient（一次握手撑很多轮），不再用完即弃 —— 好处是
        #    握手次数大幅下降，代价是必须有人负责关它，否则改一次设置就漏一个池子。
        old_cf = self.cf
        self.cf = CloudflareClient(token=str(s.get("cf_api_token") or ""))
        _close_client_soon(old_cf)
        self.notifier.configure(
            str(s.get("gotify_url") or ""), str(s.get("gotify_token") or "")
        )
        self.reload_dockers()

    def reload_dockers(self) -> None:
        """按 frpc 实例重建容器控制器。

        ⚠️ 不无条件覆盖 self.docker —— 那个字段是「默认实例」的控制器，
        外部（测试 / 旧调用方）可以直接注入。这里只在恰好一个实例、
        且 self.docker 还是空的时候把它对齐过去。
        """
        instances = store.list_frpc_instances(enabled_only=True)
        self.dockers = {
            int(i["id"]): frpc.DockerControl(
                str(i["container"] or ""), BOOTSTRAP.docker_base_url
            )
            for i in instances
            if str(i["container"] or "").strip()
        }
        if len(instances) == 1 and self.docker is None:
            self.docker = self.dockers.get(int(instances[0]["id"]))

    # ------------------------------------------------------------------
    # frpc 实例解析
    # ------------------------------------------------------------------

    def docker_for(self, instance: dict | None) -> frpc.DockerControl | None:
        """取某个 frpc 实例的容器控制器。取不到返回 None（调用方要如实报错）。"""
        if instance is not None:
            dk = self.dockers.get(int(instance["id"]))
            if dk is not None:
                return dk
        # 兜底：只有一个实例时允许用 self.docker —— 兼容外部注入与旧行为。
        # ⚠️ 多实例时**不能**兜底，否则会把 A 实例的配置改动去重启 B 的容器。
        if len(store.list_frpc_instances(enabled_only=True)) <= 1:
            return self.docker
        return None

    def frpc_for_tunnel(self, tunnel: dict,
                        instances: list[dict] | None = None) -> dict | None:
        """解析一条隧道由哪个 frpc 容器承载。返回实例 dict，或 None（未挂接）。

        **只有一级：显式绑定** `tunnels.frpc_instance_id`。

        ⚠️ 这里**故意不做**两件事：

        1. **唯一实例兜底**（旧行为：只剩一个启用的实例时，自动认领所有未绑定的
           隧道）。它让「没挂接的隧道」看起来像挂接好了 —— 用户以为程序在管它，
           实际配置写没写、容器重启没重启全看运气。更糟的是它不稳定：再加一个
           实例，这些隧道会**突然集体失去归属**，行为在那一刻突变。所以直接去掉，
           挂接必须是用户的一次明确动作。
        2. **按配置文件里的隧道名自动发现**。发现是启发式规则，一旦参与自动解析
           就会**覆盖用户的显式操作** —— 用户把隧道解绑，只要旧实例的配置文件里
           还留着那个隧道名，下一轮解析就会把它绑回去，用户永远改不动。

        发现保留为**一次性动作** `discover_bindings()`：它把推断结果写成显式绑定，
        之后走的还是这一级，完全可预期。
        """
        explicit = tunnel.get("frpc_instance_id")
        if not explicit:
            return None
        # `instances` 允许调用方传进来复用 —— 一次要解析几十条隧道时（见
        # main.list_tunnels），别为每条都扫一遍实例表。
        if instances is None:
            instances = store.list_frpc_instances(enabled_only=True)
        # 指向一个已删除 / 已停用的实例 → 当作未挂接。
        # ⚠️ 不能「随便找一个顶上」—— 那会把配置写进用户没指定的那个文件里。
        return next((i for i in instances if int(i["id"]) == int(explicit)), None)

    def discover_bindings(self, apply: bool = False) -> dict:
        """按各实例**现有的配置文件**推断隧道归属。

        默认只预览（apply=False），不写库 —— 绑定写错会让配置写到错误的文件里，
        比不绑定更糟，所以让用户先看一眼再决定。

        已经显式绑定过的隧道不参与推断（显式优先）。
        """
        instances = store.list_frpc_instances(enabled_only=True)
        names: dict[int, set[str]] = {}
        for inst in instances:
            iid = int(inst["id"])
            try:
                names[iid] = set(frpc.proxy_names(frpc.read_config(inst["config_path"])))
            except frpc.FrpcError:
                names[iid] = set()

        proposals: list[dict] = []
        ambiguous: list[dict] = []
        unmatched: list[dict] = []

        for t in store.list_tunnels():
            if t.get("frpc_instance_id"):
                continue
            pn = str(t["proxy_name"] or "").strip()
            # ⚠️ 只在**同一个 frps 作用域**里匹配。隧道名只在「一台 frps 内」唯一，
            #    跨运营商重名是常态 —— 不做作用域过滤的话，一条 mefrp 隧道会被
            #    推荐绑到「别家 frps 上恰好同名」的那个实例上，而两者毫无关系。
            tscope = scope_key(t.get("manual_node_id"))
            hits = [i for i in instances
                    if pn and pn in names.get(int(i["id"]), set())
                    and scope_key(i.get("manual_node_id")) == tscope]
            base = {"tunnel_id": int(t["id"]), "tunnel_name": t["name"],
                    "proxy_name": pn}
            if len(hits) == 1:
                proposals.append({**base, "instance_id": int(hits[0]["id"]),
                                  "instance_name": hits[0]["name"]})
            elif len(hits) > 1:
                # 多个实例的配置里都有这个名字 —— 不猜，交给人决定
                ambiguous.append({**base,
                                  "instances": [{"id": int(i["id"]),
                                                 "name": i["name"]} for i in hits]})
            else:
                unmatched.append(base)

        applied = 0
        if apply and proposals:
            for p in proposals:
                store.update_tunnel(int(p["tunnel_id"]),
                                    {"frpc_instance_id": int(p["instance_id"])})
                applied += 1
            store.add_event("info", "frpc",
                            f"自动发现：已为 {applied} 条隧道写入绑定关系")

        return {
            "ok": True,
            "applied": applied,
            "proposals": proposals,
            "ambiguous": ambiguous,
            "unmatched": unmatched,
            "instances": [
                {"id": int(i["id"]), "name": i["name"],
                 "config_path": i["config_path"],
                 "config_exists": Path(str(i["config_path"])).exists(),
                 "proxy_names": sorted(names.get(int(i["id"]), set()))}
                for i in instances
            ],
        }

    def frpc_group(self, tunnel: dict, instance: dict | None) -> list[dict]:
        """一个 frpc 容器承载的全部启用隧道（含传入的这条）。

        **本项目的模型是「一条隧道 : 一个 frpc 容器」**，所以正常情况下这里
        返回的就是 `[tunnel]` 一条 —— 挂接关系建好之后，这个函数等价于恒等。

        之所以还留着「成组」这层：它是一个**安全网**，不是给常规用法准备的。
        万一有人把两条隧道挂到同一个实例上（UI 不拦，因为排查问题时确实可能
        临时这么干），成组逻辑能保证不出错 —— 见下面的原因。而如果按单条处理，
        那种配置会直接把 frpc 写坏。

        未挂接时（instance 为 None）只返回它自己，退化成单隧道行为。

        ⚠️ 为什么切换的单位必须是「整组」而不是单条：一个 frpc 进程只能连一个
        serverAddr，所以它承载的所有隧道必然在同一个节点上。只把其中一条搬到
        新节点，合并配置时就会因为 serverAddr 不一致而直接报错 —— 结果是一条
        都写不进去，触发切换的那条反而彻底断了。
        """
        if instance is None:
            return [tunnel]
        iid = int(instance["id"])
        out: list[dict] = []
        for t in store.list_tunnels(enabled_only=True):
            inst = self.frpc_for_tunnel(t)
            if inst is not None and int(inst["id"]) == iid:
                out.append(t)
        if not any(int(t["id"]) == int(tunnel["id"]) for t in out):
            out.append(tunnel)
        return out

    # ------------------------------------------------------------------
    # 外部节点
    # ------------------------------------------------------------------
    #
    # 外部节点 = 用户粘一份 frpc 配置导入的、**没有 API** 的 frp 节点（自建 frps、
    # 别的 frp 服务商）。它和 mefrp 节点在列表里同级，能绑 frpc 实例、能绑域名，
    # 但引擎**绝不**对它做自动切换 —— 原因见 _reconcile_manual。

    def manual_node_of_tunnel(self, tunnel: dict) -> dict | None:
        """这条隧道跑在哪个外部节点上。没有则 None（= 走 mefrp API）。"""
        nid = tunnel.get("manual_node_id")
        if not nid:
            return None
        return store.get_manual_node(int(nid))

    def manual_node_of_instance(self, instance: dict | None) -> dict | None:
        if not instance:
            return None
        nid = instance.get("manual_node_id")
        if not nid:
            return None
        return store.get_manual_node(int(nid))

    def manual_node_for(self, tunnel: dict) -> dict | None:
        """这条隧道**实际**跑在哪个外部节点上。

        ⚠️ 两个来源都要看，缺一不可：

        * 隧道自己标的 `manual_node_id` —— 导入配置时勾选纳管的隧道带这个。
        * 它挂接的实例绑的节点 —— 用户先把实例指到外部节点、再挂隧道的中间态。

        只用前者的话，那个中间态的隧道会被 `_reconcile_manual` 判成
        「挂接的外部节点已不存在」并记一条假错误 —— 而它其实好端端跑着。
        """
        return (self.manual_node_of_tunnel(tunnel)
                or self.manual_node_of_instance(self.frpc_for_tunnel(tunnel)))

    def tunnel_is_manual(self, tunnel: dict) -> bool:
        """这条隧道是不是外部节点托管。

        ⚠️ 判据要**两个都看**：

        * 隧道自己的 `manual_node_id` —— 导入配置时勾选纳管的隧道会带这个。
        * 它挂接的实例绑了外部节点 —— 用户可能先把实例指到外部节点，再挂隧道。

        只看前者会漏掉「实例已被外部节点接管、但隧道还没标」的中间状态；
        只看后者则会让「导入进来还没挂接」的隧道走错分支，拿去跟 mefrp 的
        proxy 列表比对，然后被判成「隧道在 mefrp 上不存在」。
        """
        if tunnel.get("manual_node_id"):
            return True
        inst = self.frpc_for_tunnel(tunnel)
        return bool(inst and inst.get("manual_node_id"))

    async def probe_manual_node(self, node_id: int, *, force: bool = False) -> dict:
        """探外部节点的**控制端口**（serverAddr:serverPort）。

        和隧道的端到端探测是两件事：这个回答的是「节点本身还在不在」。
        带缓存，避免 UI 每刷一次就打一次连接。
        """
        node = store.get_manual_node(int(node_id))
        if node is None:
            return {"ok": False, "error": "外部节点不存在"}
        now = time.time()
        interval = float(store.get_setting("probe_interval", 60) or 60)
        cached = self.manual_probe.get(int(node_id))
        if cached and not force and now - cached[0] < interval:
            return {"ok": bool(cached[1]), "reason": cached[2],
                    "at": int(cached[0]), "cached": True}

        ok, why = await tcp_probe(
            str(node["server_addr"]), int(node["server_port"]),
            float(store.get_setting("probe_timeout", 4) or 4),
        )
        self.manual_probe[int(node_id)] = (now, ok, why)
        return {"ok": ok, "reason": why, "at": int(now), "cached": False}

    def manual_node_rows(self) -> list[dict]:
        """给 UI 用的外部节点列表（含探测结果、绑定的实例与隧道）。"""
        rows = []
        for n in store.list_manual_nodes():
            nid = int(n["id"])
            insts = store.list_instances_of_manual_node(nid)
            tunnels = store.list_tunnels_of_manual_node(nid)
            cached = self.manual_probe.get(nid)
            rows.append({
                "id": nid,
                "name": n["name"],
                "server_addr": n["server_addr"],
                "server_port": int(n["server_port"]),
                "endpoint": f"{n['server_addr']}:{int(n['server_port'])}",
                "auth_method": n["auth_method"],
                "has_token": bool(n.get("auth_token")),
                "auth_user": n.get("auth_user") or "",
                "config_format": n["config_format"],
                "note": n.get("note") or "",
                "enabled": bool(n["enabled"]),
                # 三态：None = 还没探过 / True / False
                "probe_ok": cached[1] if cached else None,
                "probe_reason": cached[2] if cached else "",
                "probe_at": int(cached[0]) if cached else 0,
                "instances": [{"id": int(i["id"]), "name": i["name"],
                               "config_path": i["config_path"]} for i in insts],
                "instance_count": len(insts),
                "tunnel_count": len(tunnels),
                "tunnels": [{
                    "id": int(t["id"]), "name": t["name"],
                    "proxy_name": t["proxy_name"],
                    "proxy_type": t["proxy_type"],
                    "remote_port": t.get("current_remote_port"),
                    "enabled": bool(t["enabled"]),
                    "dns_record_name": t.get("dns_record_name") or "",
                } for t in tunnels],
            })
        return rows

    def resolve_map(self) -> dict:
        """给 UI 用的完整绑定关系：每个实例承载哪些隧道、哪些隧道没绑定。"""
        instances = store.list_frpc_instances()
        buckets: dict[int, list[dict]] = {int(i["id"]): [] for i in instances}
        unassigned: list[dict] = []

        for t in store.list_tunnels():
            inst = self.frpc_for_tunnel(t)
            entry = {
                "id": int(t["id"]),
                "name": t["name"],
                "proxy_name": t["proxy_name"],
                "enabled": bool(t["enabled"]),
                "current_node_id": t.get("current_node_id"),
                "explicit": bool(t.get("frpc_instance_id")),
            }
            if inst is None:
                entry["resolved_by"] = ""
                unassigned.append(entry)
            else:
                iid = int(inst["id"])
                if iid in buckets:
                    buckets[iid].append(entry)

        out = []
        for inst in instances:
            iid = int(inst["id"])
            out.append({
                "id": iid,
                "name": inst["name"],
                "tunnels": buckets.get(iid, []),
                "tunnel_count": len(buckets.get(iid, [])),
            })
        return {"instances": out, "unassigned": unassigned}

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self.reload_clients()
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="guard-loop")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _loop(self) -> None:
        while not self._stop.is_set():
            interval = int(store.get_setting("engine_interval", 20) or 20)
            interval = max(5, min(interval, 3600))
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - 引擎绝不能因单次异常死掉
                self.last_error = f"引擎循环异常：{exc}"
                store.add_event("error", "system", self.last_error)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------

    async def tick(self) -> None:
        async with self._lock:
            self.tick_count += 1
            self.last_tick_at = time.time()

            if self.client is None:
                self.reload_clients()
            assert self.client is not None

            s = store.get_settings()
            # mefrp 这一侧这轮能不能用。**不能用也不代表整轮没得做** ——
            # 外部节点的隧道压根不走 mefrp API（地址就在库里），它们完全可以
            # 在 mefrp 挂掉 / 没配 token 的时候照常探测、照常同步 DNS。
            # 原来这两处都是直接 `return`，于是 mefrp 一抖，用户自建的节点就
            # 跟着一起瞎掉：探测不更新、DNS 不解析，而页面上一点线索都没有。
            remote_ok = True
            if not s.get("mefrp_token"):
                self.last_error = "尚未配置 mefrp Token"
                # 用户组这时候也是「不知道」，把原因写清楚，
                # 免得 UI 上只有一个光秃秃的「未知」让人猜。
                self.user_group = ""
                self.user_group_friendly = ""
                self.user_group_error = "尚未配置 mefrp Token"
                remote_ok = False
            else:
                # 1. 拉全量状态
                try:
                    await self._refresh_remote()
                    self._note_mefrp_ok()
                except MefrpError as exc:
                    self.last_error = str(exc)
                    # 拉取失败了 → 用户组自然也拿不到，如实记下原因。
                    if not self.user_group:
                        self.user_group_error = str(exc)
                    self._note_mefrp_fail(str(exc))
                    remote_ok = False

            # 2. 逐隧道对账
            for tunnel in store.list_tunnels(enabled_only=True):
                # ⚠️ mefrp 侧不可用时**只**对账外部节点的隧道。反过来放行 mefrp
                #    隧道是危险的：proxy 列表是陈旧的，`_evaluate` 会拿旧数据判出
                #    假故障、一路涨 fail_streak、最后触发一次不该发生的切换。
                if not remote_ok and not self.tunnel_is_manual(tunnel):
                    continue
                try:
                    await self._reconcile(tunnel)
                except Exception as exc:  # noqa: BLE001
                    store.add_event(
                        "error", "system",
                        f"处理隧道「{tunnel['name']}」时异常：{exc}",
                        tunnel_id=tunnel["id"],
                    )

            store.prune_events()

    # -- 连续失败计时（mefrp 与 DNS 共用同一套口径，见 ALERT_AFTER_SECONDS）---

    def _note_mefrp_fail(self, msg: str) -> None:
        """记一次 mefrp 拉取失败。

        ⚠️ **不要**在这里按轮记 error。巡检 20 秒一轮，移动宽带抖两分钟就会自愈，
        按轮记 error 等于把事件日志刷满红字（实测三天 122 条），而里面没有一条
        是源站真挂了。现在的口径：刚开始失败只记**一条** warn 留痕，中间保持
        安静，连续满 `alert_after_seconds` 才升 error。
        """
        now = time.time()
        if self.mefrp_fail_since is None:
            self.mefrp_fail_since = now
            self.mefrp_alert_count = 0
            store.add_event(
                "warn", "system",
                f"拉取 mefrp 状态失败：{msg}"
                f"（连续失败满 {_fmt_span(alert_after_seconds())} 才告警；"
                "中途自愈不再记录）",
            )
            return
        down = now - self.mefrp_fail_since
        # 每再满一个阈值补一条 —— 断一整天也只有 48 条，不会漏报也不会刷屏。
        if down >= alert_after_seconds() * (self.mefrp_alert_count + 1):
            self.mefrp_alert_count += 1
            store.add_event(
                "error", "system",
                f"拉取 mefrp 状态已连续失败 {_fmt_span(down)}：{msg}",
            )

    def _note_mefrp_ok(self) -> None:
        """mefrp 这一轮成功了。清 `last_error`；真告过警的才记一条恢复事件。"""
        self.last_error = ""
        if self.mefrp_fail_since is None:
            return
        down = time.time() - self.mefrp_fail_since
        alerted = self.mefrp_alert_count
        self.mefrp_fail_since = None
        self.mefrp_alert_count = 0
        if alerted:
            store.add_event(
                "success", "system",
                f"mefrp 状态已恢复（此前连续失败 {_fmt_span(down)}）",
            )

    async def _refresh_remote(self) -> None:
        assert self.client is not None
        nodes = await self.client.node_list()
        self.nodes = {n.node_id: n for n in nodes}

        try:
            self.node_status = await self.client.node_status()
        except MefrpError:
            self.node_status = {}

        # 把状态里的负载/在线信息合并进 Node
        for nid, st in self.node_status.items():
            node = self.nodes.get(nid)
            if node is None:
                continue
            node.load_percent = int(st.get("loadPercent") or 0)
            node.online_proxy = int(st.get("onlineProxy") or 0)
            node.online_client = int(st.get("onlineClient") or 0)
            node.cur_conns = int(st.get("curConns") or 0)
            node.uptime = int(st.get("uptime") or node.uptime)
            if "isOnline" in st:
                node.is_online = bool(st.get("isOnline"))

        proxies, nodes_brief = await self.client.proxy_list()
        self.proxies = {p.proxy_name: p for p in proxies}
        self.proxy_by_id = {p.proxy_id: p for p in proxies}

        # ★ /auth/proxy/list 的 nodes 子数组带真实 hostname，而 /auth/node/list
        #   对非管理员是空的 —— 这里必须把它合并进去，否则「节点地址」永远拿不到。
        self._merge_node_addresses(nodes_brief)

        try:
            info = await self.client.user_info()
            self.user_group = info.group
            self.user_group_friendly = info.friendly_group
            self.user_group_error = ""
        except MefrpError as exc:
            self.user_group = ""
            self.user_group_friendly = ""
            self.user_group_error = str(exc)

    def _merge_node_addresses(self, brief_nodes: dict[int, dict]) -> None:
        """把 proxy_list 里带 hostname 的节点信息合并进 self.nodes 与缓存。"""
        for nid, brief in (brief_nodes or {}).items():
            host = str((brief or {}).get("hostname") or "").strip()
            if not host:
                continue
            self.node_hostname_cache[int(nid)] = host
            node = self.nodes.get(int(nid))
            if node is not None and not node.hostname:
                node.hostname = host

    def node_address_cached(self, node_id: int | None) -> str:
        """同步取节点地址（只用缓存，不发请求）。给 UI 渲染用。"""
        if not node_id:
            return ""
        nid = int(node_id)
        host = self.node_hostname_cache.get(nid)
        if host:
            return host
        node = self.nodes.get(nid)
        return (node.hostname if node else "") or ""

    async def node_address(self, node_id: int | None) -> str:
        """拿节点的公网地址，结果缓存。

        三级来源，按可靠性排序：
          1. /auth/proxy/list 的 nodes 子数组（_refresh_remote 已合并进缓存）
          2. /auth/node/list 的 hostname（管理员账号才有值）
          3. **该节点上任一隧道的官方配置里的 serverAddr** —— 非管理员唯一可行的一条路

        第 3 条为什么可行：`/auth/proxy/config` 返回的配置里 serverAddr 就是节点地址，
        实测与 proxy_list 里的 hostname 完全一致（同一个节点的两个接口给出同一个 IP）。

        节点上一个隧道都没有时返回空串 —— 这不是 bug，是 mefrp 对非管理员的限制，
        地址只有在那个节点上建了隧道之后才能拿到。
        """
        if not node_id:
            return ""
        nid = int(node_id)

        host = self.node_hostname_cache.get(nid)
        if host:
            return host

        node = self.nodes.get(nid)
        if node is not None and node.hostname:
            self.node_hostname_cache[nid] = node.hostname
            return node.hostname

        if self.client is None:
            return ""

        for proxy in self.proxy_by_id.values():
            if proxy.node_id != nid:
                continue
            try:
                cfg = await self.client.proxy_config(proxy.proxy_id, "toml")
            except MefrpError:
                continue
            addr = frpc.server_addr_of(cfg)
            if addr:
                self.node_hostname_cache[nid] = addr
                if node is not None:
                    node.hostname = addr
                return addr
        return ""

    # ------------------------------------------------------------------
    # 单隧道对账
    # ------------------------------------------------------------------

    async def _reconcile(self, tunnel: dict) -> None:
        assert self.client is not None
        tid = tunnel["id"]

        # 外部节点托管的隧道走完全独立的一条路：不碰 mefrp 的 proxy 列表，
        # 也永远不会自动切换。见 _reconcile_manual。
        if self.tunnel_is_manual(tunnel):
            await self._reconcile_manual(tunnel)
            return

        proxy = self.proxies.get(tunnel["proxy_name"])

        verdict = self._evaluate(tunnel, proxy)

        # 第三层：端到端探测（带缓存，避免每个 tick 都探）。
        # ⚠️ 探测方式由隧道类型决定，见 probe_plan：
        #   · TCP/UDP 隧道 —— 探节点地址 + 远程端口
        #   · HTTP/HTTPS 隧道 —— 探「绑定域名」（节点反代按 Host 头分流），
        #     而且 auto 模式下默认跳过（TCP 层探不出问题，见 probe_plan 注释）
        if verdict.ok and proxy is not None:
            host = await self.node_address(proxy.node_id)
            if not host:
                # 地址拿不到就不能说隧道是健康的 —— 探测这层直接失效了。
                verdict = Verdict(
                    False,
                    f"拿不到节点 {proxy.node_id} 的公网地址，无法做端到端探测",
                    "address",
                )
            else:
                # ★ domain 优先取 mefrp 上**实际**绑定的域名（proxy.domain），
                #   退回库里记的 current_domain —— 两者理论上一致，但 proxy 是
                #   权威来源（刚刚从 API 拉回来的）。
                ok, why = await self._probe_cached(
                    tid, host, proxy.remote_port or 0,
                    tunnel.get("proxy_type", "tcp"),
                    domain=str(proxy.domain or tunnel.get("current_domain") or ""),
                )
                # 只有明确的 False 才算故障；None 表示「不适用，已跳过」（udp 隧道）。
                if ok is False:
                    verdict = Verdict(False, why, "probe")

        if verdict.ok:
            if tunnel["fail_streak"]:
                store.update_tunnel(tid, {"fail_streak": 0, "last_error": ""})
            store.update_tunnel(tid, {"last_ok_at": int(time.time())})
            await self._sync_dns(tunnel, proxy)
            return

        # 失败路径
        streak = int(tunnel["fail_streak"]) + 1
        threshold = int(store.get_setting("fail_threshold", 3) or 3)
        store.update_tunnel(tid, {"fail_streak": streak, "last_error": verdict.reason})

        if streak == 1:
            store.add_event(
                "warn", "probe",
                f"隧道「{tunnel['name']}」异常：{verdict.reason}",
                tunnel_id=tid, detail=f"判定层：{verdict.layer}",
            )
            if store.get_setting("notify_on_probe_fail"):
                await self._notify(
                    f"隧道异常：{tunnel['name']}", verdict.reason, "warn"
                )

        if streak < threshold:
            return

        if not store.get_setting("auto_failover", True) or not tunnel["auto_failover"]:
            store.add_event(
                "error", "failover",
                f"隧道「{tunnel['name']}」连续 {streak} 次异常，但自动切换已关闭",
                tunnel_id=tid,
            )
            return

        if self.frpc_for_tunnel(tunnel) is None:
            # 未挂接 frpc 容器的隧道不能自动切换（换节点要改配置、重启容器）。
            # ⚠️ 只在「刚跨过阈值」那一次记事件 —— 否则 streak 会一直保持在高位，
            # 每个 tick 都记一条，20 秒一条很快把日志刷满，真正的问题反而被淹没。
            if streak == threshold:
                store.add_event(
                    "error", "failover",
                    f"隧道「{tunnel['name']}」连续 {streak} 次异常，但它还没有挂接 "
                    "frpc 容器，无法自动切换",
                    tunnel_id=tid,
                    detail="到「frpc 实例」页为它挂接一个 frpc 容器"
                           "（配置文件路径 + 容器名）。",
                )
            return

        await self._failover(tunnel, verdict.reason)

    async def _reconcile_manual(self, tunnel: dict) -> None:
        """外部节点上的隧道：**只探测、只报告，永不自动切换**。

        为什么不能自动切换：外部节点没有 API，在它上面建不了也删不了隧道。
        对 mefrp 节点来说「切换」= 删掉旧 proxy、在新节点建一个同名 proxy ——
        这套动作在外部节点上根本不存在。唯一能做的只有「改本地 frpc 配置里的
        serverAddr 再重启容器」，但换过去那台是不是活着、端口有没有被占、
        鉴权对不对，我们一概不知道。硬切很可能**把一条还能用的隧道弄成彻底
        不能用**，比不切糟得多。

        所以这里诚实地只报不修：涨 fail_streak、记事件、推通知，把决定权交回人。
        ⚠️ 注意这是**实例级**的活儿，不是隧道级的：换外部节点要改写承载它的那个
        frpc 实例的配置文件（一个 frpc 进程只能连一个 serverAddr），所以入口在
        「frpc」页的「改连外部节点」，以及隧道卡片上的「更新节点配置」。
        """
        tid = int(tunnel["id"])
        node = self.manual_node_for(tunnel)
        if node is None:
            # 指向一个已经被删掉的外部节点。既不能当健康，也不能自动切 ——
            # 如实报错，让用户看见。
            store.update_tunnel(tid, {"last_error": "挂接的外部节点已不存在"})
            return

        if not node.get("enabled"):
            store.update_tunnel(
                tid, {"last_error": f"外部节点「{node['name']}」已停用"})
            return

        host = str(node["server_addr"] or "").strip()
        ptype = tunnel.get("proxy_type", "tcp")
        # ★ HTTP/HTTPS 隧道没有远程端口（mefrp 侧 remotePort 恒为 null），
        #   探测靠绑定域名。所以「没有远程端口」这条报错只对 port 组成立。
        if is_http_type(ptype):
            if not parse_domains(tunnel.get("current_domain") or ""):
                store.update_tunnel(tid, {
                    "last_error": "这条 HTTP 隧道没有绑定域名，无法探测"
                                  "（导入配置时该段没写 domain）"})
                return
            port = 0
        else:
            port = int(tunnel.get("current_remote_port") or 0)
            if not port:
                store.update_tunnel(tid, {
                    "last_error": "这条隧道没有远程端口，无法探测"
                                  "（导入配置时该段没写 remotePort）"})
                return

        ok, why = await self._probe_cached(
            tid, host, port, ptype,
            domain=str(tunnel.get("current_domain") or ""),
        )

        if ok is True:
            if tunnel["fail_streak"]:
                store.update_tunnel(tid, {"fail_streak": 0, "last_error": ""})
            store.update_tunnel(tid, {"last_ok_at": int(time.time())})
            # 外部节点没有 Proxy 对象，地址直接就是节点的 serverAddr。
            await self._sync_dns(tunnel, None, host=host)
            return

        if ok is None:
            # 协议不适用探测（udp）。外部节点上我们**没有**第二层判据可用
            # —— mefrp 那套「proxy 是否在线」是 API 给的，这里没有。
            # 所以只能如实说「没探」：**既不算失败，也不算健康**。
            #   · 不能涨 fail_streak（那会把健康隧道判成故障）；
            #   · 不能写 last_error —— 前端把它画成红色「异常」，而这里只是
            #     「探不了」。原因已经进了 probe_cache，页面上以 ⓘ 提示显示。
            #   · **但 DNS 必须照常同步**：地址对不对，跟能不能用 TCP 去探它
            #     没有任何关系。原来这里直接 return，于是 udp 的外部隧道
            #     **永远同步不了 DNS** —— 而 udp 恰恰是外部节点上最常见的一类。
            #     顺带把老代码留下的那条「无法探测」清掉（它现在是红色的）。
            if tunnel["fail_streak"] or (tunnel.get("last_error") or ""):
                store.update_tunnel(tid, {"fail_streak": 0, "last_error": ""})
            await self._sync_dns(tunnel, None, host=host)
            return

        streak = int(tunnel["fail_streak"]) + 1
        threshold = int(store.get_setting("fail_threshold", 3) or 3)
        store.update_tunnel(tid, {"fail_streak": streak, "last_error": why})

        if streak == 1:
            store.add_event(
                "warn", "probe",
                f"隧道「{tunnel['name']}」异常（外部节点「{node['name']}」）：{why}",
                tunnel_id=tid, detail=f"探测目标：{host}:{port}",
            )
            if store.get_setting("notify_on_probe_fail"):
                await self._notify(f"隧道异常：{tunnel['name']}", why, "warn")

        if streak == threshold:
            # ⚠️ 只在刚跨过阈值那一次记 —— 否则 streak 会一直保持在高位，
            #    每 20 秒一条，很快把日志刷满，真正的问题反而被淹没。
            store.add_event(
                "error", "failover",
                f"隧道「{tunnel['name']}」连续 {streak} 次异常，"
                f"但它由外部节点「{node['name']}」托管，不会自动切换",
                tunnel_id=tid,
                detail="外部节点没有 API，无法在服务端建/删隧道。"
                       "换节点是**实例级**动作：去「frpc」页把承载这条隧道的那个实例"
                       "改连到别的节点（或点隧道卡片上的「更新节点配置」重新粘一份配置）。",
            )
            await self._notify(
                f"⚠️ 隧道异常（需人工处理）：{tunnel['name']}",
                f"外部节点：{node['name']}（{host}:{port}）\n"
                f"原因：{why}\n\n外部节点不支持自动切换，请手动处理。",
                "error",
            )

    def _evaluate(self, tunnel: dict, proxy: Proxy | None) -> Verdict:
        if proxy is None:
            return Verdict(False, "隧道在 mefrp 上不存在（可能已被删除）", "proxy")
        if proxy.is_banned:
            return Verdict(False, "隧道被封禁", "proxy")
        if proxy.is_disabled:
            return Verdict(False, "隧道被手动禁用", "proxy")
        if not proxy.is_online:
            return Verdict(False, "隧道离线（frpc 未连上）", "proxy")

        node = self.nodes.get(proxy.node_id)
        if node is None:
            return Verdict(False, f"节点 {proxy.node_id} 已不在节点列表中", "node")
        if node.is_disabled:
            return Verdict(False, f"节点「{node.name}」被禁用", "node")
        if not node.is_online:
            return Verdict(False, f"节点「{node.name}」离线", "node")

        st = self.node_status.get(proxy.node_id) or {}
        if st and st.get("isOnline") is False:
            return Verdict(False, f"节点「{node.name}」状态接口报告离线", "node")

        return Verdict(True)

    async def _probe_cached(self, tunnel_id: int, host: str, port: int,
                            proxy_type: str = "tcp",
                            domain: str = "") -> tuple[bool | None, str]:
        """端到端探测（带缓存）。返回 (是否可达, 说明)。

        ⚠️ 第一个返回值是**三态**，调用方必须区分开，否则会误伤：

          True  —— 探测通过
          False —— 探测失败（真故障）
          None  —— **不适用，已跳过**（比如 udp 隧道，或者 auto 模式下的 http
                   隧道）。这不是失败，绝不能拿它去涨 fail_streak，
                   否则健康隧道会被反复切换。

        `host`/`port` 给 TCP 探测用；`domain` 给 HTTP 探测用 —— 两者不可能同时
        需要（`probe_plan` 已经按隧道类型分好流了）。
        """
        mode = str(store.get_setting("probe_mode", "auto") or "auto")
        kind, skip_why = probe_plan(proxy_type, mode)
        if kind == PROBE_NONE:
            self.probe_cache[tunnel_id] = (time.time(), None, skip_why)
            return None, skip_why

        interval = float(store.get_setting("probe_interval", 60) or 60)
        timeout = float(store.get_setting("probe_timeout", 4) or 4)
        now = time.time()
        cached = self.probe_cache.get(tunnel_id)
        if cached and now - cached[0] < interval:
            return cached[1], cached[2]

        if kind == PROBE_HTTP:
            url = http_probe_url(proxy_type, domain,
                                 str(store.get_setting("http_probe_path", "/") or "/"))
            if not url:
                why = "这条 HTTP 隧道没有绑定域名，无法做 HTTP 探测"
                self.probe_cache[tunnel_id] = (now, None, why)
                return None, why
            # HTTP 比 TCP 多一次 TLS 握手 + 一个来回，超时给宽一点，
            # 但至少 6 秒 —— 用 probe_timeout 那种 4 秒在海外节点上容易误判。
            ok, why = await http_probe(url, max(timeout, 6.0))
        else:
            ok, why = await tcp_probe(host, port, timeout)

        self.probe_cache[tunnel_id] = (now, ok, why)
        return ok, why

    # ------------------------------------------------------------------
    # 节点择优
    # ------------------------------------------------------------------

    def pick_node(self, *, exclude: set[int] | None = None,
                  proxy_type: str = "tcp",
                  prefer_node_id: int | None = None,
                  soft_prefer: bool = False) -> tuple[Node | None, str]:
        """按「用户组权限 → 硬门槛 → 排序」挑一个节点。返回 (节点, 说明)。

        门槛分两类，这个区分很关键：

        * **硬约束** —— 离线 / 被禁用 / 用户组无权限 / 隧道类型不支持。
          这些是客观事实，无论自动还是手动都不能突破。
        * **软偏好** —— 区域 / 带宽下限 / 负载上限 / 排除名单 / 冷却期。
          这些只是「自动择优」时的筛选条件。

        prefer_node_id 有两种语义：
          * soft_prefer=False（用户手动指定）—— **只受硬约束限制**。因为
            「没有满足阈值的节点时让用户手动选」这条兜底路径，如果还被阈值拦着
            就永远走不通。硬约束不过则直接失败，并把原因回给调用方。
          * soft_prefer=True（隧道里配的「锁定节点」）—— 硬约束不过就静默退回
            自动择优（由调用方决定要不要记事件）。

        ★ **软偏好按隧道类型分组**：tcp/udp 用 `allow_regions` / `min_bandwidth_mbps`
        / `max_load_percent` / `prefer_keywords` 那一套；http/https 用 `http_*`
        那一套（见 settings.PREF_KEYS）。两类的约束来源不同 —— 最典型的是
        http 受「备案」限制，默认就排除了大陆节点 —— 所以不能共用一份阈值。
        分组只发生在**取键名**这一步，下面的筛选逻辑一份都不用改。
        """
        exclude = set(exclude or set())
        kind = kind_of(proxy_type)
        now = time.time()
        s = store.get_settings()
        min_bw = float(s.get(pref_key(kind, "min_bandwidth"), 25) or 0)
        max_load = int(s.get(pref_key(kind, "max_load"), 90) or 100)
        regions = {r.strip().lower() for r in
                   str(s.get(pref_key(kind, "regions")) or "").split(",") if r.strip()}
        keywords = normalize_keywords(s.get(pref_key(kind, "keywords")))
        prefs = store.list_node_prefs()

        stats = {"total": len(self.nodes), "offline": 0, "disabled": 0,
                 "group": 0, "bandwidth": 0, "load": 0, "excluded": 0,
                 "cooldown": 0, "region": 0}
        hard = {"offline": 0, "disabled": 0, "group": 0}
        candidates: list[tuple[tuple, Node]] = []

        for node in self.nodes.values():
            # ---- 硬约束：自动与手动都必须满足 ----
            if not node.is_online:
                stats["offline"] += 1
                hard["offline"] += 1
                continue
            if node.is_disabled:
                stats["disabled"] += 1
                hard["disabled"] += 1
                continue
            if not node.allows_group(self.user_group):
                stats["group"] += 1
                hard["group"] += 1
                continue
            if not node.allows_type(proxy_type):
                stats["group"] += 1
                hard["group"] += 1
                continue

            # ---- 手动指定：过了硬约束就直接用，不受下面任何软偏好限制 ----
            if prefer_node_id is not None and node.node_id == prefer_node_id:
                return node, ""

            # ---- 软偏好：只用来筛「自动择优」的候选 ----
            if regions and (node.region or "").lower() not in regions:
                stats["region"] += 1
                continue
            pref = prefs.get(node.node_id)
            if pref and pref.get("excluded"):
                stats["excluded"] += 1
                continue
            if min_bw and node.bandwidth_mbps < min_bw:
                stats["bandwidth"] += 1
                continue
            if node.load_percent > max_load:
                stats["load"] += 1
                continue
            if node.node_id in exclude:
                stats["excluded"] += 1
                continue
            # ⚠️ 冷却期按 (隧道类型组, 节点) 记，**不是只按节点**：
            #    同一个节点对 tcp 掉链子，不代表它的 HTTP 反代也不行；反过来
            #    也一样。共用一个冷却表会让「刚被 TCP 切走的节点」连带被 HTTP
            #    隧道躲开，而两条隧道的 `node_cooldown` 时长本来就配得不一样。
            if self.node_cooldown.get((kind, node.node_id), 0) > now:
                stats["cooldown"] += 1
                continue

            pref_priority = int(pref["priority"]) if pref else 100

            sort_key = (
                keyword_rank(node, keywords),  # 节点偏好顺位：越靠前的关键词越优先
                pref_priority,                 # 手工优先级
                -node.bandwidth_mbps,          # 带宽大的优先
                node.load_percent,             # 负载低的优先
                node.node_id,
            )
            candidates.append((sort_key, node))

        if prefer_node_id is not None and not soft_prefer:
            return None, (f"指定的节点 {prefer_node_id} 不可用："
                          f"{self._explain_hard(hard)}")

        if not candidates:
            return None, self._explain_no_candidate(stats, min_bw, max_load)

        candidates.sort(key=lambda x: x[0])
        return candidates[0][1], ""

    @staticmethod
    def _explain_hard(hard: dict) -> str:
        parts = []
        if hard["offline"]:
            parts.append("节点离线")
        if hard["disabled"]:
            parts.append("节点被禁用")
        if hard["group"]:
            parts.append("当前用户组无权限或节点不支持该隧道类型")
        return "、".join(parts) if parts else "节点不在列表中"

    @staticmethod
    def _explain_no_candidate(stats: dict, min_bw: float, max_load: int) -> str:
        parts = []
        if stats["offline"]:
            parts.append(f"{stats['offline']} 个离线")
        if stats["disabled"]:
            parts.append(f"{stats['disabled']} 个被禁用")
        if stats["group"]:
            parts.append(f"{stats['group']} 个当前用户组无权限")
        if stats["region"]:
            parts.append(f"{stats['region']} 个区域不符")
        if stats["excluded"]:
            parts.append(f"{stats['excluded']} 个被排除")
        if stats["cooldown"]:
            parts.append(f"{stats['cooldown']} 个在冷却期")
        if stats["bandwidth"]:
            parts.append(f"{stats['bandwidth']} 个带宽低于 {min_bw:g}Mbps")
        if stats["load"]:
            parts.append(f"{stats['load']} 个负载高于 {max_load}%")
        detail = "；".join(parts) if parts else "节点列表为空"
        return f"没有满足条件的节点（共 {stats['total']} 个：{detail}）"

    def rank_nodes(self, proxy_type: str = "tcp") -> list[dict]:
        """给 UI 用的节点排名表。

        每个节点会带两组标记：
          * blockers   —— 硬约束不满足，手动也不能选（离线 / 禁用 / 无权限 / 类型不符）
          * warnings   —— 软偏好不满足，**手动可以覆盖**（带宽 / 负载 / 区域 / 排除 / 冷却）
          * selectable —— 没有 blockers，页面上允许手动指定
          * eligible   —— 两组都空，自动择优会用它

        ★ 软偏好按隧道类型分组（同 `pick_node`）—— 传 `proxy_type="http"` 拿到的
        就是「按 HTTP 那套偏好算出来的」排名，页面上的节点表要跟着隧道类型切。
        """
        kind = kind_of(proxy_type)
        s = store.get_settings()
        min_bw = float(s.get(pref_key(kind, "min_bandwidth"), 25) or 0)
        max_load = int(s.get(pref_key(kind, "max_load"), 90) or 100)
        regions = {r.strip().lower() for r in
                   str(s.get(pref_key(kind, "regions")) or "").split(",") if r.strip()}
        keywords = normalize_keywords(s.get(pref_key(kind, "keywords")))
        prefs = store.list_node_prefs()
        now = time.time()

        rows = []
        for node in self.nodes.values():
            pref = prefs.get(node.node_id)
            rank = keyword_rank(node, keywords)
            blockers: list[str] = []
            warnings: list[str] = []

            if not node.is_online:
                blockers.append("离线")
            if node.is_disabled:
                blockers.append("已禁用")
            if not node.allows_group(self.user_group):
                blockers.append(f"无权限（限 {node.allow_group}）")
            if not node.allows_type(proxy_type):
                blockers.append(f"不支持 {proxy_type.upper()}")

            if min_bw and node.bandwidth_mbps < min_bw:
                warnings.append(f"带宽 < {min_bw:g}Mbps")
            if node.load_percent > max_load:
                warnings.append(f"负载 > {max_load}%")
            if regions and (node.region or "").lower() not in regions:
                warnings.append(f"区域 {node.region or '未知'} 不在允许列表")
            # ★ 备案提醒：只对 http 组、且只在大陆节点上出现。**是 warning 不是
            #   blocker** —— 手动锁一个大陆节点是完全合法的选择（域名已经报备过），
            #   引擎不该替用户否决它，只该把代价说清楚。
            if kind == "http" and (node.region or "").lower() == "cn":
                warnings.append("大陆节点建 HTTP/S 站需先向管理员报备域名")
            if pref and pref.get("excluded"):
                warnings.append("已排除")
            cd = self.node_cooldown.get((kind, node.node_id), 0)
            if cd > now:
                warnings.append(f"冷却 {int(cd - now)}s")

            rows.append({
                "node_id": node.node_id,
                "name": node.name,
                # 非管理员账号下 node.hostname 恒为空，真实地址在缓存里（见 node_address）
                "hostname": self.node_address_cached(node.node_id),
                "address_known": bool(self.node_address_cached(node.node_id)),
                "region": node.region,
                "bandwidth": node.bandwidth,
                "bandwidth_mbps": node.bandwidth_mbps,
                "is_online": node.is_online,
                "is_disabled": node.is_disabled,
                "load_percent": node.load_percent,
                "online_proxy": node.online_proxy,
                "allow_group": node.allow_group,
                "allow_type": node.allow_type,
                "allow_port": node.allow_port,
                "description": node.description,
                # 节点偏好顺位：0 = 命中第一个关键词（最优先）；
                # 未命中任何关键词 = len(keywords)，排在所有命中项之后，但**仍可被选中**
                # —— 偏好是排序不是筛选。
                "keyword_rank": rank,
                "keyword_hit": rank < len(keywords),
                "priority": int(pref["priority"]) if pref else 100,
                "excluded": bool(pref and pref.get("excluded")),
                # 这个节点对外提供 HTTP(S) 的入口地址（域名或 IP），http 隧道用它
                # 做 DNS 目标；留空则退回「A 记录指向节点 IP」。见 store.node_prefs。
                "http_entry": (pref or {}).get("http_entry", "") or "",
                "blockers": blockers,
                "warnings": warnings,
                "selectable": not blockers,
                "eligible": not blockers and not warnings,
                "reasons": blockers + warnings,   # 兼容旧前端
            })

        rows.sort(key=lambda r: (
            0 if r["eligible"] else (1 if r["selectable"] else 2),
            r["keyword_rank"],
            r["priority"],
            -r["bandwidth_mbps"],
            r["load_percent"],
        ))
        return rows

    def preview_pref(self, keywords: str | list[str] | None) -> dict:
        """按给定的偏好顺序试算一遍，给设置页做即时预览。

        **只读** —— 用户在编辑偏好时不能顺手把库改了，所以这里不落任何设置，
        纯粹拿传入的顺序去算「每个关键词各自命中哪些节点、谁都没命中」。

        匹配用的是 `keyword_rank`，和真正择优时同一份逻辑 ——
        预览跟实际行为不会跑偏。
        """
        kws = normalize_keywords(keywords)
        groups = [{"keyword": k, "nodes": []} for k in kws]
        unmatched: list[str] = []
        for node in sorted(self.nodes.values(), key=lambda n: n.node_id):
            r = keyword_rank(node, kws)
            if r < len(kws):
                groups[r]["nodes"].append(node.label)
            else:
                unmatched.append(node.label)
        return {"ok": True, "keywords": kws, "groups": groups,
                "unmatched": unmatched, "total": len(self.nodes)}

    # ------------------------------------------------------------------
    # 故障转移
    # ------------------------------------------------------------------

    async def _failover(self, tunnel: dict, reason: str,
                        prefer_node_id: int | None = None,
                        ignore_cooldown: bool = False) -> dict:
        """执行一次故障转移。

        ⚠️ 前提：这条隧道**已经挂接了一个 frpc 容器**。没挂接就直接拒绝 ——
        换节点要改本地配置并重启容器，没有归属就无从下手（见下面的守卫）。

        模型是「一条隧道 : 一个 frpc 容器」，所以正常情况下这里只搬一条。
        但切换仍然按 `frpc_group` 的**整组**语义走：一个 frpc 进程只能连一个
        serverAddr（= 一个 mefrp 节点），所以同一个容器承载的所有隧道必然在同一
        个节点上。只把其中一条搬到新节点，合并配置时就会因为 serverAddr 不一致
        直接报错 —— 结果一条都写不进去，触发切换的那条反而彻底断了。成组是
        为「万一有人把多条挂到同一个容器」准备的安全网。

        返回 dict，**每一步失败都要如实回传** —— 手动切换的接口直接把结果给前端，
        如果这里静默 return，页面就会骗用户说「已触发切换」而实际什么都没做。
        """
        tid = int(tunnel["id"])

        # 外部节点托管的隧道**永不自动切换**（原因见 _reconcile_manual）。
        # 这是道防御性闸门：_reconcile_manual 压根不会调到这里，但 force_failover
        # 等其它入口可能误入。必须在这里挡住，而不是让它往下走去调 mefrp 的
        # 建/删接口 —— 那些接口操作的是「mefrp 账号里的 proxy」，而这条隧道
        # 在 mefrp 上根本不存在。
        if self.tunnel_is_manual(tunnel):
            node = self.manual_node_for(tunnel)
            name = node["name"] if node else "已删除的外部节点"
            store.add_event(
                "error", "failover",
                f"隧道「{tunnel['name']}」需要切换，但它由外部节点「{name}」托管，"
                "外部节点不支持自动切换",
                tunnel_id=tid,
            )
            return {"ok": False,
                    "error": f"这条隧道由外部节点「{name}」托管，只能手动切换"
                             "（点隧道卡片上的「切换节点」）"}

        assert self.client is not None
        now = time.time()
        cooldown = float(store.get_setting("failover_cooldown", 300) or 300)

        if not ignore_cooldown and \
                now - float(tunnel["last_failover_at"] or 0) < cooldown:
            left = int(cooldown - (now - float(tunnel["last_failover_at"] or 0)))
            store.add_event(
                "warn", "failover",
                f"隧道「{tunnel['name']}」需要切换，但仍在冷却期（{left}s）",
                tunnel_id=tid,
            )
            return {"ok": False, "error": f"仍在冷却期，还需等待 {left} 秒"}

        # 没有挂接 frpc 容器 → 拒绝切换。
        # 换节点要改本地 frpc 配置、重启它的容器，没有归属就无从下手。如果在这里
        # 硬搬 mefrp 上的 proxy，结果是「proxy 换了节点、本地却没人接」—— 比不切换
        # 更糟，因为用户会以为自愈成功了。所以如实拒绝，让他去挂接。
        instance = self.frpc_for_tunnel(tunnel)
        if instance is None:
            store.add_event(
                "error", "failover",
                f"隧道「{tunnel['name']}」需要切换，但它还没有挂接 frpc 容器，无法切换",
                tunnel_id=tid,
                detail="到「frpc 实例」页为它挂接一个 frpc 容器（配置文件路径 + 容器名）。",
            )
            return {"ok": False,
                    "error": "这条隧道还没有挂接 frpc 容器，无法切换 —— "
                             "请先到「frpc 实例」页为它挂接一个容器"}

        # 解析要一起搬走的整组隧道。正常模型（一隧道一容器）下就是它自己，
        # 见 frpc_group 里关于「安全网」的说明。
        group = self.frpc_group(tunnel, instance)
        others = [t for t in group if int(t["id"]) != tid]

        # 组内其它隧道刚被切过 → 这个实例刚动过，不能再来一次。
        # （同一次 tick 里第一条切换会把整组的 last_failover_at 都写掉，
        #   后面几条到这里就被拦住，不会重复切换。）
        if not ignore_cooldown and others:
            recent = [t for t in others
                      if now - float(t["last_failover_at"] or 0) < cooldown]
            if recent:
                left = int(cooldown - (now - float(recent[0]["last_failover_at"] or 0)))
                store.add_event(
                    "warn", "failover",
                    f"隧道「{tunnel['name']}」需要切换，但它所属的 frpc 实例"
                    f"刚切换过，仍在冷却期（{left}s）",
                    tunnel_id=tid,
                )
                return {"ok": False,
                        "error": f"所属 frpc 实例仍在冷却期，还需等待 {left} 秒"}

        group_note = (f"（连带同实例的另外 {len(others)} 条隧道一起切换）"
                      if others else "")
        store.add_event(
            "warn", "failover",
            f"隧道「{tunnel['name']}」开始故障转移，原因：{reason}{group_note}",
            tunnel_id=tid,
        )

        old_node_id = tunnel["current_node_id"]
        old_port = tunnel["current_remote_port"]
        exclude = {n for n in [old_node_id] if n}

        # 「锁定节点」是软偏好：可用就优先用它。但如果它正是我们要逃离的节点，
        # 或者它当前不可用，就退回自动择优 —— 否则锁死一个坏节点会陷入死循环。
        pin_id = int(tunnel["pin_node_id"]) if tunnel.get("pin_node_id") else None
        soft = False
        if prefer_node_id is None and pin_id and pin_id not in exclude:
            prefer_node_id, soft = pin_id, True

        node, why = self.pick_node(exclude=exclude, proxy_type=tunnel["proxy_type"],
                                   prefer_node_id=prefer_node_id, soft_prefer=soft)
        if node is None and soft:
            store.add_event("warn", "failover",
                            f"锁定节点 {pin_id} 当前不可用，改为自动择优", tunnel_id=tid)
            node, why = self.pick_node(exclude=exclude,
                                       proxy_type=tunnel["proxy_type"])
        if node is None:
            # 注意：切换失败时**不要**置 needs_downstream_review。
            # 那个标志在页面上对应「远程端口变过，去改下游」，而这里什么都没变，
            # 置了就是误报。失败原因走 last_error + 事件 + Gotify 三条路。
            store.update_tunnel(tid, {"last_error": why})
            store.add_event("error", "failover",
                            f"隧道「{tunnel['name']}」切换失败：{why}", tunnel_id=tid)
            await self._notify(
                f"⚠️ 隧道切换失败：{tunnel['name']}",
                f"{why}\n\n请到 mefrp-guard 页面手动指定节点。",
                "error",
            )
            return {"ok": False, "error": why}

        # ---- 整组搬到新节点 ----
        # 逐条「先删旧、再建新」—— 同名 proxy 不能共存，必须先腾位（见 _move_tunnel）。
        moved: list[dict] = []
        failed: list[dict] = []
        for t in group:
            r = await self._move_tunnel(t, node)
            (moved if r.get("ok") else failed).append(r)

        if failed:
            # ⚠️ 只要有一条没搬成功就**整体回滚**。
            # 半搬半不搬会让同一个 frpc 的隧道分散在两个节点上，配置文件根本没法
            # 合并（一个 frpc 只能连一个节点）—— 那比「这次切换失败」更糟：
            # 会把一个本来还能跑的状态变成彻底不能跑。
            #
            # ⚠️ 回滚是**把隧道建回原节点**，不再是「删掉新建的就完事」：
            # 「先删后建」已经把旧 proxy 删了，光删新的等于一条都不剩。
            old_node = self.nodes.get(int(old_node_id)) if old_node_id else None
            rollback_errs: list[str] = []
            for r in moved + failed:
                t = r["tunnel"]
                mtid = int(t["id"])
                if old_node is None:
                    rollback_errs.append(
                        f"{t['name']}：原节点 #{old_node_id} 已不在节点列表里，无法建回")
                    continue
                # moved 的隧道此刻挂着的是它新建出来的那个 proxy；failed 的还挂着
                # 原 id（可能已被删掉，那删除会失败并被忽略，不影响后续创建）。
                cur_pid = r.get("new_proxy_id") if r.get("ok") else None
                back = await self._move_tunnel(
                    t, old_node,
                    current_proxy_id=(cur_pid if cur_pid is not None
                                      else t["current_proxy_id"]),
                )
                if not back.get("ok"):
                    rollback_errs.append(f"{t['name']}：{back.get('error')}")
                    continue
                # 回滚也是在原节点**重新建了一个 proxy**，id 和端口都可能变 ——
                # 不写回数据库的话，库里存的还是那个已经被删掉的旧 id，
                # 下一轮 _reconcile 就会拿一个不存在的 proxyId 去比对。
                back_upd: dict[str, Any] = {
                    "current_proxy_id": back["new_proxy_id"],
                    "current_node_id": old_node.node_id,
                    "current_remote_port": back["new_port"],
                }
                if is_http_type(t.get("proxy_type")):
                    back_upd["current_domain"] = back.get("new_domain") or ""
                store.update_tunnel(mtid, back_upd)
                self.probe_cache.pop(mtid, None)

            bad = failed[0]
            err = bad.get("error") or "创建失败"
            if rollback_errs:
                store.add_event(
                    "error", "failover",
                    f"隧道「{bad['tunnel']['name']}」在新节点创建失败，"
                    f"且回滚未完全成功：{'；'.join(rollback_errs)}",
                    tunnel_id=int(bad["tunnel"]["id"]),
                )
                await self._notify(
                    f"⚠️ 隧道切换失败：{tunnel['name']}",
                    f"节点：{node.name}\n原因：{err}\n\n"
                    "⚠️ 回滚未完全成功，以下隧道需要人工检查：\n"
                    + "\n".join(f"  · {e}" for e in rollback_errs),
                    "error",
                )
                return {"ok": False,
                        "error": f"在节点「{node.name}」创建隧道失败：{err}"
                                 "（回滚未完全成功，请人工检查）"}
            store.add_event(
                "error", "failover",
                f"隧道「{bad['tunnel']['name']}」在新节点创建失败，"
                f"本次切换已回滚：{err}",
                tunnel_id=int(bad["tunnel"]["id"]),
            )
            await self._notify(
                f"⚠️ 隧道切换失败：{tunnel['name']}",
                f"节点：{node.name}\n原因：{err}\n"
                f"（本次共 {len(group)} 条隧道要一起切换，已全部建回原节点）",
                "error",
            )
            return {"ok": False,
                    "error": f"在节点「{node.name}」创建隧道失败：{err}"}

        # ---- 落库 ----
        # ⚠️ 旧隧道**已经在 _move_tunnel 里删掉了**（先删后建，见那里的说明）。
        # 这里不能再删一次 —— 那会打第二个 delete 请求，而那个 proxy 早就不在了，
        # 白白记一条「删除失败」的警告，让用户以为哪里出了问题。
        for r in moved:
            t = r["tunnel"]
            mtid = int(t["id"])
            upd = {
                "current_proxy_id": r["new_proxy_id"],
                "current_node_id": node.node_id,
                "current_remote_port": r["new_port"],
                "last_failover_at": int(now),
                "fail_streak": 0,
            }
            # ★ HTTP 隧道要落的是域名（端口对它是空的，落进去只会把旧值覆盖成 0）
            if is_http_type(t.get("proxy_type")):
                upd["current_domain"] = r.get("new_domain") or ""
            store.update_tunnel(mtid, upd)
            self.probe_cache.pop(mtid, None)

        # 冷却按 (隧道类型组, 节点) 记 —— 见 node_cooldown 字段的注释。
        ckind = kind_of(tunnel.get("proxy_type", "tcp"))
        self.node_cooldown[(ckind, node.node_id)] = now + float(
            store.get_setting(pref_key(ckind, "node_cooldown"), 1800) or 1800
        )

        # ---- 重建配置 + 重启（整组只做一次）----
        rr = await self._rebuild_and_restart(store.get_tunnel(tid) or tunnel)
        restart_ok = bool(rr.get("restart_ok"))

        # ---- 等触发的那条隧道上线，再做端到端验证 ----
        online = await self._await_online(tunnel["proxy_name"], timeout=45)
        node_addr = await self.node_address(node.node_id)
        cur_t = store.get_tunnel(tid) or tunnel
        new_port = cur_t["current_remote_port"]
        new_domain = str(cur_t.get("current_domain") or "")
        http_like = is_http_type(tunnel.get("proxy_type"))

        # 三态探测：True 通过 / False 未通过 / None 不适用（udp 隧道等）。
        # 这里必须和 _reconcile 用同一套判定，否则会出现「引擎认为健康、
        # 但切换后立刻报 error」的自相矛盾。
        #
        # ⚠️ probe_plan 的返回值在 1.0.2 从 (bool, why) 改成了 (种类, why)，
        #    调用方必须按种类分三条路走（tcp / http / none），不能再写 `if not do_probe`。
        mode = str(store.get_setting("probe_mode", "auto") or "auto")
        pkind, skip_why = probe_plan(tunnel.get("proxy_type", "tcp"), mode)
        probe_ok: bool | None = False
        probe_why = "未验证"
        if pkind == PROBE_NONE:
            probe_ok, probe_why = None, skip_why
        elif not online:
            probe_why = "隧道尚未上线，跳过端到端验证"
        elif pkind == PROBE_HTTP:
            url = http_probe_url(tunnel.get("proxy_type", "tcp"), new_domain,
                                 str(store.get_setting("http_probe_path", "/") or "/"))
            if not url:
                probe_ok, probe_why = None, "这条 HTTP 隧道没有绑定域名，无法做 HTTP 探测"
            else:
                probe_ok, probe_why = await http_probe(url)
        elif not node_addr:
            probe_why = f"拿不到节点「{node.name}」的公网地址，无法验证"
        else:
            probe_ok, probe_why = await tcp_probe(
                node_addr, new_port,
                float(store.get_setting("probe_timeout", 4) or 4),
            )

        # 更新 DNS：探测通过、或该协议本就不适用探测（None）时都该同步。
        # 只有明确的 False 才代表「地址真的不对」，那才不该写 DNS。
        # ⚠️ 要同步**整组**：它们的地址跟着节点一起变了，只改触发的那条会让其余
        #    几条的 DNS 悄悄指向旧节点，变成「配置看着正常但访问打不开」。
        dns_msgs: list[str] = []
        if online and probe_ok is not False:
            for r in moved:
                mtid = int(r["tunnel"]["id"])
                cur = store.get_tunnel(mtid) or r["tunnel"]
                try:
                    msg = await self._sync_dns(cur, r["proxy"], force=True)
                except Exception as exc:  # noqa: BLE001 - 单条 DNS 失败不能拖垮整轮
                    msg = f"更新 DNS 异常：{exc}"
                    store.add_event("error", "dns", msg, tunnel_id=mtid)
                if msg:
                    dns_msgs.append(msg if len(moved) == 1
                                    else f"{cur['name']}：{msg}")

        # 端口变了 → 标记下游待办（整组都要判，各条端口可能都变了）。
        # ⚠️ HTTP 隧道**没有端口**，这个待办对它不适用：它的对外入口是域名，
        #    域名不变（本来就是沿用同一个），下游 DNS 不用动。所以 http 组
        #    直接清 0，避免给用户一个「去改下游」的假待办。
        changed_names: list[str] = []
        for r in moved:
            mtid = int(r["tunnel"]["id"])
            if is_http_type(r["tunnel"].get("proxy_type")):
                store.update_tunnel(mtid, {"needs_downstream_review": 0})
                continue
            pc = bool(r["old_port"]) and int(r["old_port"]) != int(r["new_port"])
            store.update_tunnel(mtid, {"needs_downstream_review": 1 if pc else 0})
            if pc:
                changed_names.append(
                    f"{r['tunnel']['name']}（{r['old_port']} → {r['new_port']}）")

        port_changed = bool(old_port) and int(old_port) != int(new_port)

        if probe_ok is None:
            probe_line = f"不适用 —— {probe_why}"
        elif probe_ok:
            probe_line = "通过"
        else:
            probe_line = f"未通过 —— {probe_why}"

        # 对外入口那一行：HTTP 隧道写域名，TCP/UDP 写端口。
        if http_like:
            entry_line = f"绑定域名：{new_domain or '（未指定）'}"
        else:
            entry_line = f"端口：{old_port or '—'} → {new_port}"

        lines = [
            f"隧道：{tunnel['name']}",
            f"原因：{reason}",
            f"新节点：{node.name}（{node_addr or '地址未知'}）",
            entry_line,
        ]
        if len(moved) > 1:
            lines.append(f"连带切换：同实例另外 {len(moved) - 1} 条隧道一起搬走")
        lines += [
            f"frpc 实例：{rr.get('instance') or '未绑定'}",
            f"frpc 重启：{'成功' if restart_ok else '失败，请检查'}"
            + (f"（{rr['note']}）" if rr.get("note") else ""),
            f"隧道上线：{'是' if online else '否'}",
            f"端到端探测：{probe_line}",
        ]
        if dns_msgs:
            lines.append("DNS：" + "；".join(dns_msgs))
        if changed_names:
            lines.append("")
            lines.append("⚠️ 远程端口发生变化，请检查依赖这些端口的下游配置："
                         + "、".join(changed_names))
            note = (tunnel.get("downstream_note") or "").strip()
            if note:
                lines.append(f"备忘：{note}")

        level = "success" if (online and probe_ok is not False) else "error"
        store.add_event(
            level, "failover",
            f"隧道「{tunnel['name']}」已切换到「{node.name}」"
            + (f"（同实例共 {len(moved)} 条一起）" if len(moved) > 1 else ""),
            tunnel_id=tid, detail="\n".join(lines),
        )
        await self._notify(
            ("✅ " if level == "success" else "⚠️ ") + f"隧道已切换：{tunnel['name']}",
            "\n".join(lines), level,
        )

        # ok 表示「切换动作本身走完了」；healthy 表示「切换后端到端真的通了」。
        # 两者分开报，前端才能给出准确的提示（比如「已切到新节点，但探测没通过」）。
        # probe_ok 为 None（协议不适用探测）时，只要隧道上线就算 healthy ——
        # 不能因为「没探测」就判成不健康，那是拿工具的局限去惩罚用户。
        return {
            "ok": bool(online),
            "healthy": bool(online and probe_ok is not False),
            "node": node.name,
            "node_id": node.node_id,
            "node_hostname": node_addr,
            "old_port": old_port,
            "remote_port": new_port,
            "port_changed": port_changed,
            "restart_ok": restart_ok,
            "frpc_instance": rr.get("instance"),
            "frpc_instance_id": rr.get("instance_id"),
            "frpc_changed": bool(rr.get("changed")),
            "frpc_note": rr.get("note") or "",
            "group_size": len(moved),
            "group_tunnels": [r["tunnel"]["name"] for r in moved],
            "online": online,
            "probe_ok": probe_ok,
            "probe_skipped": probe_ok is None,
            "probe_reason": probe_why,
            "error": "" if online else (probe_why or "隧道未能上线"),
            "detail": "\n".join(lines),
        }

    async def _move_tunnel(self, tunnel: dict, node, *,
                           current_proxy_id=_UNSET) -> dict:
        """把一条隧道搬到指定节点上。成功返回新 proxy 信息，失败返回原因。

        ⚠️ **顺序必须是「先删旧、再建新」，不能反。**

        mefrp 的 proxyName 在账号内唯一，同名隧道不能共存 —— 先建会直接撞名失败，
        而这正是最初那版的做法。代价是这条隧道在「删旧」到「建新」之间会短暂
        **彻底消失**（账号上不再有它的 proxy）。对故障转移来说可以接受：它本来就
        已经不可用了。但**建新失败时一定要把旧的建回去**，否则就把「还能恢复」
        变成了「彻底没了」—— 回滚由调用方（`_failover`）负责，本函数只如实报告
        自己走到了哪一步，不落库。

        `current_proxy_id` 是给回滚用的：正常切换时不传，读 `tunnel["current_proxy_id"]`；
        回滚时由调用方传入「这条隧道此刻真正挂着的那个 proxy id」（很可能是本函数
        上一轮新建出来的），否则会去删一个早已不存在的 id。
        """
        assert self.client is not None
        tid = int(tunnel["id"])
        old_proxy_id = (tunnel["current_proxy_id"] if current_proxy_id is _UNSET
                        else current_proxy_id)
        old_port = tunnel["current_remote_port"]
        ptype = str(tunnel.get("proxy_type") or "tcp")
        http_like = is_http_type(ptype)

        # ---- 1. 先删旧的，腾出 proxyName ----
        if old_proxy_id:
            try:
                await self.client.proxy_delete(int(old_proxy_id))
                store.add_event(
                    "info", "failover",
                    f"已删除旧隧道 #{old_proxy_id}（为新建同名隧道腾位）",
                    tunnel_id=tid,
                )
            except MefrpError as exc:
                # 删不掉也继续试：它可能本来就已经不在了（比如上一轮切换删过、
                # 或回滚时又删一次）。如果它其实还在，下一步创建会因为重名失败，
                # 那时如实报错即可 —— 不能在这里就放弃。
                store.add_event(
                    "warn", "failover",
                    f"删除旧隧道 #{old_proxy_id} 失败：{exc}（仍继续尝试新建）",
                    tunnel_id=tid,
                )

        # ---- 2. 再建新的 ----
        # ⚠️ 这里按隧道类型分成两条完全不同的路：
        #
        #   · TCP/UDP —— 争端口。优先级：期望端口 → 当前端口 → 让服务端分配。
        #     用户显式写了「期望远程端口」时以它为准（这是他的意图），否则尽量
        #     保住现有端口，因为端口一变就得去改下游配置。端口被占用时靠
        #     proxy_create 报错自然落到下一档。
        #
        #   · HTTP/HTTPS —— **没有端口这回事**（mefrp 侧 remotePort 恒为 null），
        #     要保住的是**绑定域名**。域名对用户来说更稳定：换节点后域名不变，
        #     下游（DNS / Cloudflare）不用动 —— 这也正是 HTTP 隧道相对 TCP 的
        #     最大好处。所以这里直接沿用期望域名（没有就用库里的当前域名）。
        last_err = ""
        created = False

        if http_like:
            want_domain = (tunnel.get("desired_domain")
                           or tunnel.get("current_domain") or "")
            try:
                await self.client.proxy_create(
                    node_id=node.node_id,
                    proxy_name=tunnel["proxy_name"],
                    local_ip=tunnel["local_ip"],
                    local_port=int(tunnel["local_port"]),
                    proxy_type=ptype,
                    domain=want_domain,
                    locations=str(tunnel.get("route_locations") or ""),
                    http_plugin=str(tunnel.get("http_plugin") or ""),
                    crt_path=str(tunnel.get("crt_path") or ""),
                    key_path=str(tunnel.get("key_path") or ""),
                )
                created = True
                store.add_event(
                    "info", "failover",
                    f"已在节点「{node.name}」创建 HTTP 隧道「{tunnel['name']}」"
                    f"（域名 {want_domain or '未指定'}）",
                    tunnel_id=tid,
                )
            except MefrpError as exc:
                last_err = str(exc)
                store.add_event(
                    "error", "failover",
                    f"在节点「{node.name}」创建 HTTP 隧道"
                    f"「{tunnel['name']}」失败：{exc}",
                    tunnel_id=tid,
                )
        else:
            want_ports: list[int | None] = []
            for cand in (tunnel.get("desired_remote_port"), old_port):
                if cand and int(cand) not in want_ports and node.port_allowed(int(cand)):
                    want_ports.append(int(cand))
            want_ports.append(None)

            for rp in want_ports:
                try:
                    await self.client.proxy_create(
                        node_id=node.node_id,
                        proxy_name=tunnel["proxy_name"],
                        local_ip=tunnel["local_ip"],
                        local_port=int(tunnel["local_port"]),
                        proxy_type=ptype,
                        remote_port=rp,
                    )
                    created = True
                    store.add_event(
                        "info", "failover",
                        f"已在节点「{node.name}」创建隧道「{tunnel['name']}」"
                        f"（请求端口 {rp or '自动'}）",
                        tunnel_id=tid,
                    )
                    break
                except MefrpApiError as exc:
                    last_err = str(exc)
                    store.add_event(
                        "warn", "failover",
                        f"在节点「{node.name}」用端口 {rp or '自动'} 创建"
                        f"「{tunnel['name']}」失败：{exc}",
                        tunnel_id=tid,
                    )
                    continue
                except MefrpError as exc:
                    last_err = str(exc)
                    break

        if not created:
            return {"ok": False, "tunnel": tunnel, "error": last_err or "创建失败"}

        # 重新拉列表，确认新隧道的 proxyId 与实际分配的端口
        new_proxy = await self._await_proxy(tunnel["proxy_name"], timeout=20)
        if new_proxy is None:
            return {"ok": False, "tunnel": tunnel,
                    "error": "隧道已创建，但 20 秒内没在 mefrp 列表里查到"}

        return {
            "ok": True,
            "tunnel": tunnel,
            "proxy": new_proxy,
            "old_proxy_id": old_proxy_id,
            "old_port": old_port,
            # ★ HTTP 隧道没有端口，这两项恒为 0/空；域名才是它要保住的东西。
            "old_domain": tunnel.get("current_domain") or "",
            "new_proxy_id": new_proxy.proxy_id,
            "new_port": new_proxy.remote_port,
            "new_domain": ",".join(new_proxy.domains) if http_like else "",
        }

    async def _await_proxy(self, proxy_name: str, timeout: float = 20) -> Proxy | None:
        assert self.client is not None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                # 第二个返回值（nodes 子数组）不能丢 —— 它带着真实 hostname，
                # 而非管理员账号下 /auth/node/list 的 hostname 是空串。
                proxies, nodes_brief = await self.client.proxy_list()
                self.proxies = {p.proxy_name: p for p in proxies}
                self.proxy_by_id = {p.proxy_id: p for p in proxies}
                self._merge_node_addresses(nodes_brief)
                hit = self.proxies.get(proxy_name)
                if hit is not None:
                    return hit
            except MefrpError:
                pass
            await asyncio.sleep(2)
        return None

    async def _await_online(self, proxy_name: str, timeout: float = 45) -> bool:
        assert self.client is not None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                proxies, nodes_brief = await self.client.proxy_list()
                self.proxies = {p.proxy_name: p for p in proxies}
                self.proxy_by_id = {p.proxy_id: p for p in proxies}
                self._merge_node_addresses(nodes_brief)
                hit = self.proxies.get(proxy_name)
                if hit is not None and hit.is_online:
                    return True
            except MefrpError:
                pass
            await asyncio.sleep(3)
        return False

    # ------------------------------------------------------------------
    # frpc 重建
    # ------------------------------------------------------------------

    async def _rebuild_and_restart(self, tunnel: dict) -> dict:
        """重建这条隧道所属 frpc 实例的配置并按需重启。

        返回结果 dict —— **每一步失败都要如实回传**，不能只回一个 bool：
        调用方（故障转移 / 手动接口）要把「配置写了没写」「重启了没重启」
        分开告诉用户，否则页面会骗人说一切正常。
        """
        tid = int(tunnel["id"])
        inst = self.frpc_for_tunnel(tunnel)
        if inst is None:
            store.add_event(
                "warn", "frpc",
                f"隧道「{tunnel['name']}」还没有挂接 frpc 容器，配置未更新 —— "
                "请到「frpc 实例」页新建一个容器，再回隧道页点「挂接 frpc」",
                tunnel_id=tid,
            )
            return {"instance": None, "instance_id": None, "changed": False,
                    "restart_ok": False, "skipped": True,
                    "note": "还没有挂接 frpc 容器，未写配置也未重启"}

        iid = int(inst["id"])
        label = str(inst["name"])
        base = {"instance": label, "instance_id": iid}

        try:
            changed, summary = await self.rebuild_frpc(iid)
        except (frpc.FrpcError, MefrpError) as exc:
            store.add_event("error", "frpc",
                            f"重建 frpc 实例「{label}」配置失败：{exc}", tunnel_id=tid)
            return {**base, "changed": False, "restart_ok": False,
                    "error": str(exc)}

        # 外部节点托管的实例：配置不归引擎管，所以「没变化」不是异常，
        # 也不该说成「配置无变化，跳过重启」—— 那句话会让用户以为引擎
        # 检查过配置并且是对的。
        if summary.get("manual"):
            return {**base, "changed": False, "restart_ok": True, "manual": True,
                    "summary": summary, "note": summary.get("note", "")}

        if not changed:
            store.add_event("info", "frpc",
                            f"frpc 实例「{label}」配置无变化，跳过重启", tunnel_id=tid)
            return {**base, "changed": False, "restart_ok": True,
                    "summary": summary}

        if str(inst.get("restart_mode") or "docker") == "none":
            store.add_event("warn", "frpc",
                            f"frpc 实例「{label}」配置已更新，"
                            "但重启方式设为「不自动重启」，需要手动重启",
                            tunnel_id=tid)
            return {**base, "changed": True, "restart_ok": False,
                    "summary": summary,
                    "note": "该实例的 restart_mode=none，需要手动重启"}

        if not store.get_setting("auto_restart_frpc", True):
            store.add_event("warn", "frpc",
                            f"配置已更新，但「自动重启」总开关已关闭，"
                            f"需要手动重启 frpc 实例「{label}」", tunnel_id=tid)
            return {**base, "changed": True, "restart_ok": False,
                    "summary": summary,
                    "note": "auto_restart_frpc 已关闭，需要手动重启"}

        dk = self.docker_for(inst)
        if dk is None:
            msg = (f"frpc 实例「{label}」没有可用的容器控制器"
                   "（未填容器名，或 Docker 不可达）")
            store.add_event("error", "frpc", msg, tunnel_id=tid)
            return {**base, "changed": True, "restart_ok": False,
                    "summary": summary, "error": msg}

        try:
            dk.restart()
            store.add_event("success", "frpc",
                            f"frpc 实例「{label}」容器已重启", tunnel_id=tid)
            return {**base, "changed": True, "restart_ok": True, "summary": summary}
        except frpc.FrpcError as exc:
            store.add_event("error", "frpc",
                            f"重启 frpc 实例「{label}」失败：{exc}", tunnel_id=tid)
            return {**base, "changed": True, "restart_ok": False,
                    "summary": summary, "error": str(exc)}

    async def rebuild_frpc(self, instance_id: int | None = None) -> tuple[bool, dict]:
        """重建 frpc 配置。返回 (是否有变化, 摘要)。

        `instance_id` 给了就只重建那一个实例；不给则重建**全部**启用的实例。
        摘要里始终带 `proxy_count`（总数），多实例时另有 `instances` 明细。
        """
        assert self.client is not None

        if instance_id is not None:
            inst = store.get_frpc_instance(int(instance_id))
            if inst is None:
                raise frpc.FrpcError(f"frpc 实例 {instance_id} 不存在")
            result = await self._rebuild_one(inst)
            # 按单个实例重建时也要提醒「有隧道哪儿都没写进去」——
            # 否则用户只盯着这个实例看，不会发现另一条隧道静默失效了。
            self._warn_unassigned()
            return result

        instances = store.list_frpc_instances(enabled_only=True)
        if not instances:
            raise frpc.FrpcError("还没有配置任何 frpc 实例")

        any_changed = False
        details: list[dict] = []
        errors: list[str] = []
        for inst in instances:
            try:
                changed, summary = await self._rebuild_one(inst)
            except frpc.FrpcError as exc:
                errors.append(f"{inst['name']}：{exc}")
                details.append({"id": int(inst["id"]), "name": inst["name"],
                                "error": str(exc)})
                continue
            any_changed = any_changed or changed
            details.append({"id": int(inst["id"]), "name": inst["name"],
                            "changed": changed, **summary})

        if not details or all("error" in d for d in details):
            raise frpc.FrpcError("；".join(errors) or "所有 frpc 实例都重建失败")

        self._warn_unassigned()

        total = sum(int(d.get("proxy_count") or 0) for d in details)
        return any_changed, {"proxy_count": total, "instances": details,
                             "errors": errors}

    async def _rebuild_one(self, inst: dict) -> tuple[bool, dict]:
        """重建单个 frpc 实例的配置。返回 (是否变化, 摘要)。"""
        assert self.client is not None
        iid = int(inst["id"])
        label = str(inst["name"])

        # 外部节点托管的实例：配置文件由「手动切换」维护，引擎**一个字都不碰**。
        # 手工模式的语义就是手工 —— 引擎自作主张去改写它，用户手写的注释、
        # 手工加的 [[proxies]] 全都会被冲掉，而且那是用户自己维护的文件，
        # 被工具悄悄改掉是最难排查的一类问题。
        if inst.get("manual_node_id"):
            node = store.get_manual_node(int(inst["manual_node_id"]))
            nname = node["name"] if node else "已删除的外部节点"
            return False, {
                "manual": True,
                "proxy_count": 0,
                "note": f"该实例由外部节点「{nname}」托管，配置不由引擎改写",
            }

        tunnels = []
        for t in store.list_tunnels(enabled_only=True):
            if not t["current_proxy_id"]:
                continue
            inst_of = self.frpc_for_tunnel(t)
            if inst_of is not None and int(inst_of["id"]) == iid:
                tunnels.append(t)

        if not tunnels:
            # ⚠️ 不写空配置 —— 那会把用户现有、我们还没纳管的 [[proxies]] 全清掉。
            # 但要如实报错，不能静默返回 changed=False 让页面显示「成功」。
            raise frpc.FrpcError(
                f"frpc 实例「{label}」当前没有任何隧道挂接，未改动配置文件"
            )

        texts: list[str] = []
        for t in tunnels:
            cfg = await self.client.proxy_config(int(t["current_proxy_id"]), "toml")
            if not cfg.strip():
                raise frpc.FrpcError(
                    f"隧道「{t['name']}」拿到的配置是空的"
                    f"（proxyId={t['current_proxy_id']}）"
                )
            # 顺手把节点公网地址缓存下来 —— 官方配置里的 serverAddr 就是节点地址，
            # 这是非管理员账号下拿到它的唯一途径（见 node_address 的说明）。
            addr = frpc.server_addr_of(cfg)
            nid = t.get("current_node_id")
            if addr and nid:
                self.node_hostname_cache[int(nid)] = addr
                node = self.nodes.get(int(nid))
                if node is not None:
                    node.hostname = addr
            texts.append(cfg)

        merged, _globals = frpc.merge_configs(texts, label=label)
        summary = frpc.config_summary(merged)

        path = Path(str(inst["config_path"]))
        current = frpc.read_config(path)
        if current.strip() == merged.strip():
            return False, summary

        backup = frpc.write_config(merged, path=path,
                                   backup_dir=frpc.instance_backup_dir(iid))
        store.add_event(
            "info", "frpc",
            f"frpc 实例「{label}」配置已更新"
            f"（{summary.get('proxy_count', 0)} 个隧道）",
            detail=(f"路径：{path}\n"
                    f"备份：{backup.name if backup else '无（首次写入）'}"),
        )
        return True, summary

    def _warn_unassigned(self) -> None:
        """把「启用了但没有挂接容器」的隧道记一条警告。

        这种情况会真的发生：新建的隧道默认没有挂接任何 frpc 容器，而程序**不再**
        自动认领（见 frpc_for_tunnel）。没挂接就不会被写进任何 frpc.toml，
        等于静默失效。必须让用户看见，而不是让他在页面上以为一切正常。
        """
        unassigned = [t for t in store.list_tunnels(enabled_only=True)
                      if self.frpc_for_tunnel(t) is None]
        if not unassigned:
            return
        names = "、".join(t["name"] for t in unassigned[:5])
        more = f" 等 {len(unassigned)} 条" if len(unassigned) > 5 else ""
        store.add_event(
            "warn", "frpc",
            f"有 {len(unassigned)} 条已启用的隧道还没有挂接 frpc 容器"
            f"（{names}{more}），它们不会被写进任何 frpc 配置",
            detail="到「frpc 实例」页新建容器，再在「隧道」页逐条点「挂接 frpc」；"
                   "如果这些隧道本来就在某个 frpc 配置文件里跑着，可以点「自动发现绑定」"
                   "按现有配置一次性匹配。",
        )

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    async def _sync_dns(self, tunnel: dict, proxy: Proxy | None,
                        force: bool = False, host: str | None = None) -> str:
        """同步 DNS。

        `host` 是给外部节点用的 —— 那种情况下没有 mefrp 的 Proxy 对象，
        节点地址直接由调用方给出（就是外部节点的 serverAddr）。
        不传 `host` 时走原来的路：从 mefrp 反推节点地址。
        """
        tid = int(tunnel["id"])
        record_name = (tunnel.get("dns_record_name") or "").strip()
        if not record_name:
            return ""
        if not store.get_setting("auto_dns_sync", True) and not force:
            return ""

        # ⚠️ 没配 token 是**静态配置问题**，不是「这条隧道此刻解析失败了」。
        #    如果照常往下走，`CloudflareAuthError` 会被下面那个 except 抓住、
        #    每轮巡检记一条 error 事件 —— 20 秒一条 × 每条填了记录名的隧道，
        #    很快把事件日志刷满，真正的问题反而被淹掉。
        #    所以这里直接说清楚，且**只在用户明确要求时**（force）才记事件。
        if self.cf is None or not self.cf.token:
            msg = "尚未配置 Cloudflare API Token，无法同步 DNS"
            if force:
                store.add_event("error", "dns", msg, tunnel_id=tunnel["id"])
            return msg

        if host is None:
            if proxy is None:
                return ""
            node = self.nodes.get(proxy.node_id)
            if node is None:
                return ""
            # ★ HTTP/HTTPS 隧道优先解析到「节点 HTTP 入口域名」。
            #   官方文档要求「把绑定域名 CNAME 到节点域名」，但非管理员账号看不到
            #   hostname（/auth/node/list 脱敏成空串），所以只能让用户在节点偏好里
            #   手填一个 http_entry。填了就 CNAME 过去 —— 比写死 IP 更抗节点换 IP；
            #   没填就退回节点 IP 走 A 记录（实测节点反代按 Host 头分流，A 记录也能通）。
            if is_http_type(tunnel.get("proxy_type")):
                pref = store.list_node_prefs().get(int(proxy.node_id)) or {}
                entry = str(pref.get("http_entry") or "").strip()
                if entry:
                    host = entry
                else:
                    host = (await self.node_address(proxy.node_id)).strip()
            else:
                # 节点地址只能从「该节点上已有隧道的官方配置」里反推（非管理员账号下
                # /auth/node/list 的 hostname 是空串），所以这里必须走解析器而不是
                # 直接读 node.hostname。
                host = (await self.node_address(proxy.node_id)).strip()
        else:
            host = str(host).strip()

        if not host:
            msg = f"拿不到节点 {proxy.node_id if proxy else '?'} 的公网地址，无法同步 DNS"
            if force:
                store.add_event("warn", "dns", msg, tunnel_id=tunnel["id"])
            return msg
        is_ip = bool(_IPV4_RE.match(host))
        want_type = "A" if is_ip else "CNAME"

        assert self.cf is not None
        try:
            zone_id = tunnel.get("dns_zone_id")
            if not zone_id:
                zone = await self.cf.resolve_zone(record_name)
                if zone is None:
                    msg = f"找不到 {record_name} 所属的 Cloudflare zone"
                    if force:
                        store.add_event("error", "dns", msg, tunnel_id=tunnel["id"])
                    return msg
                zone_id = zone.zone_id
                store.update_tunnel(tunnel["id"], {"dns_zone_id": zone_id})

            records = await self.cf.list_records(zone_id, name=record_name)
            target = None
            for r in records:
                if r.record_id == tunnel.get("dns_record_id"):
                    target = r
                    break
            if target is None:
                for r in records:
                    if r.type.upper() in ("A", "CNAME"):
                        target = r
                        break

            if target is not None and target.type.upper() == want_type \
                    and target.content == host:
                if not tunnel.get("dns_record_id"):
                    store.update_tunnel(tunnel["id"], {"dns_record_id": target.record_id})
                self._note_dns_ok(tid)
                return ""

            proxied = bool(tunnel.get("dns_proxied"))
            rec = await self.cf.upsert(
                zone_id=zone_id,
                name=record_name,
                record_type=want_type,
                content=host,
                proxied=proxied,
                record_id=tunnel.get("dns_record_id"),
                # ⚠️ 把上面刚查到的记录交出去，别让 upsert 再查两遍 —— 写路径上
                #    那 4 个请求（4 次全新 TLS 握手）就是这么省成 2 个的。
                existing=target,
            )
            store.update_tunnel(tunnel["id"], {
                "dns_zone_id": zone_id,
                "dns_record_id": rec.record_id,
            })
            msg = f"{record_name} → {want_type} {host}"
            store.add_event("success", "dns", f"DNS 已更新：{msg}",
                            tunnel_id=tunnel["id"])
            self._note_dns_ok(tid)
            return msg
        except CloudflareError as exc:
            msg = f"更新 DNS 失败：{exc}"
            if force:
                # 用户明确点的动作（导入 / 立即探测 / 切换后同步）—— 他正站在
                # 页面前等结果，必须如实报，不套「等半小时」那层缓冲。
                store.add_event("error", "dns", msg, tunnel_id=tid)
            else:
                # `transient=False`（zone 找不到这种静态问题，重试一万次也不会好）
                # → 立刻记 error，没有「等半小时」的道理。
                self._note_dns_fail(tid, msg, transient=bool(exc.transient))
            return msg

    def _note_dns_fail(self, tid: int, msg: str, transient: bool) -> None:
        """记一次 DNS 同步失败。口径与 mefrp 完全一致（见 ALERT_AFTER_SECONDS）。

        ⚠️ 原来这里是「连续 N 次」的计数，N=3 → 1 分钟就升 error。巡检 20 秒一轮、
        每轮都顺手同步一次 DNS，于是移动宽带抖两三分钟就能刷出一屏红字。现在改成
        按时间：只留一条 warn，满 `alert_after_seconds` 才告警。
        """
        now = time.time()
        if tid not in self.dns_fail_since:
            self.dns_fail_since[tid] = now
            if transient:
                self.dns_alert_count[tid] = 0
                store.add_event(
                    "warn", "dns",
                    f"{msg}（连续失败满 {_fmt_span(alert_after_seconds())} 才告警；"
                    "中途自愈不再记录）",
                    tunnel_id=tid,
                )
            else:
                # 静态问题：立刻报。但仍按同一个节奏补报，不每轮刷。
                self.dns_alert_count[tid] = 1
                store.add_event("error", "dns", msg, tunnel_id=tid)
            return
        down = now - self.dns_fail_since[tid]
        if down >= alert_after_seconds() * (self.dns_alert_count[tid] + 1):
            self.dns_alert_count[tid] += 1
            store.add_event(
                "error", "dns",
                f"{msg}（已连续失败 {_fmt_span(down)}）",
                tunnel_id=tid,
            )

    def _note_dns_ok(self, tid: int) -> None:
        """这条隧道的 DNS 同步这一轮成功了。清连续失败状态。

        ⚠️ 只有**告过警**的才记一条恢复事件 —— 抖动一下马上自愈的，前面那条
        warn 已经留过痕了，再记一条 success 纯属噪音。
        """
        if self.dns_fail_since.pop(tid, None) is None:
            return
        if self.dns_alert_count.pop(tid, 0):
            store.add_event("success", "dns", "DNS 同步已恢复", tunnel_id=tid)

    # ------------------------------------------------------------------
    # 手动操作
    # ------------------------------------------------------------------

    async def force_failover(self, tunnel_id: int, node_id: int | None = None) -> dict:
        """手动触发一次切换。给了 node_id 就切到指定节点，否则走自动择优。"""
        tunnel = store.get_tunnel(tunnel_id)
        if tunnel is None:
            return {"ok": False, "error": "隧道不存在"}

        # 外部节点托管的隧道不能用这个接口切：它换的是「mefrp 账号里的 proxy」，
        # 而外部节点根本没有 API。换节点请走 switch_instance_to_node。
        if self.tunnel_is_manual(tunnel):
            node = self.manual_node_for(tunnel)
            name = node["name"] if node else "未知"
            return {"ok": False,
                    "error": f"这条隧道由外部节点「{name}」托管，"
                             "请用「切换节点」手动切换"}

        if self.client is None:
            self.reload_clients()

        if node_id is not None:
            node = self.nodes.get(int(node_id))
            if node is None:
                # 可能还没拉过节点列表，先刷新一次
                try:
                    await self._refresh_remote()
                except MefrpError as exc:
                    return {"ok": False, "error": f"刷新节点列表失败：{exc}"}
                node = self.nodes.get(int(node_id))
            if node is None:
                return {"ok": False, "error": f"节点 {node_id} 不存在"}
            # 硬约束：与 pick_node 的口径保持一致。带宽/负载/区域/排除/冷却
            # 都是「自动择优」的软偏好，人工指定时不该拦。
            if not node.usable:
                return {"ok": False, "error": f"节点「{node.name}」当前离线或被禁用"}
            if not node.allows_group(self.user_group):
                return {"ok": False,
                        "error": f"节点「{node.name}」限 {node.allow_group}，"
                                 f"当前用户组 {self.user_group or '未知'} 无权限"}
            if not node.allows_type(tunnel["proxy_type"]):
                return {"ok": False,
                        "error": f"节点「{node.name}」不支持 "
                                 f"{str(tunnel['proxy_type']).upper()} 隧道"}

        async with self._lock:
            return await self._failover(
                tunnel, "手动触发",
                prefer_node_id=int(node_id) if node_id else None,
                ignore_cooldown=True,
            )

    # ------------------------------------------------------------------
    # 手工切换：把实例切到某个外部节点
    # ------------------------------------------------------------------

    async def switch_instance_to_node(self, instance_id: int, node_id: int,
                                      *, restart: bool | None = None) -> dict:
        """把一个 frpc 实例切到某个外部节点上 —— 外部节点**唯一**的切换方式。

        按顺序做三件事：

          1. 改写实例配置文件里的 **server 段**（地址 / 端口 / 鉴权）
          2. 按设置决定是否重启它的容器
          3. 重新同步相关隧道的 DNS

        ⚠️ **隧道定义一个字都不动。** 切换的语义是「同一套本地服务，换一台 frps
           接」，所以 `[[proxies]]` / `[段名]` 原样保留，连注释和排版都不碰 ——
           见 frpcparse.patch_server 里为什么用文本级替换而不是重新序列化。

        `restart` 传 None 表示「按设置来」（实例的 restart_mode + 全局
        auto_restart_frpc），传 True/False 则由调用方强制。
        """
        inst = store.get_frpc_instance(int(instance_id))
        if inst is None:
            return {"ok": False, "error": f"frpc 实例 {instance_id} 不存在"}
        node = store.get_manual_node(int(node_id))
        if node is None:
            return {"ok": False, "error": f"外部节点 {node_id} 不存在"}
        if not node.get("enabled"):
            return {"ok": False, "error": f"外部节点「{node['name']}」已停用"}

        iid = int(inst["id"])
        label = str(inst["name"])
        path = Path(str(inst["config_path"]))

        try:
            current = frpc.read_config(path)
        except frpc.FrpcError as exc:
            return {"ok": False, "error": str(exc)}

        fmt = str(node.get("config_format") or "toml")
        # 手上没有现成配置（首次接管这个实例）→ 用导入时存的原文做底
        base = current if current.strip() else str(node.get("config_text") or "")

        token = str(node.get("auth_token") or "").strip()
        user = str(node.get("auth_user") or "").strip()
        method = str(node.get("auth_method") or "none")

        # ⚠️ 目标节点不需要鉴权时**不传** token/user —— patch_server 只在明确给了
        #    值时才动鉴权字段。刻意**不清空**原有的 token：清空得写
        #    `auth.token = ""`，让配置更难读；而 frps 没配鉴权时，客户端多带一个
        #    token 是无害的（服务端根本不校验）。
        try:
            patched = frpcparse.patch_server(
                base,
                addr=str(node["server_addr"]),
                port=int(node["server_port"]),
                auth_method=(method if (token or user) else None),
                auth_token=(token or None),
                auth_user=(user or None),
                fmt=fmt,
            )
        except Exception as exc:  # noqa: BLE001 - 解析/改写出任何问题都要如实回传
            return {"ok": False, "error": f"改写配置失败：{exc}"}

        async with self._lock:
            changed = patched.strip() != current.strip()
            backup = None
            if changed:
                try:
                    backup = frpc.write_config(
                        patched, path=path,
                        backup_dir=frpc.instance_backup_dir(iid))
                except frpc.FrpcError as exc:
                    return {"ok": False, "error": str(exc)}

            # ---- 落库：实例挂到新节点 ----
            # 记下它原来连的是哪个节点 —— 切走之后那个节点可能就没人用了。
            old_nid = int(inst["manual_node_id"]) if inst.get("manual_node_id") else 0
            store.update_frpc_instance(iid, {"manual_node_id": int(node["id"])})

            # 隧道跟着实例走：它们由这个实例承载，实例换服务端，它们就换了服务端。
            # 顺便按新配置里的 remotePort 刷新各自的当前端口 —— 不同节点的端口
            # 段不一样，不刷新的话下一轮探测会拿旧端口去连，白白判成故障。
            ports: dict[str, int] = {}
            try:
                ports = {p.name: int(p.remote_port or 0)
                         for p in frpcparse.parse(patched, fmt=fmt).proxies}
            except frpcparse.FrpcParseError:
                pass

            moved: list[dict] = []
            missing: list[str] = []
            for t in store.list_tunnels_of_frpc(iid):
                upd: dict[str, Any] = {"manual_node_id": int(node["id"])}
                # ⚠️ HTTP 隧道在 frpc 配置里没有 remotePort（恒为 null），
                #    拿它去查「新配置里有没有这条隧道」会永远落进 missing ——
                #    那是误报。http 组直接跳过端口刷新与 missing 判定。
                if is_http_type(t.get("proxy_type")):
                    store.update_tunnel(int(t["id"]), upd)
                    self.probe_cache.pop(int(t["id"]), None)
                    moved.append(store.get_tunnel(int(t["id"])) or t)
                    continue
                new_port = ports.get(str(t["proxy_name"]))
                if new_port:
                    upd["current_remote_port"] = new_port
                elif ports:
                    # 新配置里没有这条隧道 —— 它在这个节点上不会生效，如实报出来，
                    # 不能让用户以为切换之后它还在跑。
                    missing.append(str(t["name"]))
                store.update_tunnel(int(t["id"]), upd)
                self.probe_cache.pop(int(t["id"]), None)
                moved.append(store.get_tunnel(int(t["id"])) or t)

            # ---- 顺手清理没人用的旧节点 ----
            # 外部节点是**跟着隧道/实例走的一次性东西**，用户从不在页面上管理它。
            # 所以实例改连之后，原节点如果谁都不引用了就该消失 —— 否则每换一次
            # 节点就在库里留一条记录，用户在页面上既看不见也删不掉，只会越积越多。
            # ⚠️ 仍被隧道或别的实例引用着的不删：那些东西的配置里还写着这个地址。
            dropped_node = 0
            if old_nid and old_nid != int(node["id"]):
                still_used = (store.count_tunnels_of_manual_node(old_nid)
                              + len(store.list_instances_of_manual_node(old_nid)))
                if still_used == 0 and store.get_manual_node(old_nid) is not None:
                    store.delete_manual_node(old_nid)
                    self.manual_probe.pop(old_nid, None)
                    dropped_node = old_nid

            # ---- 重启 ----
            restart_ok = False
            restart_note = ""
            if not changed:
                restart_ok = True
                restart_note = "配置无变化，未重启"
            else:
                mode = str(inst.get("restart_mode") or "docker")
                allow = (bool(store.get_setting("auto_restart_frpc", True))
                         if restart is None else bool(restart))
                if mode == "none":
                    restart_note = "该实例的 restart_mode=none，需要手动重启"
                elif not allow:
                    restart_note = "自动重启已关闭，需要手动重启"
                else:
                    dk = self.docker_for(inst)
                    if dk is None:
                        restart_note = "没有可用的容器控制器（未填容器名，或 Docker 不可达）"
                    else:
                        try:
                            dk.restart()
                            restart_ok = True
                        except frpc.FrpcError as exc:
                            restart_note = str(exc)

        # 顺手探一下新节点，给用户即时反馈（缓存里直接写新结果）
        probe = await self.probe_manual_node(int(node["id"]), force=True)

        # ---- 重新解析 DNS ----
        # 地址变了就必须跟着改，否则「配置看着对、访问打不开」。
        # 这里**强制**同步（force=True）：切换是用户明确点的动作，DNS 记录名也是
        # 用户逐条配的，两者都表达过意图；再被全局的 auto_dns_sync 拦一道，
        # 结果就是切完了域名还指着旧地址 —— 那才是最糟的失败方式。
        dns_msgs: list[str] = []
        for t in moved:
            if not (t.get("dns_record_name") or "").strip():
                continue
            try:
                msg = await self._sync_dns(t, None, force=True,
                                           host=str(node["server_addr"]))
            except Exception as exc:  # noqa: BLE001 - 单条 DNS 失败不能拖垮整轮
                msg = f"更新 DNS 异常：{exc}"
            if msg:
                dns_msgs.append(f"{t['name']}：{msg}")

        lines = [
            f"实例：{label}",
            f"新节点：{node['name']}（{node['server_addr']}:{node['server_port']}）",
            f"配置文件：{path}",
            f"写入：{'已改写' if changed else '无变化'}"
            + (f"（备份 {backup.name}）" if backup else ""),
            f"重启：{'成功' if restart_ok else '未完成'}"
            + (f" —— {restart_note}" if restart_note else ""),
            f"节点探测：{'可达' if probe.get('ok') else '不可达'}"
            + ("" if probe.get("ok") else f" —— {probe.get('reason', '')}"),
            f"受影响隧道：{len(moved)} 条",
        ]
        if missing:
            lines.append("")
            lines.append("⚠️ 新配置里找不到这些隧道，它们在新节点上不会生效："
                         + "、".join(missing))
        if dns_msgs:
            lines.append("DNS：" + "；".join(dns_msgs))

        level = "success" if (restart_ok and probe.get("ok")) else "warn"
        store.add_event(
            level, "failover",
            f"实例「{label}」已手动切换到外部节点「{node['name']}」",
            detail="\n".join(lines),
        )
        await self._notify(
            f"{'✅' if level == 'success' else '⚠️'} 已切换外部节点：{label}",
            "\n".join(lines), level,
        )

        return {
            "ok": True,
            "instance": label,
            "instance_id": iid,
            "node": node["name"],
            "node_id": int(node["id"]),
            "endpoint": f"{node['server_addr']}:{node['server_port']}",
            "config_path": str(path),
            "changed": changed,
            "backup": backup.name if backup else "",
            "restart_ok": restart_ok,
            "restart_note": restart_note,
            "node_probe_ok": bool(probe.get("ok")),
            "node_probe_reason": probe.get("reason", ""),
            "tunnels": [t["name"] for t in moved],
            "tunnels_missing": missing,
            "dns": dns_msgs,
            "dropped_manual_node": dropped_node,
            "detail": "\n".join(lines),
        }

    # ------------------------------------------------------------------
    # 通知
    # ------------------------------------------------------------------

    async def _notify(self, title: str, message: str, level: str = "info") -> None:
        await self.notifier.send(title, message, level)

    # ------------------------------------------------------------------
    # 快照
    # ------------------------------------------------------------------

    def snapshot(self) -> Snapshot:
        s = store.get_settings()
        interval = int(s.get("engine_interval", 20) or 20)
        elapsed = time.time() - self.last_tick_at if self.last_tick_at else 0
        return Snapshot(
            ts=int(time.time()),
            running=bool(self._task and not self._task.done()),
            configured=bool(s.get("mefrp_token")),
            user_group=self.user_group,
            user_group_friendly=self.user_group_friendly,
            user_group_error=self.user_group_error,
            nodes=[n.__dict__ | {"bandwidth_mbps": n.bandwidth_mbps} for n in self.nodes.values()],
            proxies=[p.__dict__ for p in self.proxies.values()],
            last_error=self.last_error,
            tick_count=self.tick_count,
            next_tick_in=max(0, int(interval - elapsed)),
        )


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

engine = GuardEngine()
