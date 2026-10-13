"""配置层。

分两部分：
  * BOOTSTRAP —— 只能来自环境变量，进程启动时确定（路径、凭据种子、监听参数）。
  * 运行期设置 —— 存在数据库里，可以在 Web UI 上随时改。环境变量只作为首次种子。

之所以这么分：路径和端口改起来要重启容器，没必要放 UI；而「优先哪个区域的节点」
「失败几次才切换」这类策略参数，调起来应该即时生效。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(key: str, default: str = "") -> str:
    v = os.environ.get(key)
    return default if v is None else v.strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    v = _env(key, "").lower()
    return default if not v else v in ("1", "true", "yes", "on", "y")


@dataclass(frozen=True)
class Bootstrap:
    data_dir: Path
    db_path: Path
    frpc_config_path: Path
    frpc_backup_dir: Path
    frpc_container: str
    docker_base_url: str
    web_user: str
    web_password: str
    host: str
    port: int

    @property
    def auth_enabled(self) -> bool:
        return bool(self.web_user and self.web_password)


def load_bootstrap() -> Bootstrap:
    data_dir = Path(_env("MG_DATA_DIR", "/data"))
    return Bootstrap(
        data_dir=data_dir,
        db_path=data_dir / "guard.db",
        frpc_config_path=Path(_env("MG_FRPC_CONFIG", "/frpc/frpc.toml")),
        frpc_backup_dir=data_dir / "frpc-backups",
        frpc_container=_env("MG_FRPC_CONTAINER", "frpc"),
        docker_base_url=_env("MG_DOCKER_HOST", "unix:///var/run/docker.sock"),
        web_user=_env("MG_WEB_USER", ""),
        web_password=_env("MG_WEB_PASSWORD", ""),
        host=_env("MG_HOST", "0.0.0.0"),
        port=_env_int("MG_PORT", 8080),
    )


BOOTSTRAP = load_bootstrap()


# ---------------------------------------------------------------------------
# 运行期设置（存库，UI 可改）
# ---------------------------------------------------------------------------

# key -> (默认值, 说明)。默认值里的空串由环境变量补齐。
DEFAULT_SETTINGS: dict[str, object] = {
    # 凭据
    "mefrp_token": _env("MEFRP_TOKEN", ""),
    "cf_api_token": _env("CF_API_TOKEN", ""),
    "gotify_url": _env("GOTIFY_URL", ""),
    "gotify_token": _env("GOTIFY_TOKEN", ""),
    # 引擎节奏
    "engine_interval": 20,          # 主循环间隔（秒）
    "probe_interval": 60,           # 单个隧道端到端 TCP 探测的最短间隔（秒）
    "probe_timeout": 4,             # TCP 探测超时（秒）
    # ★ DNS 记录**核对**间隔（秒）。默认 900（15 分钟）。
    #
    # 为什么不是每轮都核对：地址是很少变的，而原来每个 tick（20 秒）都要为每条配了
    # DNS 的隧道打一次 `list_records`，只为确认「记录没变」—— 等于拿 Cloudflare API
    # 当心跳。实测那个 API 从家宽出去时通时不通（打三次挂两次），这些「没事找事」的
    # 请求换来的就是一屏 `ConnectTimeout`，还把巡检周期从 20 秒拖到分钟级（一次失败的
    # DNS 请求最坏要 47 秒 = 15 秒超时 × 3 次尝试）。
    #
    # 现在的规则（见 `engine._dns_check_due`）：
    #   · **地址变了 → 立刻同步**，不等间隔（记录指错比「晚一点发现被外部改过」严重得多）
    #   · 地址没变 → 到点才核对一次；成功失败都算核对过，下次隔一个间隔再来
    # 设 0 或负数 = 退回「每轮都核对」（逃生口）。
    "dns_check_interval": 900,
    # 端到端探测模式：
    #   auto —— 按隧道协议自动决定。tcp 隧道做 TCP 探测；udp 隧道**跳过** L3；
    #           **http/https 隧道也跳过**（理由见 engine.probe_plan：节点反代对
    #           任何 Host 都会完成 TCP 握手，拿 TCP 去探永远是「通」，是假阳性）。
    #   tcp  —— 强制所有隧道都做 TCP 探测（逃生口，只在你明确知道后果时用）。
    #   http —— 按类型各用各的：tcp 走 TCP 探测，http/https 走**真实 HTTP 请求**
    #           （GET 绑定域名，2xx/3xx 算通）。这是 http 隧道唯一能真正验到
    #           「域名解析对不对、链路通不通」的模式。
    #   none —— 完全关闭 L3 探测，只用 L1（mefrp 状态）+ L2（节点状态）判定。
    "probe_mode": "auto",
    "fail_threshold": 3,            # 连续失败多少次才判定为故障
    "failover_cooldown": 300,       # 一次切换之后多久内不再切换（秒）
    "node_cooldown": 1800,          # 节点被切换走之后多久内不再选它（秒）
    # ---- 节点择优：TCP/UDP（「端口型」隧道）----
    # ⚠️ 下面这一组**只管 tcp/udp**。http/https 有自己的一套（见下一个 block）——
    #    两类的约束根本不同，最典型的是 http 受「备案」限制：国内节点建站要报备，
    #    所以 http 的默认区域刻意排除了大陆。捆在一起调一个必然误伤另一个。
    "min_bandwidth_mbps": 25,       # 节点带宽下限
    "prefer_keywords": "北京",       # 优先关键词，逗号分隔，命中即排在前面
    "allow_regions": "cn",          # 允许的区域，逗号分隔；留空表示不限
    "max_load_percent": 90,         # 节点负载上限
    # ---- 节点择优：HTTP/HTTPS（「域名型」隧道）----
    # ⚠️ 默认 `cnos,oversea` = 只用港澳台 + 海外节点。**这不是随手填的默认值**：
    #    官方文档明说国内节点允许建 HTTP/S 站的话，域名需要向管理员报备（白名单），
    #    云厂商节点还要求域名在服务商处接入备案。默认避开大陆能让新用户第一次
    #    建 HTTP 隧道就成功，而不是建完发现打不开。要上大陆节点就显式把 cn 勾上。
    "http_allow_regions": "cnos,oversea",
    "http_min_bandwidth_mbps": 25,
    "http_max_load_percent": 90,
    "http_prefer_keywords": "",
    "http_node_cooldown": 1800,
    # HTTP 探测请求的路径。默认探根路径；如果你的服务在 `/` 上本来就会返回
    # 4xx/5xx（比如 API 服务、带鉴权的后台），把它改成能返回 2xx 的路径，
    # 否则开了 http 探测就会一路误报「不通」。
    "http_probe_path": "/",
    # 行为开关
    "auto_failover": True,          # 总开关：是否允许自动切换
    "auto_dns_sync": True,          # 是否自动纠正漂移的 DNS 记录
    "auto_restart_frpc": True,      # 改完配置是否自动重启 frpc
    "notify_on_probe_fail": False,  # 探测失败但未达阈值时是否也推送（默认不推，避免刷屏）
    # ★ 连续失败**多久**才把「mefrp 拉取失败 / DNS 同步失败」升级成 error 告警（秒）。
    #   ⚠️ 按时间不按次数：巡检 20 秒一轮，「连续 3 次」只有 1 分钟 —— 移动宽带的
    #   间歇性抽风会一路刷满红字（实测三天 122+64 条，没有一条是源站真挂了）。
    #   默认 1800（30 分钟）：之前只留一条 warn，满 30 分钟才告警。设 0 = 立刻告警。
    "alert_after_seconds": 1800,
    # 网络
    "user_agent": "MefrpGuard/1.0 (homelab)",
    "mefrp_base": "https://api.mefrp.com/api",

    # ---- 鉴权 ----
    # 用户名明文存（不是秘密），密码只存 PBKDF2 哈希 + 盐 + 迭代次数。
    # 首次启动时由 store 播种：环境变量优先，否则用 admin / admin123。
    "web_user": _env("MG_WEB_USER", "") or "admin",
    "web_password_hash": "",        # 十六进制 PBKDF2-HMAC-SHA256
    "web_password_salt": "",        # 每实例随机盐
    "web_password_iter": 0,         # 哈希时的迭代次数（跟着哈希一起存，便于日后调高）
    "session_ttl_hours": 168,       # 会话有效期，默认 7 天
    "login_max_attempts": 5,        # 连续失败几次锁定
    "login_lockout_seconds": 300,   # 锁定时长（秒）
}

# ⚠️ 这里曾经有一个 `FORCE_IPV4_LOCAL_ADDRESS = "0.0.0.0"`（1.0.3 中途加、随即撤掉）。
#
# 思路是：有些环境里域名**优先解析出 IPv6**、而那条路由是个**黑洞**，anyio 又
# **主动**把 IPv6 重排到候选列表首位（`anyio/_core/_sockets.py` 里那句 "Organize
# the list so that the first address is an IPv6 address"），于是 httpx 一头撞进去
# 挂到 connect 超时；传 `local_address="0.0.0.0"` 能把解析锁在 `AF_INET`。
#
# 做法本身有效，**但它治的不是我们的病**：实测 guard 宿主所在网段 IPv6 **根本没有
# 路由** —— 连 IPv6 是**秒失败**而不是挂起，anyio 立刻就落到 IPv4 了；而真正在抖的是
# IPv4 到 Cloudflare anycast（104.19.192.x）的路径。那是运营商侧的特性，程序里绕不过去。
# 既然没用，就别让「永远不用 IPv6」这个代价白付。
#
# 真把程序搬到「IPv6 是黑洞」的机器上（比如那台 `ubuntu2204`）再加回来 —— 那时它有用。

# ★ DNS「站点已恢复」的迟滞窗口（秒）。站点必须**连续干净满这个窗口**才算恢复。
#
# 为什么需要它：原来的恢复判据是「这一轮一条隧道都没失败」。看着对，但碰上一个
# **抖动型**的故障源就完全失效 —— 实测 2026-10-13 那天，CF API 从家宽出去是
# 「打三次挂两次、偶尔通一次」：每一次偶然成功的那一轮都会把「连续失败」状态
# 清零，下一轮再挂就又是一条全新的 warn。结果 12:35~16:36 四小时里刷出 **62 条
# warn、0 条 error** —— 30 分钟的告警**永远攒不满**（没有哪一段是连续失败 30
# 分钟的），而聚合的意义（一条故障只报一条）被这一条判据整个吃掉。
#
# 现在：窗口内的偶发成功只当抖动 —— 不清零、不记事件、不推进告警计时。
# 取值参考实测的抖动间隔（93~625 秒）：10 分钟足够把这种抖动整个包进同一段。
DNS_RECOVER_GRACE_SECONDS = 600.0

# 只读设置：只允许程序内部写，不接受 /api/settings 的写入。
# ⚠️ 密码哈希必须在这里 —— 否则任何人都能通过设置接口把密码改成自己知道的值。
# 改密码走专门的 /api/auth/password（需要验证当前密码）。
READONLY_SETTINGS = frozenset({
    "web_password_hash", "web_password_salt", "web_password_iter",
})

SECRET_KEYS = {"mefrp_token", "cf_api_token", "gotify_token",
               "web_password_hash", "web_password_salt"}


# mefrp 节点区域的三档（官方 `/auth/createProxyData` 的 region 枚举，实测一致）。
# ⚠️ 「备案」只跟**中国大陆**有关：cn 节点建 HTTP/S 站要报备域名白名单，cnos
#    （港澳台）与 oversea 都不需要大陆备案。所以 http 组的默认区域是后两者。
REGION_CHOICES: tuple[tuple[str, str], ...] = (
    ("cn", "中国大陆"),
    ("cnos", "港澳台"),
    ("oversea", "海外"),
)

REGION_LABELS = dict(REGION_CHOICES)


# ★ 「端口型」（tcp/udp）与「域名型」（http/https）**两套并存的节点择优偏好**。
#
# 为什么是两张表而不是一堆 if：这两类隧道的约束来源完全不同 ——
#   · tcp/udp 只受节点性能与用户组限制，跟域名、备案都无关；
#   · http/https 多了一层「备案」：国内节点要报备白名单，所以默认就该避开大陆。
# 把键名集中在这里，`engine.pick_node` / `rank_nodes` 只要按隧道类型取一组键，
# 择优逻辑本身**一份都不用改** —— 否则「按类型分叉」会渗进每个筛选条件里。
PREF_KEYS: dict[str, dict[str, str]] = {
    "port": {
        "regions": "allow_regions",
        "min_bandwidth": "min_bandwidth_mbps",
        "max_load": "max_load_percent",
        "keywords": "prefer_keywords",
        "node_cooldown": "node_cooldown",
    },
    "http": {
        "regions": "http_allow_regions",
        "min_bandwidth": "http_min_bandwidth_mbps",
        "max_load": "http_max_load_percent",
        "keywords": "http_prefer_keywords",
        "node_cooldown": "http_node_cooldown",
    },
}


def pref_key(kind: str, name: str) -> str:
    """取某类隧道（`"port"` / `"http"`）某个偏好项对应的设置键名。

    认不出来的 kind 一律当 `port` —— 和 `mefrp.kind_of` 的保守方向一致。
    """
    table = PREF_KEYS.get(kind) or PREF_KEYS["port"]
    return table.get(name) or PREF_KEYS["port"][name]


def default_of(key: str):
    return DEFAULT_SETTINGS.get(key)
