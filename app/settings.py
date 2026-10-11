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
    # 端到端探测模式：
    #   auto —— 按隧道协议自动决定。tcp 隧道做 TCP 探测；udp 隧道**跳过** L3。
    #           为什么 udp 要跳过：mefrp 的 udp 隧道在节点上开的是 UDP 端口，
    #           没有 TCP 监听，用 TCP 握手去探必然失败 → 健康隧道被永久误判成
    #           故障 → fail_streak 涨到阈值后对好隧道发起无意义切换。
    #   tcp  —— 强制所有隧道都做 TCP 探测（逃生口，只在你明确知道后果时用）。
    #   none —— 完全关闭 L3 探测，只用 L1（mefrp 状态）+ L2（节点状态）判定。
    "probe_mode": "auto",
    "fail_threshold": 3,            # 连续失败多少次才判定为故障
    "failover_cooldown": 300,       # 一次切换之后多久内不再切换（秒）
    "node_cooldown": 1800,          # 节点被切换走之后多久内不再选它（秒）
    # 节点择优
    "min_bandwidth_mbps": 25,       # 节点带宽下限
    "prefer_keywords": "北京",       # 优先关键词，逗号分隔，命中即排在前面
    "allow_regions": "cn",          # 允许的区域，逗号分隔；留空表示不限
    "max_load_percent": 90,         # 节点负载上限
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

# 只读设置：只允许程序内部写，不接受 /api/settings 的写入。
# ⚠️ 密码哈希必须在这里 —— 否则任何人都能通过设置接口把密码改成自己知道的值。
# 改密码走专门的 /api/auth/password（需要验证当前密码）。
READONLY_SETTINGS = frozenset({
    "web_password_hash", "web_password_salt", "web_password_iter",
})

SECRET_KEYS = {"mefrp_token", "cf_api_token", "gotify_token",
               "web_password_hash", "web_password_salt"}


def default_of(key: str):
    return DEFAULT_SETTINGS.get(key)
