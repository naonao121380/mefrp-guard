"""鉴权原语：密码哈希、会话令牌、登录防爆破。

只用标准库（`hashlib` / `hmac` / `secrets`），不引入新依赖 —— 这个服务的依赖越少越好。

三条安全约定，改代码时不要破坏：

1. **密码永不明文落库。** 用 PBKDF2-HMAC-SHA256 + 每用户随机盐 + 高迭代次数。
   参数一起存下来（`iterations`），这样以后调高迭代数时老密码仍然能验证。
2. **会话令牌也永不明文落库。** 库里只存令牌的 SHA-256。
   令牌本身是 256 位随机数，熵足够高，不需要 PBKDF2（那是给低熵密码用的）。
   这样即使数据库泄露，攻击者也拿不到可用的会话。
3. **比较一律用 `hmac.compare_digest`。** 普通 `==` 会在第一个不同字节处提前返回，
   理论上能被计时攻击逐字节猜出。

⚠️ 会话令牌**不能**用 PBKDF2 存：验证时要遍历所有会话，每次算 30 万轮哈希会把
请求拖死。高熵令牌用一次 SHA-256 即可，且可以按哈希直接查库（O(1)）。
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time

# PBKDF2 迭代次数。OWASP 对 PBKDF2-HMAC-SHA256 的建议是 600,000，
# 这里取 300,000 —— 单次验证约 100~200ms，对「偶尔登录一次」的场景完全够用，
# 但在低功耗 CPU（软路由、迷你主机那一档）上也不至于让登录卡到不可用。
DEFAULT_ITERATIONS = 300_000
SALT_BYTES = 16
TOKEN_BYTES = 32

# 默认凭据。首次启动且没有环境变量覆盖时用它播种。
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "admin123"


# ---------------------------------------------------------------------------
# 密码
# ---------------------------------------------------------------------------

def hash_password(password: str, *, salt: str | None = None,
                  iterations: int = DEFAULT_ITERATIONS) -> tuple[str, str, int]:
    """返回 (hash_hex, salt_hex, iterations)。salt 为空时随机生成。"""
    if salt:
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = secrets.token_bytes(SALT_BYTES)
    iterations = max(1, int(iterations))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return dk.hex(), salt_bytes.hex(), iterations


def verify_password(password: str, *, hash_hex: str, salt_hex: str,
                    iterations: int) -> bool:
    """校验密码。任何异常（空参数、盐不是合法 hex）一律返回 False，不往上抛。"""
    if not hash_hex or not salt_hex or not iterations:
        return False
    try:
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    try:
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt_bytes, int(iterations)
        )
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


def is_default_password(password_hash: str, salt: str, iterations: int) -> bool:
    """当前密码是不是那个众所周知的默认值。

    用来在 UI 上提示「你还在用默认密码」。注意这是**主动拿默认密码去比对**，
    不是存了个明文标志位 —— 后者会在用户改完密码又改回来时失准。
    """
    if not password_hash or not salt:
        return False
    return verify_password(DEFAULT_PASSWORD, hash_hex=password_hash,
                           salt_hex=salt, iterations=iterations)


# ---------------------------------------------------------------------------
# 会话令牌
# ---------------------------------------------------------------------------

def new_token() -> str:
    """生成一个新的会话令牌（给客户端）。"""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_fingerprint(token: str) -> str:
    """令牌的 SHA-256，落库用这个。

    高熵令牌用快哈希是安全的 —— 攻击者没法对 256 位随机数做字典/暴力枚举。
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def same(a: str, b: str) -> bool:
    """常量时间字符串比较。"""
    return hmac.compare_digest(a or "", b or "")


# ---------------------------------------------------------------------------
# 登录防爆破
# ---------------------------------------------------------------------------

class LoginThrottle:
    """按来源 IP 记录登录失败，超限就锁定一段时间。

    纯内存，进程重启即清空 —— 这是有意的：
    锁定状态不值得持久化，而重启后重新开始计数也不会造成安全问题。

    为什么需要它：默认密码是公开的，如果没有限速，任何人都可以在内网
    用字典把 admin 的密码刷出来。有 5 次/5 分钟的闸门，爆破就不现实了。
    """

    def __init__(self) -> None:
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def remaining_lock(self, ip: str) -> int:
        """还剩多少秒解锁。0 表示没被锁。

        ⚠️ 必须向上取整，不能用 `int()` 截断：
        剩余 0.9 秒时 `int(0.9) == 0`，调用方会以为「已经解锁了」，
        但服务端其实还在锁定 —— 短锁定（几秒）会因此形同虚设。
        """
        with self._lock:
            until = self._locked_until.get(ip, 0.0)
        return max(0, math.ceil(until - time.time()))

    def is_locked(self, ip: str) -> bool:
        return self.remaining_lock(ip) > 0

    def record_failure(self, ip: str, *, max_attempts: int,
                       lockout_seconds: int, window_seconds: int = 900) -> int:
        """记一次失败。返回剩余可用尝试次数（0 表示已被锁定）。"""
        now = time.time()
        with self._lock:
            stamps = [t for t in self._fails.get(ip, []) if now - t < window_seconds]
            stamps.append(now)
            self._fails[ip] = stamps
            if len(stamps) >= max(1, max_attempts):
                self._locked_until[ip] = now + max(1, lockout_seconds)
                self._fails[ip] = []
                return 0
            return max(0, max_attempts - len(stamps))

    def reset(self, ip: str) -> None:
        """登录成功后清空该 IP 的失败记录。"""
        with self._lock:
            self._fails.pop(ip, None)
            self._locked_until.pop(ip, None)

    def clear_all(self) -> None:
        with self._lock:
            self._fails.clear()
            self._locked_until.clear()


THROTTLE = LoginThrottle()


def client_ip(request) -> str:
    """取真实来源 IP。

    反代（Lucky / Cloudflare）后面必须看 X-Forwarded-For，否则所有请求
    的 IP 都是反代的地址，限速会把所有人一起锁死。
    ⚠️ 这个头是客户端可伪造的 —— 所以它只用来做「限速分桶」，绝不用于授权判断。
    """
    xff = request.headers.get("x-forwarded-for", "") or ""
    first = xff.split(",")[0].strip()
    if first:
        return first
    real = (request.headers.get("x-real-ip", "") or "").strip()
    if real:
        return real
    # 两个头都没有、或者是空串 → 回退到 socket 对端。
    # 不要返回 "unknown"：那会把所有这类客户端挤进同一个限速桶，
    # 一个人被锁会连累其他人。
    return getattr(request.client, "host", None) or "unknown"
