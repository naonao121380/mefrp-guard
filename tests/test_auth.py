# -*- coding: utf-8 -*-
"""鉴权原语的纯逻辑测试：密码哈希 / 会话令牌 / 登录防爆破。

不依赖任何第三方库，也不碰数据库 —— 可以直接跑：

    python tests/test_auth.py

这一层是安全边界，所以断言写得比较死：不只测「对不对」，还测
「参数被篡改/被清空时是否安全地失败」。
"""

from __future__ import annotations

import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import auth  # noqa: E402

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
# 密码哈希
# ===========================================================================

def test_hash() -> None:
    print("[hash] 密码哈希")

    h1, s1, i1 = auth.hash_password("hunter2hunter2")
    h2, s2, i2 = auth.hash_password("hunter2hunter2")

    check("返回三段（hash/salt/iterations）", all([h1, s1, i1]), (h1[:8], s1[:8], i1))
    check("hash 是 64 位 hex（SHA-256 输出长度）", len(h1) == 64 and all(c in "0123456789abcdef" for c in h1), len(h1))
    check("salt 是 32 位 hex（16 字节）", len(s1) == 32, len(s1))
    check("迭代次数是默认值", i1 == auth.DEFAULT_ITERATIONS, i1)

    # ★ 关键：同一个密码两次哈希必须不同（否则说明盐没随机）
    check("★ 同一密码两次哈希不同（盐是随机的）", h1 != h2 and s1 != s2, (h1[:12], h2[:12]))
    check("★ 同一密码两次的盐不同", s1 != s2)

    check("正确密码验得过", auth.verify_password("hunter2hunter2", hash_hex=h1, salt_hex=s1, iterations=i1))
    check("错误密码验不过", not auth.verify_password("hunter2hunter3", hash_hex=h1, salt_hex=s1, iterations=i1))
    check("空密码验不过", not auth.verify_password("", hash_hex=h1, salt_hex=s1, iterations=i1))
    check("密码大小写敏感", not auth.verify_password("HUNTER2HUNTER2", hash_hex=h1, salt_hex=s1, iterations=i1))
    check("另一个盐上验不过（盐确实参与了运算）",
          not auth.verify_password("hunter2hunter2", hash_hex=h1, salt_hex=s2, iterations=i1))

    # 指定盐时必须可复现 —— 这是「调高迭代数后老密码仍能验证」的基础
    h3, s3, i3 = auth.hash_password("abc", salt=s1, iterations=1000)
    h4, s4, i4 = auth.hash_password("abc", salt=s1, iterations=1000)
    check("指定盐时结果可复现", (h3, s3, i3) == (h4, s4, i4))
    check("指定盐时用的是给定盐", s3 == s1)

    # ★ 迭代次数必须真的参与运算，且能被独立验证
    hA, sA, _ = auth.hash_password("abc", salt=s1, iterations=1000)
    hB, sB, _ = auth.hash_password("abc", salt=s1, iterations=2000)
    check("★ 1000 轮与 2000 轮结果不同", hA != hB)
    check("用正确的迭代数验得过", auth.verify_password("abc", hash_hex=hA, salt_hex=sA, iterations=1000))
    check("★ 用错误的迭代数验不过", not auth.verify_password("abc", hash_hex=hA, salt_hex=sA, iterations=2000))


def test_hash_degrades_safely() -> None:
    """参数缺失/损坏时必须安全失败，不能抛异常、更不能误判为通过。"""
    print("[hash] 异常输入的安全降级")

    for name, kw in [
        ("空 hash", dict(hash_hex="", salt_hex="aa" * 16, iterations=1000)),
        ("空 salt", dict(hash_hex="bb" * 32, salt_hex="", iterations=1000)),
        ("迭代数为 0", dict(hash_hex="bb" * 32, salt_hex="aa" * 16, iterations=0)),
        ("salt 不是合法 hex", dict(hash_hex="bb" * 32, salt_hex="zzzz", iterations=1000)),
        ("hash 不是合法 hex", dict(hash_hex="nothex", salt_hex="aa" * 16, iterations=1000)),
    ]:
        try:
            got = auth.verify_password("whatever", **kw)
            check(f"{name} -> 安全返回 False", got is False, got)
        except Exception as exc:  # noqa: BLE001
            check(f"{name} -> 安全返回 False", False, f"抛了 {exc!r}")

    # 迭代数为负也不能崩
    try:
        auth.hash_password("x", salt="aa" * 16, iterations=-5)
        check("负迭代数不抛异常（被夹到 1）", True)
    except Exception as exc:  # noqa: BLE001
        check("负迭代数不抛异常（被夹到 1）", False, repr(exc))


def test_default_password_detection() -> None:
    print("[hash] 默认密码识别")

    h, s, i = auth.hash_password(auth.DEFAULT_PASSWORD)
    check("★ 默认密码能被识别出来", auth.is_default_password(h, s, i) is True)

    h2, s2, i2 = auth.hash_password("something-else-1234")
    check("★ 改过的密码不会被误判为默认", auth.is_default_password(h2, s2, i2) is False)

    check("空参数不崩、返回 False", auth.is_default_password("", "", 0) is False)
    check("默认用户名是 admin", auth.DEFAULT_USER == "admin")
    check("默认密码是 admin123", auth.DEFAULT_PASSWORD == "admin123")


# ===========================================================================
# 会话令牌
# ===========================================================================

def test_token() -> None:
    print("[token] 会话令牌")

    t1, t2 = auth.new_token(), auth.new_token()
    check("两次生成的令牌不同", t1 != t2)
    check("令牌足够长（≥32 字符）", len(t1) >= 32, len(t1))
    check("令牌是 URL 安全的（无 +/= 等）",
          all(c.isalnum() or c in "-_" for c in t1), t1)

    f1 = auth.token_fingerprint(t1)
    check("指纹是 64 位 hex", len(f1) == 64 and all(c in "0123456789abcdef" for c in f1), len(f1))
    check("同一令牌指纹稳定", f1 == auth.token_fingerprint(t1))
    check("★ 不同令牌指纹不同", f1 != auth.token_fingerprint(t2))
    check("★ 指纹里不含令牌原文", t1 not in f1)

    check("same() 相同为真", auth.same("abc", "abc") is True)
    check("same() 不同为假", auth.same("abc", "abd") is False)
    check("same() 长度不同为假", auth.same("abc", "abcd") is False)
    check("same() 空串不崩", auth.same("", "") is True)
    check("same() None 不崩", auth.same(None, "") is True)


# ===========================================================================
# 登录防爆破
# ===========================================================================

def test_throttle() -> None:
    print("[throttle] 登录防爆破")

    th = auth.LoginThrottle()
    ip = "10.0.0.9"

    check("初始未锁定", th.is_locked(ip) is False)
    check("初始剩余锁定 0 秒", th.remaining_lock(ip) == 0)

    # max=3：第 1、2 次失败返回剩余次数，第 3 次触发锁定
    check("第 1 次失败 -> 还剩 2 次", th.record_failure(ip, max_attempts=3, lockout_seconds=60) == 2)
    check("第 2 次失败 -> 还剩 1 次", th.record_failure(ip, max_attempts=3, lockout_seconds=60) == 1)
    check("还没锁定", th.is_locked(ip) is False)
    check("★ 第 3 次失败 -> 剩余 0（触发锁定）",
          th.record_failure(ip, max_attempts=3, lockout_seconds=60) == 0)
    check("★ 已被锁定", th.is_locked(ip) is True)
    check("★ 锁定倒计时在 1~60 秒之间", 0 < th.remaining_lock(ip) <= 60, th.remaining_lock(ip))

    # 不同 IP 互不影响 —— 否则一个人爆破会把所有人锁死
    check("★ 其他 IP 不受影响", th.is_locked("10.0.0.10") is False)

    th.reset(ip)
    check("reset 后解锁", th.is_locked(ip) is False)
    check("★ reset 后计数也清零（不是只解锁）",
          th.record_failure(ip, max_attempts=3, lockout_seconds=60) == 2)
    th.reset(ip)

    # 锁定时间已过 -> 自动解锁
    th2 = auth.LoginThrottle()
    th2.record_failure("1.1.1.1", max_attempts=1, lockout_seconds=1)
    check("max=1 时一次失败就锁", th2.is_locked("1.1.1.1") is True)
    time.sleep(1.2)
    check("★ 锁定时间过后自动解锁", th2.is_locked("1.1.1.1") is False)

    # 窗口过期：很久以前的失败不该把现在的正常用户锁掉
    th3 = auth.LoginThrottle()
    th3.record_failure("2.2.2.2", max_attempts=3, lockout_seconds=60, window_seconds=1)
    time.sleep(1.2)
    check("★ 超出统计窗口的旧失败被清掉",
          th3.record_failure("2.2.2.2", max_attempts=3, lockout_seconds=60, window_seconds=1) == 2)

    th.clear_all()
    check("clear_all 清空全部", th.is_locked(ip) is False and th.is_locked("10.0.0.10") is False)

    # max_attempts=0/负数不能变成「永不锁定」，也不能变成「永远锁定」
    th4 = auth.LoginThrottle()
    check("max_attempts=0 被夹到 1（一次就锁）",
          th4.record_failure("3.3.3.3", max_attempts=0, lockout_seconds=60) == 0
          and th4.is_locked("3.3.3.3") is True)


def test_client_ip() -> None:
    print("[throttle] 来源 IP 解析")

    class _Req:
        def __init__(self, headers, host="127.0.0.1"):
            self.headers = headers
            class _C: pass
            c = _C(); c.host = host
            self.client = c

    check("X-Forwarded-For 优先，且只取第一个",
          auth.client_ip(_Req({"x-forwarded-for": "1.2.3.4, 5.6.7.8"})) == "1.2.3.4")
    check("没有 XFF 时用 X-Real-IP",
          auth.client_ip(_Req({"x-real-ip": "9.9.9.9"})) == "9.9.9.9")
    check("都没有时用 socket 对端地址",
          auth.client_ip(_Req({}, host="7.7.7.7")) == "7.7.7.7")
    check("XFF 为空串时回退", auth.client_ip(_Req({"x-forwarded-for": "  "}, host="8.8.8.8")) == "8.8.8.8")


if __name__ == "__main__":
    test_hash()
    test_hash_degrades_safely()
    test_default_password_detection()
    test_token()
    test_throttle()
    test_client_ip()
    print(f"\n==> PASS {PASS} / FAIL {FAIL}")
    sys.exit(1 if FAIL else 0)
