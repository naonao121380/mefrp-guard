# -*- coding: utf-8 -*-
"""通知防刷护栏（Gotify 是接给人的，刷屏 = 让提醒失效）。

背景：2026-11-13 凌晨一次接口改版，故障转移在同一处反复失败，一晚上推了几百条
一模一样的 Gotify。事后复盘发现两个设计缺陷：

  1. 去重键是**正文哈希** —— 正文里带着冷却秒数（每次退避都变）、端口号、
     节点名，于是「同一句话」每次都算出不同的键，去重形同虚设；
  2. 只有时间窗去重 —— 一个持续一夜的故障会老老实实每 30 分钟报一次。

本文件钉住现在的三层护栏：

  [A] 稳定 key：正文变了也只发一条（这是刷屏能穿过去的关键）
  [B] 情形语义：reset() 之后才能再报
  [C] 全局限流：不管调用方怎么写，单位时间内的条数有硬上限
  [D] 发送失败：短退避重试，不吞掉整个窗口，也不会打成死循环
  [E] 用户主动发的测试消息 force=True 绕过所有护栏

⚠️ 全程不碰外网：`httpx.AsyncClient` 换成了记录器。
"""

from __future__ import annotations

import asyncio
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import notifier as N  # noqa: E402
from app.notifier import Notifier  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, extra: object = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  ->  {extra}")


# ---------------- 假 httpx（只实现用到的部分）----------------
class _Resp:
    def __init__(self, code: int = 200):
        self.status_code = code


class _FakeClient:
    posts: list[dict] = []
    raise_exc: Exception | None = None
    status: int = 200

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        if _FakeClient.raise_exc is not None:
            raise _FakeClient.raise_exc
        _FakeClient.posts.append(json or {})
        return _Resp(_FakeClient.status)

    async def get(self, url):
        return _Resp(200)


class _FakeHTTPX:
    AsyncClient = _FakeClient
    HTTPError = ConnectionError


N.httpx = _FakeHTTPX()  # type: ignore[assignment]


def fresh() -> Notifier:
    _FakeClient.posts = []
    _FakeClient.raise_exc = None
    _FakeClient.status = 200
    return Notifier("http://gotify.local", "tk")


def send(n: Notifier, msg: str, *, key=None, force=False, level="error"):
    return asyncio.run(n.send("⚠️ 隧道切换失败：ikuai_ovpn", msg, level,
                              key=key, force=force))


# ===========================================================================
# [A] 稳定 key：正文变了也只发一条
# ===========================================================================
print("[A] 稳定 key：同一个情形只发一条（正文里的秒数/端口不能影响判定）")

n = fresh()
ok1 = send(n, "已进入冷却（第 1 次连续失败，下次重试前等 5 分）", key="t12:failover-fail")
ok2 = send(n, "已进入冷却（第 2 次连续失败，下次重试前等 10 分）", key="t12:failover-fail")
ok3 = send(n, "已进入冷却（第 3 次连续失败，下次重试前等 20 分）", key="t12:failover-fail")
check("★ 正文每次都不一样，但同 key 只真的发出去 1 条", len(_FakeClient.posts) == 1,
      len(_FakeClient.posts))
check("第一次算发出（True）", ok1 is True)
check("后两次被判定为重复（False + duplicate）",
      ok2 is False and ok3 is False and n.last_reason == "duplicate", n.last_reason)

send(n, "完全不同的一件事", key="t12:paused")
check("不同 key -> 照常发", len(_FakeClient.posts) == 2, len(_FakeClient.posts))

n_nokey = fresh()
send(n_nokey, "原因 A")
send(n_nokey, "原因 B")
check("不传 key 时退回正文哈希（正文不同 = 两条，这是兜底不是推荐）",
      len(_FakeClient.posts) == 2, len(_FakeClient.posts))

# ===========================================================================
# [B] 情形语义：reset 之后才能再报
# ===========================================================================
print("[B] reset()：条件恢复后重新武装")

n = fresh()
send(n, "隧道离线", key="t7:probe-fail")
send(n, "隧道离线", key="t7:probe-fail")
check("窗口内重复 -> 1 条", len(_FakeClient.posts) == 1, len(_FakeClient.posts))
n.reset("t7:probe-fail")
send(n, "隧道离线", key="t7:probe-fail")
check("★ 恢复后再次故障 -> 允许第二条", len(_FakeClient.posts) == 2,
      len(_FakeClient.posts))

# ===========================================================================
# [C] 全局限流
# ===========================================================================
print("[C] 全局限流：不管调用方怎么写，条数有硬上限")

n = fresh()
results = [send(n, f"第 {i} 条不同的事", key=f"k{i}") for i in range(16)]
sent_ok = sum(1 for r in results if r)
check("一分钟内第 11 条起被丢弃（上限 10）", sent_ok == 10, sent_ok)
check("被丢弃的会记数", n.suppressed == 6, n.suppressed)
check("★ 被限流时额外推**一条**汇总提示（不是每条都推）",
      len(_FakeClient.posts) == 11, len(_FakeClient.posts))
check("汇总提示的标题是「通知已被限流」",
      "限流" in _FakeClient.posts[-1]["title"], _FakeClient.posts[-1]["title"])
check("last_reason = rate_limited", n.last_reason == "rate_limited", n.last_reason)

n2 = fresh()
n2._limit_notice_at = time.monotonic() - 10     # 一小时内已经提示过
r = [send(n2, f"x{i}", key=f"y{i}") for i in range(14)]
check("限流提示本身也是一小时一条（不会自己变成刷屏源）",
      len(_FakeClient.posts) == 10, len(_FakeClient.posts))

# 窗口滑过去之后要能恢复：把发送日志整体往前挪 61 秒
n3 = fresh()
[send(n3, f"a{i}", key=f"z{i}") for i in range(10)]
check("先用满 10 条", sum(1 for t in n3._sent_log) == 10, len(n3._sent_log))
n3._sent_log = type(n3._sent_log)(t - 61 for t in n3._sent_log)
check("★ 一分钟窗口滑过后恢复发送", send(n3, "第 11 条", key="z11") is True)

# ===========================================================================
# [D] 发送失败：短退避，不吞窗口
# ===========================================================================
print("[D] 发送失败：60 秒短退避 + 可重试")

n = fresh()
_FakeClient.raise_exc = ConnectionError("boom")
r1 = send(n, "隧道离线", key="t9:probe-fail")
check("连不上 -> 返回 False", r1 is False)
check("last_reason = error（调用方据此判断「还没发出去」）",
      n.last_reason == "error", n.last_reason)
check("★ 传输失败不进「已发」账本（否则这条告警会被吞掉整个窗口）",
      "t9:probe-fail" not in n._sent_at)
_FakeClient.raise_exc = None
r2 = send(n, "隧道离线", key="t9:probe-fail")
check("60 秒退避内不立刻重打", r2 is False and n.last_reason == "duplicate", n.last_reason)
n._fail_at["t9:probe-fail"] = time.monotonic() - 61
check("★ 退避过后可以正常补发", send(n, "隧道离线", key="t9:probe-fail") is True)

n = fresh()
_FakeClient.status = 500
send(n, "隧道离线", key="t9:probe-fail")
check("Gotify 5xx -> last_reason = http_error", n.last_reason == "http_error", n.last_reason)
check("★ 有响应（哪怕失败）就算处理过，窗口内不再重打",
      "t9:probe-fail" in n._sent_at)

n = fresh()
_FakeClient.raise_exc = ConnectionError("boom")
send(n, "先断一次", key="a")
_FakeClient.raise_exc = None
_FakeClient.status = 500
send(n, "再来一次 5xx", key="b")
check("★ 上一次的 error 不会残留（5xx 必须判成 http_error，不能当连不上）",
      n.last_reason == "http_error", n.last_reason)

# ===========================================================================
# [E] 用户主动的测试消息
# ===========================================================================
print("[E] force=True：用户点按钮发测试消息，不能被吞")

n = fresh()
send(n, "测试", key="test", force=True)
send(n, "测试", key="test", force=True)
check("★ 连点两次测试消息，两条都发出去", len(_FakeClient.posts) == 2,
      len(_FakeClient.posts))

print()
print(f"PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
