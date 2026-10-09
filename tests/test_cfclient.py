# -*- coding: utf-8 -*-
"""Cloudflare 客户端：连接复用 / 传输层重试 / transient 分类。

⚠️ 这个文件**必须用真的 httpx** —— 它要验的就是 httpx 交互本身（重试了几次、
   连接池有没有复用、异常有没有被正确分类），拿桩替掉就什么都没验到了。
   所以它需要 httpx（其余纯逻辑测试不需要）：

       PYTHONPATH=.devdeps python tests/test_cfclient.py

这里钉住的三件事，都对应真实踩过的坑：

  1. **每次请求都新建连接池** —— 一次 DNS 同步最多 3 个请求 = 3 次全新 TLS
     握手（写路径上原来是 4 个），而巡检每 20 秒就来一轮。国内到 Cloudflare
     一次握手几百毫秒到一秒多，握手次数直接放大了「握手中途超时」的概率。
  2. **零重试** —— 网络抖一下整条同步就失败，事件日志里出现红色「更新 DNS
     失败」，而下一轮立刻又好了。看起来就像 DNS 功能坏了。
  3. **不区分「瞬时失败」和「配置错误」** —— 两者都被记成 error，用户没法从
     日志里分辨「等一下就好」和「你得去改配置」。
"""

from __future__ import annotations

import asyncio
import pathlib
import sys

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.cloudflare import (  # noqa: E402
    CloudflareAuthError,
    CloudflareClient,
    CloudflareError,
    DnsRecord,
)

PASS = 0
FAIL = 0


def check(label: str, cond: bool) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \u2705 {label}")
    else:
        FAIL += 1
        print(f"  \u274c {label}")


class FakeTransport(httpx.AsyncBaseTransport):
    """可控的假传输层。

    · 前 `fail` 次抛 `exc`，之后正常返回 `payload`；
    · 记下被调用了几次（= 真正打出去几个请求），这是本文件最主要的观测量。
    """

    def __init__(self, fail: int = 0, exc=None, payload=None,
                 status: int = 200, by_method=None):
        self.fail = fail
        self.exc = exc or httpx.ConnectTimeout
        self.payload = (payload if payload is not None
                        else {"success": True, "result": []})
        self.status = status
        # 按 HTTP 方法给不同的响应体。列表接口（GET）返回数组、写入接口
        # （POST/PUT）返回单个对象 —— 一个 payload 糊不了两种形状。
        self.by_method = by_method or {}
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        if self.calls <= self.fail:
            raise self.exc(f"假的 {self.exc.__name__}")
        body = self.by_method.get(request.method, self.payload)
        return httpx.Response(self.status, json=body, request=request)


class NotTransient(httpx.HTTPError):
    """一个**不是**传输层的 httpx 错误。

    真实世界里这条分支对应「URL 写错 / 协议不支持」之类 —— 重试一百次也是
    同样的结果。这里用自定义子类造出来，是因为 httpx 自带的非传输层错误
    （TooManyRedirects 之类）没法从传输层直接抛。
    """


def main() -> int:
    print("=== Cloudflare 客户端：连接复用 / 重试 / transient 分类 ===")

    # ------------------------------------------------------------------
    print("  --- ★ 传输层失败会退避重试 ---")
    t = FakeTransport(fail=2, exc=httpx.ConnectTimeout)
    c = CloudflareClient("tok", retries=2, backoff=0.0, transport=t)
    zones = asyncio.run(c.list_zones())
    check("★ 前 2 次 ConnectTimeout 之后第 3 次成功", t.calls == 3)
    check("返回值正常解析", zones == [])

    t = FakeTransport(fail=1, exc=httpx.ReadTimeout)
    c = CloudflareClient("tok", retries=2, backoff=0.0, transport=t)
    asyncio.run(c.list_zones())
    check("只抖 1 次时第 2 次就成功（不用等满重试次数）", t.calls == 2)

    # ------------------------------------------------------------------
    print("  --- 重试耗尽：抛错、带类型名、标 transient ---")
    t = FakeTransport(fail=99, exc=httpx.ReadTimeout)
    c = CloudflareClient("tok", retries=1, backoff=0.0, transport=t)
    err: CloudflareError | None = None
    try:
        asyncio.run(c.list_zones())
    except CloudflareError as exc:  # noqa: BLE001 - 这就是被测行为
        err = exc
    check("★ 重试耗尽后抛 CloudflareError", err is not None)
    check("★ transient=True（调用方据此记 warn 而不是红色 error）",
          err is not None and err.transient is True)
    check("★ 消息里带异常**类型名**（否则日志只剩一句空话）",
          err is not None and "ReadTimeout" in str(err))
    check("尝试次数 = retries + 1 = 2", t.calls == 2)

    t = FakeTransport(fail=99)
    c = CloudflareClient("tok", retries=0, backoff=0.0, transport=t)
    try:
        asyncio.run(c.list_zones())
    except CloudflareError:
        pass
    check("retries=0 → 老老实实只打 1 次", t.calls == 1)

    # ------------------------------------------------------------------
    print("  --- 不该重试的错误：一次就放弃 ---")
    t = FakeTransport(fail=99, exc=NotTransient)
    c = CloudflareClient("tok", retries=2, backoff=0.0, transport=t)
    err = None
    try:
        asyncio.run(c.list_zones())
    except CloudflareError as exc:  # noqa: BLE001
        err = exc
    check("★ 非传输层错误**不**重试（重试也没用）", t.calls == 1)
    check("非传输层错误 transient=False", err is not None and err.transient is False)

    # Cloudflare 返回 5xx / success=false：业务错误，同样不重试。
    t = FakeTransport(payload={"success": False,
                               "errors": [{"code": 10000, "message": "内部错误"}]},
                      status=500)
    c = CloudflareClient("tok", retries=2, backoff=0.0, transport=t)
    err = None
    try:
        asyncio.run(c.list_zones())
    except CloudflareError as exc:  # noqa: BLE001
        err = exc
    check("HTTP 500 + success=false 不重试", t.calls == 1)
    check("业务错误 transient=False，消息里带 Cloudflare 的 code/message",
          err is not None and err.transient is False
          and "10000" in str(err) and "内部错误" in str(err))

    # ------------------------------------------------------------------
    print("  --- ★ 连接池复用（原来每个请求都新建）---")
    created: list[int] = []
    _real_client = httpx.AsyncClient

    class CountingClient(_real_client):  # type: ignore[misc,valid-type]
        def __init__(self, *a, **k):
            created.append(1)
            super().__init__(*a, **k)

    httpx.AsyncClient = CountingClient  # type: ignore[misc]
    try:
        t = FakeTransport()
        c = CloudflareClient("tok", transport=t)

        async def three_requests():
            await c.list_zones()
            await c.list_zones()
            await c.list_zones()

        asyncio.run(three_requests())
    finally:
        httpx.AsyncClient = _real_client  # type: ignore[misc]

    check("★ 3 个请求只建了 1 个连接池（原来是 3 个 = 3 次 TLS 握手）",
          len(created) == 1)
    check("3 个请求确实都打出去了", t.calls == 3)

    # 跨事件循环必须重建：测试里每个用例一次 asyncio.run()（= 一个新循环），
    # 复用旧池子会炸在 "attached to a different loop"。生产只有一个循环，
    # 所以这个判断平时永远不触发 —— 但它是测试能跑起来的前提。
    t = FakeTransport()
    c = CloudflareClient("tok", transport=t)

    async def grab():
        return c._http()

    a = asyncio.run(grab())
    b = asyncio.run(grab())
    check("★ 换事件循环会重建连接池（否则炸 attached to a different loop）",
          a is not b)

    # ------------------------------------------------------------------
    print("  --- ★ upsert 不再自查两遍 ---")
    ok_body = {"success": True,
               "result": {"id": "rec1", "name": "a.example.com",
                          "type": "A", "content": "1.2.3.4", "proxied": False}}
    existing = DnsRecord(record_id="rec1", zone_id="z", name="a.example.com",
                         type="A", content="9.9.9.9", proxied=False)

    t = FakeTransport(payload=ok_body)
    c = CloudflareClient("tok", transport=t)
    asyncio.run(c.upsert(zone_id="z", name="a.example.com", record_type="A",
                         content="1.2.3.4", existing=existing))
    check("★ 传了 existing → 只打 1 个请求（PUT），不再 list_records 两遍",
          t.calls == 1)

    t = FakeTransport(payload={"success": True, "result": []},
                      by_method={"POST": ok_body})
    c = CloudflareClient("tok", transport=t)
    asyncio.run(c.upsert(zone_id="z", name="a.example.com", record_type="A",
                         content="1.2.3.4"))
    check("不传 existing → 保留老行为（自查一遍 + 新建）", t.calls == 2)

    # 老调用方（只给 record_id）保留原行为：按 id 查一遍 → 命中 → PUT，2 个请求。
    ok_list = {"success": True, "result": [
        {"id": "rec1", "zone_id": "z", "name": "a.example.com",
         "type": "A", "content": "9.9.9.9", "proxied": False}]}
    t = FakeTransport(payload=ok_list, by_method={"PUT": ok_body})
    c = CloudflareClient("tok", transport=t)
    asyncio.run(c.upsert(zone_id="z", name="a.example.com", record_type="A",
                         content="1.2.3.4", record_id="rec1"))
    check("只给 record_id（老调用方）→ 按 id 查一遍 + PUT", t.calls == 2)

    # 按 id 找不到时还要**再按类型查一遍** —— 这就是「写路径 4 个请求」的来源，
    # 也正是传 existing 能省掉的那两个。
    t = FakeTransport(payload=ok_list, by_method={"PUT": ok_body})
    c = CloudflareClient("tok", transport=t)
    asyncio.run(c.upsert(zone_id="z", name="a.example.com", record_type="A",
                         content="1.2.3.4", record_id="已经失效的id"))
    check("★ 按 id 找不到 → 再按类型查一遍（老行为 = 3 个请求）", t.calls == 3)

    # ------------------------------------------------------------------
    print("  --- 没配 token：一个请求都不发 ---")
    t = FakeTransport()
    c = CloudflareClient("", transport=t)
    err = None
    try:
        asyncio.run(c.list_zones())
    except CloudflareAuthError as exc:  # noqa: BLE001
        err = exc
    check("★ 没配 token 直接抛 CloudflareAuthError，不打请求", t.calls == 0)
    check("CloudflareAuthError 是 CloudflareError 的子类，且 transient=False",
          err is not None and isinstance(err, CloudflareError)
          and err.transient is False)
    check("token 两侧空白被 strip 掉（' ' 也算没配）",
          CloudflareClient("   ").token == ""
          and CloudflareClient("  tok  ").token == "tok")

    print()
    print(f"  断言 {PASS + FAIL} 条，通过 {PASS}，失败 {FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
