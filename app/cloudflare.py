"""Cloudflare DNS 客户端。

只用 DNS 相关的几个接口，Token 权限要 Zone.DNS:Edit。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

API = "https://api.cloudflare.com/client/v4"

# 只对**传输层**错误重试：连不上 / 超时 / 连接被重置 / 代理挂了。
# HTTP 状态码错误（401/403/5xx）重试没有意义 —— 那是请求本身的问题，
# 再打十次也是同样的结果，只会把日志和配额一起浪费掉。
_TRANSIENT = (httpx.TransportError,)

# 「调用方没提这个参数」的哨兵。不能拿 None 代替 —— None 是有意义的取值
# （「我查过了，这个记录名底下什么都没有」），两者必须能区分开。
_UNSET: Any = object()


class CloudflareError(Exception):
    """Cloudflare 调用失败。

    `transient=True` 表示失败发生在**传输层**（重试完了还是连不上 / 超时）。
    调用方据此决定这条失败记成 `warn` 还是 `error`：一次网络抖动就往事件日志
    里写红色「异常」，看起来就像 DNS 功能坏了 —— 而实际上下一轮就好了。
    """

    def __init__(self, message: str, transient: bool = False):
        super().__init__(message)
        self.transient = bool(transient)


class CloudflareAuthError(CloudflareError):
    """Token 缺失 / 无效 / 权限不够。属于**静态配置问题**，不是「这条隧道此刻
    解析失败了」，所以调用方通常连事件都不该记（见 engine._sync_dns）。"""


@dataclass
class DnsRecord:
    record_id: str
    zone_id: str
    name: str
    type: str
    content: str
    proxied: bool
    ttl: int = 1


@dataclass
class Zone:
    zone_id: str
    name: str


class CloudflareClient:
    def __init__(self, token: str, timeout: float = 15.0,
                 retries: int = 2, backoff: float = 0.6,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.token = (token or "").strip()
        self.timeout = timeout
        # 传输层失败额外重试几次。`retries=2` = 一次调用最多打 3 次。
        self.retries = max(0, int(retries))
        self.backoff = max(0.0, float(backoff))
        # 只在测试里注入（假的传输层），生产走默认。
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._loop: Any = None

    # -- 连接池 -------------------------------------------------------------

    def _http(self) -> httpx.AsyncClient:
        """拿一个**可复用**的连接池。

        ⚠️ 原来这里写的是 `async with httpx.AsyncClient(...)` —— **每个请求
        新建一个**。而一次 DNS 同步最多要打 3 个请求（`list_records` →
        `upsert` 里的 `list_records` → `PUT`），也就是 3 次全新的 DNS 解析 +
        TCP + TLS 握手，彼此不复用；偏偏巡检每 20 秒就来一轮。

        从国内连 Cloudflare，一次 TLS 握手几百毫秒到一秒多很正常，握手次数
        直接放大了「握手中途超时」的概率 —— 事件日志里那些成对的
        ConnectTimeout / ReadTimeout 就是这么来的（本机还有个
        `http_proxy=127.0.0.1:51140` 的本地代理，它抖一下更是必中）。
        复用之后一次握手能撑很多轮，重试也才有意义：失败的那条连接会被丢弃，
        下一次重试换一条新的。

        ⚠️ 为什么要比 `_loop`：测试里每个用例一次 `asyncio.run()`，也就是**一个
        新的事件循环**，连接池不能跨循环复用（否则炸在 "attached to a different
        loop"）。生产只有一个循环，所以这个判断平时永远不触发。
        """
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._client = httpx.AsyncClient(timeout=self.timeout,
                                             transport=self._transport)
            self._loop = loop
        return self._client

    async def aclose(self) -> None:
        """关掉连接池。被替换掉的客户端一定要调这个，否则连接会一直挂着。"""
        client, self._client = self._client, None
        self._loop = None
        if client is None:
            return
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 - 关连接池失败不值得惊动调用方
            pass

    async def _request(self, method: str, path: str,
                       json_body: dict | None = None,
                       params: dict | None = None) -> Any:
        if not self.token:
            raise CloudflareAuthError("尚未配置 Cloudflare API Token")

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        url = f"{API}{path}"

        # 传输层失败退避重试。attempt 从 1 起，超过 retries 就放弃。
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._http().request(
                    method, url, headers=headers, json=json_body, params=params
                )
                break
            except _TRANSIENT as exc:
                # ⚠️ 必须带上异常**类型**：httpx 的超时类异常 str() 常常是空串，
                #    只拼 {exc} 的话事件日志里就只剩一句「请求 Cloudflare 失败：」，
                #    完全看不出是超时、连不上、还是代理挂了 —— 这坑真踩过。
                if attempt > self.retries:
                    raise CloudflareError(
                        f"请求 Cloudflare 失败（已重试 {self.retries} 次）："
                        f"{type(exc).__name__}: {exc}",
                        transient=True,
                    ) from exc
                await asyncio.sleep(self.backoff * attempt)
            except httpx.HTTPError as exc:
                # 非传输层的 httpx 错误（URL 写错、协议不支持之类）—— 重试无益。
                raise CloudflareError(
                    f"请求 Cloudflare 失败：{type(exc).__name__}: {exc}"
                ) from exc

        try:
            payload = resp.json()
        except ValueError as exc:
            raise CloudflareError(
                f"Cloudflare 返回非 JSON（HTTP {resp.status_code}）：{resp.text[:200]}"
            ) from exc

        if not payload.get("success"):
            errors = payload.get("errors") or []
            msg = "; ".join(
                f"[{e.get('code')}] {e.get('message')}" for e in errors
            ) or f"HTTP {resp.status_code}"
            if resp.status_code in (401, 403):
                raise CloudflareAuthError(msg)
            raise CloudflareError(msg)

        return payload.get("result")

    # -- zone ---------------------------------------------------------------

    async def list_zones(self) -> list[Zone]:
        result = await self._request("GET", "/zones", params={"per_page": 50}) or []
        return [
            Zone(zone_id=str(z.get("id")), name=str(z.get("name")))
            for z in result if isinstance(z, dict)
        ]

    async def resolve_zone(self, record_name: str) -> Zone | None:
        """按记录名找出它属于哪个 zone（取最长匹配后缀）。"""
        name = record_name.strip().lower().rstrip(".")
        zones = await self.list_zones()
        best: Zone | None = None
        for z in zones:
            zn = z.name.lower()
            if name == zn or name.endswith("." + zn):
                if best is None or len(zn) > len(best.name):
                    best = z
        return best

    # -- dns ----------------------------------------------------------------

    async def list_records(self, zone_id: str, name: str | None = None) -> list[DnsRecord]:
        params: dict[str, Any] = {"per_page": 100}
        if name:
            params["name"] = name
        result = await self._request(
            "GET", f"/zones/{zone_id}/dns_records", params=params
        ) or []
        return [
            DnsRecord(
                record_id=str(r.get("id")),
                zone_id=str(r.get("zone_id") or zone_id),
                name=str(r.get("name")),
                type=str(r.get("type")),
                content=str(r.get("content")),
                proxied=bool(r.get("proxied")),
                ttl=int(r.get("ttl") or 1),
            )
            for r in result if isinstance(r, dict)
        ]

    async def upsert(self, *, zone_id: str, name: str, record_type: str,
                     content: str, proxied: bool = False, ttl: int = 1,
                     record_id: str | None = None,
                     existing: Any = _UNSET) -> DnsRecord:
        """有 record_id 就更新，没有就按名字找一条同类型的更新，再没有就新建。

        `existing` 是**调用方已经查到**的那条记录（明确知道没有就传 `None`）。
        传了就不再自己去 `list_records`。

        ⚠️ 为什么要这个参数：原来的写法在写路径上一共要打 **4 个请求**
        （`_sync_dns` 查一次 → 这里按 id 查一次 → 没找到再按类型查一次 →
        写入一次），也就是 4 次全新的 TLS 握手。调用方手里明明已经有那份
        记录列表了，再查两遍纯属白花握手钱 —— 而握手恰恰是最容易超时的一步。
        传了之后写路径只剩 2 个请求。不传（默认）时行为完全不变。
        """
        target: DnsRecord | None
        if existing is not _UNSET:
            target = existing
        else:
            target = None
            if record_id:
                for r in await self.list_records(zone_id, name=name):
                    if r.record_id == record_id:
                        target = r
                        break
            if target is None:
                for r in await self.list_records(zone_id, name=name):
                    if r.type.upper() == record_type.upper():
                        target = r
                        break

        body = {
            "type": record_type.upper(),
            "name": name,
            "content": content,
            "ttl": ttl,
            "proxied": bool(proxied),
        }
        # CNAME 才能开橙云；A 记录开橙云只在 HTTP 场景有意义，交由调用方决定
        if record_type.upper() not in ("A", "AAAA", "CNAME"):
            body.pop("proxied", None)

        if target is not None:
            result = await self._request(
                "PUT", f"/zones/{zone_id}/dns_records/{target.record_id}", body
            )
        else:
            result = await self._request(
                "POST", f"/zones/{zone_id}/dns_records", body
            )
        result = result or {}
        return DnsRecord(
            record_id=str(result.get("id") or (target.record_id if target else "")),
            zone_id=zone_id,
            name=str(result.get("name") or name),
            type=str(result.get("type") or record_type),
            content=str(result.get("content") or content),
            proxied=bool(result.get("proxied")),
        )

    async def delete(self, zone_id: str, record_id: str) -> None:
        await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    async def ping(self) -> dict[str, Any]:
        zones = await self.list_zones()
        return {"ok": True, "zone_count": len(zones),
                "zones": [z.name for z in zones]}
