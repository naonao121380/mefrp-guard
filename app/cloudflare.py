"""Cloudflare DNS 客户端。

只用 DNS 相关的几个接口，Token 权限要 Zone.DNS:Edit。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

API = "https://api.cloudflare.com/client/v4"


class CloudflareError(Exception):
    pass


class CloudflareAuthError(CloudflareError):
    pass


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
    def __init__(self, token: str, timeout: float = 15.0):
        self.token = (token or "").strip()
        self.timeout = timeout

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
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(
                    method, url, headers=headers, json=json_body, params=params
                )
        except httpx.HTTPError as exc:
            # ⚠️ 必须带上异常**类型**：httpx 的超时类异常 str() 常常是空串，
            #    只拼 {exc} 的话事件日志里就只剩一句「请求 Cloudflare 失败：」，
            #    完全看不出是超时、连不上、还是 TLS 出错 —— 这坑真踩过。
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
                     record_id: str | None = None) -> DnsRecord:
        """有 record_id 就更新，没有就按名字找一条同类型的更新，再没有就新建。"""
        target: DnsRecord | None = None
        if record_id:
            existing = await self.list_records(zone_id, name=name)
            for r in existing:
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
