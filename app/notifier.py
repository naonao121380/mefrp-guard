"""Gotify 推送。

用 Gotify 的 REST 接口 POST /message，鉴权走 X-Gotify-Key 头。
推送失败不影响主流程，只记一条事件。
"""

from __future__ import annotations

import httpx

# Gotify 的 priority 语义：0~3 安静，4~7 普通，8+ 会常驻通知
PRIORITY = {
    "info": 2,
    "success": 4,
    "warn": 7,
    "error": 9,
}


class Notifier:
    def __init__(self, base_url: str = "", token: str = "", timeout: float = 10.0):
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = (token or "").strip()
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.token)

    def configure(self, base_url: str, token: str) -> None:
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = (token or "").strip()

    async def send(self, title: str, message: str, level: str = "info") -> bool:
        if not self.enabled:
            return False
        url = f"{self.base_url}/message"
        payload = {
            "title": title[:200],
            "message": message[:4000],
            "priority": PRIORITY.get(level, 4),
        }
        headers = {"X-Gotify-Key": self.token}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
            return resp.status_code < 300
        except httpx.HTTPError:
            return False

    async def ping(self) -> dict:
        if not self.base_url:
            return {"ok": False, "error": "未配置 Gotify 地址"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/health")
            return {"ok": resp.status_code < 300, "status": resp.status_code}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
