"""Gotify 推送。

用 Gotify 的 REST 接口 POST /message，鉴权走 X-Gotify-Key 头。
推送失败不影响主流程，只记一条事件。
"""

from __future__ import annotations

import time

import httpx

# Gotify 的 priority 语义：0~3 安静，4~7 普通，8+ 会常驻通知
PRIORITY = {
    "info": 2,
    "success": 4,
    "warn": 7,
    "error": 9,
}

# ★ 相同内容的**去重窗口**（秒）。同一段 (标题, 正文, 级别) 在窗口内只推一次。
#
# 为什么必须有这一层：2026-11-13 凌晨 mefrp 改了接口（不再接受空端口），
# 故障转移每次都在同一处失败，于是「同一句话」被每轮巡检推一次 —— 一晚上
# 几百条一模一样的 Gotify，把真正要看的东西全埋了。上游已经加了冷却退避，
# 这里是**最后一道闸**：不管调用方怎么循环，重复的同一句话不会连续轰炸。
#
# 不同级别给不同窗口：error 最吵也该最少重复（30 分钟一次足够提醒），
# success/info 只是一次性告知，重复没有意义。
DEDUPE_WINDOWS = {
    "error": 1800.0,
    "warn": 900.0,
    "success": 120.0,
    "info": 120.0,
}


class Notifier:
    def __init__(self, base_url: str = "", token: str = "", timeout: float = 10.0):
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = (token or "").strip()
        self.timeout = timeout
        # key -> 上次真正发出去的时刻（monotonic）。只存内存：重启后重新计数，
        # 最多多推一条，不影响正确性。
        self._sent_at: dict[tuple[str, str, str], float] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.token)

    def configure(self, base_url: str, token: str) -> None:
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = (token or "").strip()

    def _is_duplicate(self, title: str, message: str, level: str) -> bool:
        """窗口内是否已经推过一模一样的一条。"""
        key = (level, title[:200], message[:4000])
        last = self._sent_at.get(key)
        if last is None:
            return False
        return time.monotonic() - last < DEDUPE_WINDOWS.get(level, 300.0)

    def _mark_sent(self, title: str, message: str, level: str) -> None:
        """记下「这条推出去了」。

        ⚠️ 只在**拿到响应之后**记，不在发送前记：Gotify 短暂不可用时如果提前
        记账，窗口内这条消息就永远补不上了。发送异常（连接失败）不记账，
        下一次调用会正常重试。
        """
        now = time.monotonic()
        self._sent_at[(level, title[:200], message[:4000])] = now
        # 顺手清理过期键，避免长跑实例里无限增长（key 里含完整正文）。
        if len(self._sent_at) > 256:
            self._sent_at = {
                k: v for k, v in self._sent_at.items()
                if now - v < DEDUPE_WINDOWS.get(k[0], 300.0)
            }

    async def send(self, title: str, message: str, level: str = "info") -> bool:
        if not self.enabled:
            return False
        if self._is_duplicate(title, message, level):
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
        except httpx.HTTPError:
            return False
        # Gotify 有响应（哪怕 4xx）就算「这条已经处理过」，别在下一轮重复推。
        self._mark_sent(title, message, level)
        return resp.status_code < 300

    async def ping(self) -> dict:
        if not self.base_url:
            return {"ok": False, "error": "未配置 Gotify 地址"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/health")
            return {"ok": resp.status_code < 300, "status": resp.status_code}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
