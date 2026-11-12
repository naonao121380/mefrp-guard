"""Gotify 推送 —— 带三道防刷护栏。

用 Gotify 的 REST 接口 POST /message，鉴权走 X-Gotify-Key 头。
推送失败不影响主流程，只记一条事件。

⚠️ 为什么一个「发通知」的模块要写这么多：Gotify 是接给**人**的提醒通道，
它一响就是要人放下手里的事去看。2026-11-13 凌晨 mefrp 改了接口，故障转移
在同一处反复失败，一晚上推了几百条一模一样的告警 —— 那不是「提醒」，那是
让提醒本身失效（真出事时人已经麻了）。所以这里宁可漏一条，也不能刷屏。

三道护栏，从里到外：

  1. **按 key 去重**（`DEDUPE_WINDOWS`）：同一个 key 在窗口内只发一次。
     调用方应当传**稳定的 key**（例如 `t12:failover-fail`），不要依赖正文
     哈希 —— 正文里只要带一个变化的数字（冷却秒数、端口号、节点名），
     哈希就变了，去重形同虚设，这正是刷屏能穿过去的原因之一。
  2. **情形（episode）语义**：`reset(key)` 清掉一个 key 的去重记录。引擎在
     「条件恢复」时调用它，于是同一个问题一次只报一条，恢复了再犯才报第二条。
  3. **全局硬限流**（`RATE_LIMITS`）：不管上游代码怎么写、有没有传 key，
     单位时间内最多就发这么多条，超出的丢弃并合并成**一条**提示。这是最后
     一道闸，专门对付「以后新写的代码又忘了去重」。
"""

from __future__ import annotations

import time
from collections import deque

import httpx

# Gotify 的 priority 语义：0~3 安静，4~7 普通，8+ 会常驻通知
PRIORITY = {
    "info": 2,
    "success": 4,
    "warn": 7,
    "error": 9,
}

# ★ 同一个 key 的**去重窗口**（秒）。窗口内只推一次。
#
# 时间窗是第一道闸，不是「一次故障只报一条」的最终保证 —— 那个由引擎的
# `_notify_once`（情形语义）负责。这里兜的是「调用方忘了传 key / 忘了做
# 情形判断」的情况：至少不会每 20 秒一条。
DEDUPE_WINDOWS = {
    "error": 1800.0,
    "warn": 900.0,
    "success": 120.0,
    "info": 120.0,
}

# ★ 发送失败后的**短退避**（秒）。Gotify 短暂不可用时不要每轮巡检都重打一遍，
#   但也不能像成功那样记满整个去重窗口 —— 否则 Gotify 抖一下，这条告警就
#   被吞掉半小时。
FAIL_BACKOFF = 60.0

# ★ 全局硬限流：`(窗口秒数, 窗口内最多发几条)`，按数组顺序逐条检查。
#
# 取值的依据：正常运维一天也就几条到十几条；一个节点挂掉带着 10 条隧道一起
# 出事是 10 条，还在上限内。而「代码出 bug 在循环里发通知」的量级是几百上千，
# 一定会撞上这两道线。
RATE_LIMITS: tuple[tuple[float, int], ...] = (
    (60.0, 10),
    (3600.0, 40),
)

# 被限流之后，最多每小时推**一条**「有通知被丢弃」的提示。
LIMIT_NOTICE_WINDOW = 3600.0


class Notifier:
    def __init__(self, base_url: str = "", token: str = "", timeout: float = 10.0):
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = (token or "").strip()
        self.timeout = timeout
        # key -> 上次真正发出去的时刻（monotonic）。只存内存：重启后重新计数，
        # 最多多推一条，不影响正确性。
        self._sent_at: dict[str, float] = {}
        # key -> 上次发送失败的时刻。用来做短退避，见 FAIL_BACKOFF。
        self._fail_at: dict[str, float] = {}
        # 真正发出去的每一条的时刻，用于全局限流（滑动窗口）。
        self._sent_log: deque[float] = deque()
        # 累计被限流丢弃的条数（给 UI / 排障看，不参与判断）。
        self.suppressed: int = 0
        # 上一次「限流提示」发出的时刻。
        self._limit_notice_at: float = 0.0
        # 最近一次 send() 的结果：sent / duplicate / rate_limited / error /
        # disabled / http_error。调用方靠它区分「重复被拦」和「真的发失败了」。
        self.last_reason: str = "disabled"

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.token)

    def configure(self, base_url: str, token: str) -> None:
        self.base_url = (base_url or "").strip().rstrip("/")
        self.token = (token or "").strip()

    # ------------------------------------------------------------------
    # 去重账本
    # ------------------------------------------------------------------

    @staticmethod
    def _key_of(title: str, message: str, level: str, key: str | None) -> str:
        """取去重键。调用方给了就用它，否则退回「级别 + 标题 + 正文」哈希。

        ⚠️ 完全没有 key 时这里只能用正文 —— 这也是为什么所有调用点都该显式
        传 key：正文里带数值（端口、秒数）会让每条都「不重复」。
        """
        if key:
            return key
        return f"{level}|{title[:200]}|{message[:4000]}"

    def _is_duplicate(self, k: str, level: str) -> bool:
        now = time.monotonic()
        last = self._sent_at.get(k)
        if last is not None and now - last < DEDUPE_WINDOWS.get(level, 300.0):
            return True
        failed = self._fail_at.get(k)
        if failed is not None and now - failed < FAIL_BACKOFF:
            return True
        return False

    def _mark_sent(self, k: str) -> None:
        """记下「这条推出去了」。

        ⚠️ 只在**拿到响应之后**记，不在发送前记：Gotify 短暂不可用时如果提前
        记账，窗口内这条消息就永远补不上了。发送异常不记账（改用 `_fail_at`
        做 60 秒短退避），下一次调用会正常重试。
        """
        now = time.monotonic()
        self._sent_at[k] = now
        self._fail_at.pop(k, None)
        self._sent_log.append(now)
        # 顺手清理过期键，避免长跑实例里无限增长。
        if len(self._sent_at) > 256:
            self._sent_at = {
                key: v for key, v in self._sent_at.items()
                if now - v < max(DEDUPE_WINDOWS.values())
            }
        if len(self._fail_at) > 256:
            self._fail_at = {
                key: v for key, v in self._fail_at.items()
                if now - v < FAIL_BACKOFF
            }

    def reset(self, *keys: str) -> None:
        """解除这些 key 的去重记录（= 条件已恢复，下次再发生可以重新报）。

        引擎在「隧道恢复健康 / 人工介入」时调用。没有这一步，去重窗口一旦没过，
        同一类问题在窗口里就彻底哑了；有了它，语义才是「一次故障一条」而不是
        「每 N 分钟一条」。
        """
        for k in keys:
            self._sent_at.pop(k, None)
            self._fail_at.pop(k, None)

    # ------------------------------------------------------------------
    # 限流
    # ------------------------------------------------------------------

    def _rate_limited(self) -> bool:
        now = time.monotonic()
        horizon = max(w for w, _ in RATE_LIMITS)
        while self._sent_log and now - self._sent_log[0] > horizon:
            self._sent_log.popleft()
        for window, cap in RATE_LIMITS:
            used = sum(1 for t in self._sent_log if now - t <= window)
            if used >= cap:
                return True
        return False

    async def _notice_limited(self) -> None:
        """限流发生时，每小时最多推一条「有通知被丢弃」的提示。

        ⚠️ 这条提示**绕过限流**（否则永远发不出去），但仍然受「每小时一条」
        约束 —— 用它自己的时间戳判断，不进 `_sent_log`。
        """
        now = time.monotonic()
        if now - self._limit_notice_at < LIMIT_NOTICE_WINDOW:
            return
        self._limit_notice_at = now
        await self._post(
            "⚠️ mefrp-guard 通知已被限流",
            f"过去一小时内有 {self.suppressed} 条通知被丢弃 —— 这个量远超正常巡检，"
            "通常是某个循环在反复报同一个问题。\n\n"
            "请到页面「事件」里看真实原因；Gotify 这边刻意不再继续推送。",
            "error",
        )

    # ------------------------------------------------------------------
    # 发送
    # ------------------------------------------------------------------

    async def _post(self, title: str, message: str, level: str) -> bool:
        # ⚠️ 每次先把状态清干净：`last_reason` 是跨调用共享的，残留上一次的
        #   "error" 会让「这次其实是 5xx」被误判成「连不上」，从而走错分支。
        self.last_reason = "sending"
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
            self.last_reason = "error"
            return False
        if resp.status_code >= 300:
            self.last_reason = "http_error"
            return False
        self.last_reason = "sent"
        return True

    async def send(self, title: str, message: str, level: str = "info",
                   *, key: str | None = None, force: bool = False) -> bool:
        """推一条通知。

        `key`   稳定去重键（强烈建议每次都传，且**不要**把变化的数字拼进去）。
        `force` 跳过所有护栏 —— 只给「用户点按钮主动发的测试消息」用。
        """
        if not self.enabled:
            self.last_reason = "disabled"
            return False

        k = self._key_of(title, message, level, key)

        if not force:
            if self._is_duplicate(k, level):
                self.last_reason = "duplicate"
                return False
            if self._rate_limited():
                self.suppressed += 1
                self.last_reason = "rate_limited"
                await self._notice_limited()
                return False

        ok = await self._post(title, message, level)
        if ok:
            self._mark_sent(k)
        elif self.last_reason == "error":
            # 传输层失败（连不上 / 超时）—— 短退避，不吞掉整个窗口。
            self._fail_at[k] = time.monotonic()
        else:
            # Gotify 有响应但状态码异常（4xx/5xx）：说明这条「已经处理过」，
            # 记满窗口，别在下一轮继续打（打一个坏 token 一万次也没用）。
            self._mark_sent(k)
        return ok

    async def ping(self) -> dict:
        if not self.base_url:
            return {"ok": False, "error": "未配置 Gotify 地址"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/health")
            return {"ok": resp.status_code < 300, "status": resp.status_code}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}
