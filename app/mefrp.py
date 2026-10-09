"""mefrp 5.0 开放 API 客户端。

接口来源：https://apidoc.mefrp.com/
Base URL：https://api.mefrp.com/api
认证：Authorization: Bearer <用户 Token>

两个必须遵守的约束（来自官方文档）：
  1. User-Agent 必须像样，且不能以 `MEFrp-Client` 开头，否则会被 CDN / WAF 拦截。
  2. 被拦截时返回的是 HTML，解析 JSON 会报错。所以这里统一检查响应首字符是不是 `<`。

另外两个是**实测**出来的坑（文档里没有，但踩了就会静默失效）：

  3. `/auth/user/group` **这个端点不存在** —— 返回 HTTP 404，但 `message` 是服务器的
     通用 banner「ME Frp 5.21 API Server is OK!」，看起来像「服务正常」，`data` 却是
     null。只看 message 会误判。真实用户组在 `/auth/user/info`：
         group         = "default"      ← 机器名，用于匹配节点的 allowGroup
         friendlyGroup = "正式用户"      ← 展示名，只在 UI 上给人看

  4. `/auth/node/list` 对**非管理员**账号把 `hostname` 脱敏成空串（实测 45 个节点全空，
     `servicePort` 也是 0、`token` 是空串）。真实节点公网地址只出现在
     `/auth/proxy/list` 返回的 `nodes` 子数组里，或 `/auth/proxy/config` 生成的
     TOML 的 `serverAddr` 里。所以 `proxy_list()` 的第二个返回值**不能丢**。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_BASE = "https://api.mefrp.com/api"
DEFAULT_UA = "MefrpGuard/1.0 (homelab)"


class MefrpError(Exception):
    """通用错误。"""


class MefrpAuthError(MefrpError):
    """Token 为空、格式错误或已失效。"""


class MefrpWafBlocked(MefrpError):
    """被 CDN / WAF 拦截，返回的是 HTML 而不是 JSON。"""


class MefrpApiError(MefrpError):
    """接口返回了非 200 的业务码。"""

    def __init__(self, code: int, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class Node:
    node_id: int
    name: str
    hostname: str = ""
    description: str = ""
    allow_group: str = ""
    allow_port: str = ""
    allow_type: str = ""
    region: str = ""
    bandwidth: str = ""
    is_online: bool = False
    is_disabled: bool = False
    version: str = ""
    load_percent: int = 0
    uptime: int = 0
    online_proxy: int = 0
    online_client: int = 0
    cur_conns: int = 0

    @property
    def bandwidth_mbps(self) -> float:
        """把 '200Mbps' / '1Gbps' / '不限' 解析成 Mbps 数值。"""
        s = (self.bandwidth or "").strip().lower()
        if not s:
            return 0.0
        m = re.search(r"([\d.]+)\s*(g|gb|gbps|gbit)", s)
        if m:
            return float(m.group(1)) * 1000
        m = re.search(r"([\d.]+)\s*(m|mb|mbps|mbit)", s)
        if m:
            return float(m.group(1))
        m = re.search(r"([\d.]+)", s)
        if m:
            return float(m.group(1))
        if any(k in s for k in ("不限", "unlimited", "inf")):
            return 100000.0
        return 0.0

    @property
    def label(self) -> str:
        tags = []
        if self.region:
            tags.append(self.region)
        if self.bandwidth:
            tags.append(self.bandwidth)
        return f"{self.name}" + (f"（{' · '.join(tags)}）" if tags else "")

    @property
    def usable(self) -> bool:
        return self.is_online and not self.is_disabled

    def allows_group(self, group: str) -> bool:
        """allowGroup 形如 'admin;sponsor;vip'。空表示不限。"""
        raw = (self.allow_group or "").strip()
        if not raw:
            return True
        allowed = {p.strip().lower() for p in re.split(r"[;,|\s]+", raw) if p.strip()}
        return group.strip().lower() in allowed

    def allows_type(self, proxy_type: str) -> bool:
        raw = (self.allow_type or "").strip()
        if not raw:
            return True
        allowed = {p.strip().lower() for p in re.split(r"[;,|\s]+", raw) if p.strip()}
        return proxy_type.strip().lower() in allowed

    def port_allowed(self, port: int) -> bool:
        """allowPort 形如 '40000-65535' 或 '10000-20000;30000-31000'。"""
        raw = (self.allow_port or "").strip()
        if not raw:
            return True
        for chunk in re.split(r"[;,|\s]+", raw):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                try:
                    lo, hi = chunk.split("-", 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except ValueError:
                    continue
            elif chunk.isdigit() and int(chunk) == port:
                return True
        return False


@dataclass
class Proxy:
    proxy_id: int
    proxy_name: str
    proxy_type: str = "tcp"
    node_id: int = 0
    local_ip: str = ""
    local_port: int = 0
    remote_port: int = 0
    is_online: bool = False
    is_banned: bool = False
    is_disabled: bool = False
    domain: str = ""
    run_id: str = ""
    last_start_time: int = 0
    last_close_time: int = 0
    client_version: str = ""
    username: str = ""

    @property
    def healthy_flags(self) -> bool:
        return self.is_online and not self.is_banned and not self.is_disabled


@dataclass
class UserInfo:
    username: str = ""
    group: str = ""             # 机器名，用于匹配节点的 allowGroup，如 "default"
    friendly_group: str = ""    # 展示名，如 "正式用户"
    max_proxies: int = 0
    used_proxies: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 客户端
# ---------------------------------------------------------------------------

def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class MefrpClient:
    def __init__(self, token: str, base: str = DEFAULT_BASE,
                 user_agent: str = DEFAULT_UA, timeout: float = 15.0):
        self.token = (token or "").strip()
        self.base = (base or DEFAULT_BASE).rstrip("/")
        self.user_agent = user_agent or DEFAULT_UA
        self.timeout = timeout

    # -- 底层 ---------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _request(self, method: str, path: str,
                       json_body: dict | None = None) -> Any:
        if not self.token:
            raise MefrpAuthError("尚未配置 mefrp 访问 Token")

        url = f"{self.base}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout,
                                         follow_redirects=True) as client:
                resp = await client.request(
                    method, url, headers=self._headers(), json=json_body
                )
        except httpx.HTTPError as exc:
            raise MefrpError(f"请求 mefrp 失败：{exc}") from exc

        text = resp.text or ""
        if text.lstrip().startswith("<"):
            raise MefrpWafBlocked(
                "响应是 HTML，说明被 CDN / WAF 拦截了。"
                "检查 User-Agent 是否合规（不能以 MEFrp-Client 开头），"
                "以及是否触发了频率限制。"
            )

        try:
            payload = resp.json()
        except ValueError as exc:
            raise MefrpError(f"响应不是合法 JSON：{text[:200]}") from exc

        if not isinstance(payload, dict):
            raise MefrpError(f"响应结构异常：{text[:200]}")

        code = _to_int(payload.get("code"), 0)
        message = str(payload.get("message") or "")
        if code == 200:
            return payload.get("data")
        if code == 401 or resp.status_code == 401:
            raise MefrpAuthError(message or "Token 为空或格式错误")
        raise MefrpApiError(code, message or f"HTTP {resp.status_code}")

    # -- 节点 ---------------------------------------------------------------

    async def node_list(self) -> list[Node]:
        data = await self._request("GET", "/auth/node/list") or []
        nodes: list[Node] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            nodes.append(Node(
                node_id=_to_int(item.get("nodeId")),
                name=str(item.get("name") or ""),
                hostname=str(item.get("hostname") or ""),
                description=str(item.get("description") or ""),
                allow_group=str(item.get("allowGroup") or ""),
                allow_port=str(item.get("allowPort") or ""),
                allow_type=str(item.get("allowType") or ""),
                region=str(item.get("region") or ""),
                bandwidth=str(item.get("bandwidth") or ""),
                is_online=bool(item.get("isOnline")),
                is_disabled=bool(item.get("isDisabled")),
                version=str(item.get("version") or ""),
                uptime=_to_int(item.get("upTime")),
                online_proxy=_to_int(item.get("onlineProxy")),
                online_client=_to_int(item.get("onlineClient")),
                cur_conns=_to_int(item.get("curConns")),
            ))
        return nodes

    async def node_status(self) -> dict[int, dict[str, Any]]:
        """返回 nodeId -> 状态字典。注意节点数据有 5 分钟 Redis 缓存。"""
        data = await self._request("GET", "/auth/node/status") or []
        out: dict[int, dict[str, Any]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            nid = _to_int(item.get("nodeId"))
            if nid:
                out[nid] = item
        return out

    async def node_secret(self, node_id: int) -> dict[str, Any]:
        """拿节点的真实服务端口与连接 Token。"""
        return await self._request(
            "POST", "/auth/node/secret", {"nodeId": int(node_id)}
        ) or {}

    # -- 隧道 ---------------------------------------------------------------

    async def proxy_list(self) -> tuple[list[Proxy], dict[int, dict[str, Any]]]:
        """返回 (隧道列表, 节点简表)。"""
        data = await self._request("GET", "/auth/proxy/list") or {}
        proxies: list[Proxy] = []
        for item in (data.get("proxies") or []):
            if not isinstance(item, dict):
                continue
            proxies.append(Proxy(
                proxy_id=_to_int(item.get("proxyId")),
                proxy_name=str(item.get("proxyName") or ""),
                proxy_type=str(item.get("proxyType") or "tcp").lower(),
                node_id=_to_int(item.get("nodeId")),
                local_ip=str(item.get("localIp") or ""),
                local_port=_to_int(item.get("localPort")),
                remote_port=_to_int(item.get("remotePort")),
                is_online=bool(item.get("isOnline")),
                is_banned=bool(item.get("isBanned")),
                is_disabled=bool(item.get("isDisabled")),
                domain=str(item.get("domain") or ""),
                run_id=str(item.get("runId") or ""),
                last_start_time=_to_int(item.get("lastStartTime")),
                last_close_time=_to_int(item.get("lastCloseTime")),
                client_version=str(item.get("clientVersion") or ""),
                username=str(item.get("username") or ""),
            ))
        nodes: dict[int, dict[str, Any]] = {}
        for item in (data.get("nodes") or []):
            if isinstance(item, dict):
                nid = _to_int(item.get("nodeId"))
                if nid:
                    nodes[nid] = item
        return proxies, nodes

    async def proxy_create(self, *, node_id: int, proxy_name: str,
                           local_ip: str, local_port: int,
                           proxy_type: str = "tcp",
                           remote_port: int | None = None,
                           domain: str = "",
                           use_encryption: bool = False,
                           use_compression: bool = False) -> None:
        body: dict[str, Any] = {
            "nodeId": int(node_id),
            "proxyName": proxy_name,
            "localIp": local_ip,
            "localPort": int(local_port),
            "proxyType": proxy_type,
            "domain": domain,
            "accessKey": "",
            "hostHeaderRewrite": "",
            "httpPlugin": "",
            "requestHeaders": {},
            "httpUser": "",
            "httpPassword": "",
            "crtPath": "",
            "keyPath": "",
            "proxyProtocolVersion": "",
            "useEncryption": bool(use_encryption),
            "useCompression": bool(use_compression),
        }
        if remote_port:
            body["remotePort"] = int(remote_port)
        await self._request("POST", "/auth/proxy/create", body)

    async def proxy_delete(self, proxy_id: int) -> None:
        await self._request("POST", "/auth/proxy/delete", {"proxyId": int(proxy_id)})

    async def proxy_config(self, proxy_id: int, fmt: str = "toml") -> str:
        """拿官方生成的单隧道配置文本。fmt 支持 toml / json / yml / ini（必须小写）。"""
        data = await self._request(
            "POST", "/auth/proxy/config", {"proxyId": int(proxy_id), "format": fmt}
        ) or {}
        return str(data.get("config") or "")

    # -- 账户 ---------------------------------------------------------------

    async def user_info(self) -> UserInfo:
        """用户信息。**用户组的唯一正确来源。**

        实测返回（2026-10-07）：
            {"email", "friendlyGroup": "正式用户", "group": "default", "inBound",
             "isRealname", "maxProxies": 10, "outBound", "regTime", "status",
             "todaySigned", "traffic", "usedProxies": 2, "userId", "username"}

        ⚠️ 不要用 `/auth/user/group` —— **那个端点不存在**，返回 HTTP 404 且
        message 是服务器通用 banner（`ME Frp 5.21 API Server is OK!`），
        看起来像「服务正常」但 data 是 null，会导致用户组永远拿不到。
        """
        data = await self._request("GET", "/auth/user/info") or {}
        if not isinstance(data, dict):
            return UserInfo()
        return UserInfo(
            username=str(data.get("username") or data.get("name") or ""),
            group=str(data.get("group") or "").strip(),
            friendly_group=str(data.get("friendlyGroup") or "").strip(),
            max_proxies=_to_int(data.get("maxProxies")),
            used_proxies=_to_int(data.get("usedProxies")),
            raw=data,
        )

    async def user_group(self) -> str:
        """拿当前账号所属用户组（机器名），用于过滤节点权限。失败时返回空串。

        空串在 Node.allows_group 里的语义是「不过滤」，所以拿不到时不会误拦节点，
        但页面上会显示成「未知」—— 调用方应当把错误原因一并暴露出去。
        """
        try:
            return (await self.user_info()).group
        except MefrpError:
            return ""

    async def user_frp_token(self) -> str:
        data = await self._request("GET", "/auth/user/frpToken") or {}
        if isinstance(data, dict):
            return str(data.get("token") or "")
        return ""

    # -- 便捷 ---------------------------------------------------------------

    async def ping(self) -> dict[str, Any]:
        """连通性自检，用于 UI 上的「测试连接」按钮。"""
        nodes = await self.node_list()
        info = await self.user_info()
        online = sum(1 for n in nodes if n.is_online and not n.is_disabled)
        return {
            "ok": True,
            "node_total": len(nodes),
            "node_online": online,
            "user_group": info.group,
            "friendly_group": info.friendly_group,
            "username": info.username,
            "max_proxies": info.max_proxies,
            "used_proxies": info.used_proxies,
        }
