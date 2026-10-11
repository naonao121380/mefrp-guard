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

  5. **`domain` 是一个「文本化的 JSON 数组」字符串** —— 这个字段的格式是 HTTP/HTTPS
     隧道里最容易踩错的一处。官方 schema 的原话是「列表被文本化，需要额外处理，
     如 `["mefrp.com"]`」，创建隧道的示例里写的是 `domain: '["example.com"]'`。
     也就是说它既不是裸域名、也不是真的 JSON 数组，而是**JSON 数组的文本**。
     读回来是同一个形式。见下面的 `parse_domains` / `join_domains`。

  HTTP/HTTPS 隧道与 TCP/UDP 的差别**只有两个字段**（官方创建隧道 spec 原文）：

     · `remotePort` —— TCP/UDP 必填；HTTP/HTTPS **必须显式传 `null`**（不是省略）；
     · `domain`     —— TCP/UDP 传 `""`；HTTP/HTTPS 传上面那个文本化数组。

  这两处传错的后果不是「报错」而是「隧道建出来不通」，所以 `proxy_create`
  里按类型强制分支，不给调用方自由发挥的余地。
"""

from __future__ import annotations

import json
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
# 隧道类型
# ---------------------------------------------------------------------------

# mefrp 支持的四类隧道。**分成两组**不是洁癖 —— 它们在创建参数、端到端探测、
# 节点择优偏好、DNS 语义上全都不一样，代码里到处都要按这个分叉：
#
#   · port 组（tcp / udp）—— 有「远程端口」，用户直连 `节点:端口`，
#     **不依赖域名**，所以 DNS 是可选的锦上添花。
#   · http 组（http / https）—— **没有远程端口**，靠「绑定域名」工作；
#     节点上跑着反代，按请求的 Host 头把流量分到不同隧道。
#     域名必须解析到承载它的那个节点，否则这条隧道对外**根本不可达** ——
#     所以对 http 组来说 DNS 不是可选项，是生命线。
PORT_TYPES = ("tcp", "udp")
HTTP_TYPES = ("http", "https")
ALL_TYPES = PORT_TYPES + HTTP_TYPES


def is_http_type(proxy_type: Any) -> bool:
    """这条隧道是不是「靠域名工作」的那一类（http / https）。"""
    return str(proxy_type or "").strip().lower() in HTTP_TYPES


def kind_of(proxy_type: Any) -> str:
    """把隧道类型归成两组之一：`"http"` 或 `"port"`。

    认不出来的类型一律当 `port` 处理 —— 那是**保守**的一侧：port 组会去要
    远程端口、会做端口探测，行为跟这个工具 1.0.1 之前对「所有隧道」的做法
    一致。反过来把未知类型当 http 会让它拿不到端口、还可能去绑域名。
    """
    return "http" if is_http_type(proxy_type) else "port"


# ---------------------------------------------------------------------------
# domain 字段的解析 / 序列化
# ---------------------------------------------------------------------------

def parse_domains(raw: Any) -> list[str]:
    """把 mefrp 的 `domain` 字段解析成域名列表。

    ⚠️ 这个字段**不是**一眼能看出来的那种格式。官方 schema 的原文是
    「列表被文本化，需要额外处理，如 `["mefrp.com"]`」，创建隧道的示例里
    写的是 `domain: '["example.com"]'` —— 它是一个**字符串**，内容是
    JSON 数组的文本：

        '["a.example.com"]'                 → ['a.example.com']
        '["a.example.com","b.example.com"]' → ['a.example.com', 'b.example.com']

    这里刻意做得**宽容**：JSON 数组、逗号/分号分隔的裸串、单个裸域名都认。
    理由是 1.0.2 开发时账号上还没有 HTTP 隧道可以实测，官方文档也只是
    「如 `["mefrp.com"]`」这种举例 —— 宽容解析至少不会把将来某天格式
    变体的数据读坏。序列化那一侧（`join_domains`）则**严格**照官方示例来。
    """
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [str(x).strip() for x in raw if str(x).strip()]

    s = str(raw).strip()
    if not s:
        return []
    if s.startswith("[") and s.endswith("]"):
        try:
            data = json.loads(s)
        except ValueError:
            data = None
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
        # 解析不动就往下走按分隔符切 —— 别把整串 `["a"` 当成一个域名
    return [p.strip() for p in re.split(r"[,;\s]+", s) if p.strip()]


def join_domains(names: Any) -> str:
    """把域名列表序列化成 mefrp 的 `domain` 字段要的形式。

    严格照官方创建隧道示例：`'["example.com"]'` —— JSON 数组的**文本**。
    传裸域名 `example.com` 会被后端拒绝；传真的数组则不是字符串类型。

    空列表返回 `""` —— TCP/UDP 隧道的 `domain` 就是这个值。
    """
    if names is None:
        return ""
    items = parse_domains(names) if isinstance(names, str) else \
        [str(x).strip() for x in names if str(x).strip()]
    return json.dumps(items, ensure_ascii=False) if items else ""


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
    # HTTP/HTTPS 隧道才有意义：路径路由规则（逗号分隔）与传输层协议。
    locations: str = ""
    transport_protocol: str = ""

    @property
    def domains(self) -> list[str]:
        """绑定的域名列表。⚠️ 原始字段是「文本化 JSON 数组」，见 parse_domains。"""
        return parse_domains(self.domain)

    @property
    def is_http(self) -> bool:
        """是不是靠域名工作的那一类（http / https）。"""
        return is_http_type(self.proxy_type)

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
                locations=str(item.get("locations") or ""),
                transport_protocol=str(item.get("transportProtocol") or ""),
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
                           domain: Any = "",
                           locations: str = "",
                           http_plugin: str = "",
                           crt_path: str = "",
                           key_path: str = "",
                           request_headers: dict | None = None,
                           response_headers: dict | None = None,
                           proxy_protocol_version: str = "",
                           transport_protocol: str = "",
                           use_encryption: bool = False,
                           use_compression: bool = False) -> None:
        """在 mefrp 上创建一条隧道。

        ⚠️ **HTTP/HTTPS 与 TCP/UDP 的差别就落在两个字段上**（官方创建隧道
        spec 原文，五组示例）：

          · `remotePort` —— TCP/UDP 传端口号；HTTP/HTTPS **必须显式传 `null`**
            （示例里写的是 `remotePort: null`，**不是省略这个键**）。
          · `domain`     —— TCP/UDP 传 `""`；HTTP/HTTPS 传**文本化的 JSON
            数组**，形如 `'["example.com"]'`（见 `join_domains`）。

        传错的后果不是「接口报错」而是**隧道建出来不通**：给了端口的 http
        隧道在节点上不会被反代接管；`domain` 传成裸域名则绑定不上，隧道
        永远没有 Host 能匹配到它。所以这里按类型强制分支，调用方不用（也
        不该）自己判断该传什么。

        `http_plugin` 是「隧道类型 × 内网服务协议」的配对，四种合法组合：

            http  + 内网 HTTP  → 留空
            http  + 内网 HTTPS → "http2https"
            https + 内网 HTTP  → "https2http"（需要 crt_path / key_path）
            https + 内网 HTTPS → "https2https"（需要 crt_path / key_path）

        ⚠️ `https` 的证书路径是**节点侧**的路径（官方示例 `/etc/crt/example.com.crt`），
        对免费用户基本用不上 —— 想给站点上 TLS，实用做法是用 `http` 隧道
        再让 Cloudflare 在前面终结 TLS（DNS 记录 proxied=on）。
        """
        pt = str(proxy_type or "tcp").strip().lower()
        http_like = is_http_type(pt)

        body: dict[str, Any] = {
            "nodeId": int(node_id),
            "proxyName": proxy_name,
            "localIp": local_ip,
            "localPort": int(local_port),
            "proxyType": pt,
            # ★ HTTP/HTTPS 恒为 null；TCP/UDP 没指定期望端口时也传 null
            #   （让节点自己分配），而不是把这个键省掉 —— spec 里它是必填项。
            "remotePort": None if http_like else (int(remote_port) if remote_port else None),
            # ★ 只有 http 组才带域名相关的这些字段，port 组一律清空，
            #   免得把上一次的残留带进一条 TCP 隧道。
            "domain": join_domains(domain) if http_like else "",
            "locations": (locations or "").strip() if http_like else "",
            "httpPlugin": (http_plugin or "").strip() if http_like else "",
            "crtPath": (crt_path or "").strip() if http_like else "",
            "keyPath": (key_path or "").strip() if http_like else "",
            "accessKey": "",
            "hostHeaderRewrite": "",
            "requestHeaders": dict(request_headers or {}),
            "responseHeaders": dict(response_headers or {}),
            "httpUser": "",
            "httpPassword": "",
            "proxyProtocolVersion": proxy_protocol_version or "",
            "transportProtocol": transport_protocol or "",
            "useEncryption": bool(use_encryption),
            "useCompression": bool(use_compression),
        }
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
