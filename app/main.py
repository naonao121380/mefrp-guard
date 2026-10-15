"""FastAPI 后端。

职责很薄：把引擎的状态暴露出去、把 UI 的操作转成对引擎/存储的调用。
所有业务逻辑都在 engine.py 里，这里只做参数校验和错误翻译。
"""

from __future__ import annotations

import asyncio
import base64
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import auth, frpc, frpcparse, store
from .cloudflare import CloudflareClient, CloudflareError
from .engine import (PROBE_HTTP, PROBE_NONE, PROBE_TCP, engine, http_probe,
                     http_probe_url, probe_plan, tcp_probe)
from .mefrp import (MefrpClient, MefrpError, is_http_type, join_domains,
                    parse_domains)
from .settings import (BOOTSTRAP, DEFAULT_SETTINGS, READONLY_SETTINGS,
                       SECRET_KEYS)

WEB_DIR = Path(__file__).parent / "web"

# 枚举型设置：key -> 允许的取值集合。
# 写错的值必须报 400，不能静默降级 —— 否则用户以为「关了探测」其实还在探。
ENUM_SETTINGS: dict[str, set[str]] = {
    # auto = 按隧道类型自动决定（TCP/UDP 探端口，HTTP 跳过 —— 见 engine.probe_plan）
    # tcp  = 一律做 TCP 探测（对 http 隧道是假阳性，不推荐）
    # http = 按类型：http/https 隧道做 HTTP 探测，tcp/udp 照旧做 TCP 探测
    # none = 全部关闭
    "probe_mode": {"auto", "tcp", "http", "none"},
}


# ---------------------------------------------------------------------------
# 生命周期
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init()
    store.add_event("info", "system", "mefrp-guard 启动")
    engine.reload_clients()
    await engine.start()
    try:
        yield
    finally:
        await engine.stop()
        store.add_event("info", "system", "mefrp-guard 停止")


app = FastAPI(title="mefrp-guard", version="1.0.3", lifespan=lifespan,
              docs_url=None, redoc_url=None)


# ---------------------------------------------------------------------------
# 鉴权
#
# 双通道，按顺序尝试：
#   1. `Authorization: Basic` —— 给脚本 / curl / 自动化用（保持向后兼容）
#   2. 会话 Cookie `mg_session` —— 给浏览器用（登录页换来的）
#
# 为什么要有会话 Cookie：浏览器原生的 Basic 认证弹窗既丑又没法「登出」，
# 而且会把凭据缓存到进程结束。表单登录 + HttpOnly Cookie 才能做到
# 「显式登出」「会话过期」「改密码后立刻踢掉旧会话」。
#
# 凭据存在库里（settings 表），不是环境变量 —— 这样才能在 UI 上改密码。
# 环境变量只在**首次启动且还没有哈希**时作为种子。
# ---------------------------------------------------------------------------

SESSION_COOKIE = "mg_session"
# ⚠️ **故意不返回 `WWW-Authenticate: Basic`。**
#    带上它，浏览器就会弹原生 Basic 对话框（还盖在登录页上面），并且把那组凭据
#    **缓存**下来、之后每个请求都自动附加 —— 那个对话框没法登出，正是引入登录页
#    要摆脱的东西（README.dev.md 的「认证」一节写明了这一点）。
#    Basic 头本身仍然**被接受**（见 `is_authenticated` 的兜底分支），只是不再主动
#    挑战：`curl -u` 和脚本都是**主动**发 Authorization 头的，不依赖挑战。
#    （这条以前是 `_UNAUTHORIZED = {"WWW-Authenticate": ...}`，实现和上面那句设计
#      意图是矛盾的 —— 2026-10-15 去掉。）


def auth_enabled() -> bool:
    """有哈希就说明凭据已播种 → 鉴权生效。正常情况下恒为 True。"""
    return bool(store.get_setting("web_password_hash"))


def _stored_credentials() -> tuple[str, str, str, int]:
    return (
        str(store.get_setting("web_user") or ""),
        str(store.get_setting("web_password_hash") or ""),
        str(store.get_setting("web_password_salt") or ""),
        int(store.get_setting("web_password_iter") or 0),
    )


def check_credentials(user: str, password: str) -> bool:
    """校验用户名 + 密码。

    ⚠️ 用户名和密码**都要**参与校验且都用常量时间比较，
    否则「用户名对不对」会从响应时间上泄露出去。
    """
    stored_user, h, salt, iters = _stored_credentials()
    if not h:
        return False
    ok_user = auth.same(user or "", stored_user)
    ok_pass = auth.verify_password(password or "", hash_hex=h,
                                   salt_hex=salt, iterations=iters)
    return bool(ok_user and ok_pass)


def _origin_ok(request: Request) -> bool:
    """跨站写请求防护。

    Cookie 认证天生会被 CSRF 攻击（浏览器会自动带上 Cookie）。
    两道防线：
      * 主防线是 Cookie 的 `SameSite=Strict` —— 跨站请求根本不会带上它。
      * 这里是第二道：写操作如果带了 `Origin`，就必须和本站同源。

    只检查「带了 Origin 的情况」是有意的 —— curl / 脚本不带 Origin，
    不能因此把它们拒掉。
    """
    origin = request.headers.get("origin", "")
    if not origin or origin == "null":
        return True
    try:
        netloc = urlparse(origin).netloc.lower()
    except ValueError:
        return False
    if not netloc:
        return True
    allowed = {
        (request.headers.get("host") or "").lower(),
        (request.headers.get("x-forwarded-host") or "").lower(),
    }
    allowed.discard("")
    return netloc in allowed


def is_authenticated(request: Request) -> bool:
    """**不抛异常**的鉴权检查。

    和 require_auth 的分工：这个返回布尔，给「未登录要重定向到登录页」的
    页面路由用；require_auth 负责抛带具体原因的 401/403，给 API 用。

    ★ **会话 Cookie 优先，Basic 兜底** —— 顺序不能反，理由见下面的长注释。
    """
    if not auth_enabled():
        return True

    # ★ 先看 Cookie。`Authorization: Basic` 是**兼容通道**（脚本 / curl /
    #   自动化），它只该在「没有有效会话」时兜底 —— 绝不能反过来压过 Cookie。
    #
    #   为什么顺序这么要紧：浏览器会把认证过的 Basic 凭据按 **origin + realm**
    #   缓存下来，之后**每个**请求都自动附加（preemptive），不管服务器这次
    #   有没有挑战它。1.0.0 / 1.0.1 是 Basic 时代，从那个版本升上来的浏览器里
    #   必然躺着这组凭据；只要用户改过密码，它就是失效的（前面若挂了 Lucky /
    #   nginx 的 BasicAuth，反代还会把**它自己**那组凭据透传进来，那就更对不上）。
    #
    #   如果 Basic 排在前面，`check_credentials` 一失败就 `return False` ——
    #   Cookie 永远没机会生效，用户看到的是：
    #       输入正确密码 → 登录成功 → 跳首页 → 又被踢回登录页 → 再登 → 再踢……
    #   也就是「登录页疯狂刷新」。实测：有效 Cookie + 错误 Basic 时，
    #   `/` 返回 302、`/api/auth/me` 返回 authenticated:false、`/api/overview` 401。
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        sess = store.get_session(auth.token_fingerprint(token))
        if sess is not None:
            request.state.username = sess["username"]
            return True

    header = request.headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            raw = base64.b64decode(header.split(None, 1)[1]).decode("utf-8")
            user, _, password = raw.partition(":")
        except Exception:  # noqa: BLE001
            return False
        if check_credentials(user, password):
            request.state.username = user
            return True
        return False

    return False


def require_auth(request: Request) -> None:
    """FastAPI 依赖。不通过就抛 401 / 403。"""
    if not auth_enabled():
        return

    # 写操作先过 CSRF 闸门
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not _origin_ok(request):
            raise HTTPException(status_code=403, detail="跨站请求被拒绝")

    if is_authenticated(request):
        return

    raise HTTPException(status_code=401, detail="需要登录")


Auth = Depends(require_auth)


# ---------------------------------------------------------------------------
# 登录 / 登出 / 改密码
# ---------------------------------------------------------------------------

class LoginIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class PasswordIn(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=1, max_length=256)
    new_username: str = Field("", max_length=64)


def _set_session_cookie(resp: Response, token: str, ttl_hours: int,
                        request: Request) -> None:
    """种会话 Cookie。

    * `HttpOnly` —— JS 读不到，XSS 也偷不走
    * `SameSite=Strict` —— 跨站请求不会带上，是 CSRF 的主防线
    * `Secure` —— 只在确实走 HTTPS 时才加。内网是 HTTP，硬加会导致
      浏览器直接不存这个 Cookie，登录完还是未登录状态。
    """
    secure = (request.url.scheme == "https"
              or request.headers.get("x-forwarded-proto", "").lower() == "https")
    resp.set_cookie(
        SESSION_COOKIE, token,
        max_age=max(60, int(ttl_hours) * 3600),
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )


@app.get("/login")
async def login_page() -> HTMLResponse:
    """登录页。**不需要鉴权** —— 否则就成了死循环。"""
    path = WEB_DIR / "login.html"
    if not path.exists():
        return HTMLResponse("<h1>login.html 缺失</h1>", status_code=500)
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/api/auth/me")
async def whoami(request: Request) -> dict[str, Any]:
    """当前会话状态。

    ⚠️ **故意不挂 Auth 依赖** —— 未登录时返回 200 + `authenticated: false`，
    而不是 401。这样登录页可以安静地问一句「我登录了吗」，
    不用在浏览器控制台里刷一堆红色 401。

    未登录时不返回 `password_is_default` —— 那等于对外广播
    「这台机器还在用默认密码」，没有任何必要。
    """
    if not is_authenticated(request):
        return {"authenticated": False, "username": str(store.get_setting("web_user") or "")}
    return {
        "authenticated": True,
        "username": str(store.get_setting("web_user") or ""),
        "auth_enabled": auth_enabled(),
        "password_is_default": auth.is_default_password(
            str(store.get_setting("web_password_hash") or ""),
            str(store.get_setting("web_password_salt") or ""),
            int(store.get_setting("web_password_iter") or 0),
        ),
        "session_ttl_hours": int(store.get_setting("session_ttl_hours", 168) or 168),
    }


@app.post("/api/auth/login")
async def do_login(payload: LoginIn, request: Request,
                   response: Response) -> dict[str, Any]:
    """登录。**不需要鉴权**（这是入口），但有防爆破。"""
    ip = auth.client_ip(request)
    left = auth.THROTTLE.remaining_lock(ip)
    if left > 0:
        raise HTTPException(
            status_code=429,
            detail=f"登录失败次数过多，请 {left} 秒后再试",
            headers={"Retry-After": str(left)},
        )

    if not check_credentials(payload.username, payload.password):
        max_attempts = int(store.get_setting("login_max_attempts", 5) or 5)
        lockout = int(store.get_setting("login_lockout_seconds", 300) or 300)
        remaining = auth.THROTTLE.record_failure(
            ip, max_attempts=max_attempts, lockout_seconds=lockout)
        store.add_event("warn", "auth",
                        f"登录失败：用户名 {payload.username!r}（来源 {ip}）")
        if remaining == 0:
            store.add_event("error", "auth",
                            f"登录失败次数达上限，已锁定 {ip} {lockout} 秒")
            raise HTTPException(
                status_code=429,
                detail=f"登录失败次数过多，请 {lockout} 秒后再试",
                headers={"Retry-After": str(lockout)},
            )
        raise HTTPException(status_code=401,
                            detail=f"账号或密码错误（还可尝试 {remaining} 次）")

    auth.THROTTLE.reset(ip)
    ttl = int(store.get_setting("session_ttl_hours", 168) or 168)
    token = auth.new_token()
    store.create_session(
        auth.token_fingerprint(token), payload.username, ttl * 3600,
        user_agent=request.headers.get("user-agent", ""), ip=ip,
    )
    store.purge_expired_sessions()
    store.add_event("info", "auth", f"登录成功：{payload.username}（来源 {ip}）")
    _set_session_cookie(response, token, ttl, request)
    return {"ok": True, "username": payload.username,
            "expires_in": ttl * 3600}


@app.post("/api/auth/logout")
async def do_logout(request: Request, response: Response) -> dict[str, Any]:
    """登出。删掉服务端会话 + 清 Cookie。

    ⚠️ 必须删服务端记录 —— 只清 Cookie 的话，那个令牌在过期前仍然可用，
    等于「登出」是个摆设。
    """
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        store.delete_session(auth.token_fingerprint(token))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/password")
async def change_password(payload: PasswordIn, request: Request,
                          response: Response) -> dict[str, Any]:
    """改用户名 / 密码。**必须验证当前密码。**

    改完把该用户的**所有**会话踢掉，再给当前这个客户端发一个新会话 ——
    否则旧密码泄露期间建立的会话在改密码后依然有效，改密码就白改了。
    """
    stored_user, h, salt, iters = _stored_credentials()
    if not auth.verify_password(payload.current_password, hash_hex=h,
                                salt_hex=salt, iterations=iters):
        store.add_event("warn", "auth", "修改密码失败：当前密码不正确")
        raise HTTPException(status_code=403, detail="当前密码不正确")

    new_user = (payload.new_username or "").strip() or stored_user
    if len(new_user) > 64:
        raise HTTPException(400, "用户名过长")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "新密码至少 8 位")
    if payload.new_password == auth.DEFAULT_PASSWORD:
        raise HTTPException(400, "新密码不能与默认密码相同")

    nh, nsalt, niters = auth.hash_password(payload.new_password)
    store.set_settings({
        "web_user": new_user,
        "web_password_hash": nh,
        "web_password_salt": nsalt,
        "web_password_iter": niters,
    })

    kicked = store.delete_sessions_for(stored_user)
    if new_user != stored_user:
        kicked += store.delete_sessions_for(new_user)

    ttl = int(store.get_setting("session_ttl_hours", 168) or 168)
    token = auth.new_token()
    store.create_session(
        auth.token_fingerprint(token), new_user, ttl * 3600,
        user_agent=request.headers.get("user-agent", ""),
        ip=auth.client_ip(request),
    )
    _set_session_cookie(response, token, ttl, request)
    store.add_event("info", "auth",
                    f"凭据已更新：用户名 {new_user}，已注销 {kicked} 个其他会话")
    return {"ok": True, "username": new_user, "sessions_revoked": kicked}



# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------

class TunnelIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    proxy_name: str = Field(..., min_length=1, max_length=64)
    proxy_type: str = Field("tcp", pattern="^(tcp|udp|http|https)$")
    local_ip: str = "127.0.0.1"
    local_port: int = Field(..., ge=1, le=65535)
    # ⚠️ 端口只对 TCP/UDP 有意义；HTTP/HTTPS 恒为 null（见 mefrp.proxy_create）。
    #    这里不做 Field 层面的强制，交给 create_tunnel 按类型校验 —— 因为
    #    「该填哪个」取决于 proxy_type，Pydantic 的字段约束表达不了这种条件。
    desired_remote_port: int | None = Field(None, ge=1, le=65535)
    # ---- HTTP/HTTPS 专用 ----
    # 想绑定的域名。可以传单个域名、逗号分隔的多个、或已经是 JSON 数组文本。
    # 统一由 mefrp.join_domains 归一化，见 create_tunnel。
    desired_domain: str = ""
    # 内网服务协议 → httpPlugin 映射，见 mefrp.proxy_create 的矩阵：
    #   http + HTTP  → ''            http + HTTPS → 'http2https'
    #   https + HTTP → 'https2http'  https + HTTPS → 'https2https'
    http_plugin: str = ""
    # 路径路由规则，逗号分隔（mefrp 的 locations 字段）。
    route_locations: str = ""
    # ⚠️ https 隧道才需要，而且是**节点侧**的证书路径 —— 免费用户基本用不上。
    crt_path: str = ""
    key_path: str = ""
    pin_node_id: int | None = None
    enabled: bool = True
    auto_failover: bool = True
    dns_record_name: str = ""
    dns_proxied: bool = False
    downstream_note: str = ""
    frpc_instance_id: int | None = None
    # 自由标签。留空 = 走默认（mefrp 隧道默认 'mefrp'，见 create_tunnel）。
    tag: str = ""


class TunnelPatch(BaseModel):
    name: str | None = None
    proxy_type: str | None = None
    local_ip: str | None = None
    local_port: int | None = None
    desired_remote_port: int | None = None
    desired_domain: str | None = None
    http_plugin: str | None = None
    route_locations: str | None = None
    crt_path: str | None = None
    key_path: str | None = None
    pin_node_id: int | None = None
    enabled: bool | None = None
    auto_failover: bool | None = None
    dns_record_name: str | None = None
    dns_proxied: bool | None = None
    downstream_note: str | None = None
    needs_downstream_review: bool | None = None
    # ⚠️ 标签要能显式清空（改成空串）。走 exclude_none 的话传 "" 会被当成
    #    「没提这个字段」丢掉，所以看 model_fields_set 判断，见 patch_tunnel。
    tag: str | None = None
    # ⚠️ 这个字段要能显式置空（解绑），所以不能走 exclude_none 的老路 ——
    # 见 patch_tunnel 里对 model_fields_set 的处理。
    frpc_instance_id: int | None = None
    # ⚠️ 同理：这个字段存在的**唯一目的**是让「传非空值」能被识别出来并拒绝，
    #    见 patch_tunnel。没有它的话 Pydantic 会把未知字段直接丢掉，
    #    那道防护就成了死代码。
    manual_node_id: int | None = None


class FrpcIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    config_path: str = Field(..., min_length=1)
    container: str = ""
    restart_mode: str = Field("docker", pattern="^(docker|none)$")
    enabled: bool = True
    note: str = ""


class FrpcPatch(BaseModel):
    name: str | None = None
    config_path: str | None = None
    container: str | None = None
    restart_mode: str | None = Field(None, pattern="^(docker|none)$")
    enabled: bool | None = None
    note: str | None = None
    # ⚠️ 只接受 null（解绑回 mefrp API 模式）。绑定要改写配置文件 + 重启容器，
    #    必须走 /api/manual-nodes/{id}/switch，见 frpc_patch 里的说明。
    manual_node_id: int | None = None


class BindIn(BaseModel):
    """把若干隧道绑定到某个 frpc 实例（frpc_instance_id 为空 = 解绑）。"""
    tunnel_ids: list[int] = Field(default_factory=list)
    frpc_instance_id: int | None = None


class FailoverIn(BaseModel):
    node_id: int | None = None


class NodePrefIn(BaseModel):
    priority: int | None = None
    excluded: bool | None = None
    note: str | None = None


class PrefPreviewIn(BaseModel):
    keywords: list[str] = Field(default_factory=list)


class OrphanAdoptIn(BaseModel):
    name: str | None = None
    dns_record_name: str = ""
    downstream_note: str = ""
    auto_failover: bool = True


class SettingsIn(BaseModel):
    model_config = {"extra": "allow"}


class ManualParseIn(BaseModel):
    """只解析、不落库。给导入对话框做即时预览。"""
    text: str = Field(..., min_length=1)
    format: str | None = Field(None, pattern="^(toml|ini)$")
    # 更新模式下要传正在编辑的节点 id。两个作用：
    #   · `taken_names` 才知道该在**哪个作用域**里判「已纳管」——隧道名只在
    #     同一台 frps 内唯一，拿 mefrp 作用域去判外部节点的隧道是错的；
    #   · `duplicate` 才不会把「你正在编辑的这个节点自己」报成地址重复。
    node_id: int | None = None


class ManualProxyIn(BaseModel):
    """用户在导入对话框里勾选的一条隧道。"""
    name: str = Field(..., min_length=1, max_length=64)
    adopt: bool = True
    dns_record_name: str = ""
    enabled: bool = True


class ManualNodeIn(BaseModel):
    name: str = Field("", max_length=64)
    text: str = Field(..., min_length=1)
    format: str | None = Field(None, pattern="^(toml|ini)$")
    note: str = ""
    enabled: bool = True
    # 勾选的隧道。**没列出来的就是不纳管** —— 前端会把解析结果全列出来，
    # 用户取消勾选的项会带 adopt=false 或者干脆不出现。
    proxies: list[ManualProxyIn] = Field(default_factory=list)
    # 导入时直接把这些隧道挂到这个 frpc 实例上，并把它切到本节点。
    # 一个 frpc 进程只能连一个 serverAddr，所以「隧道由谁承载」和
    # 「谁来连这个节点」是同一件事，一次问清楚比让用户回头再挂一次强。
    frpc_instance_id: int | None = None
    # 给这次纳管的隧道打同一个标签（留空 = 不打）。外部节点的隧道不自动打标
    # —— 它是用户自己从服务商那儿拿来的，叫什么叫用户说了算。
    tag: str = ""
    # 「这个地址已经导入过了」时，是否允许**清掉那个空节点再重建**。
    #
    # ⚠️ 默认 False，而且只对「零隧道 + 零实例」的残留节点生效。刻意做成显式开关：
    #    静默沿用旧记录是绝对不行的 —— 旧配置里的 proxies 可能和新配置不同，
    #    沿用会让旧隧道留在「没有任何人知道」的状态（幽灵隧道）。
    #    至于还有隧道挂着的节点，重建就等于删隧道，那属于 `DELETE /api/manual-nodes`
    #    的职责（它会报出删了几条），不该由「导入」顺手干。
    overwrite: bool = False


class ManualNodePatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=64)
    server_addr: str | None = Field(None, min_length=1)
    server_port: int | None = Field(None, ge=1, le=65535)
    auth_method: str | None = Field(None, pattern="^(token|user|none)$")
    auth_token: str | None = None
    auth_user: str | None = None
    note: str | None = None
    enabled: bool | None = None
    # 「重新粘一份配置」这条路：给了 text 就由后端自己解析出服务端要素、
    # 格式和原文，前端不必把字段拆开传。这比让用户逐个改地址/端口/token
    # 更贴近实际 —— 外部节点是一次性的，用户手上有的就是一段配置。
    text: str | None = Field(None, min_length=1)
    format: str | None = Field(None, pattern="^(toml|ini)$")


class ManualSwitchIn(BaseModel):
    instance_id: int
    # None = 按设置来（实例的 restart_mode + 全局 auto_restart_frpc）
    restart: bool | None = None


# 标签归一化：去首尾空白、把内部连续空白折成一个空格、截到 32 字符。
# 不强制小写 —— 用户可能想用「公司frps」这种带中文/大写的标签。
# 筛选是精确匹配，所以「同一个标签」必须归一化后完全一致，否则
# '  mefrp ' 和 'mefrp' 会被当成两个标签。
def _norm_tag(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text[:32]


# ---------------------------------------------------------------------------
# 基础
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"ok": True, "ts": int(time.time())}


def _icon(name: str, media_type: str) -> FileResponse:
    path = WEB_DIR / name
    if not path.exists():
        raise HTTPException(404, "图标文件缺失")
    return FileResponse(path, media_type=media_type)


# 站点图标。**两个路径都要提供**，少一个就会有一类浏览器看到空白图标：
#
#   /favicon.svg —— Chrome / Edge / Firefox 用它。矢量，任意尺寸都清晰，
#                   在 <link rel="icon" type="image/svg+xml"> 里被声明。
#   /favicon.ico —— Safari（macOS 和 iOS）**完全不使用 SVG favicon**，会回落到
#                   这个路径；部分嵌入式 webview 也只认它。没有这个文件，
#                   Safari 用户看到的就是一片空白 —— 不是 404 图标，是空白。
#
# 两条都**不需要登录** —— 浏览器取图标时不保证带上 Cookie，
# 加了鉴权反而会变成 401 导致图标不显示。
@app.get("/favicon.svg", include_in_schema=False)
async def favicon_svg() -> FileResponse:
    return _icon("favicon.svg", "image/svg+xml")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico() -> FileResponse:
    return _icon("favicon.ico", "image/x-icon")


@app.get("/", include_in_schema=False)
async def index(request: Request):
    """UI 首页。

    未登录时**重定向到登录页**，而不是回 401 —— 浏览器收到带
    `WWW-Authenticate: Basic` 的 401 会弹原生对话框，那个对话框既丑
    又没法登出，正是引入登录页要摆脱的东西。
    """
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=302)
    path = WEB_DIR / "index.html"
    if not path.exists():
        raise HTTPException(500, "UI 文件缺失")
    return FileResponse(path, media_type="text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# 总览
# ---------------------------------------------------------------------------

@app.get("/api/overview")
async def overview(_: None = Auth) -> dict[str, Any]:
    snap = engine.snapshot()
    tunnels = store.list_tunnels()

    items = []
    for t in tunnels:
        # ⚠️ 用 manual_node_for（两个来源都看），不是 manual_node_of_tunnel。
        #    后者只看隧道自己标的 manual_node_id，会漏掉「实例已经切到外部节点、
        #    但隧道还没标」的中间态 —— 那种隧道在页面上会被当成 mefrp 隧道，
        #    然后拿去跟 mefrp 的 proxy 列表比对，判出一个不存在的假故障。
        mn = engine.manual_node_for(t)
        # 外部节点上的隧道**不查 mefrp 的 proxy** —— 它压根不在那边，查了只会
        # 得到一个「隧道在 mefrp 上不存在」的假故障。
        proxy = engine.proxies.get(t["proxy_name"]) if mn is None else None
        node = engine.nodes.get(t["current_node_id"]) if t["current_node_id"] else None
        cached = engine.probe_cache.get(t["id"])
        # 节点地址走缓存解析器：非管理员账号下 node.hostname 恒为空串，
        # 真实地址来自 proxy_list 的 nodes 子数组或官方配置里的 serverAddr。
        # 外部节点不用反推 —— serverAddr 就在库里。
        addr = (str(mn["server_addr"]) if mn
                else engine.node_address_cached(t["current_node_id"]))
        inst = engine.frpc_for_tunnel(t)
        # ★ HTTP/HTTPS 隧道的「公网入口」是**域名**，不是 地址:端口。
        #   它的 current_remote_port 恒为 null，照老逻辑拼出来会是空串，
        #   页面上就永远显示「—」，用户以为没配好。
        t_http = is_http_type(t.get("proxy_type"))
        # 域名优先用 mefrp 上**实际**绑定的；还没建/还没刷新时退回用户填的期望值 ——
        # 否则刚建完的隧道在页面上会显示「没有绑定域名」，看着像没保存上。
        dom_list = (parse_domains(t.get("current_domain") or "")
                    or parse_domains(t.get("desired_domain") or "")) if t_http else []
        if t_http and dom_list:
            scheme = "https" if str(t.get("proxy_type")).lower() == "https" else "http"
            public_endpoint = f"{scheme}://{dom_list[0]}"
        else:
            public_endpoint = (f"{addr}:{t['current_remote_port']}"
                               if addr and t["current_remote_port"] else "")
        items.append({
            **t,
            "node_source": "manual" if mn else "api",
            "manual_node_id": int(mn["id"]) if mn else None,
            "manual_node_name": mn["name"] if mn else "",
            "proxy_found": proxy is not None,
            "proxy_online": bool(proxy and proxy.is_online),
            "proxy_remote_port": proxy.remote_port if proxy else None,
            "node_name": mn["name"] if mn else (node.name if node else ""),
            "node_hostname": addr,
            "address_known": bool(addr),
            "is_http": t_http,
            "domains": dom_list,
            # 公网访问入口。TCP/UDP 是 203.0.113.10:41234；HTTP/S 是 http(s)://域名
            "public_endpoint": public_endpoint,
            # 归属的 frpc 实例（可能是显式绑定，也可能是自动解析出来的）
            "frpc_instance_name": inst["name"] if inst else "",
            "frpc_bound": inst is not None,
            # probe_ok 三态：True 可达 / False 失败 / None 不适用或尚未探测。
            # probe_skipped 用来把「不适用」和「还没探过」区分开。
            "probe_ok": cached[1] if cached else None,
            "probe_skipped": bool(cached and cached[1] is None),
            "probe_reason": cached[2] if cached else "",
            "probe_at": int(cached[0]) if cached else 0,
        })

    instances = store.list_frpc_instances()
    views = [_instance_view(i) for i in instances]
    primary_view = views[0] if views else {}

    return {
        "engine": {
            "running": snap.running,
            "configured": snap.configured,
            "user_group": snap.user_group,
            "user_group_friendly": snap.user_group_friendly,
            "user_group_error": snap.user_group_error,
            "last_error": snap.last_error,
            "tick_count": snap.tick_count,
            "next_tick_in": snap.next_tick_in,
            "node_total": len(engine.nodes),
            "node_online": sum(1 for n in engine.nodes.values() if n.usable),
            "address_known": len(engine.node_hostname_cache),
            # 外部节点与 mefrp 节点**同级**展示，但分开计数 —— 页面上要能一眼
            # 看出「哪些是 API 管的、哪些是我手工贴进去的」。
            "manual_node_total": len(store.list_manual_nodes()),
            "manual_node_enabled": sum(
                1 for n in store.list_manual_nodes() if n["enabled"]),
        },
        "tunnels": items,
        "frpc": {
            "container": primary_view.get("container_state", {"available": False}),
            "config_path": primary_view.get("config_path",
                                            str(BOOTSTRAP.frpc_config_path)),
            "config_summary": primary_view.get("config_summary", {}),
            "instances": views,
            "instance_count": len(instances),
            "unassigned_count": sum(1 for i in items if not i["frpc_bound"]),
        },
        "pending_review": [t for t in items if t.get("needs_downstream_review")],
    }


# ---------------------------------------------------------------------------
# 隧道
# ---------------------------------------------------------------------------

@app.get("/api/tunnels")
async def list_tunnels(tag: str | None = None,
                       _: None = Auth) -> list[dict[str, Any]]:
    """列出受管隧道。

    `?tag=` 按标签筛选；`?tag=`（空串）筛「没打标签的」。不传 = 全量。
    ⚠️ 这里要能区分「不传」和「传空串」，所以默认值是 None 而不是 ""。

    ⚠️ 每条都要带上 `frpc_bound` / `frpc_instance_name`。这两个字段原来**只在**
    `/api/overview` 里算，于是同一个隧道在两个接口里的形状不一样：前端的
    「手动切换」对话框（`failover()`）读的是这个接口，`t.frpc_bound` 拿到
    `undefined` —— falsy，于是**挂接明明成功了，还是提示「它还没有挂接 frpc
    容器，无法切换」**。实测踩过（隧道卡片因为另有 `=== undefined` 兜底，
    反而显示正常，更让人以为是挂接没生效）。
    实例表只查一次，别在循环里逐条查。
    """
    rows = store.list_tunnels(tag=(_norm_tag(tag) if tag is not None else None))
    instances = store.list_frpc_instances(enabled_only=True)
    out: list[dict[str, Any]] = []
    for t in rows:
        inst = engine.frpc_for_tunnel(t, instances)
        out.append({
            **t,
            "frpc_instance_name": inst["name"] if inst else "",
            "frpc_bound": inst is not None,
        })
    return out


@app.get("/api/tags")
async def list_tags(_: None = Auth) -> list[dict[str, Any]]:
    """所有在用的隧道标签 + 各自条数。给隧道页的筛选条用。"""
    return store.list_tags()


@app.get("/api/orphans")
async def list_orphans(_: None = Auth) -> list[dict[str, Any]]:
    """mefrp 账号里存在、但还没被本程序纳管的隧道。

    用途：手工在 mefrp 网页上建过的隧道，可以通过这里「纳管」进来，
    不必先在页面里新建一条再手动填 proxyId。
    """
    # ⚠️ 只拿 **mefrp 作用域**的隧道来比对。外部节点的隧道跟 mefrp 的 proxy 列表
    #    本来就不是一回事 —— 把它们一起算进来的话，「别家 frps 上恰好同名的隧道」
    #    会把 mefrp 上一条**真·未纳管**的隧道藏掉，用户在页面上永远看不到它。
    managed = {t["proxy_name"] for t in store.list_tunnels()
               if not t.get("manual_node_id")}
    out: list[dict[str, Any]] = []
    for p in engine.proxies.values():
        if p.proxy_name in managed:
            continue
        node = engine.nodes.get(p.node_id)
        out.append({
            "proxy_id": p.proxy_id,
            "proxy_name": p.proxy_name,
            "proxy_type": p.proxy_type,
            "node_id": p.node_id,
            "node_name": node.name if node else "",
            "node_hostname": node.hostname if node else "",
            "remote_port": p.remote_port,
            "local_ip": p.local_ip,
            "local_port": p.local_port,
            "is_online": p.is_online,
            "is_banned": p.is_banned,
            "is_disabled": p.is_disabled,
        })
    out.sort(key=lambda x: x["proxy_id"])
    return out


@app.post("/api/tunnels")
async def create_tunnel(payload: TunnelIn, _: None = Auth) -> dict[str, Any]:
    # ⚠️ 查重限定在 **mefrp 作用域**（默认值就是它）。别家 frps 上有同名隧道
    #    不影响这里 —— 各运营商的命名空间互不相干。
    #    展示名（name）**不查重**：它不是唯一键，重名是允许的。
    if store.find_tunnel_by_proxy(payload.proxy_name):
        raise HTTPException(400, f"proxy_name「{payload.proxy_name}」已被占用")
    # ⚠️ DNS 记录名是**全局**唯一（不像 proxy_name 只在 mefrp 作用域内）。
    #    这里不查的话，两条隧道会每 20 秒对着同一条记录互相覆盖。
    _claim_dns_name(payload.dns_record_name)
    data = payload.model_dump()
    data["enabled"] = int(data["enabled"])
    data["auto_failover"] = int(data["auto_failover"])
    data["dns_proxied"] = int(data["dns_proxied"])

    # ★ 按隧道类型做条件校验 —— 这是 1.0.2 的核心分歧点：
    #   · HTTP/HTTPS —— 靠**域名**工作，必须填绑定域名；端口对它没意义（mefrp 侧
    #     恒为 null），填了会被静默忽略，不如直接报错让用户少走弯路。
    #   · TCP/UDP —— 靠**端口**工作，domain 字段必须为空（填了 mefrp 也不认）。
    http_like = is_http_type(payload.proxy_type)
    if http_like:
        if not parse_domains(payload.desired_domain):
            raise HTTPException(
                400,
                "HTTP/HTTPS 隧道必须填写「绑定域名」—— 它是靠域名工作的，"
                "没有域名节点反代就不知道该把请求转给谁。")
        if payload.desired_remote_port:
            raise HTTPException(
                400,
                "HTTP/HTTPS 隧道没有远程端口（mefrp 侧 remotePort 恒为 null）—— "
                "请把「期望远程端口」留空。对外入口是「绑定域名」。")
        # 归一化成 mefrp 要的「文本化 JSON 数组」（见 mefrp.join_domains）
        data["desired_domain"] = join_domains(payload.desired_domain)
        data["desired_remote_port"] = None
    else:
        if parse_domains(payload.desired_domain):
            raise HTTPException(
                400,
                "TCP/UDP 隧道不能绑定域名 —— 域名只对 HTTP/HTTPS 隧道有意义。"
                "对外入口是「远程端口」。")
        # 归一化：port 组的这几项一律清空，避免从 http 改类型后残留旧值。
        data["desired_domain"] = ""
        data["http_plugin"] = ""
        data["route_locations"] = ""
        data["crt_path"] = ""
        data["key_path"] = ""

    # 这个端点建的都是 **mefrp** 隧道（外部节点的隧道只能从 frpc 配置导入），
    # 所以没指定标签时默认打上 'mefrp' —— 这样隧道页一进来就能按来源分组，
    # 不用用户挨条去标。想改成别的标签直接传 tag 覆盖即可。
    data["tag"] = _norm_tag(payload.tag) or "mefrp"
    tid = store.create_tunnel(data)
    store.add_event("info", "system", f"新增受管隧道「{payload.name}」", tunnel_id=tid)
    return {"ok": True, "id": tid}


@app.patch("/api/tunnels/{tunnel_id}")
async def patch_tunnel(tunnel_id: int, payload: TunnelPatch,
                       _: None = Auth) -> dict[str, Any]:
    if store.get_tunnel(tunnel_id) is None:
        raise HTTPException(404, "隧道不存在")
    data = payload.model_dump(exclude_none=True)
    for key in ("enabled", "auto_failover", "dns_proxied", "needs_downstream_review"):
        if key in data:
            data[key] = int(bool(data[key]))

    # ⚠️ 标签要能**显式清空**（改成空串）。`exclude_none` 只挡 None，空串会照传，
    #    但归一化必须做 —— 否则 ' mefrp ' 和 'mefrp' 会变成两个标签。统一走
    #    model_fields_set，语义和 frpc_instance_id 一致。
    if "tag" in payload.model_fields_set:
        data["tag"] = _norm_tag(payload.tag)
    else:
        data.pop("tag", None)

    # ⚠️ frpc_instance_id 要能「显式解绑」。走 exclude_none 的话传 null 会被丢掉，
    # 用户就永远解不了绑 —— 所以看 model_fields_set 判断「客户端到底提没提这个字段」。
    if "frpc_instance_id" in payload.model_fields_set:
        iid = payload.frpc_instance_id
        if iid is not None and store.get_frpc_instance(int(iid)) is None:
            raise HTTPException(404, f"frpc 实例 {iid} 不存在")
        data["frpc_instance_id"] = int(iid) if iid else None

    # ⚠️ 改记录名也要查重，而且必须 `exclude_id=自己` —— 否则用户只是改个别的
    #    字段、记录名原样带上，就会把自己判成冲突，连保存都保存不了。
    if "dns_record_name" in data:
        _claim_dns_name(data["dns_record_name"], exclude_id=tunnel_id)

    # ★ 域名字段要归一化成 mefrp 要的「文本化 JSON 数组」。PATCH 走的是
    #   exclude_none，前端传裸域名（"a.com,b.com"）上来，不归一化的话库里就存
    #   裸串、跟 create 那条路存进去的形状不一致，后面比对/显示全乱。
    if "desired_domain" in data:
        cur = store.get_tunnel(tunnel_id) or {}
        # 类型以「这次要改成的」为准，没改类型就看库里现有的。
        ptype = str(data.get("proxy_type") or cur.get("proxy_type") or "tcp")
        if is_http_type(ptype):
            if not parse_domains(data["desired_domain"]):
                raise HTTPException(
                    400, "HTTP/HTTPS 隧道必须填写「绑定域名」—— 它是靠域名工作的。")
            data["desired_domain"] = join_domains(data["desired_domain"])
        else:
            if parse_domains(data["desired_domain"]):
                raise HTTPException(
                    400, "TCP/UDP 隧道不能绑定域名 —— 域名只对 HTTP/HTTPS 有意义。")
            data["desired_domain"] = ""
    # 改类型时也要顺手清掉「另一套」的字段，避免 http↔tcp 来回切之后留下残值。
    if "proxy_type" in data and not is_http_type(data["proxy_type"]):
        for k in ("http_plugin", "route_locations", "crt_path", "key_path"):
            data[k] = ""
    if "proxy_type" in data and is_http_type(data["proxy_type"]):
        # HTTP 隧道没有远程端口 —— 显式置空，别留着上一次的残值。
        data["desired_remote_port"] = None

    # ⚠️ manual_node_id 只允许「解绑」（传 null）。想绑到外部节点必须走
    #    /api/manual-nodes/{id}/switch —— 那条路会**改写配置文件并重启容器**。
    #    直接改这一列只会让库里说「隧道在节点 A」而配置文件里还写着 B，
    #    两边对不上，而用户完全看不出来。
    if "manual_node_id" in payload.model_fields_set:
        want = payload.manual_node_id
        if want:
            raise HTTPException(
                400,
                "绑定外部节点请用「frpc」页的「切到外部节点」—— "
                "那条路会同时改写配置文件并重启容器，直接改字段不会。")
        data["manual_node_id"] = None

    # ★ 改了「DNS 记录名」或「橙云」必须**当场**去 CF 落一次，不能等下一轮巡检
    #   —— 那一轮还会被 `_dns_check_due` 拦下（地址没变），用户改完页面看着毫无
    #   动静，最长要等 `dns_check_interval`（默认 15 分钟）才生效。
    #   ⚠️ 记录名变了还要把缓存的 zone/record id 一起清掉：新名字可能落在**别的
    #   zone** 里，留着旧的 zone_id 会拿错误的 zone 去改记录。
    old = store.get_tunnel(tunnel_id) or {}
    name_changed = ("dns_record_name" in data
                    and str(old.get("dns_record_name") or "")
                        != str(data.get("dns_record_name") or ""))
    proxied_changed = ("dns_proxied" in data
                       and bool(old.get("dns_proxied"))
                           != bool(data.get("dns_proxied")))
    if name_changed:
        data["dns_zone_id"] = None
        data["dns_record_id"] = None

    store.update_tunnel(tunnel_id, data)

    if name_changed or proxied_changed:
        cur = store.get_tunnel(tunnel_id) or {}
        try:
            mn = engine.manual_node_for(cur)
            if mn is not None:
                # 外部节点没有 mefrp 的 Proxy 对象，地址由节点记录直接给出。
                await engine._sync_dns(cur, None, force=True,
                                       host=str(mn.get("server_addr") or ""))
            else:
                await engine._sync_dns(
                    cur, engine.proxies.get(cur.get("proxy_name") or ""),
                    force=True)
        except Exception:  # noqa: BLE001 - DNS 同步失败不该让「保存」这一步失败
            pass
    return {"ok": True}


@app.delete("/api/tunnels/{tunnel_id}")
async def remove_tunnel(tunnel_id: int, delete_remote: bool = False,
                        _: None = Auth) -> dict[str, Any]:
    tunnel = store.get_tunnel(tunnel_id)
    if tunnel is None:
        raise HTTPException(404, "隧道不存在")

    if delete_remote and tunnel["current_proxy_id"] and engine.client:
        try:
            await engine.client.proxy_delete(int(tunnel["current_proxy_id"]))
            store.add_event("info", "system",
                            f"已删除 mefrp 上的隧道 #{tunnel['current_proxy_id']}",
                            tunnel_id=tunnel_id)
        except MefrpError as exc:
            raise HTTPException(502, f"删除远端隧道失败：{exc}") from exc

    store.delete_tunnel(tunnel_id)
    store.add_event("info", "system", f"移除受管隧道「{tunnel['name']}」")

    # ---- 顺手清理没人用的外部节点 ----
    # 外部节点（自建 frps / 别的 frp 服务商）是**跟着隧道走的一次性东西**：
    # 它本来就不该在节点列表里常驻，所以隧道删光之后这条记录也没有存在的
    # 意义了。不清理的话，用户每导一次配置就在库里留一条，越积越多，
    # 而他在页面上根本看不见、也删不掉。
    #
    # ⚠️ 被 frpc 实例引用着的**不能删** —— 那个实例的配置文件里还写着这个
    #    地址，删了节点记录之后实例的「当前连的节点」就无从解释了。
    dropped_node = 0
    nid = tunnel.get("manual_node_id")
    if nid:
        nid = int(nid)
        still_used = (store.count_tunnels_of_manual_node(nid)
                      + len(store.list_instances_of_manual_node(nid)))
        if still_used == 0:
            store.delete_manual_node(nid)
            engine.manual_probe.pop(nid, None)
            dropped_node = nid

    return {"ok": True, "dropped_manual_node": dropped_node}


@app.post("/api/tunnels/{tunnel_id}/failover")
async def manual_failover(tunnel_id: int, payload: FailoverIn,
                          _: None = Auth) -> dict[str, Any]:
    result = await engine.force_failover(tunnel_id, payload.node_id)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error") or "切换失败")
    return result


@app.post("/api/orphans/{proxy_id}/adopt")
async def adopt_orphan(proxy_id: int, payload: OrphanAdoptIn,
                       _: None = Auth) -> dict[str, Any]:
    """把一条未纳管的 mefrp 隧道直接变成受管记录（不需要先手建占位记录）。

    本地地址/端口、当前节点、当前端口都从 mefrp 上实读，不用手填。
    """
    proxy = engine.proxy_by_id.get(int(proxy_id))
    if proxy is None:
        raise HTTPException(404, f"mefrp 上找不到 proxyId={proxy_id} 的隧道，先刷新一次")

    # 查重限定在 mefrp 作用域 —— 别家 frps 上有同名隧道不影响这条能不能纳管。
    if store.find_tunnel_by_proxy(proxy.proxy_name):
        raise HTTPException(400, f"隧道「{proxy.proxy_name}」已经纳管过了")
    _claim_dns_name(payload.dns_record_name)

    # 展示名不再做「重名就加后缀」的处理：它不是唯一键，重名是允许的，
    # 硬改名字只会让人认不出这条隧道原本叫什么。
    name = (payload.name or proxy.proxy_name).strip()[:64] or proxy.proxy_name

    tid = store.create_tunnel({
        "name": name,
        "proxy_name": proxy.proxy_name,
        "proxy_type": proxy.proxy_type or "tcp",
        "local_ip": proxy.local_ip or "127.0.0.1",
        "local_port": int(proxy.local_port or 0) or 1,
        "desired_remote_port": int(proxy.remote_port or 0) or None,
        "pin_node_id": int(proxy.node_id or 0) or None,
        "enabled": 1,
        "auto_failover": int(bool(payload.auto_failover)),
        "current_proxy_id": proxy.proxy_id,
        "current_node_id": proxy.node_id,
        "current_remote_port": proxy.remote_port,
        "dns_record_name": payload.dns_record_name.strip(),
        "dns_proxied": 0,
        "downstream_note": payload.downstream_note.strip(),
        # 纳管的都是 mefrp 上的隧道 —— 默认标签就是它，方便按来源筛。
        "tag": "mefrp",
    })
    store.add_event("success", "system",
                    f"已纳管 mefrp 隧道「{proxy.proxy_name}」（#{proxy.proxy_id}）",
                    tunnel_id=tid)
    return {"ok": True, "id": tid, "name": name,
            "local": f"{proxy.local_ip}:{proxy.local_port}",
            "remote_port": proxy.remote_port}


@app.post("/api/tunnels/{tunnel_id}/adopt")
async def adopt_proxy(tunnel_id: int, proxy_id: int, _: None = Auth) -> dict[str, Any]:
    """把 mefrp 上已存在的隧道绑定到这条受管记录上。"""
    if store.get_tunnel(tunnel_id) is None:
        raise HTTPException(404, "隧道不存在")
    proxy = engine.proxy_by_id.get(int(proxy_id))
    if proxy is None:
        raise HTTPException(404, f"mefrp 上找不到 proxyId={proxy_id} 的隧道")

    other = store.find_tunnel_by_proxy(proxy.proxy_name)
    if other and other["id"] != tunnel_id:
        raise HTTPException(400, f"隧道「{proxy.proxy_name}」已绑定到另一条记录")

    upd: dict[str, Any] = {
        "proxy_name": proxy.proxy_name,
        "proxy_type": proxy.proxy_type,
        "current_proxy_id": proxy.proxy_id,
        "current_node_id": proxy.node_id,
        "current_remote_port": proxy.remote_port,
        "fail_streak": 0,
        "last_error": "",
    }
    # 只在这条记录还没标签时补 'mefrp'。已经有标签的话说明用户自己设过，
    # 接管一条隧道不该顺手把人家分的组改掉。
    if not _norm_tag((store.get_tunnel(tunnel_id) or {}).get("tag")):
        upd["tag"] = "mefrp"
    store.update_tunnel(tunnel_id, upd)
    store.add_event("success", "system",
                    f"已接管隧道「{proxy.proxy_name}」（#{proxy.proxy_id}）",
                    tunnel_id=tunnel_id)
    return {"ok": True}


async def _sync_dns_after_probe(tunnel: dict[str, Any], mn: dict[str, Any] | None,
                                host: str) -> str:
    """探测之后顺手同步一次 DNS，返回给前端看的说明。

    ⚠️ 为什么「立即探测」也要管 DNS：探测和 DNS 是**两件独立的事**，
    但用户点这个按钮的意图是「让这条隧道现在就是对的」。只回一句「可达」、
    域名却还指着旧地址，等于没修好。而且在这里同步一次，用户能**当场**在弹窗里
    看到 DNS 的结果（成功 / 找不到 zone / token 没权限），不必去翻事件日志。

    ⚠️ **必须 `force=True`**：DNS 平时有核对节流（`dns_check_interval`，默认 15 分钟，
    见 `engine._dns_check_due`），但那节流是给**引擎自动巡检**用的 —— 省掉「地址没变
    还每轮去打一次 CF」。而这里是人**刚刚按了按钮**，他要的就是「现在核对一次」。
    不加 `force` 的话，用户点了「立即探测」，弹窗里 DNS 那行会是空的（地址没变、
    还没到点），恰好违背上面那句「让这条隧道现在就是对的」。
    切换节点（`engine`）和导入外部节点（`main`）两条路都传了 `force`，这里必须一致。
    """
    try:
        return await engine._sync_dns(
            tunnel,
            None if mn is not None else engine.proxies.get(tunnel["proxy_name"]),
            force=True,
            host=host,
        )
    except Exception as exc:  # noqa: BLE001 - 单条 DNS 失败不拖垮这次探测
        return f"更新 DNS 异常：{exc}"


@app.post("/api/tunnels/{tunnel_id}/probe")
async def probe_now(tunnel_id: int, _: None = Auth) -> dict[str, Any]:
    tunnel = store.get_tunnel(tunnel_id)
    if tunnel is None:
        raise HTTPException(404, "隧道不存在")

    # ⚠️ 先按**作用域**分流。外部节点的隧道**不在 mefrp 上**，不能拿 proxy_name
    #    去 mefrp 的 proxy 列表里查 —— 各运营商的命名空间互不相干，跨作用域按
    #    名字找东西，轻则报一个莫名其妙的「mefrp 上找不到这条隧道」，重则
    #    **查到一条同名的 mefrp proxy**，然后去探测一条完全不相干的隧道。
    mn = engine.manual_node_for(tunnel)
    ptype = tunnel.get("proxy_type", "tcp")
    http_like = is_http_type(ptype)

    if mn is not None:
        host = str(mn["server_addr"] or "").strip()
        node_name = str(mn["name"])
        if http_like:
            # HTTP 隧道没有远程端口，靠绑定域名。这里不要求 host 一定拿得到
            # （探测本来就用不到节点地址），但域名必须有。
            port = 0
        else:
            port = int(tunnel.get("current_remote_port") or 0)
            if not port:
                raise HTTPException(409, "这条隧道没有远程端口，无法探测"
                                         "（导入配置时那一段没写 remotePort）")
    else:
        proxy = engine.proxies.get(tunnel["proxy_name"])
        if proxy is None:
            raise HTTPException(404, "mefrp 上找不到这条隧道，先刷新一次状态")
        node = engine.nodes.get(proxy.node_id)
        if node is None:
            raise HTTPException(404, f"节点 {proxy.node_id} 不在列表中")

        node_name = node.name
        if http_like:
            # ⚠️ HTTP 隧道**不需要节点地址**：探测打的是绑定域名，节点反代按
            #    Host 头分流。所以这里不能因为「拿不到节点公网地址」就报 409 ——
            #    非管理员账号下节点地址本来就经常拿不到，那会让 HTTP 隧道永远
            #    点不了「立即探测」。
            host = ""
            port = 0
        else:
            host = await engine.node_address(proxy.node_id)
            if not host:
                raise HTTPException(409, (
                    f"拿不到节点「{node.name}」的公网地址。"
                    "mefrp 对非管理员账号不返回节点地址（/auth/node/list 的 hostname 是空串），"
                    "只有在那个节点上建过隧道才能反推出来。"
                ))
            port = int(proxy.remote_port)

    timeout = float(store.get_setting("probe_timeout", 4) or 4)
    target = f"{host}:{port}"

    # 探测方式按类型分流，见 engine.probe_plan：
    #   · TCP/UDP —— 探节点地址 + 远程端口
    #   · HTTP/HTTPS —— 探绑定域名（节点反代按 Host 头分流）
    # 这里和引擎每轮做的事必须**同一套判定**，否则会出现「引擎认为健康、
    # 手动点一下却报故障」的自相矛盾。
    mode = str(store.get_setting("probe_mode", "auto") or "auto")
    pkind, skip_why = probe_plan(ptype, mode)

    # 域名取自「mefrp 上实际绑定的」（proxy.domain 权威）→ 退回库里记的。
    cur_domain = ""
    if http_like:
        if mn is None:
            cur_domain = str(proxy.domain or tunnel.get("current_domain") or "")
        else:
            cur_domain = str(tunnel.get("current_domain") or "")
        url = http_probe_url(ptype, cur_domain,
                             str(store.get_setting("http_probe_path", "/") or "/"))
        target = url or "（未绑定域名）"

    if pkind == PROBE_NONE:
        engine.probe_cache[tunnel_id] = (time.time(), None, skip_why)
        # ⚠️ 「不适用探测」不等于「地址不对」—— DNS 该同步还得同步。
        #    这里原来直接 return，于是 **udp 隧道点「立即探测」永远不解析 DNS**，
        #    而 udp 恰恰是外部节点上最常见的一类。_reconcile_manual 里的同款分支
        #    已经修过了，这里必须跟上 —— 否则「点按钮」和「等引擎」两条路行为不一致，
        #    用户点一次按钮反而更懵。
        dns_msg = await _sync_dns_after_probe(tunnel, mn, host)
        return {
            "ok": None, "skipped": True, "reason": skip_why,
            "target": target, "node": node_name, "proxy_type": ptype,
            "dns": dns_msg,
        }

    if pkind == PROBE_HTTP:
        if not url:
            why = "这条 HTTP 隧道没有绑定域名，无法做 HTTP 探测"
            engine.probe_cache[tunnel_id] = (time.time(), None, why)
            return {
                "ok": None, "skipped": True, "reason": why,
                "target": target, "node": node_name, "proxy_type": ptype,
                "dns": "",
            }
        ok, why = await http_probe(url)
        engine.probe_cache[tunnel_id] = (time.time(), ok, why)
        # 探测通过 = 域名/地址是对的，顺手同步 DNS（和引擎每轮做的事一致）。
        # 探测失败时**不动 DNS** —— 地址并没有变，改它只会把一条本来对的记录改坏。
        dns_msg = await _sync_dns_after_probe(tunnel, mn, host) if ok else ""
        return {
            "ok": ok, "skipped": False, "reason": why,
            "target": target, "node": node_name, "proxy_type": ptype,
            "dns": dns_msg,
        }

    ok, why = await tcp_probe(host, port, timeout)
    engine.probe_cache[tunnel_id] = (time.time(), ok, why)
    # 探测通过 = 地址是对的，顺手把 DNS 纠到这条地址上（和引擎每轮做的事一致）。
    # 探测失败时**不动 DNS** —— 地址并没有变，改它只会把一条本来对的记录改坏。
    dns_msg = await _sync_dns_after_probe(tunnel, mn, host) if ok else ""
    return {
        "ok": ok, "skipped": False, "reason": why,
        "target": target, "node": node_name, "proxy_type": ptype,
        "dns": dns_msg,
    }


# ---------------------------------------------------------------------------
# 节点
# ---------------------------------------------------------------------------

@app.get("/api/nodes")
async def list_nodes(proxy_type: str = "tcp", _: None = Auth) -> dict[str, Any]:
    rows = engine.rank_nodes(proxy_type)
    return {
        "user_group": engine.user_group,
        "user_group_friendly": engine.user_group_friendly,
        "user_group_error": engine.user_group_error,
        "proxy_type": proxy_type,
        "nodes": rows,
        "prefs": store.list_node_prefs(),
        # 有多少个节点已经知道公网地址。非管理员账号下只有「建过隧道」的节点才有地址，
        # 所以这个数通常远小于节点总数，页面上要如实说明。
        "address_known": sum(1 for r in rows if r["address_known"]),
    }


@app.post("/api/nodes/refresh")
async def refresh_nodes(_: None = Auth) -> dict[str, Any]:
    try:
        await engine._refresh_remote()  # noqa: SLF001 - 就是给 UI 用的手动刷新
    except MefrpError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"ok": True, "count": len(engine.nodes)}


@app.post("/api/nodes/pref-preview")
async def nodes_pref_preview(payload: PrefPreviewIn,
                             _: None = Auth) -> dict[str, Any]:
    """按给定顺序试算节点偏好，给设置页做即时预览。

    **只读** —— 用户还在编辑偏好列表，不能顺手把库改了。
    匹配逻辑复用 engine.keyword_rank，所以预览和真正择优的结果不会跑偏。

    （字面量路由写在 /api/nodes/{node_id}/pref 前面：两者段数不同、本来也不冲突，
    放在前面只是跟本文件其它字面量路由保持一致的写法。）
    """
    return engine.preview_pref(payload.keywords)


@app.post("/api/nodes/{node_id}/pref")
async def set_node_pref(node_id: int, payload: NodePrefIn,
                        _: None = Auth) -> dict[str, Any]:
    store.upsert_node_pref(
        int(node_id), payload.priority, payload.excluded, payload.note
    )
    return {"ok": True}


# ---------------------------------------------------------------------------
# 外部节点
#
# 由用户粘贴一份 frpc 配置导入，**与 mefrp 节点同级**：能绑 frpc 实例、能绑域名，
# 唯独不支持自动切换 —— 没有 API 就没法在服务端建/删隧道，换节点只能靠人点。
#
# ⚠️ 路由注册顺序：所有**字面量**路径（/parse、/probe）必须排在 /{node_id} 之前。
#    Starlette 按注册顺序匹配，否则 /api/manual-nodes/parse 会先去撞
#    {node_id} 的 int 解析，直接 422。
# ---------------------------------------------------------------------------

def _manual_view(node: dict) -> dict[str, Any]:
    """单个外部节点的对外视图（不含 token 明文）。"""
    nid = int(node["id"])
    insts = store.list_instances_of_manual_node(nid)
    tunnels = store.list_tunnels_of_manual_node(nid)
    cached = engine.manual_probe.get(nid)
    return {
        "id": nid,
        "name": node["name"],
        "server_addr": node["server_addr"],
        "server_port": int(node["server_port"]),
        "endpoint": f"{node['server_addr']}:{int(node['server_port'])}",
        "auth_method": node["auth_method"],
        # ⚠️ 只回「有没有」，不回明文 —— token 泄露给前端没有任何必要。
        "has_token": bool(node.get("auth_token")),
        "auth_user": node.get("auth_user") or "",
        "config_format": node["config_format"],
        "note": node.get("note") or "",
        "enabled": bool(node["enabled"]),
        "probe_ok": cached[1] if cached else None,
        "probe_reason": cached[2] if cached else "",
        "probe_at": int(cached[0]) if cached else 0,
        "instances": [{"id": int(i["id"]), "name": i["name"],
                       "config_path": i["config_path"]} for i in insts],
        "instance_count": len(insts),
        "tunnel_count": len(tunnels),
    }


def _node_conflict(node: dict[str, Any]) -> dict[str, Any]:
    """把一个「地址撞车」的外部节点描述成**可操作**的结构。

    ⚠️ 这里刻意带上 `existing_id` 和两个计数，而不是只回一句话。原因是一个踩过的坑：
       原来只回「请直接编辑那个节点」，但一个**零隧道**的残留节点在页面上是够不着的
       —— 节点不进节点页，隧道卡片是按隧道渲染的，没有隧道就没有卡片，也就没有任何
       入口能到达它。用户既改不了也删不掉，重新导入**永久被堵**。这是死路，不是提示。
       带上 id 之后前端才能给出「打开那个节点的更新对话框」这个真入口，
       以及「它本来就是空的，清掉重建」这条出路。
    """
    nid = int(node["id"])
    return {
        "code": "node_addr_exists",
        "message": f"这个地址已经导入过了（节点「{node['name']}」）。",
        "existing_id": nid,
        "existing_name": str(node["name"]),
        "tunnel_count": store.count_tunnels_of_manual_node(nid),
        "instance_count": len(store.list_instances_of_manual_node(nid)),
    }


def _dns_name_conflict(record_name: str, *,
                       exclude_id: int | None = None) -> dict[str, Any] | None:
    """DNS 记录名撞车就返回一份可操作的结构，没撞返回 None。

    ⚠️ 为什么这必须是**硬拒绝**、而且没有 overwrite 开关：两条隧道共用一个
    DNS 记录名不是「谁先谁后」的问题，是它们会一直互相覆盖 —— 两边都在健康
    路径上每轮同步一次（默认 20 秒），一个写节点 A 的地址、一个写节点 B 的，
    解析结果每 20 秒翻一次面，而日志里只有一行行「DNS 已更新」，看不出在打架。
    （隧道名重名是另一回事：那个只在「一台 frps 内」唯一，跨运营商重名合法，
      所以走的是 find_tunnel_by_proxy 那套按作用域查的逻辑。）
    """
    name = (record_name or "").strip()
    if not name:
        return None
    other = store.find_tunnel_by_dns_name(name, exclude_id=exclude_id)
    if other is None:
        return None
    return {
        "code": "dns_name_taken",
        "message": f"DNS 记录「{name}」已经归隧道「{other['name']}」"
                   f"（#{other['id']}）管了。",
        "existing_id": int(other["id"]),
        "existing_name": str(other["name"]),
        "record_name": name,
        "hint": "两条隧道用同一个记录名会每轮互相覆盖（默认 20 秒一次），"
                "必须各用各的名字 —— 比如给这条换个前缀。",
    }


def _claim_dns_name(record_name: str, *,
                    exclude_id: int | None = None) -> None:
    """查重，撞了就抛 409（带结构化 detail）。"""
    conflict = _dns_name_conflict(record_name, exclude_id=exclude_id)
    if conflict is not None:
        raise HTTPException(409, conflict)


@app.post("/api/manual-nodes/parse")
async def manual_nodes_parse(payload: ManualParseIn,
                             _: None = Auth) -> dict[str, Any]:
    """解析一份 frpc 配置，**不落库**。给导入对话框做即时预览。"""
    try:
        parsed = frpcparse.parse(payload.text, payload.format)
    except frpcparse.FrpcParseError as exc:
        raise HTTPException(400, str(exc)) from exc

    dup = store.find_manual_node_by_addr(parsed.server_addr, parsed.server_port)
    # 更新模式下「撞到我自己」不是冲突 —— 前端不必再判一次 editing，判断收在后端。
    if dup is not None and payload.node_id and int(dup["id"]) == int(payload.node_id):
        dup = None

    # 解析出来的隧道里，哪些名字**在这个作用域里**已经被纳管了。
    # ⚠️ 新建时必然是空列表 —— 新节点就是一台新的 frps，那个命名空间里什么都没有。
    #    以前这里拿 mefrp 作用域去查，于是「mefrp 上有一条同名的」会被报成
    #    「已纳管」，把一条其实能正常导入的隧道标成不可选。
    taken: list[str] = []
    if payload.node_id:
        taken = [p.name for p in parsed.proxies
                 if store.find_tunnel_by_proxy(p.name,
                                               manual_node_id=payload.node_id)]
    return {
        "ok": True,
        **parsed.as_dict(),
        "taken_names": taken,
        # 撞车的那个节点（结构化），没撞就是 None。
        "duplicate": _node_conflict(dup) if dup is not None else None,
    }


@app.post("/api/manual-nodes/probe")
async def manual_nodes_probe_all(_: None = Auth) -> dict[str, Any]:
    """把所有外部节点探一遍。"""
    out = []
    for n in store.list_manual_nodes():
        r = await engine.probe_manual_node(int(n["id"]), force=True)
        out.append({"id": int(n["id"]), "name": n["name"], **r})
    return {"ok": True, "results": out}


@app.get("/api/manual-nodes")
async def manual_nodes_list(_: None = Auth) -> dict[str, Any]:
    return {
        "nodes": engine.manual_node_rows(),
        "count": len(store.list_manual_nodes()),
        "formats": list(frpcparse.FORMATS),
    }


@app.post("/api/manual-nodes")
async def manual_node_create(payload: ManualNodeIn,
                             _: None = Auth) -> dict[str, Any]:
    """导入一个外部节点，并按勾选纳管它配置里的隧道。"""
    try:
        parsed = frpcparse.parse(payload.text, payload.format)
    except frpcparse.FrpcParseError as exc:
        raise HTTPException(400, str(exc)) from exc

    dup = store.find_manual_node_by_addr(parsed.server_addr, parsed.server_port)
    if dup is not None:
        conflict = _node_conflict(dup)
        # ---- 这条路是「出路」，不是「墙」 ----
        # 原来这里只有一句 400「请直接编辑那个节点」，而那个节点很可能**够不着**
        # （零隧道的残留节点没有任何 UI 入口）→ 用户被永久堵住。所以现在：
        #   · 回结构化 detail（带 existing_id / 两个计数），前端据此给出下一步；
        #   · 允许 overwrite 显式覆盖**空节点**（残留节点就是这么来的）。
        if not payload.overwrite:
            raise HTTPException(409, conflict)
        busy = conflict["tunnel_count"] or conflict["instance_count"]
        if busy:
            # 有隧道/实例挂着的节点**不允许**从这里覆盖：那等于顺手删隧道，
            # 而且删的是用户精心配过 dns 记录名、标签、挂接关系的那几条。
            # 要删就走 DELETE /api/manual-nodes/{id}，它会明确报出删了几条。
            raise HTTPException(409, {
                **conflict,
                "code": "node_in_use",
                "message": (
                    f"节点「{dup['name']}」上还挂着 "
                    f"{conflict['tunnel_count']} 条隧道、"
                    f"{conflict['instance_count']} 个 frpc 实例，不能覆盖重建 —— "
                    "那会连带删掉它们。请改用「更新节点配置」"
                    "（只改服务端要素、不动隧道），"
                    "或者先在隧道页删掉那几条隧道再重新导入。"),
            })
        # 空节点：删掉重建。事件里留痕，免得「我的节点怎么没了」无从追溯。
        store.delete_manual_node(int(dup["id"]))
        engine.manual_probe.pop(int(dup["id"]), None)
        store.add_event(
            "warn", "node",
            f"导入时覆盖了残留的空节点「{dup['name']}」"
            f"（{dup['server_addr']}:{int(dup['server_port'])}，"
            "零隧道零实例，已删除后按新配置重建）",
        )

    name = (payload.name or parsed.label).strip()[:64] or parsed.label
    if store.get_manual_node_by_name(name):
        raise HTTPException(400, f"外部节点名「{name}」已存在")

    nid = store.create_manual_node({
        "name": name,
        "server_addr": parsed.server_addr,
        "server_port": parsed.server_port,
        "auth_method": parsed.auth_method,
        "auth_token": parsed.auth_token,
        "auth_user": parsed.auth_user,
        "config_format": parsed.fmt,
        "config_text": payload.text,
        "note": payload.note.strip(),
        "enabled": int(bool(payload.enabled)),
    })

    # ---- 纳管勾选的隧道 ----
    specs = {p.name: p for p in parsed.proxies}
    adopted: list[str] = []
    skipped: list[dict[str, str]] = []
    # DNS 记录名撞车的条目。⚠️ 和 skipped 分开记：这些隧道**是纳管了的**，
    # 只是没给它填记录名 —— 混进 skipped 会让前端报「没纳管」，那是假话。
    dns_clash: list[dict[str, str]] = []
    # 刚建出来的隧道行。下一步要拿它们逐个同步 DNS，所以这里必须留住整行，
    # 不能只留名字 —— dns_record_name / dns_zone_id 都在行里。
    created: list[dict[str, Any]] = []
    for item in payload.proxies:
        if not item.adopt:
            continue
        spec = specs.get(item.name)
        if spec is None:
            skipped.append({"name": item.name, "why": "配置里没有这一段"})
            continue
        # ⚠️ 只在**本节点这个作用域**里查重。拿全局查是错的 ——
        #    mefrp 上有一条同名隧道，不代表这份配置里的隧道「已经纳管过了」，
        #    它们是两台不同 frps 上的两条隧道，命名空间互不相干。
        #    新导入时这里必然为空（节点刚建），保留这道检查是防重复调用。
        if store.find_tunnel_by_proxy(spec.name, manual_node_id=nid):
            skipped.append({"name": spec.name, "why": "这个节点上已有同名隧道"})
            continue

        # 展示名直接用隧道本名。⚠️ **不做跨作用域改名** —— 展示名不是唯一键，
        # 不同 frps 上重名是正常的，改成 `xxx-7` 反而让人看不出它原本叫什么。
        #
        # ⚠️ DNS 记录名撞车时**只放弃这一个字段**，隧道照建。整份导入失败太重了：
        #    用户粘的是 frpc 配置，记录名只是顺带填的，很可能只是复制粘贴时忘了
        #    改前缀。所以这里如实报出来（dns_clash），让他回头去「编辑隧道」改。
        rec_name = item.dns_record_name.strip()
        clash = _dns_name_conflict(rec_name)
        if clash is not None:
            dns_clash.append({
                "name": spec.name,
                "record_name": rec_name,
                "existing_id": str(clash["existing_id"]),
                "existing_name": str(clash["existing_name"]),
            })
            rec_name = ""
        store.create_tunnel({
            "name": spec.name,
            "proxy_name": spec.name,
            "proxy_type": spec.proxy_type,
            "local_ip": spec.local_ip,
            "local_port": spec.local_port or 1,
            "current_remote_port": spec.remote_port or None,
            "manual_node_id": nid,
            "enabled": int(bool(item.enabled)),
            # ⚠️ 外部节点的隧道**一律关掉自动切换** —— 没有 API，切不了。
            #    留着这个开关只会让用户以为它会自愈。
            "auto_failover": 0,
            "dns_record_name": rec_name,
            "frpc_instance_id": payload.frpc_instance_id,
            # 这次纳管的隧道统一打上用户填的标签（留空 = 不打）。
            "tag": _norm_tag(payload.tag),
        })
        adopted.append(spec.name)
        row = store.find_tunnel_by_proxy(spec.name, manual_node_id=nid)
        if row is not None:
            created.append(row)

    # ---- 顺手把 DNS 纠一遍 ----
    # ⚠️ 导入时**立刻**同步，而不是等引擎下一轮（最长 20 秒）。三个理由：
    #   · 用户粘完配置就站在页面前，什么都不发生他会以为「没生效」——这正是
    #     「手动添加的隧道好像没有自动进行 cf dns 解析」这个疑问的来源；
    #   · DNS 失败的原因（找不到 zone、token 没权限）必须**当场**说出来，否则
    #     它只躺在事件日志里，用户根本不会去看；
    #   · 导入 = 用户明确粘了一份配置并逐条填了记录名，意图是清楚的。
    # 所以这里 force=True：不受「自动纠正漂移的 DNS」那个开关拦（那个开关管的是
    # 引擎每轮的自动巡检，不是用户刚下达的指令）。失败不影响导入本身。
    dns_msgs: list[str] = []
    for t in created:
        if not (t.get("dns_record_name") or "").strip():
            continue
        try:
            msg = await engine._sync_dns(t, None, force=True,
                                         host=parsed.server_addr)
        except Exception as exc:  # noqa: BLE001 - 单条 DNS 失败不拖垮整次导入
            msg = f"更新 DNS 异常：{exc}"
        if msg:
            dns_msgs.append(f"{t['name']}：{msg}")

    detail = [
        f"格式：{parsed.fmt}",
        f"鉴权：{parsed.auth_method}",
        f"配置里的隧道：{'、'.join(specs) or '（无）'}",
        f"已纳管：{'、'.join(adopted) or '（无）'}",
    ]
    if skipped:
        detail.append("跳过：" + "；".join(f"{s['name']}（{s['why']}）" for s in skipped))
    if dns_clash:
        detail.append("DNS 记录名撞车（这几条没填记录名，隧道本身已纳管）：" + "；".join(
            f"{c['name']} 想填 {c['record_name']}，但已被 "
            f"「{c['existing_name']}」#{c['existing_id']} 占用" for c in dns_clash))
    if parsed.warnings:
        detail.append("解析提示：" + "；".join(parsed.warnings))
    if dns_msgs:
        detail.append("DNS：" + "；".join(dns_msgs))

    store.add_event(
        "success", "node",
        f"导入外部节点「{name}」（{parsed.server_addr}:{parsed.server_port}）"
        + (f"，纳管 {len(adopted)} 条隧道" if adopted else "，未纳管隧道"),
        detail="\n".join(detail),
    )

    # ---- 指定了承载实例就顺手切过去 ----
    # 用户勾了「这些隧道由哪个实例承载」，那就必须把那个实例的配置文件改到
    # 这个节点上，否则库里的绑定关系和机器上跑的东西对不上 —— 而用户完全看不出来。
    switched: dict[str, Any] | None = None
    if payload.frpc_instance_id:
        switched = await engine.switch_instance_to_node(
            int(payload.frpc_instance_id), nid)

    return {
        "ok": True,
        "id": nid,
        "name": name,
        "endpoint": f"{parsed.server_addr}:{parsed.server_port}",
        "format": parsed.fmt,
        "adopted": adopted,
        "skipped": skipped,
        # DNS 记录名撞车的条目。前端要当场说出来 —— 否则用户会以为记录名填上了，
        # 然后去怀疑「怎么没解析」。
        "dns_clash": dns_clash,
        "warnings": parsed.warnings,
        "switched": switched,
        # 导入时顺手做的 DNS 同步结果（每条一行）。前端把它显示在成功弹窗里
        # —— 失败原因（找不到 zone、token 没权限）必须当场说出来，否则用户
        # 只会觉得「怎么没解析」，然后去翻日志。
        "dns": dns_msgs,
        # 覆盖重建时回被删掉的那个残留节点的名字，前端好把这件事说出口。
        "overwritten": dup["name"] if (dup is not None and payload.overwrite) else "",
        "node": _manual_view(store.get_manual_node(nid) or {}),
    }


@app.post("/api/manual-nodes/{node_id}/probe")
async def manual_node_probe(node_id: int, _: None = Auth) -> dict[str, Any]:
    if store.get_manual_node(node_id) is None:
        raise HTTPException(404, "外部节点不存在")
    return {"ok": True, **(await engine.probe_manual_node(node_id, force=True))}


@app.post("/api/manual-nodes/{node_id}/switch")
async def manual_node_switch(node_id: int, payload: ManualSwitchIn,
                             _: None = Auth) -> dict[str, Any]:
    """把某个 frpc 实例切到这个外部节点上。**外部节点唯一的切换方式。**"""
    result = await engine.switch_instance_to_node(
        int(payload.instance_id), int(node_id), restart=payload.restart)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error") or "切换失败")
    return result


@app.get("/api/manual-nodes/{node_id}")
async def manual_node_get(node_id: int, _: None = Auth) -> dict[str, Any]:
    node = store.get_manual_node(node_id)
    if node is None:
        raise HTTPException(404, "外部节点不存在")
    return {**_manual_view(node), "config_text": node.get("config_text") or ""}


@app.patch("/api/manual-nodes/{node_id}")
async def manual_node_patch(node_id: int, payload: ManualNodePatch,
                            _: None = Auth) -> dict[str, Any]:
    """改外部节点。

    ⚠️ 改了**服务端要素**（地址 / 端口 / 鉴权）之后，必须把改动传导到绑定的实例上
       —— 否则库里说「节点是 A」，实例配置文件里还写着 B，两边对不上，而用户
       完全看不出来。传导直接复用切换那条路（改写 server 段 → 按设置重启 →
       重新解析 DNS），所以「编辑节点」和「切换到此节点」的行为完全一致。
    """
    node = store.get_manual_node(node_id)
    if node is None:
        raise HTTPException(404, "外部节点不存在")

    data = payload.model_dump(exclude_none=True)
    data.pop("text", None)
    data.pop("format", None)

    # 「重新粘一份配置」这条路：后端自己解析，前端不必把字段拆开传。
    # 这比让用户逐个改地址/端口/token 更贴近实际 —— 外部节点是一次性的，
    # 用户手上有的就是服务商官网给的那一段配置。
    if payload.text:
        try:
            parsed = frpcparse.parse(payload.text, payload.format)
        except frpcparse.FrpcParseError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not parsed.server_addr:
            raise HTTPException(400, "这份配置里没读到 serverAddr / server_addr")
        data.update({
            "server_addr": parsed.server_addr,
            "server_port": parsed.server_port,
            "auth_method": parsed.auth_method,
            # ⚠️ 这里**要**原样覆盖 token：用户粘的是新配置，里面没有 token
            #    就说明新的节点不需要 token，旧的必须清掉，不能留着。
            "auth_token": parsed.auth_token,
            "auth_user": parsed.auth_user,
            "config_format": parsed.fmt,
            "config_text": payload.text,
        })

    if "enabled" in data:
        data["enabled"] = int(bool(data["enabled"]))
    if "name" in data:
        new_name = str(data["name"]).strip()[:64]
        if not new_name:
            raise HTTPException(400, "节点名不能为空")
        other = store.get_manual_node_by_name(new_name)
        if other is not None and int(other["id"]) != int(node_id):
            raise HTTPException(400, f"外部节点名「{new_name}」已存在")
        data["name"] = new_name

    server_keys = ("server_addr", "server_port", "auth_method",
                   "auth_token", "auth_user")
    server_changed = any(k in data and data[k] != node.get(k) for k in server_keys)

    if server_changed:
        addr = str(data.get("server_addr", node["server_addr"])).strip()
        port = int(data.get("server_port", node["server_port"]))
        if not addr:
            raise HTTPException(400, "服务端地址不能为空")
        dup = store.find_manual_node_by_addr(addr, port)
        if dup is not None and int(dup["id"]) != int(node_id):
            raise HTTPException(409, {
                **_node_conflict(dup),
                "message": f"这个地址已被节点「{dup['name']}」占用。",
            })

    store.update_manual_node(node_id, data)
    node = store.get_manual_node(node_id) or node

    switched: list[dict[str, Any]] = []
    if server_changed:
        for inst in store.list_instances_of_manual_node(node_id):
            switched.append(await engine.switch_instance_to_node(
                int(inst["id"]), int(node_id)))

    return {
        "ok": True,
        "server_changed": server_changed,
        "switched": switched,
        "node": _manual_view(node),
    }


@app.delete("/api/manual-nodes/{node_id}")
async def manual_node_delete(node_id: int, keep_tunnels: bool = False,
                             _: None = Auth) -> dict[str, Any]:
    """删外部节点。

    绑在上面的实例会被解绑（退回 mefrp API 模式），从它导入的隧道默认一起删掉
    —— 那些隧道离开了这个节点就没有意义了（没有 API 能在别处重建它们）。
    想留个记录就传 `keep_tunnels=true`，那样只解绑不删。
    """
    node = store.get_manual_node(node_id)
    if node is None:
        raise HTTPException(404, "外部节点不存在")

    unbound = store.unbind_instances_of_manual_node(node_id)
    tunnels = store.list_tunnels_of_manual_node(node_id)
    removed = 0
    if keep_tunnels:
        store.unbind_tunnels_of_manual_node(node_id)
    else:
        for t in tunnels:
            store.delete_tunnel(int(t["id"]))
            engine.probe_cache.pop(int(t["id"]), None)
            removed += 1

    store.delete_manual_node(node_id)
    engine.manual_probe.pop(int(node_id), None)

    store.add_event(
        "warn", "node",
        f"删除外部节点「{node['name']}」"
        f"（解绑 {unbound} 个 frpc 实例，"
        + (f"移除 {removed} 条隧道" if removed else f"保留 {len(tunnels)} 条隧道记录")
        + "）",
    )
    return {"ok": True, "unbound_instances": unbound, "removed_tunnels": removed,
            "kept_tunnels": len(tunnels) - removed}


# ---------------------------------------------------------------------------
# frpc 实例
#
# ⚠️ 路由注册顺序有讲究：所有**字面量**路径（/api/frpc/map、/api/frpc/rebuild …）
#    必须排在 /api/frpc/{instance_id} **前面**。Starlette 按注册顺序匹配，
#    否则 /api/frpc/map 会先去撞 {instance_id} 的 int 解析，直接 422。
# ---------------------------------------------------------------------------

def _primary_instance() -> dict | None:
    instances = store.list_frpc_instances()
    return instances[0] if instances else None


def _instance_view(inst: dict, *, with_config: bool = False) -> dict[str, Any]:
    """给 UI 用的实例视图：配置摘要 + 容器状态 + 承载的隧道 + 备份数。"""
    iid = int(inst["id"])
    path = Path(str(inst["config_path"]))
    mode = str(inst.get("restart_mode") or "docker")

    text = ""
    summary: dict[str, Any] = {}
    read_error = ""
    try:
        text = frpc.read_config(path)
        if text:
            summary = frpc.config_summary(text)
    except frpc.FrpcError as exc:
        read_error = str(exc)

    if mode == "none":
        state: dict[str, Any] = {"available": True, "name": "",
                                 "status": "不自动重启"}
    else:
        dk = engine.docker_for(inst)
        state = dk.state() if dk is not None else {
            "available": False, "error": "未配置容器名，或 Docker 不可达"
        }
    state = {**state, "restart_mode": mode}

    tunnels = store.list_tunnels_of_frpc(iid)
    # 这个实例是不是挂在外部节点上。挂上了就说明：配置文件由手动切换维护，
    # 引擎不会自动改写它，也不会有自动切换 —— 页面上要如实标出来。
    mn = store.get_manual_node(int(inst["manual_node_id"])) \
        if inst.get("manual_node_id") else None
    out: dict[str, Any] = {
        **inst,
        "id": iid,
        "enabled": bool(inst["enabled"]),
        "manual_node_id": int(mn["id"]) if mn else None,
        "manual_node_name": mn["name"] if mn else "",
        "manual_node_endpoint": (f"{mn['server_addr']}:{int(mn['server_port'])}"
                                 if mn else ""),
        "node_source": "manual" if mn else "api",
        "config_exists": path.exists(),
        "config_summary": summary,
        "config_read_error": read_error,
        "container_state": state,
        "tunnels": [
            {"id": int(t["id"]), "name": t["name"], "proxy_name": t["proxy_name"],
             "enabled": bool(t["enabled"]),
             "current_node_id": t.get("current_node_id")}
            for t in tunnels
        ],
        "tunnel_count": len(tunnels),
        "backup_count": len(frpc.list_backups(iid)),
    }
    if with_config:
        out["config"] = text
    return out


def _check_path_available(path: Path, *, exclude_id: int | None = None) -> None:
    """校验配置路径合法且没被别的实例占用。

    ⚠️ 两个实例共用一个配置文件会互相覆盖，是必须拦住的配置错误。
    """
    if not path.is_absolute():
        raise HTTPException(
            400, "配置路径必须是绝对路径（相对路径会随进程工作目录变化）"
        )
    for other in store.list_frpc_instances():
        if exclude_id is not None and int(other["id"]) == int(exclude_id):
            continue
        if Path(str(other["config_path"])) == path:
            raise HTTPException(
                400, f"配置路径已被实例「{other['name']}」占用：{path}"
            )


@app.get("/api/frpc")
async def frpc_info(_: None = Auth) -> dict[str, Any]:
    instances = store.list_frpc_instances()
    primary = instances[0] if instances else None
    head = _instance_view(primary, with_config=True) if primary else {}
    return {
        # —— 兼容旧前端：把第一个实例的字段平铺在顶层 ——
        "config_path": head.get("config_path", str(BOOTSTRAP.frpc_config_path)),
        "config": head.get("config", ""),
        "summary": head.get("config_summary", {}),
        "container": head.get("container_state", {"available": False}),
        "backups": frpc.list_backups(int(primary["id"])) if primary else [],
        # —— 多实例 ——
        "instances": [_instance_view(i) for i in instances],
        "instance_count": len(instances),
        "restart_modes": list(store.RESTART_MODES),
    }


@app.post("/api/frpc")
async def frpc_create(payload: FrpcIn, _: None = Auth) -> dict[str, Any]:
    name = payload.name.strip()
    if store.get_frpc_instance_by_name(name):
        raise HTTPException(400, f"frpc 实例名「{name}」已存在")
    path = Path(payload.config_path.strip())
    _check_path_available(path)

    iid = store.create_frpc_instance({
        "name": name,
        "config_path": str(path),
        "container": payload.container.strip(),
        "restart_mode": payload.restart_mode,
        "enabled": int(bool(payload.enabled)),
        "note": payload.note.strip(),
    })
    engine.reload_dockers()
    store.add_event("info", "frpc",
                    f"新增 frpc 实例「{name}」（配置 {path}）")
    return {"ok": True, "id": iid}


@app.post("/api/frpc/rebuild")
async def frpc_rebuild(restart: bool = False, _: None = Auth) -> dict[str, Any]:
    """重建**全部**实例的配置。"""
    try:
        changed, summary = await engine.rebuild_frpc()
    except (frpc.FrpcError, MefrpError) as exc:
        raise HTTPException(400, str(exc)) from exc

    restarted: list[str] = []
    if restart and changed:
        for inst in store.list_frpc_instances(enabled_only=True):
            dk = engine.docker_for(inst)
            if dk is None:
                continue
            try:
                dk.restart()
                restarted.append(str(inst["name"]))
            except frpc.FrpcError:
                pass
    return {"ok": True, "changed": changed, "restarted": bool(restarted),
            "restarted_instances": restarted, "summary": summary}


@app.post("/api/frpc/restart")
async def frpc_restart(instance_id: int | None = None,
                       _: None = Auth) -> dict[str, Any]:
    """重启容器。不给 instance_id 就重启第一个实例（兼容旧调用）。"""
    inst = (store.get_frpc_instance(int(instance_id)) if instance_id
            else _primary_instance())
    if inst is None:
        raise HTTPException(404, "没有可用的 frpc 实例")
    dk = engine.docker_for(inst)
    if dk is None:
        raise HTTPException(502, f"实例「{inst['name']}」没有可用的容器控制器")
    try:
        return {"ok": True, "instance": inst["name"], **(dk.restart() or {})}
    except frpc.FrpcError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/frpc/logs")
async def frpc_logs(tail: int = 120, instance_id: int | None = None,
                    _: None = Auth) -> dict[str, Any]:
    inst = (store.get_frpc_instance(int(instance_id)) if instance_id
            else _primary_instance())
    if inst is None:
        raise HTTPException(404, "没有可用的 frpc 实例")
    dk = engine.docker_for(inst)
    if dk is None:
        raise HTTPException(502, f"实例「{inst['name']}」没有可用的容器控制器")
    try:
        return {"ok": True, "instance": inst["name"], "logs": dk.logs(tail=tail)}
    except frpc.FrpcError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.post("/api/frpc/restore")
async def frpc_restore(name: str, instance_id: int | None = None,
                       _: None = Auth) -> dict[str, Any]:
    inst = (store.get_frpc_instance(int(instance_id)) if instance_id
            else _primary_instance())
    if inst is None:
        raise HTTPException(404, "没有可用的 frpc 实例")
    try:
        frpc.restore_backup(name, instance_id=int(inst["id"]),
                            path=Path(str(inst["config_path"])))
    except frpc.FrpcError as exc:
        raise HTTPException(400, str(exc)) from exc
    store.add_event("info", "frpc",
                    f"实例「{inst['name']}」已从备份 {Path(name).name} 恢复配置")
    return {"ok": True}


@app.get("/api/frpc/map")
async def frpc_map(_: None = Auth) -> dict[str, Any]:
    """隧道 ↔ frpc 实例的绑定关系总览（含解析方式与未绑定清单）。"""
    return engine.resolve_map()


@app.post("/api/frpc/discover")
async def frpc_discover(apply: bool = False, _: None = Auth) -> dict[str, Any]:
    """按各实例**现有的配置文件**自动推断隧道归属。

    默认只预览（apply=false），不写库。apply=true 会把推断结果**写成显式绑定** ——
    之后解析就只看显式绑定，不再依赖启发式规则（见 engine.frpc_for_tunnel）。
    """
    return engine.discover_bindings(apply=apply)


@app.post("/api/frpc/bind")
async def frpc_bind(payload: BindIn, _: None = Auth) -> dict[str, Any]:
    """批量绑定 / 解绑（frpc_instance_id 传 null 或 0 表示解绑）。"""
    iid = int(payload.frpc_instance_id) if payload.frpc_instance_id else None
    if iid is not None and store.get_frpc_instance(iid) is None:
        raise HTTPException(404, f"frpc 实例 {iid} 不存在")

    updated = 0
    skipped: list[int] = []
    for tid in payload.tunnel_ids:
        if store.get_tunnel(int(tid)) is None:
            skipped.append(int(tid))
            continue
        store.update_tunnel(int(tid), {"frpc_instance_id": iid})
        updated += 1

    if updated:
        label = store.get_frpc_instance(iid)["name"] if iid else "（解绑）"
        store.add_event("info", "frpc",
                        f"已把 {updated} 条隧道绑定到 frpc 实例「{label}」")
    return {"ok": True, "updated": updated, "skipped": skipped}


@app.get("/api/frpc/{instance_id}")
async def frpc_get(instance_id: int, _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")
    return _instance_view(inst, with_config=True)


@app.patch("/api/frpc/{instance_id}")
async def frpc_patch(instance_id: int, payload: FrpcPatch,
                     _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")

    data = payload.model_dump(exclude_none=True)

    if "name" in data:
        data["name"] = str(data["name"]).strip()
        if not data["name"]:
            raise HTTPException(400, "实例名不能为空")
        dup = store.get_frpc_instance_by_name(data["name"])
        if dup and int(dup["id"]) != int(instance_id):
            raise HTTPException(400, f"实例名「{data['name']}」已被占用")

    if "config_path" in data:
        p = Path(str(data["config_path"]).strip())
        _check_path_available(p, exclude_id=int(instance_id))
        data["config_path"] = str(p)

    if "container" in data:
        data["container"] = str(data["container"]).strip()

    if "enabled" in data:
        data["enabled"] = int(bool(data["enabled"]))

    # ⚠️ manual_node_id 只允许「解绑」（传 null）。想绑到某个外部节点必须走
    #    /api/manual-nodes/{id}/switch —— 那条路会**改写配置文件并重启容器**。
    #    直接改这一列只会让库里说「实例在节点 A」而配置文件里还写着 B，
    #    两边对不上，用户完全看不出来。
    if "manual_node_id" in payload.model_fields_set:
        want = payload.manual_node_id
        if want:
            raise HTTPException(
                400,
                "绑定外部节点请用「frpc」页的「切到外部节点」—— "
                "那条路会同时改写配置文件并重启容器，直接改字段不会。")
        data["manual_node_id"] = None

    store.update_frpc_instance(instance_id, data)
    engine.reload_dockers()
    return {"ok": True}


@app.delete("/api/frpc/{instance_id}")
async def frpc_delete(instance_id: int, unbind: bool = False,
                      _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")

    bound = store.count_tunnels_of_frpc(instance_id)
    if bound and not unbind:
        raise HTTPException(
            400,
            f"还有 {bound} 条隧道绑定在该实例上。"
            "加 ?unbind=true 一并解绑，或先把它们改绑到别的实例。",
        )

    n = store.unbind_tunnels_of_frpc(instance_id) if bound else 0
    store.delete_frpc_instance(instance_id)
    engine.reload_dockers()
    store.add_event("info", "frpc",
                    f"已删除 frpc 实例「{inst['name']}」"
                    + (f"，同时解绑了 {n} 条隧道" if n else ""))
    return {"ok": True, "unbound": n}


@app.post("/api/frpc/{instance_id}/rebuild")
async def frpc_rebuild_one(instance_id: int, restart: bool = False,
                           _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")
    try:
        changed, summary = await engine.rebuild_frpc(int(instance_id))
    except (frpc.FrpcError, MefrpError) as exc:
        raise HTTPException(400, str(exc)) from exc

    restarted = False
    note = ""
    if restart and changed:
        if str(inst.get("restart_mode") or "docker") == "none":
            note = "该实例的 restart_mode=none，需要手动重启"
        else:
            dk = engine.docker_for(inst)
            if dk is None:
                raise HTTPException(
                    502, "配置已写入，但该实例没有可用的容器控制器（容器名或 Docker）")
            try:
                dk.restart()
                restarted = True
            except frpc.FrpcError as exc:
                raise HTTPException(502, f"配置已写入，但重启失败：{exc}") from exc
    return {"ok": True, "changed": changed, "restarted": restarted,
            "note": note, "summary": summary}


@app.post("/api/frpc/{instance_id}/restart")
async def frpc_restart_one(instance_id: int, _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")
    dk = engine.docker_for(inst)
    if dk is None:
        raise HTTPException(502, f"实例「{inst['name']}」没有可用的容器控制器")
    try:
        return {"ok": True, **(dk.restart() or {})}
    except frpc.FrpcError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/frpc/{instance_id}/logs")
async def frpc_logs_one(instance_id: int, tail: int = 120,
                        _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")
    dk = engine.docker_for(inst)
    if dk is None:
        raise HTTPException(502, f"实例「{inst['name']}」没有可用的容器控制器")
    try:
        return {"ok": True, "logs": dk.logs(tail=tail)}
    except frpc.FrpcError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/frpc/{instance_id}/backups")
async def frpc_backups(instance_id: int, _: None = Auth) -> dict[str, Any]:
    if store.get_frpc_instance(instance_id) is None:
        raise HTTPException(404, "frpc 实例不存在")
    return {"ok": True, "backups": frpc.list_backups(int(instance_id))}


@app.post("/api/frpc/{instance_id}/restore")
async def frpc_restore_one(instance_id: int, name: str,
                           _: None = Auth) -> dict[str, Any]:
    inst = store.get_frpc_instance(instance_id)
    if inst is None:
        raise HTTPException(404, "frpc 实例不存在")
    try:
        frpc.restore_backup(name, instance_id=int(instance_id),
                            path=Path(str(inst["config_path"])))
    except frpc.FrpcError as exc:
        raise HTTPException(400, str(exc)) from exc
    store.add_event("info", "frpc",
                    f"实例「{inst['name']}」已从备份 {Path(name).name} 恢复配置")
    return {"ok": True}


# ---------------------------------------------------------------------------
# 事件
# ---------------------------------------------------------------------------

@app.get("/api/events")
async def list_events(limit: int = 200, tunnel_id: int | None = None,
                      _: None = Auth) -> list[dict[str, Any]]:
    return store.list_events(limit=min(limit, 1000), tunnel_id=tunnel_id)


# ---------------------------------------------------------------------------
# 设置
# ---------------------------------------------------------------------------

def _mask(key: str, value: Any) -> Any:
    if key not in SECRET_KEYS:
        return value
    v = str(value or "")
    if not v:
        return ""
    return f"{v[:4]}…{v[-4:]}" if len(v) > 10 else "已设置"


@app.get("/api/settings")
async def get_settings(_: None = Auth) -> dict[str, Any]:
    raw = store.get_settings()
    # ⚠️ 只读键（密码哈希/盐/迭代数）**整条不返回**，而不是打码返回 ——
    # 打码也会泄露哈希的头尾各 4 个 hex 字符，而这些值对 UI 毫无用处。
    visible = {k: v for k, v in raw.items() if k not in READONLY_SETTINGS}
    return {
        "settings": {k: _mask(k, v) for k, v in visible.items()},
        "secret_keys": sorted(SECRET_KEYS),
        "readonly_keys": sorted(READONLY_SETTINGS),
        "defaults": {k: v for k, v in DEFAULT_SETTINGS.items()
                     if k not in READONLY_SETTINGS},
        "frpc_container": BOOTSTRAP.frpc_container,
        "config_path": str(BOOTSTRAP.frpc_config_path),
        "auth_enabled": auth_enabled(),
        "username": str(store.get_setting("web_user") or ""),
        # 节点偏好（手工优先级 / 排除 / 备注）。它不参与择优打分，是给节点页
        # 显示和编辑用的，所以单独放这里、不混进 /api/nodes 的 nodes 数组里。
        "node_prefs": store.list_node_prefs(),
    }


@app.put("/api/settings")
async def put_settings(payload: SettingsIn, _: None = Auth) -> dict[str, Any]:
    data = payload.model_dump()
    clean: dict[str, Any] = {}
    for key, value in data.items():
        if key not in DEFAULT_SETTINGS:
            continue
        # ⚠️ 只读设置一律跳过：密码哈希如果能从这个接口写，
        # 任何拿到会话的人都能把密码改成自己知道的值。
        # 改密码走 /api/auth/password（要验当前密码）。
        if key in READONLY_SETTINGS:
            continue
        # 空字符串代表「不改」，避免 UI 上把已保存的密钥覆盖掉
        if key in SECRET_KEYS and (value is None or str(value).strip() == ""):
            continue
        default = DEFAULT_SETTINGS[key]
        if isinstance(default, bool):
            clean[key] = bool(value)
        elif isinstance(default, int) and not isinstance(default, bool):
            try:
                clean[key] = int(value)
            except (TypeError, ValueError):
                raise HTTPException(400, f"字段 {key} 需要整数") from None
        else:
            clean[key] = str(value)

        allowed = ENUM_SETTINGS.get(key)
        if allowed is not None:
            val = str(clean[key]).strip().lower()
            if val not in allowed:
                raise HTTPException(
                    400, f"字段 {key} 只能是 {' / '.join(sorted(allowed))}")
            clean[key] = val

    store.set_settings(clean)
    engine.reload_clients()
    if clean:
        store.add_event("info", "system",
                        "设置已更新：" + "、".join(sorted(clean)))
    return {"ok": True, "updated": sorted(clean)}


# ---------------------------------------------------------------------------
# 连通性自检
# ---------------------------------------------------------------------------

@app.post("/api/test/mefrp")
async def test_mefrp(token: str | None = None, _: None = Auth) -> dict[str, Any]:
    s = store.get_settings()
    client = MefrpClient(
        token=token or str(s.get("mefrp_token") or ""),
        base=str(s.get("mefrp_base") or ""),
        user_agent=str(s.get("user_agent") or ""),
    )
    try:
        return await client.ping()
    except MefrpError as exc:
        return {"ok": False, "error": str(exc)}


@app.post("/api/test/cloudflare")
async def test_cloudflare(token: str | None = None, _: None = Auth) -> dict[str, Any]:
    s = store.get_settings()
    client = CloudflareClient(token=token or str(s.get("cf_api_token") or ""))
    try:
        return await client.ping()
    except CloudflareError as exc:
        return {"ok": False, "error": str(exc)}


@app.post("/api/test/gotify")
async def test_gotify(send: bool = False, _: None = Auth) -> dict[str, Any]:
    if send:
        ok = await engine.notifier.send(
            "mefrp-guard 测试消息", "如果你看到这条，说明 Gotify 通道是通的。", "info"
        )
        return {"ok": ok}
    return await engine.notifier.ping()


@app.exception_handler(MefrpError)
async def _mefrp_error_handler(_req: Request, exc: MefrpError) -> JSONResponse:
    return JSONResponse(status_code=502, content={"detail": str(exc)})
