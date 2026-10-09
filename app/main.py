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

from . import auth, frpc, store
from .cloudflare import CloudflareClient, CloudflareError
from .engine import engine, probe_plan, tcp_probe
from .mefrp import MefrpClient, MefrpError
from .settings import (BOOTSTRAP, DEFAULT_SETTINGS, READONLY_SETTINGS,
                       SECRET_KEYS)

WEB_DIR = Path(__file__).parent / "web"

# 枚举型设置：key -> 允许的取值集合。
# 写错的值必须报 400，不能静默降级 —— 否则用户以为「关了探测」其实还在探。
ENUM_SETTINGS: dict[str, set[str]] = {
    "probe_mode": {"auto", "tcp", "none"},
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


app = FastAPI(title="mefrp-guard", version="1.0.0", lifespan=lifespan,
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
_UNAUTHORIZED = {"WWW-Authenticate": 'Basic realm="mefrp-guard"'}


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
    """
    if not auth_enabled():
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

    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return False
    sess = store.get_session(auth.token_fingerprint(token))
    if sess is None:
        return False
    request.state.username = sess["username"]
    return True


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

    raise HTTPException(status_code=401, detail="需要登录", headers=_UNAUTHORIZED)


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
    desired_remote_port: int | None = Field(None, ge=1, le=65535)
    pin_node_id: int | None = None
    enabled: bool = True
    auto_failover: bool = True
    dns_record_name: str = ""
    dns_proxied: bool = False
    downstream_note: str = ""
    frpc_instance_id: int | None = None


class TunnelPatch(BaseModel):
    name: str | None = None
    proxy_type: str | None = None
    local_ip: str | None = None
    local_port: int | None = None
    desired_remote_port: int | None = None
    pin_node_id: int | None = None
    enabled: bool | None = None
    auto_failover: bool | None = None
    dns_record_name: str | None = None
    dns_proxied: bool | None = None
    downstream_note: str | None = None
    needs_downstream_review: bool | None = None
    # ⚠️ 这个字段要能显式置空（解绑），所以不能走 exclude_none 的老路 ——
    # 见 patch_tunnel 里对 model_fields_set 的处理。
    frpc_instance_id: int | None = None


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
        proxy = engine.proxies.get(t["proxy_name"])
        node = engine.nodes.get(t["current_node_id"]) if t["current_node_id"] else None
        cached = engine.probe_cache.get(t["id"])
        # 节点地址走缓存解析器：非管理员账号下 node.hostname 恒为空串，
        # 真实地址来自 proxy_list 的 nodes 子数组或官方配置里的 serverAddr。
        addr = engine.node_address_cached(t["current_node_id"])
        inst = engine.frpc_for_tunnel(t)
        items.append({
            **t,
            "proxy_found": proxy is not None,
            "proxy_online": bool(proxy and proxy.is_online),
            "proxy_remote_port": proxy.remote_port if proxy else None,
            "node_name": node.name if node else "",
            "node_hostname": addr,
            "address_known": bool(addr),
            # 公网访问入口，例如 203.0.113.10:41234
            "public_endpoint": f"{addr}:{t['current_remote_port']}"
                               if addr and t["current_remote_port"] else "",
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
async def list_tunnels(_: None = Auth) -> list[dict[str, Any]]:
    return store.list_tunnels()


@app.get("/api/orphans")
async def list_orphans(_: None = Auth) -> list[dict[str, Any]]:
    """mefrp 账号里存在、但还没被本程序纳管的隧道。

    用途：手工在 mefrp 网页上建过的隧道，可以通过这里「纳管」进来，
    不必先在页面里新建一条再手动填 proxyId。
    """
    managed = {t["proxy_name"] for t in store.list_tunnels()}
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
    if store.find_tunnel_by_proxy(payload.proxy_name):
        raise HTTPException(400, f"proxy_name「{payload.proxy_name}」已被占用")
    data = payload.model_dump()
    data["enabled"] = int(data["enabled"])
    data["auto_failover"] = int(data["auto_failover"])
    data["dns_proxied"] = int(data["dns_proxied"])
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

    # ⚠️ frpc_instance_id 要能「显式解绑」。走 exclude_none 的话传 null 会被丢掉，
    # 用户就永远解不了绑 —— 所以看 model_fields_set 判断「客户端到底提没提这个字段」。
    if "frpc_instance_id" in payload.model_fields_set:
        iid = payload.frpc_instance_id
        if iid is not None and store.get_frpc_instance(int(iid)) is None:
            raise HTTPException(404, f"frpc 实例 {iid} 不存在")
        data["frpc_instance_id"] = int(iid) if iid else None

    store.update_tunnel(tunnel_id, data)
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
    return {"ok": True}


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

    if store.find_tunnel_by_proxy(proxy.proxy_name):
        raise HTTPException(400, f"隧道「{proxy.proxy_name}」已经纳管过了")

    name = (payload.name or proxy.proxy_name).strip()[:64] or proxy.proxy_name
    if any(t["name"] == name for t in store.list_tunnels()):
        name = f"{name}-{proxy.proxy_id}"

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

    store.update_tunnel(tunnel_id, {
        "proxy_name": proxy.proxy_name,
        "proxy_type": proxy.proxy_type,
        "current_proxy_id": proxy.proxy_id,
        "current_node_id": proxy.node_id,
        "current_remote_port": proxy.remote_port,
        "fail_streak": 0,
        "last_error": "",
    })
    store.add_event("success", "system",
                    f"已接管隧道「{proxy.proxy_name}」（#{proxy.proxy_id}）",
                    tunnel_id=tunnel_id)
    return {"ok": True}


@app.post("/api/tunnels/{tunnel_id}/probe")
async def probe_now(tunnel_id: int, _: None = Auth) -> dict[str, Any]:
    tunnel = store.get_tunnel(tunnel_id)
    if tunnel is None:
        raise HTTPException(404, "隧道不存在")
    proxy = engine.proxies.get(tunnel["proxy_name"])
    if proxy is None:
        raise HTTPException(404, "mefrp 上找不到这条隧道，先刷新一次状态")
    node = engine.nodes.get(proxy.node_id)
    if node is None:
        raise HTTPException(404, f"节点 {proxy.node_id} 不在列表中")

    host = await engine.node_address(proxy.node_id)
    if not host:
        raise HTTPException(409, (
            f"拿不到节点「{node.name}」的公网地址。"
            "mefrp 对非管理员账号不返回节点地址（/auth/node/list 的 hostname 是空串），"
            "只有在那个节点上建过隧道才能反推出来。"
        ))

    timeout = float(store.get_setting("probe_timeout", 4) or 4)
    target = f"{host}:{proxy.remote_port}"
    ptype = tunnel.get("proxy_type", "tcp")

    # UDP 隧道不能做 TCP 探测 —— 直连会必然失败，返回「不可达」是在骗用户。
    # 这里如实回一个「不适用」，让前端显示成中性提示而不是红色报错。
    mode = str(store.get_setting("probe_mode", "auto") or "auto")
    do_probe, skip_why = probe_plan(ptype, mode)
    if not do_probe:
        engine.probe_cache[tunnel_id] = (time.time(), None, skip_why)
        return {
            "ok": None, "skipped": True, "reason": skip_why,
            "target": target, "node": node.name, "proxy_type": ptype,
        }

    ok, why = await tcp_probe(host, proxy.remote_port, timeout)
    engine.probe_cache[tunnel_id] = (time.time(), ok, why)
    return {
        "ok": ok, "skipped": False, "reason": why,
        "target": target, "node": node.name, "proxy_type": ptype,
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
    out: dict[str, Any] = {
        **inst,
        "id": iid,
        "enabled": bool(inst["enabled"]),
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
