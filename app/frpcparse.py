"""从用户粘贴的 frpc 配置里解析出「节点 + 隧道」。

为什么需要这个模块
------------------
mefrp 有开放 API，节点和隧道都能查、能建、能删 —— 所以引擎可以自动择优、自动
故障转移。但**其它 frp 服务商、以及自建 frps，根本没有 API**。对它们而言，唯一
的真相来源就是用户手上那份 frpc 配置：里面写着服务端地址、端口、鉴权方式，以及
这条 frpc 要把哪些本地服务暴露出去。

本模块只做一件事：把一份 frpc 配置读成结构化数据。**不碰网络、不碰数据库**，
纯函数，方便单测。

frpc 的配置格式随版本换过，两种都要认
------------------------------------
* **TOML** —— frpc >= 0.52.0，现行格式::

      serverAddr = "1.2.3.4"
      serverPort = 7000
      auth.method = "token"
      auth.token = "xxx"

      [[proxies]]
      name = "ssh"
      type = "tcp"
      localIP = "127.0.0.1"
      localPort = 22
      remotePort = 6000

* **INI** —— frpc < 0.52.0，老格式。网上大量存量教程和配置还是这个::

      [common]
      server_addr = 1.2.3.4
      server_port = 7000
      token = xxx

      [ssh]
      type = tcp
      local_ip = 127.0.0.1
      local_port = 22
      remote_port = 6000

⚠️ 两种格式的键名大小写和分隔符都不一样（`serverAddr` vs `server_addr`、
   `localIP` vs `local_ip`）。而且**用户从网上抄来的配置经常是混合写法** ——
   比如 TOML 里写成了 `server_addr`。所以这里一律先把键名归一化
   （转小写 + 去掉 `_` 和 `-`）再取值，两种写法都认。

⚠️ 老 INI 里还有 `[plugin_xxx]` 这类**插件子配置段**，它们不是隧道，是挂在某条
   隧道上的插件参数。判定办法：段里没有 `type` 也没有 `local_port` 的，当插件段
   处理 —— 仍然列出来，但打上标记，让用户在勾选时能分辨。
"""

from __future__ import annotations

import configparser
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any

FORMATS = ("toml", "ini")


class FrpcParseError(Exception):
    """配置既不是合法 TOML 也不是合法 INI，或者里面找不到服务端地址。"""


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class ProxySpec:
    """配置里的一条隧道（TOML 的 [[proxies]] 或 INI 的一个段）。"""
    name: str
    proxy_type: str = "tcp"
    local_ip: str = "127.0.0.1"
    local_port: int = 0
    remote_port: int = 0
    domain: str = ""
    # 老 INI 的插件段：有段名但没有 type/local_port。列出来但默认不勾选。
    plugin: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "proxy_type": self.proxy_type,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_port": self.remote_port,
            "domain": self.domain,
            "plugin": self.plugin,
        }


@dataclass
class ParsedConfig:
    fmt: str = "toml"
    server_addr: str = ""
    server_port: int = 7000
    auth_method: str = "none"        # token | user | none
    auth_token: str = ""
    auth_user: str = ""
    proxies: list[ProxySpec] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """给 UI 用的默认名称：地址带端口，可读且天然唯一。"""
        if not self.server_addr:
            return ""
        return f"{self.server_addr}:{self.server_port}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.fmt,
            "server_addr": self.server_addr,
            "server_port": self.server_port,
            "auth_method": self.auth_method,
            "has_token": bool(self.auth_token),
            "auth_user": self.auth_user,
            "label": self.label,
            "proxies": [p.as_dict() for p in self.proxies],
            "proxy_count": len(self.proxies),
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def _norm(key: str) -> str:
    """键名归一化：小写 + 去掉下划线和连字符。

    这样 `serverAddr` / `server_addr` / `server-addr` / `ServerAddr` 会撞到
    同一个键上。用户抄配置时的写法差异不应该成为解析失败的理由。
    """
    return re.sub(r"[-_]", "", (key or "").strip().lower())


def _to_int(v: Any, default: int = 0) -> int:
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _flat(d: dict) -> dict[str, Any]:
    """把一层 dict 的键归一化。值不动。"""
    return {_norm(k): v for k, v in (d or {}).items()}


def _pick(d: dict[str, Any], *names: str) -> Any:
    """按归一化后的键名依次取值，第一个非空的赢。"""
    for n in names:
        v = d.get(_norm(n))
        if v not in (None, ""):
            return v
    return None


def _as_domain(v: Any) -> str:
    """customDomains 可能是数组（TOML）也可能是逗号分隔串（INI）。"""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ",".join(str(x).strip() for x in v if str(x).strip())
    return str(v).strip()


# ---------------------------------------------------------------------------
# 格式识别
# ---------------------------------------------------------------------------

def detect_format(text: str) -> str:
    """判断这份配置是 TOML 还是 INI。

    判据顺序有讲究：

    1. **先看有没有 `[common]`** —— 这是老 INI 独有的标志段，TOML 里不会出现
       这个段名（TOML 的服务端地址是顶层键）。先判它最稳。
    2. 再试着用 tomllib 真解析一次。能解析成 dict 且有顶层 `serverAddr`/`serverPort`
       或 `proxies` 的，就是 TOML。
    3. 都不成立才落到 INI。

    ⚠️ 不能反过来「先试 TOML」：`[common]` 这种段头在 TOML 里也合法（是个表名），
       一份内容极简的 INI 有可能被 TOML 解析器接受，于是被误判成 TOML，
       然后所有 INI 的键都取不到值。
    """
    if re.search(r"^\s*\[\s*common\s*\]", text, re.MULTILINE | re.IGNORECASE):
        return "ini"
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return "ini"
    if not isinstance(parsed, dict):
        return "ini"
    flat = _flat(parsed)
    if _pick(flat, "serverAddr", "server_addr") or parsed.get("proxies"):
        return "toml"
    # TOML 解析通过但既没有服务端地址也没有 proxies —— 更像是一份恰好能被
    # TOML 接受的 INI（比如只有一个 [common] 段之外的空配置）。交给 INI 路径，
    # 那边的报错信息更贴切。
    return "ini"


# ---------------------------------------------------------------------------
# TOML
# ---------------------------------------------------------------------------

def _parse_toml(text: str) -> ParsedConfig:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise FrpcParseError(f"不是合法的 TOML：{exc}") from exc
    if not isinstance(data, dict):
        raise FrpcParseError("TOML 顶层不是一个表")

    out = ParsedConfig(fmt="toml")
    flat = _flat(data)

    out.server_addr = str(_pick(flat, "serverAddr", "server_addr", "server") or "").strip()
    out.server_port = _to_int(_pick(flat, "serverPort", "server_port"), 7000)

    # 鉴权：三种写法都见过
    #   * `[auth]` 表 / `auth.token = "x"`   —— frpc >= 0.52 的规范写法
    #   * 顶层 `token = "x"`                  —— 老写法，新版已废弃但仍有人用
    #   * `authenticationMethod`              —— 更老的键名
    auth = data.get("auth")
    auth_flat = _flat(auth) if isinstance(auth, dict) else {}
    token = _pick(auth_flat, "token") or _pick(flat, "token", "authToken")
    user = _pick(auth_flat, "user") or _pick(flat, "user")
    method = _pick(auth_flat, "method") or _pick(flat, "authenticationMethod")

    out.auth_token = str(token or "").strip()
    out.auth_user = str(user or "").strip()
    if method:
        out.auth_method = str(method).strip().lower()
    elif out.auth_token:
        out.auth_method = "token"
    elif out.auth_user:
        out.auth_method = "user"
    else:
        out.auth_method = "none"

    # ⚠️ `[proxies]` 和 `[[proxies]]` 只差一对方括号，语义完全不同：前者是
    #    「一张叫 proxies 的表」，后者才是「proxies 数组」。写成前者的话 frpc
    #    那边直接不生效，而这里若静默当成 0 条隧道，用户只会看到「导入成功、
    #    0 条隧道」，根本不知道错在哪 —— 必须明说。
    proxies_raw = data.get("proxies")
    if isinstance(proxies_raw, dict):
        out.warnings.append(
            "配置里写的是 [proxies]（单表）而不是 [[proxies]]（数组）—— "
            "frpc 不会把它当成隧道，检查一下是不是少了一对方括号")
        proxies_raw = None

    for item in (proxies_raw or []):
        if not isinstance(item, dict):
            continue
        pf = _flat(item)
        name = str(_pick(pf, "name") or "").strip()
        if not name:
            out.warnings.append("有一条 [[proxies]] 没有 name，已跳过")
            continue
        out.proxies.append(ProxySpec(
            name=name,
            proxy_type=str(_pick(pf, "type", "proxyType") or "tcp").strip().lower(),
            local_ip=str(_pick(pf, "localIP", "localIp", "localAddr") or "127.0.0.1").strip(),
            local_port=_to_int(_pick(pf, "localPort")),
            remote_port=_to_int(_pick(pf, "remotePort")),
            domain=_as_domain(_pick(pf, "customDomains", "subdomain", "customDomain")),
        ))

    if not out.proxies:
        out.warnings.append("配置里没有任何 [[proxies]]，导入后需要手工补隧道")
    return out


# ---------------------------------------------------------------------------
# INI
# ---------------------------------------------------------------------------

def _parse_ini(text: str) -> ParsedConfig:
    cp = configparser.RawConfigParser(strict=False, allow_no_value=True)
    # ⚠️ 关掉键名小写化，自己用 _norm 归一化 —— configparser 默认只做小写，
    #    而 `local_ip` 和 `localIP` 在它眼里是两个不同的键。
    cp.optionxform = str  # type: ignore[assignment]
    try:
        cp.read_string(text)
    except configparser.Error as exc:
        raise FrpcParseError(f"不是合法的 INI：{exc}") from exc

    out = ParsedConfig(fmt="ini")

    # ---- [common] ----
    common: dict[str, Any] = {}
    for section in cp.sections():
        if section.strip().lower() == "common":
            common = {k: v for k, v in cp.items(section)}
            break
    if not common and cp.defaults():
        # 有些配置把所有东西都写在 [DEFAULT] 里（罕见但合法）
        common = dict(cp.defaults())

    cf = _flat(common)
    out.server_addr = str(_pick(cf, "serverAddr", "server") or "").strip()
    out.server_port = _to_int(_pick(cf, "serverPort"), 7000)
    out.auth_token = str(_pick(cf, "token", "authToken") or "").strip()
    out.auth_user = str(_pick(cf, "user") or "").strip()
    method = _pick(cf, "authenticationMethod", "authMethod")
    if method:
        out.auth_method = str(method).strip().lower()
    elif out.auth_token:
        out.auth_method = "token"
    elif out.auth_user:
        out.auth_method = "user"
    else:
        out.auth_method = "none"

    # ---- 其余段 = 隧道 ----
    for section in cp.sections():
        if section.strip().lower() == "common":
            continue
        sf = _flat({k: v for k, v in cp.items(section)})
        ptype = str(_pick(sf, "type", "proxyType") or "").strip().lower()
        local_port = _to_int(_pick(sf, "localPort"))
        # ⚠️ 判据是「有没有 plugin 键」或「段名以 plugin_ 开头」，不是「有没有
        #    type」—— 老 frpc 的插件段**照样带 `type = tcp`**，靠 type 判断会
        #    全部漏掉。插件段的特征是它由插件提供本地服务，所以没有 local_port。
        plugin = bool(_pick(sf, "plugin")) or section.strip().lower().startswith("plugin_")
        out.proxies.append(ProxySpec(
            name=section.strip(),
            proxy_type=ptype or "tcp",
            local_ip=str(_pick(sf, "localIP", "localAddr") or "127.0.0.1").strip(),
            local_port=local_port,
            remote_port=_to_int(_pick(sf, "remotePort")),
            domain=_as_domain(_pick(sf, "customDomains", "subdomain", "customDomain")),
            plugin=plugin,
        ))
        if plugin:
            out.warnings.append(
                f"段「{section}」是个插件代理（本地服务由插件提供，没有 local_port）"
            )

    if not out.proxies:
        out.warnings.append("配置里除了 [common] 没有任何段，导入后需要手工补隧道")
    return out


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------

def parse(text: str, fmt: str | None = None) -> ParsedConfig:
    """解析一份 frpc 配置。`fmt` 给了就强制按那个格式解析，否则自动识别。"""
    raw = (text or "").strip()
    if not raw:
        raise FrpcParseError("配置内容是空的")
    if fmt and fmt not in FORMATS:
        raise FrpcParseError(f"不支持的配置格式：{fmt}")

    chosen = fmt or detect_format(raw)
    out = _parse_toml(raw) if chosen == "toml" else _parse_ini(raw)

    if not out.server_addr:
        raise FrpcParseError(
            "没解析出服务端地址（TOML 的 serverAddr / INI 的 [common] server_addr）。"
            "确认粘贴的是 frpc 客户端配置，不是 frps 服务端配置。"
        )
    if not (1 <= out.server_port <= 65535):
        out.warnings.append(f"服务端端口 {out.server_port} 不在 1-65535 范围内，已按 7000 处理")
        out.server_port = 7000
    return out


# ---------------------------------------------------------------------------
# 改写服务端段
# ---------------------------------------------------------------------------
#
# 手工切换节点时，要**只动服务端那几行**，其余（proxies、注释、格式）原样保留。
# 所以这里是文本级替换，不是「解析 → 改 dict → 重新序列化」—— 后者会把用户的
# 注释和排版全部抹掉，而配置文件是用户要长期维护的东西，抹掉排版是不可接受的。

def _toml_set(text: str, key: str, rendered: str) -> tuple[str, bool]:
    """把 TOML 里 `key = ...` 的值换成 `rendered`。返回 (新文本, 是否命中)。"""
    pat = re.compile(rf"^([ \t]*)({re.escape(key)})([ \t]*)=[^\n]*$", re.MULTILINE)
    if pat.search(text):
        return pat.sub(lambda m: f"{m.group(1)}{m.group(2)} = {rendered}",
                       text, count=1), True
    return text, False


def _toml_insert_top(text: str, lines: list[str]) -> str:
    """把顶层键插到「第一个表头之前」。

    ⚠️ TOML 的顶层键必须写在任何 `[table]` 之前，插错位置会被解析成那张表里的
       键，语义完全变了（`serverAddr` 跑进 `[auth]` 里就不再是服务端地址）。
    """
    if not lines:
        return text
    rows = text.split("\n")
    for i, line in enumerate(rows):
        if re.match(r"^\s*\[", line):
            return "\n".join(rows[:i] + lines + [""] + rows[i:])
    # 整份配置没有表头 —— 直接追加到末尾
    body = text.rstrip("\n")
    return (body + "\n" + "\n".join(lines) + "\n") if body else "\n".join(lines) + "\n"


def _toml_has_key(text: str, key: str) -> bool:
    return bool(re.search(rf"^[ \t]*{re.escape(key)}[ \t]*=", text, re.MULTILINE))


def _toml_has_table(text: str, name: str) -> bool:
    return bool(re.search(rf"^[ \t]*\[{re.escape(name)}\][ \t]*$", text, re.MULTILINE))


def _toml_set_in_table(text: str, table: str, key: str,
                       rendered: str) -> tuple[str, bool]:
    """在 `[table]` 段体里改 `key = ...`；键不存在则补在该段末尾。"""
    m = re.search(rf"^[ \t]*\[{re.escape(table)}\][ \t]*$", text, re.MULTILINE)
    if not m:
        return text, False
    start = text.find("\n", m.end())
    start = len(text) if start < 0 else start + 1
    nxt = re.search(r"^[ \t]*\[", text[start:], re.MULTILINE)
    end = len(text) if not nxt else start + nxt.start()
    body = text[start:end]

    pat = re.compile(rf"^([ \t]*)({re.escape(key)})([ \t]*)=[^\n]*$", re.MULTILINE)
    if pat.search(body):
        body = pat.sub(lambda mm: f"{mm.group(1)}{mm.group(2)} = {rendered}", body, count=1)
    else:
        body = body.rstrip("\n") + f"\n{key} = {rendered}\n"
    return text[:start] + body + text[end:], True


def _toml_set_auth(text: str, *, method: str | None, token: str | None,
                   user: str | None) -> str:
    """改鉴权字段，**沿用配置里原本的写法**。

    有人写 `auth.token`（点号），有人写 `[auth]` 表，还有人写顶层 `token`
    （老写法）。强行统一成一种会让 diff 看起来像把配置整个重写了一遍，
    用户会不敢用；更要命的是**写法混用会直接产出非法 TOML** ——
    比如原配置有 `[auth]` 表，我们却在顶层又插一个 `auth.method`，
    TOML 解析器会报「duplicate key」，整份配置直接不可用。
    """
    if method is None and token is None and user is None:
        return text

    has_dotted = any(_toml_has_key(text, f"auth.{k}") for k in ("token", "user", "method"))
    has_table = _toml_has_table(text, "auth")
    has_legacy = any(_toml_has_key(text, k) for k in ("token", "user"))

    if not (has_dotted or has_table or has_legacy):
        # 原配置完全没有鉴权段 → 补一套现代写法（点号形式，放顶层）
        lines = []
        if method:
            lines.append(f"auth.method = {_q(method)}")
        if token:
            lines.append(f"auth.token = {_q(token)}")
        if user:
            lines.append(f"auth.user = {_q(user)}")
        return _toml_insert_top(text, lines) if lines else text

    def put(leaf: str, val: str) -> None:
        nonlocal text
        out, hit = _toml_set(text, f"auth.{leaf}", _q(val))
        if hit:
            text = out
            return
        if has_table:
            out, hit = _toml_set_in_table(text, "auth", leaf, _q(val))
            if hit:
                text = out
                return
        if leaf in ("token", "user"):
            out, hit = _toml_set(text, leaf, _q(val))
            if hit:
                text = out
                return
        # ⚠️ method 在老写法（只有顶层 token/user）里没有对应键，**不要**硬塞一个
        #    `auth.method` —— 那会和新版 frpc 的解析规则打架。老写法本来就不带
        #    method，保持原样即可。
        if leaf == "method" and has_legacy and not has_dotted and not has_table:
            return
        text = _toml_insert_top(text, [f"auth.{leaf} = {_q(val)}"])

    for leaf, val in (("token", token), ("user", user), ("method", method)):
        if val is not None:
            put(leaf, val)
    return text


def _q(v: str) -> str:
    """渲染成 TOML 双引号字符串（转义反斜杠和引号）。"""
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ini_section_span(text: str, section: str) -> tuple[int, int] | None:
    """找到 `[section]` 段体（不含段头那一行）的起止下标。找不到返回 None。"""
    m = re.search(rf"^[ \t]*\[[ \t]*{re.escape(section)}[ \t]*\][ \t]*$",
                  text, re.MULTILINE | re.IGNORECASE)
    if not m:
        return None
    start = text.find("\n", m.end())
    start = len(text) if start < 0 else start + 1
    nxt = re.search(r"^[ \t]*\[", text[start:], re.MULTILINE)
    end = len(text) if not nxt else start + nxt.start()
    return start, end


def _ini_set(text: str, section: str, key: str, value: str) -> tuple[str, bool]:
    span = _ini_section_span(text, section)
    if span is None:
        return text, False
    start, end = span
    body = text[start:end]
    pat = re.compile(rf"^([ \t]*)({re.escape(key)})([ \t]*)=[^\n]*$",
                     re.MULTILINE | re.IGNORECASE)
    if pat.search(body):
        body = pat.sub(lambda m: f"{m.group(1)}{m.group(2)} = {value}", body, count=1)
    else:
        body = body.rstrip("\n") + f"\n{key} = {value}\n"
    return text[:start] + body + text[end:], True


def patch_server(text: str, *, addr: str, port: int,
                 auth_method: str | None = None,
                 auth_token: str | None = None,
                 auth_user: str | None = None,
                 fmt: str | None = None) -> str:
    """把配置里的服务端段改写成给定值，其余内容原样保留。

    这是「手工切换节点」的核心动作：换的只是**服务端要素**，隧道定义（本地服务
    暴露成什么）不动 —— 因为切换的语义是「同一套本地服务，换一台 frps 接」。
    """
    raw = (text or "")
    if not raw.strip():
        return _render_fresh(addr=addr, port=port, auth_method=auth_method,
                             auth_token=auth_token, auth_user=auth_user,
                             fmt=fmt or "toml")

    chosen = fmt or detect_format(raw)

    if chosen == "toml":
        out = raw
        # 有就改，没有就攒起来一起补到顶层最前面。
        # ⚠️ 必须逐个判断「命中与否」，不能靠 `"serverAddr" not in raw` 这种子串
        #    判断 —— 那样一份已经写过 serverAddr 的配置会被再插一行，
        #    变成 duplicate key，整份 TOML 直接解析不了。
        missing: list[str] = []
        for key, rendered in (("serverAddr", _q(addr)),
                              ("serverPort", str(int(port)))):
            out, hit = _toml_set(out, key, rendered)
            if not hit:
                missing.append(f"{key} = {rendered}")
        if missing:
            out = _toml_insert_top(out, missing)
        return _toml_set_auth(out, method=auth_method, token=auth_token,
                              user=auth_user)

    out = raw
    if _ini_section_span(out, "common") is None:
        # 没有任何 [common] 段 → 补一个在最前面
        out = f"[common]\nserver_addr = {addr}\nserver_port = {int(port)}\n\n" + out.lstrip()
    else:
        out, _ = _ini_set(out, "common", "server_addr", addr)
        out, _ = _ini_set(out, "common", "server_port", str(int(port)))
    if auth_token is not None:
        out, hit = _ini_set(out, "common", "token", auth_token)
        if not hit:
            out, _ = _ini_set(out, "common", "authentication_method", "token")
            out, _ = _ini_set(out, "common", "token", auth_token)
    if auth_user is not None:
        out, _ = _ini_set(out, "common", "user", auth_user)
    return out


def _render_fresh(*, addr: str, port: int, auth_method: str | None,
                  auth_token: str | None, auth_user: str | None,
                  fmt: str) -> str:
    """手上没有现成配置时，从零渲染一份最小可用的服务端段。"""
    if fmt == "ini":
        lines = ["[common]", f"server_addr = {addr}", f"server_port = {int(port)}"]
        if auth_token:
            lines.append("authentication_method = token")
            lines.append(f"token = {auth_token}")
        elif auth_user:
            lines.append("authentication_method = user")
            lines.append(f"user = {auth_user}")
        return "\n".join(lines) + "\n"
    lines = [f"serverAddr = {_q(addr)}", f"serverPort = {int(port)}"]
    if auth_token:
        lines += ["auth.method = \"token\"", f"auth.token = {_q(auth_token)}"]
    elif auth_user:
        lines += ["auth.method = \"user\"", f"auth.user = {_q(auth_user)}"]
    return "\n".join(lines) + "\n"


def server_of(text: str) -> tuple[str, int]:
    """只取服务端地址和端口。取不到返回 ("", 0)。"""
    try:
        p = parse(text)
    except FrpcParseError:
        return "", 0
    return p.server_addr, p.server_port
