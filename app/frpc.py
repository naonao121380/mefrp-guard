"""frpc 配置生成与容器管控。

设计前提
--------
一个 frpc 进程只能连一个 `serverAddr`，所以**同一个 frpc 实例承载的所有隧道
必须落在同一个节点上**。本模块在合并配置时校验这一点，发现不一致就直接报错
而不是写出一份错配置。

⚠️ 这条约束是**按实例**成立的，不是全局的。系统支持多个 frpc 实例，每个实例
   有自己的配置路径和容器，各自守着一个节点 —— 实例之间互不牵连。全局只允许
   一个节点是旧版的限制，已经被多实例解开了。

配置来源用的是 mefrp 官方的 `/auth/proxy/config`，而不是自己拼 TOML。
理由：官方格式可能随版本变，用官方生成的结果最不容易踩坑。
合并时只在文本层面做「保留第一份的全局段 + 拼接所有 [[proxies]] 块」，
最后用 tomllib 回读校验一遍，确保产出是合法 TOML。
"""

from __future__ import annotations

import datetime as dt
import re
import shutil
import tomllib
from pathlib import Path

from .settings import BOOTSTRAP


class FrpcError(Exception):
    pass


# ---------------------------------------------------------------------------
# TOML 合并
# ---------------------------------------------------------------------------

PROXY_MARKER = "[[proxies]]"


def _split_toml(text: str) -> tuple[str, list[str]]:
    """把一份 frpc TOML 拆成 (全局段, [proxies 块...])。"""
    idx = text.find(PROXY_MARKER)
    if idx < 0:
        return text, []
    head = text[:idx]
    rest = text[idx:]
    chunks = rest.split(PROXY_MARKER)
    blocks = []
    for chunk in chunks[1:]:
        body = chunk.rstrip()
        if body:
            blocks.append(f"{PROXY_MARKER}{body}")
    return head, blocks


def _unquote(value: str) -> str:
    """剥掉 TOML 字符串的引号（单引号字面量和双引号都要处理）。"""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def _global_of(text: str) -> dict[str, str]:
    """粗略提取全局段里的 serverAddr / serverPort，用于一致性校验。

    ⚠️ mefrp 官方生成的配置用的是 TOML **单引号**字面量：
        serverAddr = '203.0.113.10'
    两种引号都必须剥掉，否则同一个地址只要引号风格不同，就会被误判成
    「受管隧道不在同一个节点上」而拒绝生成配置。
    """
    head, _ = _split_toml(text)
    out: dict[str, str] = {}
    for key in ("serverAddr", "serverPort"):
        m = re.search(rf"^\s*{key}\s*=\s*(.+?)\s*$", head, re.MULTILINE)
        if m:
            out[key] = _unquote(m.group(1))
    return out


def server_addr_of(text: str) -> str:
    """从一份官方单隧道配置里取出节点公网地址。取不到返回空串。

    这是**唯一**能拿到节点公网地址的地方：
      * /auth/node/list 对非管理员把 hostname 脱敏成空串
      * /auth/node/secret 只给 serverPort 和 token，没有 hostname
      * /auth/proxy/list 的 nodes 子数组只覆盖「已有隧道」的节点
    """
    return _global_of(text).get("serverAddr", "")


def merge_configs(texts: list[str], *, label: str = "") -> tuple[str, dict[str, str]]:
    """合并多份单隧道配置。

    返回 (合并后的 TOML 文本, 全局段摘要)。
    各份配置的 serverAddr / serverPort 不一致时抛 FrpcError。

    `label` 只用于把报错说清楚是哪个 frpc 实例出的问题 —— 多实例之后
    「受管隧道不在同一个节点上」这句话单独看已经不够定位了。
    """
    usable = [t for t in texts if t and t.strip()]
    if not usable:
        raise FrpcError("没有任何可用的隧道配置，无法生成 frpc 配置")

    who = f"frpc 实例「{label}」的" if label else ""

    globals_part = ""
    blocks: list[str] = []
    summaries: list[dict[str, str]] = []

    for i, text in enumerate(usable):
        head, blk = _split_toml(text)
        summaries.append(_global_of(text))
        if i == 0:
            globals_part = head
        blocks.extend(blk)

    # 一致性校验：同一个 frpc 实例里的隧道必须连同一个 frps
    first = summaries[0]
    for s in summaries[1:]:
        for key in ("serverAddr", "serverPort"):
            if s.get(key) and first.get(key) and s[key] != first[key]:
                raise FrpcError(
                    f"{who}受管隧道不在同一个节点上：serverAddr/serverPort 不一致"
                    f"（{first.get(key)} vs {s.get(key)}）。"
                    "一个 frpc 实例只能连一个节点，"
                    "请把这些隧道统一到同一节点，或把它们拆到不同的 frpc 实例上。"
                )

    if not blocks:
        raise FrpcError("官方配置里没有解析到 [[proxies]] 段，格式可能已变更")

    merged = globals_part.rstrip() + "\n\n" + "\n\n".join(blocks) + "\n"

    # 回读校验，确保是合法 TOML 且 proxies 数量对得上
    try:
        parsed = tomllib.loads(merged)
    except tomllib.TOMLDecodeError as exc:
        raise FrpcError(f"合并后的配置不是合法 TOML：{exc}") from exc

    proxies = parsed.get("proxies") or []
    if len(proxies) != len(blocks):
        raise FrpcError(
            f"合并结果异常：proxies 块数 {len(blocks)}，解析出 {len(proxies)} 个"
        )

    return merged, first


def config_summary(text: str) -> dict:
    """给 UI 用的配置摘要。"""
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return {"valid": False, "error": str(exc)}
    proxies = parsed.get("proxies") or []
    return {
        "valid": True,
        "server_addr": parsed.get("serverAddr", ""),
        "server_port": parsed.get("serverPort", ""),
        "user": parsed.get("user", ""),
        "proxy_count": len(proxies),
        "proxy_names": [str(p.get("name") or "") for p in proxies],
        "proxies": [
            {
                "name": p.get("name", ""),
                "type": p.get("type", ""),
                "local": f"{p.get('localIP', '')}:{p.get('localPort', '')}",
                "remote_port": p.get("remotePort", ""),
                "domain": p.get("subdomain", "") or p.get("customDomains", ""),
            }
            for p in proxies
        ],
    }


# ---------------------------------------------------------------------------
# 文件读写
# ---------------------------------------------------------------------------

def instance_backup_dir(instance_id: int) -> Path:
    """某个 frpc 实例的备份目录。

    ⚠️ 每个实例一个子目录，不能共用一个平铺目录 —— 否则两个实例的
    `frpc-20261007-120000.toml` 会重名互相覆盖，恢复时也可能把 A 实例的
    配置写进 B 实例的文件。
    """
    return BOOTSTRAP.frpc_backup_dir / f"inst-{int(instance_id)}"


def read_config(path: Path | str) -> str:
    """读指定路径的配置。文件不存在返回空串（不是错误 —— 首次部署就是这样）。"""
    p = Path(path)
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise FrpcError(f"读取 {p} 失败：{exc}") from exc


def backup_config(path: Path | str, backup_dir: Path | str,
                  keep: int = 30) -> Path | None:
    """写入前备份现有配置，保留最近 keep 份。"""
    p = Path(path)
    if not p.exists():
        return None
    d = Path(backup_dir)
    d.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dest = d / f"frpc-{stamp}.toml"
    try:
        shutil.copy2(p, dest)
    except OSError as exc:
        raise FrpcError(f"备份配置失败：{exc}") from exc

    backups = sorted(d.glob("frpc-*.toml"))
    for old in (backups[:-keep] if len(backups) > keep else []):
        try:
            old.unlink()
        except OSError:
            pass
    return dest


def proxy_names(text: str) -> list[str]:
    """提取一份 frpc 配置里所有 [[proxies]] 的 name。

    用途：自动发现「这条隧道现在被哪个 frpc 承载」—— 用户现有的
    frpc.toml 里本来就写着隧道名，不用他手填绑定关系。
    解析失败一律返回空列表（宁可发现不出来，也不能因为一份坏配置让整轮崩掉）。
    """
    if not text or not text.strip():
        return []
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    out: list[str] = []
    for p in parsed.get("proxies") or []:
        name = str(p.get("name") or "").strip()
        if name:
            out.append(name)
    return out


def carries(text: str, proxy_name: str) -> bool:
    """这份配置里是否包含指定隧道名。"""
    return proxy_name in proxy_names(text)


def read_current() -> str:
    """读**默认实例**的配置。保留这个函数只为兼容旧调用方与测试。"""
    return read_config(BOOTSTRAP.frpc_config_path)


def backup_current(keep: int = 30) -> Path | None:
    """备份**默认实例**的配置。兼容用；新代码请走 backup_config。"""
    return backup_config(BOOTSTRAP.frpc_config_path, BOOTSTRAP.frpc_backup_dir,
                         keep=keep)


def write_config(text: str, *, path: Path | None = None,
                 backup_dir: Path | None = None) -> Path | None:
    """备份后原子写入。返回备份文件路径（若产生了备份）。

    `path` / `backup_dir` 不传时退回到默认实例的位置 —— 多实例场景下
    调用方**必须**显式传，否则会把 A 实例的配置写到 B 实例的文件里。
    """
    target = Path(path) if path else BOOTSTRAP.frpc_config_path
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = backup_config(target, Path(backup_dir) if backup_dir
                           else BOOTSTRAP.frpc_backup_dir)

    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(target)
    except OSError as exc:
        raise FrpcError(f"写入 {target} 失败：{exc}") from exc
    return backup


def list_backups(instance_id: int | None = None) -> list[dict]:
    """列出备份。

    `instance_id` 给了就只看那个实例的目录；不给则看旧版的平铺根目录
    （兼容老调用方）。
    """
    d = instance_backup_dir(instance_id) if instance_id else BOOTSTRAP.frpc_backup_dir
    out = []
    for p in sorted(d.glob("frpc-*.toml"), reverse=True):
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({
            "name": p.name,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
        })
    return out


def restore_backup(name: str, *, instance_id: int | None = None,
                   path: Path | None = None) -> str:
    """从备份恢复，返回恢复出来的内容。文件名做了路径穿越防护。"""
    safe = Path(name).name
    d = instance_backup_dir(instance_id) if instance_id else BOOTSTRAP.frpc_backup_dir
    src = d / safe
    if not src.exists():
        raise FrpcError(f"备份不存在：{safe}")
    text = src.read_text(encoding="utf-8")
    write_config(text, path=path,
                 backup_dir=(d if instance_id else BOOTSTRAP.frpc_backup_dir))
    return text


# ---------------------------------------------------------------------------
# 容器管控
# ---------------------------------------------------------------------------

class DockerControl:
    """封装对 frpc 容器的操作。没挂 docker.sock 时所有方法返回不可用。"""

    def __init__(self, container_name: str, base_url: str):
        self.container_name = container_name
        self.base_url = base_url
        self._client = None
        self._error = ""

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import docker  # 延迟导入，缺库时不影响其它功能
        except ImportError as exc:
            self._error = f"未安装 docker SDK：{exc}"
            return None
        try:
            self._client = docker.DockerClient(base_url=self.base_url, timeout=30)
            self._client.ping()
        except Exception as exc:  # noqa: BLE001 - docker 库会抛各种异常
            self._error = f"连接 Docker 失败：{exc}"
            self._client = None
        return self._client

    @property
    def available(self) -> bool:
        return self._get_client() is not None

    @property
    def error(self) -> str:
        if self._client is None:
            self._get_client()
        return self._error

    def state(self) -> dict:
        client = self._get_client()
        if client is None:
            return {"available": False, "error": self._error}
        try:
            c = client.containers.get(self.container_name)
            c.reload()
            return {
                "available": True,
                "name": c.name,
                "status": c.status,
                "image": (c.image.tags or [""])[0] if c.image else "",
                "started_at": (c.attrs.get("State") or {}).get("StartedAt", ""),
                "restart_count": c.attrs.get("RestartCount", 0),
            }
        except Exception as exc:  # noqa: BLE001
            return {"available": True, "error": f"找不到容器 {self.container_name}：{exc}"}

    def restart(self, timeout: int = 15) -> dict:
        client = self._get_client()
        if client is None:
            raise FrpcError(f"无法操作 Docker：{self._error}")
        try:
            c = client.containers.get(self.container_name)
            c.restart(timeout=timeout)
            c.reload()
            return {"ok": True, "status": c.status}
        except Exception as exc:  # noqa: BLE001
            raise FrpcError(f"重启容器 {self.container_name} 失败：{exc}") from exc

    def logs(self, tail: int = 100) -> str:
        client = self._get_client()
        if client is None:
            raise FrpcError(f"无法操作 Docker：{self._error}")
        try:
            c = client.containers.get(self.container_name)
            raw = c.logs(tail=tail, timestamps=True)
            return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        except Exception as exc:  # noqa: BLE001
            raise FrpcError(f"读取容器日志失败：{exc}") from exc
