# -*- coding: utf-8 -*-
"""`[proxies.metadatas]` 值类型规范化（1.0.3 补丁）。

用户实测：mefrp 给 HTTP 隧道生成的配置里 `mefrpRedirectHTTPS = true` 会让
frpc 启动失败 ——

    decode proxy at index 0: unmarshal ProxyConfig error:
    json: cannot unmarshal bool into Go struct field
    HTTPProxyConfig.ProxyBaseConfig.metadatas of type string

因为 frp 里 `metadatas` 是 `map[string]string`。修复是**引号化**（不是删段），
这样 mefrp 服务端的「HTTP 自动跳 HTTPS」语义还能留着。

纯逻辑测试，不依赖第三方库：
    python tests/test_frpc_metadata.py
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import tomllib

TMP = tempfile.mkdtemp(prefix="mg-meta-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import frpc                                  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, extra: object = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  ->  {extra}")


# 用户原样贴过来的那份配置（mefrp 面板生成）
REAL = """serverAddr = '192.238.143.158'
serverPort = 2333
user = '14ed159a7ef27e71ca1e2cfc23030c34'
[auth]
method = 'token'
token = 'MEFrpServerToken'
[[proxies]]
name = 'gotify'
type = 'http'
localIP = '10.215.171.11'
localPort = 43443
customDomains = ["gotify.723000.xyz"]
[proxies.metadatas]
mefrpRedirectHTTPS = true
[proxies.transport]
useEncryption = false
useCompression = false
"""


def test_basic() -> None:
    print("[normalize] 布尔值 -> 字符串")
    out = frpc.normalize_metadatas(REAL)
    check("不再有裸 true", "mefrpRedirectHTTPS = true" not in out, out)
    check("变成字符串 true", 'mefrpRedirectHTTPS = "true"' in out, out)

    parsed = tomllib.loads(out)
    meta = parsed["proxies"][0]["metadatas"]
    check("回读 metadatas 是 dict", isinstance(meta, dict), meta)
    check("回读值是字符串", meta.get("mefrpRedirectHTTPS") == "true", meta)

    # 其它段一个字节都不能动
    check("transport 段保留", parsed["proxies"][0]["transport"]["useCompression"] is False,
          parsed["proxies"][0].get("transport"))
    check("全局段保留", parsed["serverAddr"] == "192.238.143.158", parsed.get("serverAddr"))
    check("customDomains 保留",
          parsed["proxies"][0]["customDomains"] == ["gotify.723000.xyz"],
          parsed["proxies"][0].get("customDomains"))
    check("false 布尔没被误改成字符串（transport 段）",
          "useCompression = false" in out, out)

    # 幂等
    check("重复规范化结果一致", frpc.normalize_metadatas(out) == out)


def test_types() -> None:
    print("[normalize] 数字 / 多种写法")
    txt = """[[proxies]]
name = 'a'
[proxies.metadatas]
flag = true
off = false
num = 123
neg = -4.5
exp = 1e3
quoted = "already"
literal = 'also'
listy = ["x", "y"]
"""
    out = frpc.normalize_metadatas(txt)
    meta = tomllib.loads(out)["proxies"][0]["metadatas"]
    check("bool true -> str", meta["flag"] == "true", meta)
    check("bool false -> str", meta["off"] == "false", meta)
    check("int -> str", meta["num"] == "123", meta)
    check("负数 -> str", meta["neg"] == "-4.5", meta)
    check("科学计数 -> str", meta["exp"] == "1e3", meta)
    check("字符串保持原样", meta["quoted"] == "already", meta)
    check("单引号字符串保持原样", meta["literal"] == "also", meta)
    check("数组保持数组", meta["listy"] == ["x", "y"], meta)
    check("没有重复加引号", 'quoted = ""already""' not in out, out)


def test_scope() -> None:
    print("[normalize] 只动 metadatas 段")
    txt = """[[proxies]]
name = 'a'
[proxies.transport]
useEncryption = false
[proxies.metadatas]
k = true
[[proxies]]
name = 'b'
type = 'tcp'
remotePort = 41234
"""
    out = frpc.normalize_metadatas(txt)
    parsed = tomllib.loads(out)
    check("metadatas 里的被改", parsed["proxies"][0]["metadatas"]["k"] == "true", parsed)
    check("transport 里的布尔没被改",
          parsed["proxies"][0]["transport"]["useEncryption"] is False, parsed)
    check("第二条隧道没被动", parsed["proxies"][1]["remotePort"] == 41234, parsed)
    check("只有一处引号化", out.count('k = "true"') == 1, out)


def test_comments_and_blank() -> None:
    print("[normalize] 注释 / 空行 / 行尾注释")
    txt = """[[proxies]]
name = 'a'
[proxies.metadatas]   # mefrp 生成
# 这一行是注释
mefrpRedirectHTTPS = true   # 自动跳 https

other = false
"""
    out = frpc.normalize_metadatas(txt)
    check("段头注释保留", "[proxies.metadatas]   # mefrp 生成" in out, out)
    check("整行注释保留", "# 这一行是注释" in out, out)
    check("行尾注释保留", '# 自动跳 https' in out, out)
    check("空行保留", "\n\nother" in out, out)
    meta = tomllib.loads(out)["proxies"][0]["metadatas"]
    check("带行尾注释的值仍被引号化", meta["mefrpRedirectHTTPS"] == "true", meta)
    check("另一个布尔也被引号化", meta["other"] == "false", meta)


def test_inline_table_untouched() -> None:
    print("[normalize] 多行数组不破坏")
    txt = """[[proxies]]
name = 'a'
[proxies.metadatas]
vals = [
  1,
  2,
]
after = true
"""
    out = frpc.normalize_metadatas(txt)
    check("多行数组内容原样", "  1,\n  2,\n" in out, out)
    meta = tomllib.loads(out)["proxies"][0]["metadatas"]
    check("数组没被引号化", meta["vals"] == [1, 2], meta)
    check("数组后面的键仍被处理", meta["after"] == "true", meta)


def test_no_metadata() -> None:
    print("[normalize] 没有 metadatas 段时零改动")
    cfg = """serverAddr = "1.2.3.4"
serverPort = 7000
[[proxies]]
name = "nas"
type = "tcp"
localIP = "127.0.0.1"
localPort = 5000
remotePort = 41234
"""
    check("原样返回", frpc.normalize_metadatas(cfg) == cfg)
    check("空串安全", frpc.normalize_metadatas("") == "")


def test_merge() -> None:
    print("[merge] 合并入口自动规范化")
    tcp = """serverAddr = '192.238.143.158'
serverPort = 2333
[[proxies]]
name = 'nas'
type = 'tcp'
localIP = '10.215.171.11'
localPort = 5000
remotePort = 41234
"""
    merged, glob = frpc.merge_configs([REAL, tcp], label="默认")

    check("合并后无裸布尔", "mefrpRedirectHTTPS = true" not in merged, merged)
    check("合并后有字符串", 'mefrpRedirectHTTPS = "true"' in merged, merged)
    check("两条隧道都在", merged.count("[[proxies]]") == 2, merged.count("[[proxies]]"))
    check("serverAddr 仍能取到", glob.get("serverAddr") == "192.238.143.158", glob)

    parsed = tomllib.loads(merged)
    check("回的 TOML 合法且 metadatas 是字符串",
          parsed["proxies"][0]["metadatas"]["mefrpRedirectHTTPS"] == "true", parsed["proxies"][0])
    check("另一条隧道没有 metadatas 段", "metadatas" not in parsed["proxies"][1],
          parsed["proxies"][1])

    sm = frpc.config_summary(merged)
    check("摘要仍然合法", sm.get("valid") is True, sm)
    check("摘要 proxy_count=2", sm.get("proxy_count") == 2, sm.get("proxy_count"))


if __name__ == "__main__":
    test_basic()
    test_types()
    test_scope()
    test_comments_and_blank()
    test_inline_table_untouched()
    test_no_metadata()
    test_merge()
    print(f"\n==> PASS {PASS} / FAIL {FAIL}")
    sys.exit(1 if FAIL else 0)
