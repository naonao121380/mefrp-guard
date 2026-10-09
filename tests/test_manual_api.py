# -*- coding: utf-8 -*-
"""外部节点（1.0.1）HTTP 端点测试：真实启动应用，逐条打端点。不碰外网。

独立文件 + 独立数据目录，因为 store 是模块级单例 —— 和 test_manual_node.py
放同一个进程里会互相污染数据库。

⚠️ 所有探测目标都指向 127.0.0.1 上没人监听的端口，连接会被立刻拒绝，
   不会等超时，也不会真的去连外网。
"""

from __future__ import annotations

import base64
import os
import pathlib
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="mg-manual-api-")
os.environ.update(
    MG_DATA_DIR=TMP,
    MG_FRPC_CONFIG=os.path.join(TMP, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
    MG_WEB_USER="admin",
    MG_WEB_PASSWORD="s3cret-pass",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient          # noqa: E402
from app.main import app                            # noqa: E402
from app import frpcparse                           # noqa: E402

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret-pass").decode()}
PASS = FAIL = 0


def check(name: str, cond: bool, extra: object = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  ->  {extra}")


# 地址用 127.0.0.1 + 没人听的端口：探测会立刻被拒，不占测试时间。
CONF = '''serverAddr = "127.0.0.1"
serverPort = 1

auth.token = "imported-tok"

[[proxies]]
name = "hk-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 16022

[[proxies]]
name = "hk-web"
type = "tcp"
localIP = "127.0.0.1"
localPort = 5000
remotePort = 16080
'''

CONF_INI = '''[common]
server_addr = 127.0.0.1
server_port = 2
token = ini-tok

[ini-tun]
type = tcp
local_ip = 127.0.0.1
local_port = 8080
remote_port = 18080
'''

with TestClient(app) as c:
    print("[1] 鉴权")
    r = c.get("/api/manual-nodes")
    check("未登录 -> 401", r.status_code == 401, r.status_code)
    r = c.post("/api/manual-nodes/parse", json={"text": CONF})
    check("未登录 parse -> 401", r.status_code == 401, r.status_code)
    r = c.get("/api/manual-nodes", headers=AUTH)
    check("登录后 200", r.status_code == 200, r.text[:200])
    check("空库时 count=0", r.json()["count"] == 0, r.json())
    check("带 formats 字段", "toml" in r.json()["formats"], r.json())

    print("[2] 解析预览（不落库）")
    r = c.post("/api/manual-nodes/parse", headers=AUTH,
               json={"text": CONF, "format": None})
    # ⚠️ 这条路由是字面量，必须排在 /api/manual-nodes/{node_id} 之前 ——
    #    注册反了的话 "parse" 会被拿去解析成 int，直接 422。
    check("★ /parse 没被 /{node_id} 吃掉（路由顺序）", r.status_code == 200, r.text[:200])
    d = r.json()
    check("解析出 2 条隧道", d["proxy_count"] == 2, d)
    check("服务端地址对", d["server_addr"] == "127.0.0.1", d["server_addr"])
    check("★ 返回里没有 token 明文", "imported-tok" not in r.text, "泄露了")
    check("只回「有没有 token」", d["has_token"] is True, d)
    check("隧道名带出来", [x["name"] for x in d["proxies"]] == ["hk-ssh", "hk-web"], d["proxies"])
    check("★ parse 不落库",
          c.get("/api/manual-nodes", headers=AUTH).json()["count"] == 0)
    r = c.post("/api/manual-nodes/parse", headers=AUTH, json={"text": "垃圾配置"})
    check("坏配置 -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/manual-nodes/parse", headers=AUTH, json={"text": ""})
    check("空配置 -> 422", r.status_code == 422, r.status_code)

    print("[3] 导入（勾选 hk-ssh，跳过 hk-web）")
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "name": "自建-香港", "text": CONF, "format": None, "note": "测试用",
        "enabled": True,
        "proxies": [
            {"name": "hk-ssh", "adopt": True, "dns_record_name": ""},
            {"name": "hk-web", "adopt": False, "dns_record_name": ""},
        ],
    })
    check("导入 200", r.status_code == 200 and r.json()["ok"], r.text[:300])
    imp = r.json()
    nid = imp["id"]
    check("只纳管勾选的那条", imp["adopted"] == ["hk-ssh"], imp["adopted"])
    check("★ 返回里没有 token 明文", "imported-tok" not in r.text, "泄露了")
    check("端点格式对", imp["endpoint"] == "127.0.0.1:1", imp["endpoint"])

    lst = c.get("/api/manual-nodes", headers=AUTH).json()
    node = [n for n in lst["nodes"] if n["id"] == nid][0]
    check("列表里有这个节点", node["name"] == "自建-香港", node)
    check("隧道计数为 1", node["tunnel_count"] == 1, node)
    check("格式识别为 toml", node["config_format"] == "toml", node)
    check("★ 列表里也没有 token 明文",
          "imported-tok" not in c.get("/api/manual-nodes", headers=AUTH).text)

    print("[4] 重复导入应被拒（但要给得出路 —— 见 [20]）")
    r = c.post("/api/manual-nodes", headers=AUTH, json={"text": CONF, "proxies": []})
    check("同地址 -> 409", r.status_code == 409, r.status_code)
    check("理由点出已有节点名", "自建-香港" in r.text, r.text[:200])
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "name": "自建-香港", "text": CONF.replace("serverPort = 1", "serverPort = 9"),
        "proxies": []})
    check("重名 -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/manual-nodes/parse", headers=AUTH, json={"text": CONF})
    d4 = r.json()["duplicate"]
    check("parse 里提示地址重复", d4 and d4["existing_name"] == "自建-香港", d4)
    check("parse 里带上 existing_id", d4["existing_id"] == nid, d4)

    print("[5] 导入的隧道：自动切换必须关掉")
    tun = [t for t in c.get("/api/tunnels", headers=AUTH).json()
           if t["proxy_name"] == "hk-ssh"][0]
    check("★ auto_failover = 0", tun["auto_failover"] == 0, tun["auto_failover"])
    check("隧道绑到了外部节点", tun["manual_node_id"] == nid, tun)
    check("远程端口从配置读出来", tun["current_remote_port"] == 16022, tun)

    print("[6] overview 标出 node_source=manual")
    ov = c.get("/api/overview", headers=AUTH).json()
    check("engine 里有外部节点计数", ov["engine"]["manual_node_total"] >= 1, ov["engine"])
    item = [t for t in ov["tunnels"] if t["proxy_name"] == "hk-ssh"][0]
    check("★ node_source = manual", item["node_source"] == "manual", item["node_source"])
    check("带外部节点名", item["manual_node_name"] == "自建-香港", item["manual_node_name"])
    check("节点地址取自 serverAddr", item["node_hostname"] == "127.0.0.1", item["node_hostname"])
    check("★ 手工隧道不查 mefrp proxy（proxy_found=False）",
          item["proxy_found"] is False, item["proxy_found"])

    print("[7] 手工隧道拒绝自动切换")
    r = c.post(f"/api/tunnels/{tun['id']}/failover", headers=AUTH, json={"node_id": None})
    check("★ 自动切换被拒", r.status_code == 400, r.status_code)
    check("★ 理由点明外部节点", "外部节点" in r.text, r.text[:200])
    check("★ 理由给出人工路径", "切换" in r.text, r.text[:200])

    print("[8] 手动切换：改写配置 + 保留隧道定义")
    cfg = os.path.join(TMP, "frpc-switch.toml")
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write('serverAddr = "1.1.1.1"\nserverPort = 7000\n\n'
                 '# 这是注释\n[[proxies]]\nname = "hk-ssh"\ntype = "tcp"\n'
                 'localIP = "127.0.0.1"\nlocalPort = 22\nremotePort = 11111\n')
    r = c.post("/api/frpc", headers=AUTH, json={
        "name": "切换测试实例", "config_path": cfg, "container": "",
        "restart_mode": "none", "note": "", "enabled": True})
    check("建实例 200", r.status_code == 200, r.text[:200])
    inst_id = r.json()["id"]
    c.patch(f"/api/tunnels/{tun['id']}", headers=AUTH, json={"frpc_instance_id": inst_id})

    r = c.post(f"/api/manual-nodes/{nid}/switch", headers=AUTH,
               json={"instance_id": inst_id, "restart": False})
    check("切换 200", r.status_code == 200, r.text[:300])
    sw = r.json()
    check("实例名对", sw["instance"] == "切换测试实例", sw)
    check("端点对", sw["endpoint"] == "127.0.0.1:1", sw["endpoint"])
    check("配置确实被改写了", sw["changed"] is True, sw)
    check("受影响的隧道列了出来", sw["tunnels"] == ["hk-ssh"], sw["tunnels"])
    check("节点探测结果如实回传（这里是不可达）",
          sw["node_probe_ok"] is False and bool(sw["node_probe_reason"]), sw)

    txt = open(cfg, encoding="utf-8").read()
    check("★ 新 serverAddr 写进去了", 'serverAddr = "127.0.0.1"' in txt, txt)
    check("★ 没有重复的 serverAddr", txt.count("serverAddr") == 1, txt.count("serverAddr"))
    check("★ 注释保留", "# 这是注释" in txt, txt)
    check("★ 隧道定义原样保留",
          'remotePort = 11111' in txt and 'name = "hk-ssh"' in txt, txt)
    check("★ 改写后仍是合法 TOML",
          frpcparse.parse(txt, "toml").server_addr == "127.0.0.1", txt)

    inst_view = c.get("/api/frpc", headers=AUTH).json()["instances"][0]
    check("实例已挂到外部节点", inst_view["manual_node_id"] == nid, inst_view)
    check("实例视图标了 node_source=manual", inst_view["node_source"] == "manual", inst_view)
    check("实例视图带节点名", inst_view["manual_node_name"] == "自建-香港", inst_view)

    print("[9] 手工实例不参与引擎重建")
    r = c.post(f"/api/frpc/{inst_id}/rebuild?restart=false", headers=AUTH)
    check("重建 200", r.status_code == 200, r.text[:200])
    check("★ 如实返回「手工托管、引擎不改写」",
          (r.json().get("summary") or {}).get("manual") is True, r.json().get("summary"))

    print("[10] PATCH 服务端要素：传导到实例")
    r = c.patch(f"/api/manual-nodes/{nid}", headers=AUTH,
                json={"server_addr": "127.0.0.2"})
    check("PATCH 200", r.status_code == 200, r.text[:300])
    pd = r.json()
    check("标出服务端要素变了", pd["server_changed"] is True, pd)
    check("传导到了那个实例", len(pd["switched"]) == 1, pd["switched"])
    check("传导结果里实例名对", pd["switched"][0]["instance"] == "切换测试实例", pd["switched"])
    txt2 = open(cfg, encoding="utf-8").read()
    check("★ 实例配置文件跟着改了", 'serverAddr = "127.0.0.2"' in txt2, txt2)

    print("  --- 改备注不该触发传导 ---")
    r = c.patch(f"/api/manual-nodes/{nid}", headers=AUTH, json={"note": "只改备注"})
    check("改备注 200", r.status_code == 200, r.text[:200])
    check("★ 没标记 server_changed", r.json()["server_changed"] is False, r.json())
    check("★ 没有传导动作", r.json()["switched"] == [], r.json())

    print("  --- 改到已被占用的地址+端口组合应被拒 ---")
    c.post("/api/manual-nodes", headers=AUTH, json={
        "name": "第二个节点", "text": CONF_INI, "proxies": []})
    # nid 现在是 127.0.0.2:1，第二个节点是 127.0.0.1:2。
    # 必须**同时**改地址和端口才撞得上 —— 只改端口不会撞。
    r = c.patch(f"/api/manual-nodes/{nid}", headers=AUTH,
                json={"server_addr": "127.0.0.1", "server_port": 2})
    check("地址+端口撞上另一个节点 -> 409", r.status_code == 409, r.status_code)
    check("撞车提示也带 existing_id",
          r.json()["detail"].get("existing_id") != nid, r.json())
    check("理由点出占用的节点名", "第二个节点" in r.text, r.text[:200])
    r = c.patch(f"/api/manual-nodes/{nid}", headers=AUTH, json={"server_port": 2})
    check("只改端口不撞 -> 200", r.status_code == 200, r.text[:200])
    c.patch(f"/api/manual-nodes/{nid}", headers=AUTH, json={"server_port": 1})

    print("[11] 不允许直接 PATCH 绑外部节点")
    r = c.patch(f"/api/tunnels/{tun['id']}", headers=AUTH, json={"manual_node_id": nid})
    check("★ 隧道直接绑外部节点被拒", r.status_code == 400, r.status_code)
    check("★ 理由指向「frpc」页的切换入口", "切到外部节点" in r.text, r.text[:200])
    r = c.patch(f"/api/frpc/{inst_id}", headers=AUTH, json={"manual_node_id": nid})
    check("★ 实例直接绑外部节点也被拒", r.status_code == 400, r.status_code)
    r = c.patch(f"/api/tunnels/{tun['id']}", headers=AUTH, json={"manual_node_id": None})
    check("传 null 解绑是允许的", r.status_code == 200, r.text[:200])
    r = c.patch(f"/api/tunnels/{tun['id']}", headers=AUTH, json={"manual_node_id": nid})
    check("解绑后再绑回来仍被拒", r.status_code == 400, r.status_code)
    # 上面那次「传 null 解绑」把隧道和外部节点的直接关联断开了 —— 重新切一次，
    # 让引擎按实例把关联补回来，后面的删除测试才有隧道可删。
    r = c.post(f"/api/manual-nodes/{nid}/switch", headers=AUTH,
               json={"instance_id": inst_id, "restart": False})
    check("重新切换后隧道重新关联上", r.json()["tunnels"] == ["hk-ssh"], r.json())
    check("库里也确实关联回来了",
          c.get("/api/tunnels", headers=AUTH).json()[0]["manual_node_id"] == nid,
          c.get("/api/tunnels", headers=AUTH).json()[0])

    print("[12] 探测端点")
    r = c.post(f"/api/manual-nodes/{nid}/probe", headers=AUTH)
    check("单节点探测 200", r.status_code == 200, r.text[:200])
    check("返回 ok 字段", "ok" in r.json(), r.json())
    r = c.post("/api/manual-nodes/probe", headers=AUTH)
    check("全量探测 200", r.status_code == 200, r.text[:200])
    check("results 是数组且长度对", len(r.json()["results"]) == 2, r.json())
    r = c.post("/api/manual-nodes/99999/probe", headers=AUTH)
    check("探测不存在的节点 -> 404", r.status_code == 404, r.status_code)
    r = c.post(f"/api/manual-nodes/{nid}/switch", headers=AUTH,
               json={"instance_id": 99999, "restart": False})
    check("切换到不存在的实例 -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/manual-nodes/99999/switch", headers=AUTH,
               json={"instance_id": inst_id, "restart": False})
    check("用不存在的节点切换 -> 400", r.status_code == 400, r.status_code)

    print("[13] 删除")
    r = c.delete(f"/api/manual-nodes/{nid}", headers=AUTH)
    check("删除 200", r.status_code == 200, r.text[:200])
    dd = r.json()
    check("报告解绑的实例数", dd["unbound_instances"] == 1, dd)
    check("报告删除的隧道数", dd["removed_tunnels"] == 1, dd)
    check("节点没了", all(n["id"] != nid
              for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]))
    check("实例被解绑",
          c.get("/api/frpc", headers=AUTH).json()["instances"][0]["manual_node_id"] is None)
    check("隧道被删掉", all(t["proxy_name"] != "hk-ssh"
              for t in c.get("/api/tunnels", headers=AUTH).json()))
    r = c.delete(f"/api/manual-nodes/{nid}", headers=AUTH)
    check("重复删除 -> 404", r.status_code == 404, r.status_code)

    print("[14] 保留隧道记录的删法")
    # 重新导入一个节点，这次**勾选**它配置里的隧道，才能验证 keep_tunnels
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "name": "保留测试节点",
        "text": CONF_INI.replace("server_port = 2", "server_port = 5"),
        "proxies": [{"name": "ini-tun", "adopt": True, "dns_record_name": ""}]})
    check("带隧道导入 200", r.status_code == 200, r.text[:200])
    nid3 = r.json()["id"]
    check("纳管了 ini-tun", r.json()["adopted"] == ["ini-tun"], r.json())
    r = c.delete(f"/api/manual-nodes/{nid3}?keep_tunnels=true", headers=AUTH)
    check("keep_tunnels 删除 200", r.status_code == 200, r.text[:200])
    check("★ 隧道被保留", r.json()["kept_tunnels"] == 1, r.json())
    check("★ 保留下来的隧道已解绑",
          all(t.get("manual_node_id") is None
              for t in c.get("/api/tunnels", headers=AUTH).json()
              if t["proxy_name"] == "ini-tun"),
          [t for t in c.get("/api/tunnels", headers=AUTH).json()
           if t["proxy_name"] == "ini-tun"])

    print("[15] 停用的节点不能切换过去")
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "name": "停用节点", "text": CONF_INI.replace("server_port = 2", "server_port = 3"),
        "enabled": False, "proxies": []})
    nid4 = r.json()["id"]
    r = c.post(f"/api/manual-nodes/{nid4}/switch", headers=AUTH,
               json={"instance_id": inst_id, "restart": False})
    check("★ 切到停用节点 -> 400", r.status_code == 400, r.status_code)
    check("理由点明「已停用」", "停用" in r.text, r.text[:200])

    # ------------------------------------------------------------------
    # 以下三节覆盖「外部节点是隧道的附属信息」这个模型 —— 入口在隧道页，
    # 一次粘配置就把节点 + 隧道 + 承载实例全配好，用完删隧道自动清理。
    # ------------------------------------------------------------------
    print("[16] 一步导入：粘配置 + 指定承载实例")
    cfg2 = os.path.join(TMP, "frpc-two.toml")
    with open(cfg2, "w", encoding="utf-8") as fh:
        fh.write('serverAddr = "1.1.1.1"\nserverPort = 7000\n')
    r = c.post("/api/frpc", headers=AUTH, json={
        "name": "一步导入实例", "config_path": cfg2, "container": "",
        "restart_mode": "none", "note": "", "enabled": True})
    inst2 = r.json()["id"]

    CONF2 = CONF.replace('serverAddr = "127.0.0.1"', 'serverAddr = "198.51.100.7"') \
                .replace("hk-", "two-")
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF2,
        "proxies": [{"name": "two-ssh", "adopt": True, "dns_record_name": ""}],
        "frpc_instance_id": inst2})
    check("带实例导入 200", r.status_code == 200, r.text[:300])
    d2 = r.json()
    nid5 = d2["id"]
    check("纳管了隧道", d2["adopted"] == ["two-ssh"], d2["adopted"])
    check("★ 返回里带上了切换结果", (d2.get("switched") or {}).get("ok") is True,
          d2.get("switched"))
    two = [t for t in c.get("/api/tunnels", headers=AUTH).json()
           if t["proxy_name"] == "two-ssh"]
    check("隧道建出来了", len(two) == 1, two)
    check("★ 隧道直接挂到了指定的实例上", two[0]["frpc_instance_id"] == inst2, two[0])
    txt = open(cfg2, encoding="utf-8").read()
    check("★ 实例的 frpc 配置被改写", 'serverAddr = "198.51.100.7"' in txt, txt)
    check("★ 改写后仍是合法 TOML",
          frpcparse.parse(txt, "toml").server_addr == "198.51.100.7", txt)
    check("实例被记到节点上",
          [i for i in c.get("/api/frpc", headers=AUTH).json()["instances"]
           if i["id"] == inst2][0]["manual_node_id"] == nid5)

    print("[17] PATCH 重传一份配置：后端重新解析")
    NEW = CONF2.replace('serverAddr = "198.51.100.7"', 'serverAddr = "198.51.100.8"')
    r = c.patch(f"/api/manual-nodes/{nid5}", headers=AUTH, json={"text": NEW})
    check("重传配置 200", r.status_code == 200, r.text[:300])
    check("★ 识别出服务端要素变了", r.json()["server_changed"] is True, r.json())
    check("新端点对", r.json()["node"]["endpoint"] == "198.51.100.8:1",
          r.json()["node"]["endpoint"])
    txt = open(cfg2, encoding="utf-8").read()
    check("★ 实例配置跟着改了", 'serverAddr = "198.51.100.8"' in txt, txt)
    r = c.patch(f"/api/manual-nodes/{nid5}", headers=AUTH, json={"text": NEW})
    check("★ 同一份配置再传一次不触发传导",
          r.json()["server_changed"] is False, r.json())
    check("★ 也没有多余的重启动作", r.json()["switched"] == [], r.json())
    r = c.patch(f"/api/manual-nodes/{nid5}", headers=AUTH, json={"text": "这不是配置"})
    check("重传坏配置 -> 400", r.status_code == 400, r.status_code)
    r = c.patch(f"/api/manual-nodes/{nid5}", headers=AUTH,
                json={"text": "serverPort = 7000"})
    check("没有 serverAddr 的配置 -> 400", r.status_code == 400, r.status_code)

    print("[18] 删掉最后一条隧道会自动清理外部节点")
    # 先把实例解绑（否则实例还引用着这个节点，不该清理）
    c.patch(f"/api/frpc/{inst2}", headers=AUTH, json={"manual_node_id": None})
    tid2 = [t for t in c.get("/api/tunnels", headers=AUTH).json()
            if t["proxy_name"] == "two-ssh"][0]["id"]
    r = c.delete(f"/api/tunnels/{tid2}", headers=AUTH)
    check("删隧道 200", r.status_code == 200, r.text[:200])
    check("★ 报告清理掉了外部节点", r.json()["dropped_manual_node"] == nid5, r.json())
    check("★ 节点记录确实没了",
          all(n["id"] != nid5
              for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]))
    # 反例：实例还引用着的时候**不能**清
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF2.replace("two-", "three-"),
        "proxies": [{"name": "three-ssh", "adopt": True, "dns_record_name": ""}],
        "frpc_instance_id": inst2})
    nid6 = r.json()["id"]
    tid3 = [t for t in c.get("/api/tunnels", headers=AUTH).json()
            if t["proxy_name"] == "three-ssh"][0]["id"]
    r = c.delete(f"/api/tunnels/{tid3}", headers=AUTH)
    check("★ 实例还引用着时不清理", r.json()["dropped_manual_node"] == 0, r.json())
    check("★ 节点还在",
          any(n["id"] == nid6
              for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]))

    print("[19] 实例改连到别的节点：旧节点没人用了要自动清掉")
    # 此刻 inst2 挂在 nid6 上，但 nid6 已经没有隧道了（three-ssh 刚被删）。
    # 再把 inst2 切到新导入的 nid7 —— 切走之后 nid6 就彻底没人引用了。
    # ⚠️ 每份新配置都得换 serverAddr：同地址会被「已经导入过了」挡下来。
    def addr(conf, ip):
        return conf.replace('serverAddr = "198.51.100.7"',
                            f'serverAddr = "{ip}"')

    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": addr(CONF2, "203.0.113.9").replace("two-", "four-"),
        "proxies": [{"name": "four-ssh", "adopt": True, "dns_record_name": ""}],
        "frpc_instance_id": inst2})
    check("改连到新节点 200", r.status_code == 200, r.text[:300])
    d4 = r.json()
    nid7 = d4["id"]
    sw = d4.get("switched") or {}
    check("★ 报告清理掉了旧节点", sw.get("dropped_manual_node") == nid6, sw)
    names = {n["id"] for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]}
    check("★ 旧节点记录确实没了", nid6 not in names, names)
    check("新节点在", nid7 in names, names)
    check("实例现在挂在 nid7",
          [i for i in c.get("/api/frpc", headers=AUTH).json()["instances"]
           if i["id"] == inst2][0]["manual_node_id"] == nid7)
    # 反例：旧节点还有隧道的时候不能清
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": addr(CONF2, "203.0.113.10").replace("two-", "five-"),
        "proxies": [{"name": "five-ssh", "adopt": True, "dns_record_name": ""}]})
    nid8 = r.json()["id"]          # 这次不指定实例 → five-ssh 留在 nid8 上
    r = c.post(f"/api/manual-nodes/{nid8}/switch", headers=AUTH,
               json={"instance_id": inst2, "restart": False})
    check("切到有隧道的节点 200", r.status_code == 200, r.text[:300])
    # 这一切把 four-ssh 也带到了 nid8，nid7 就空了 —— 该被清
    check("★ 旧节点 nid7 被清掉", r.json().get("dropped_manual_node") == nid7, r.json())
    check("★ 新节点 nid8 有隧道，不会被清",
          any(n["id"] == nid8
              for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]))

    print("[20] 「这个地址已经导入过了」必须给出路，而不是死路")
    # 用户报的原话：清掉自建隧道后「我这里添加还是提示已有隧道」。
    # 根因：① 那条提示只给了「请直接编辑那个节点」，而**零隧道的残留节点在页面上
    #          够不着**（节点不进节点页、隧道卡片按隧道渲染，没隧道就没卡片）
    #          → 改不了也删不掉，重新导入**永久被堵**；
    #       ② 残留节点本身就是那个同名 bug 的产物：导入时隧道被全局重名判掉，
    #          于是只留下一个空节点。
    CONF20 = '''serverAddr = "203.0.113.77"
serverPort = 7000

auth.token = "c20-tok"

[[proxies]]
name = "c20-ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 26022
'''
    # ① 复刻指纹：导入一份配置、**一条都不勾** → 零隧道 + 零实例的残留节点
    r = c.post("/api/manual-nodes", headers=AUTH,
               json={"text": CONF20, "proxies": []})
    check("导入但不纳管 200", r.status_code == 200, r.text[:300])
    empty_id = r.json()["id"]
    check("残留节点：零隧道", r.json()["node"]["tunnel_count"] == 0, r.json()["node"])
    check("残留节点：零实例", r.json()["node"]["instance_count"] == 0, r.json()["node"])

    # ② 原样再导一次 → 409，且 detail 必须是**结构化**的（前端要靠 existing_id
    #    才能给出「打开那个节点」这个真入口）
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF20, "proxies": [{"name": "c20-ssh", "adopt": True}]})
    check("★ 同地址重导 -> 409", r.status_code == 409, r.status_code)
    det = r.json()["detail"]
    check("★ detail 是结构化对象", isinstance(det, dict), det)
    check("★ 带上 existing_id", det.get("existing_id") == empty_id, det)
    check("带上 tunnel_count", det.get("tunnel_count") == 0, det)
    check("带上 instance_count", det.get("instance_count") == 0, det)
    check("带 code=node_addr_exists", det.get("code") == "node_addr_exists", det)
    check("★ 被拒时没有偷偷建出第二个节点",
          [n["id"] for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]]
          .count(empty_id) == 1)

    # ③ parse 也给同样的信息 —— 前端预览靠它，而不是「先失败一次再猜」
    p = c.post("/api/manual-nodes/parse", headers=AUTH,
               json={"text": CONF20}).json()
    check("★ parse 回 duplicate 对象", isinstance(p.get("duplicate"), dict),
          p.get("duplicate"))
    check("★ 旧的 duplicate_of 字段已去掉", "duplicate_of" not in p, list(p))
    check("duplicate 带 existing_id", p["duplicate"]["existing_id"] == empty_id,
          p["duplicate"])
    # 更新模式下「撞到自己」不是冲突 —— 否则打开更新对话框、一解析就报重复，很吓人
    p2 = c.post("/api/manual-nodes/parse", headers=AUTH,
                json={"text": CONF20, "node_id": empty_id}).json()
    check("★ 更新模式下撞到自己 -> duplicate 为 None",
          p2.get("duplicate") is None, p2.get("duplicate"))

    # ④ 有隧道挂着的节点**不允许**覆盖重建 —— 那等于顺手删隧道（还是用户
    #    精心配过 dns 记录名 / 标签 / 挂接关系的那几条）
    busy = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF20.replace("203.0.113.77", "203.0.113.78"),
        "proxies": [{"name": "c20-ssh", "adopt": True}]}).json()
    busy_id = busy["id"]
    check("④ 有隧道的节点建好了", busy["adopted"] == ["c20-ssh"], busy)
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF20.replace("203.0.113.77", "203.0.113.78"),
        "proxies": [{"name": "c20-ssh", "adopt": True}], "overwrite": True})
    check("★ 覆盖有隧道的节点 -> 409", r.status_code == 409, r.status_code)
    check("★ code=node_in_use", r.json()["detail"].get("code") == "node_in_use", r.json())
    nodes20 = c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]
    check("★ 被拒后节点还在", any(n["id"] == busy_id for n in nodes20), nodes20)
    check("★ 被拒后隧道还在",
          any(t["manual_node_id"] == busy_id
              for t in c.get("/api/tunnels", headers=AUTH).json()))

    # ⑤ 用户那个场景完整走一遍：覆盖重建空节点 → 这次真的纳管进来
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF20, "proxies": [{"name": "c20-ssh", "adopt": True}],
        "overwrite": True})
    check("★ 覆盖空节点 -> 200", r.status_code == 200, r.text[:300])
    d20 = r.json()
    check("★ 报告清掉了哪个节点（前端要把这件事说出口）",
          d20["overwritten"] == "203.0.113.77:7000", d20)
    check("★ 这次隧道被纳管了", d20["adopted"] == ["c20-ssh"], d20)
    check("★ 没跳过任何一条", d20["skipped"] == [], d20)
    new_id = d20["id"]
    check("★ 新节点是新 id", new_id != empty_id, (new_id, empty_id))
    names20 = {n["id"] for n in c.get("/api/manual-nodes", headers=AUTH).json()["nodes"]}
    check("★ 残留节点记录没了", empty_id not in names20, names20)
    check("新节点在", new_id in names20, names20)

    print("[21] ★ 导入时顺手同步 DNS；UDP 隧道点「立即探测」也必须同步")
    # 用户报的 bug：「手动添加的隧道好像没有自动进行 cf dns 解析？」
    # 两处根因，都不是「用户忘了填记录名」：
    #   ① 导入接口**从来不碰 DNS**，全靠引擎下一轮巡检（最长 20 秒）。用户粘完
    #      配置站在页面前什么都不发生 → 以为「没生效」，也不会去翻事件日志；
    #   ② 更硬的一条：udp 隧道在引擎里走 `ok is None`（不适用探测）分支，那里
    #      原来**直接 return**，于是 udp 的外部隧道**永远**同步不了 DNS —— 而
    #      udp 恰恰是外部节点上最常见的一类。探测端点里同款分支也一样。
    class FakeCF:
        """只记「写了什么」。list_records 恒返回空 → 每次都会走 upsert，
        这样「有没有真的走到 Cloudflare」就变成一个可断言的信号。"""

        def __init__(self) -> None:
            # `_sync_dns` 会先看「有没有配 token」，假客户端也得有这个属性。
            self.token = "fake-cf-token"
            self.upserts: list[dict] = []

        async def resolve_zone(self, name: str):
            from app.cloudflare import Zone
            return Zone(zone_id="ZAPI", name="example.com")

        async def list_records(self, zone_id: str, name: str | None = None):
            return []

        async def upsert(self, **kw):
            from app.cloudflare import DnsRecord
            self.upserts.append(kw)
            return DnsRecord("RAPI", kw["zone_id"], kw["name"],
                             kw["record_type"], kw["content"], False)

    from app.engine import engine as ENG   # noqa: PLC0415

    CONF21 = '''serverAddr = "203.0.113.90"
serverPort = 7000

[[proxies]]
name = "c21-udp"
type = "udp"
localIP = "127.0.0.1"
localPort = 5000
remotePort = 26050
'''
    cf21 = FakeCF()
    # ⚠️ 必须**紧贴调用前**注入：引擎 tick 里 `if self.client is None:
    #    self.reload_clients()` 会把 cf 换回真的（测试库里没配 token，
    #    一旦被换掉就会以「尚未配置 Cloudflare API Token」响亮失败，不会假通过）。
    ENG.cf = cf21
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF21,
        "proxies": [{"name": "c21-udp", "adopt": True,
                     "dns_record_name": "c21.example.com"}]})
    check("导入 200", r.status_code == 200, r.text[:300])
    d21 = r.json()
    check("★ 导入时就同步了 DNS（不必等引擎下一轮）",
          len(d21.get("dns") or []) == 1, d21.get("dns"))
    check("★ 响应里说清了改成了什么",
          "c21.example.com" in (d21["dns"][0] if d21.get("dns") else ""),
          d21.get("dns"))
    check("★ Cloudflare 那边真的写了", len(cf21.upserts) == 1, cf21.upserts)
    check("★ 目标地址用的是外部节点的 serverAddr（没有 proxy 可用）",
          bool(cf21.upserts) and cf21.upserts[0]["content"] == "203.0.113.90",
          cf21.upserts)

    tun21 = [t for t in c.get("/api/tunnels", headers=AUTH).json()
             if t["proxy_name"] == "c21-udp"][0]
    check("★ 解析出的 zone 落了库", tun21["dns_zone_id"] == "ZAPI", tun21)
    check("★ 记录 id 落了库", tun21["dns_record_id"] == "RAPI", tun21)

    # 探测端点：udp 在 auto 模式下**不探测**，但 DNS 该同步还得同步。
    cf21.upserts.clear()
    ENG.cf = cf21
    r = c.post(f"/api/tunnels/{tun21['id']}/probe", headers=AUTH)
    check("udp 探测 200", r.status_code == 200, r.text[:300])
    check("★ 如实回「不适用」而不是假装失败",
          r.json().get("skipped") is True, r.json())
    check("★ 但照样同步了 DNS（原来这里直接 return）",
          "c21.example.com" in (r.json().get("dns") or ""), r.json())
    check("★ 确实又走到了 Cloudflare", len(cf21.upserts) == 1, cf21.upserts)

    # 反例：没填记录名 = 用户明确不管这条的 DNS，一次都不该去问 Cloudflare。
    cf21.upserts.clear()
    r = c.post("/api/manual-nodes", headers=AUTH, json={
        "text": CONF21.replace("203.0.113.90", "203.0.113.91"),
        "proxies": [{"name": "c21-udp", "adopt": True, "dns_record_name": ""}]})
    check("不填记录名也能导入", r.status_code == 200, r.text[:300])
    check("★ 没填记录名 -> 完全不碰 Cloudflare", cf21.upserts == [], cf21.upserts)
    check("★ 也不谎报 DNS 结果", (r.json().get("dns") or []) == [],
          r.json().get("dns"))

print()
print(f"==> PASS {PASS} / FAIL {FAIL}")
sys.exit(1 if FAIL else 0)
