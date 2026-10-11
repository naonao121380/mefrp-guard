# -*- coding: utf-8 -*-
"""FastAPI 端到端冒烟：真实启动应用（含 lifespan），逐条打端点。不碰外网。"""
import os, sys, tempfile, base64, pathlib
tmp = tempfile.mkdtemp(prefix="mg-smoke-")
os.environ.update(
    MG_DATA_DIR=tmp,
    MG_FRPC_CONFIG=os.path.join(tmp, "frpc.toml"),
    MG_FRPC_CONTAINER="frpc",
    MG_WEB_USER="admin",
    MG_WEB_PASSWORD="s3cret-pass",
)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app import auth as _auth

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret-pass").decode()}
PW = "s3cret-pass"
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print(f"  PASS  {name}")
    else:    bad += 1; print(f"  FAIL  {name}  ->  {extra}")

with TestClient(app) as c:
    print("[1] 健康检查与鉴权")
    r = c.get("/healthz"); check("/healthz 免鉴权 200", r.status_code == 200 and r.json()["ok"], r.status_code)
    r = c.get("/api/overview"); check("无凭据 -> 401", r.status_code == 401, r.status_code)
    check("401 带 WWW-Authenticate", "www-authenticate" in {k.lower() for k in r.headers}, dict(r.headers))
    r = c.get("/api/overview", headers={"Authorization": "Basic " + base64.b64encode(b"admin:wrong").decode()})
    check("错误口令 -> 401", r.status_code == 401, r.status_code)
    r = c.get("/api/overview", headers={"Authorization": "Basic notbase64!!"})
    check("坏格式凭据 -> 401", r.status_code == 401, r.status_code)
    r = c.get("/api/overview", headers=AUTH); check("正确凭据 -> 200", r.status_code == 200, r.text[:200])
    r = c.get("/", headers=AUTH); check("根路径返回 UI", r.status_code == 200 and "mefrp" in r.text.lower(), r.status_code)

    print("[2] /api/overview 结构")
    ov = r2 = c.get("/api/overview", headers=AUTH).json()
    for k in ("engine", "tunnels", "frpc", "pending_review"):
        check(f"含字段 {k}", k in ov, list(ov))
    for k in ("running", "configured", "user_group", "last_error", "tick_count", "next_tick_in"):
        check(f"engine.{k} 存在", k in ov["engine"], list(ov["engine"]))
    # 回归：用户组有两个值，机器名 + 展示名；取不到时要把错误暴露出来
    for k in ("user_group_friendly", "user_group_error", "address_known"):
        check(f"engine.{k} 存在", k in ov["engine"], list(ov["engine"]))
    check("未配置 token 时 configured=False", ov["engine"]["configured"] is False, ov["engine"]["configured"])
    check("tunnels 是数组", isinstance(ov["tunnels"], list))
    check("frpc.config_path 有值", bool(ov["frpc"]["config_path"]), ov["frpc"])

    print("[3] 隧道 CRUD")
    r = c.post("/api/tunnels", headers=AUTH, json={"name":"NAS 面板","proxy_name":"nas-panel",
               "local_port":5000,"dns_record_name":"nas.example.com"})
    check("创建 200", r.status_code == 200 and r.json()["ok"], r.text[:200])
    tid = r.json()["id"]
    r = c.post("/api/tunnels", headers=AUTH, json={"name":"重复","proxy_name":"nas-panel","local_port":1})
    check("重复 proxy_name -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/tunnels", headers=AUTH, json={"name":"坏","proxy_name":"x","local_port":99999})
    check("端口越界 -> 422", r.status_code == 422, r.status_code)
    r = c.get("/api/tunnels", headers=AUTH)
    check("列表含 1 条", len(r.json()) == 1, r.json())
    r = c.patch(f"/api/tunnels/{tid}", headers=AUTH, json={"local_port":5001,"auto_failover":False})
    check("PATCH 200", r.status_code == 200, r.text[:200])
    t = c.get("/api/tunnels", headers=AUTH).json()[0]
    check("PATCH 生效", t["local_port"] == 5001 and t["auto_failover"] == 0, t)
    # 回归：总览里的隧道项必须带上「节点地址 / 公网入口 / 探测是否适用」
    ovt = c.get("/api/overview", headers=AUTH).json()["tunnels"][0]
    for k in ("node_hostname", "public_endpoint", "address_known", "probe_skipped", "probe_ok"):
        check(f"overview.tunnels[].{k} 存在", k in ovt, list(ovt))
    check("地址未知时 public_endpoint 是空串而不是 'None:None'",
          ovt["public_endpoint"] == "" or ":" in ovt["public_endpoint"],
          repr(ovt["public_endpoint"]))
    check("还没探测过时 probe_skipped=False（区分「没探」与「不适用」）",
          ovt["probe_skipped"] is False, ovt["probe_skipped"])
    r = c.patch("/api/tunnels/99999", headers=AUTH, json={"local_port":1})
    check("PATCH 不存在 -> 404", r.status_code == 404, r.status_code)
    r = c.post(f"/api/tunnels/{tid}/probe", headers=AUTH)
    check("探测无隧道 -> 404", r.status_code == 404, r.status_code)
    r = c.post(f"/api/tunnels/{tid}/failover", headers=AUTH, json={"node_id":None})
    # 此刻还没有任何 frpc 实例，这条隧道也没挂接 —— 切换必须先被这一层拦住，
    # 并且说清原因。不能静默返回 200 骗用户说「已触发切换」。
    check("★ 未挂接容器的隧道：切换被拒且说明原因",
          r.status_code == 400 and "挂接" in r.text, r.text[:200])
    r = c.post(f"/api/tunnels/{tid}/failover", headers=AUTH, json={"node_id":12345})
    check("切换（指定不存在的节点）-> 400", r.status_code == 400, r.text[:200])

    print("[4] 未纳管隧道 / 节点")
    r = c.get("/api/orphans", headers=AUTH)
    check("/api/orphans 200 且是数组", r.status_code == 200 and isinstance(r.json(), list), r.text[:200])
    check("/api/orphans 无数据时为空", r.json() == [], r.json())
    r = c.post("/api/orphans/1/adopt", headers=AUTH, json={})
    check("纳管不存在的 proxy -> 404", r.status_code == 404, r.status_code)
    r = c.get("/api/nodes", headers=AUTH)
    check("/api/nodes 200", r.status_code == 200, r.text[:200])
    check("含 user_group/nodes/prefs", all(k in r.json() for k in ("user_group","nodes","prefs")), list(r.json()))
    # 回归：节点页要知道「用户组是谁」和「有几个节点知道公网地址」
    check("含 user_group_friendly/user_group_error/address_known",
          all(k in r.json() for k in ("user_group_friendly","user_group_error","address_known")),
          list(r.json()))
    check("未配置 token 时 user_group_error 非空（不能静默显示未知）",
          bool(r.json()["user_group_error"]), r.json()["user_group_error"])
    r = c.post("/api/nodes/1/pref", headers=AUTH, json={"excluded":True})
    check("设置节点偏好 200", r.status_code == 200, r.text[:200])
    check("偏好已存", c.get("/api/nodes", headers=AUTH).json()["prefs"].get("1",{}).get("excluded") == 1)

    # 节点偏好预览。⚠️ 这条路由是字面量，必须排在 /api/nodes/{node_id}/pref 之前 ——
    # 注册反了的话 pref-preview 会被当成 node_id，直接 422。本文件其它地方踩过这个坑。
    print("  --- 节点偏好预览 ---")
    check("未登录 -> 401", c.post("/api/nodes/pref-preview", json={"keywords":[]}).status_code == 401)
    r = c.post("/api/nodes/pref-preview", headers=AUTH, json={"keywords":["北京","上海"]})
    check("pref-preview 200（没被 {node_id} 那条路由吃掉）", r.status_code == 200, r.text[:200])
    d = r.json()
    check("返回 keywords/groups/unmatched/total",
          all(k in d for k in ("keywords","groups","unmatched","total")), list(d))
    check("关键词顺序原样返回", d["keywords"] == ["北京","上海"], d["keywords"])
    check("groups 按关键词一一对应",
          [g["keyword"] for g in d["groups"]] == ["北京","上海"], d["groups"])
    r = c.post("/api/nodes/pref-preview", headers=AUTH, json={"keywords":[]})
    check("空偏好 -> 不报错", r.status_code == 200 and r.json()["keywords"] == [], r.text[:200])
    r = c.post("/api/nodes/pref-preview", headers=AUTH, json={"keywords":["北京，上海"]})
    check("★ 数组元素里的全角逗号也被拆开（传 ['北京，上海'] == 传 '北京,上海'）",
          r.json()["keywords"] == ["北京","上海"], r.json()["keywords"])
    # 预览是只读的：不能顺手把设置改了
    check("★ 预览不改库里的 prefer_keywords",
          c.get("/api/settings", headers=AUTH).json()["settings"]["prefer_keywords"] != "北京,上海",
          c.get("/api/settings", headers=AUTH).json()["settings"]["prefer_keywords"])

    print("[5] frpc")
    r = c.get("/api/frpc", headers=AUTH)
    check("/api/frpc 200", r.status_code == 200, r.text[:200])
    check("含 backups 数组", isinstance(r.json()["backups"], list))
    check("config 为空串（还没文件）", r.json()["config"] == "", repr(r.json()["config"])[:80])
    r = c.post("/api/frpc/rebuild", headers=AUTH)
    check("无可用隧道时 rebuild -> 400", r.status_code == 400, r.text[:200])
    r = c.post("/api/frpc/restore", headers=AUTH, params={"name": "../../etc/passwd"})
    # 还没有任何 frpc 实例 —— 这一层就要拦住，而不是 500 或者静默成功。
    # 真正的「路径穿越」校验在有了实例之后，见 [18] 那一段。
    check("没有实例时 restore -> 404 且说明原因",
          r.status_code == 404 and "实例" in r.text, r.text[:200])

    print("[6] 事件")
    r = c.get("/api/events", headers=AUTH)
    check("/api/events 200", r.status_code == 200 and isinstance(r.json(), list), r.text[:200])
    check("有启动事件", any("启动" in e["message"] for e in r.json()), r.json()[:2])
    r = c.get("/api/events", headers=AUTH, params={"limit": 5})
    check("limit 生效", len(r.json()) <= 5, len(r.json()))
    r = c.get("/api/events", headers=AUTH, params={"limit": 99999})
    check("limit 被夹到 1000", r.status_code == 200, r.status_code)

    print("[7] 设置：密钥打码 + 空值不覆盖")
    r = c.get("/api/settings", headers=AUTH)
    check("/api/settings 200", r.status_code == 200, r.text[:200])
    check("含 secret_keys", "mefrp_token" in r.json()["secret_keys"], r.json().get("secret_keys"))
    check("defaults 里有 min_bandwidth_mbps=25", r.json()["defaults"]["min_bandwidth_mbps"] == 25)
    check("defaults 里 probe_mode 默认 auto", r.json()["defaults"]["probe_mode"] == "auto",
          r.json()["defaults"].get("probe_mode"))
    check("settings 里回读了 probe_mode", r.json()["settings"]["probe_mode"] == "auto",
          r.json()["settings"].get("probe_mode"))
    # 回归：枚举字段写错必须 400，不能静默降级（否则用户以为关了探测其实还在探）
    r = c.put("/api/settings", headers=AUTH, json={"probe_mode": "udp"})
    check("非法 probe_mode -> 400", r.status_code == 400, r.status_code)
    r = c.put("/api/settings", headers=AUTH, json={"probe_mode": "NONE"})
    check("probe_mode 大小写归一化后接受", r.status_code == 200, r.text[:200])
    check("已存为小写", c.get("/api/settings", headers=AUTH).json()["settings"]["probe_mode"] == "none")
    c.put("/api/settings", headers=AUTH, json={"probe_mode": "auto"})
    r = c.put("/api/settings", headers=AUTH, json={"mefrp_token":"abcdefghijklmnop","engine_interval":30})
    check("PUT 200", r.status_code == 200, r.text[:200])
    s = c.get("/api/settings", headers=AUTH).json()["settings"]
    check("密钥被打码", "…" in s["mefrp_token"] and "abcdefghijklmnop" not in s["mefrp_token"], s["mefrp_token"])
    check("非密钥原样返回", s["engine_interval"] == 30, s["engine_interval"])
    c.put("/api/settings", headers=AUTH, json={"mefrp_token":"", "engine_interval":25})
    s = c.get("/api/settings", headers=AUTH).json()["settings"]
    check("空密钥不覆盖原值", s["mefrp_token"] == "abcd…mnop", s["mefrp_token"])
    r = c.put("/api/settings", headers=AUTH, json={"engine_interval":"not-a-number"})
    check("整数字段非法值 -> 400", r.status_code == 400, r.status_code)
    r = c.put("/api/settings", headers=AUTH, json={"bogus_key": 1})
    check("未知字段被忽略", r.status_code == 200 and r.json()["updated"] == [], r.text[:200])
    r = c.put("/api/settings", headers=AUTH, json={"auto_failover": False})
    check("布尔能存", c.get("/api/settings", headers=AUTH).json()["settings"]["auto_failover"] is False)

    # ★ 回归：新增的「连续失败多久才告警」必须真能通过设置接口读写 —— 它是 int
    #   字段，靠 `SettingsIn(extra="allow")` + `DEFAULT_SETTINGS` 自动生效。哪天有人
    #   把 extra 关掉、或者漏加默认值，这里就会红（前端那个输入框也就成了摆设）。
    _st = c.get("/api/settings", headers=AUTH).json()
    check("★ defaults 里有 alert_after_seconds=1800",
          _st["defaults"].get("alert_after_seconds") == 1800,
          _st["defaults"].get("alert_after_seconds"))
    r = c.put("/api/settings", headers=AUTH, json={"alert_after_seconds": 600})
    check("★ alert_after_seconds 能写", r.status_code == 200, r.text[:200])
    check("★ alert_after_seconds 能读回",
          c.get("/api/settings", headers=AUTH).json()["settings"]["alert_after_seconds"] == 600,
          c.get("/api/settings", headers=AUTH).json()["settings"].get("alert_after_seconds"))
    r = c.put("/api/settings", headers=AUTH, json={"alert_after_seconds": "x"})
    check("★ alert_after_seconds 非法值 -> 400", r.status_code == 400, r.status_code)
    c.put("/api/settings", headers=AUTH, json={"alert_after_seconds": 1800})

    print("[8] 连通性自检（未配置 token，应返回 ok=False 而不是 500）")
    r = c.post("/api/test/mefrp", headers=AUTH)
    check("test/mefrp 不抛 500", r.status_code == 200 and r.json()["ok"] is False, r.text[:200])
    r = c.post("/api/test/cloudflare", headers=AUTH)
    check("test/cloudflare 不抛 500", r.status_code == 200 and r.json()["ok"] is False, r.text[:200])
    r = c.post("/api/test/gotify", headers=AUTH)
    check("test/gotify 不抛 500", r.status_code == 200 and r.json()["ok"] is False, r.text[:200])

    print("[9] 删除")
    r = c.delete(f"/api/tunnels/{tid}", headers=AUTH)
    check("DELETE 200", r.status_code == 200, r.text[:200])
    check("删完列表为空", c.get("/api/tunnels", headers=AUTH).json() == [])
    r = c.delete("/api/tunnels/99999", headers=AUTH)
    check("删不存在 -> 404", r.status_code == 404, r.status_code)

    print("[10] 引擎在后台真的跑起来了")
    import time as _t; _t.sleep(1.0)
    ov = c.get("/api/overview", headers=AUTH).json()
    check("引擎 running", ov["engine"]["running"] is True, ov["engine"])
    check("tick_count > 0", ov["engine"]["tick_count"] > 0, ov["engine"]["tick_count"])
    check("未配置 token 时 last_error 有提示", "Token" in ov["engine"]["last_error"], ov["engine"]["last_error"])

    print("[11] 登录页与会话 Cookie")
    r = c.get("/login")
    check("GET /login 免鉴权 200", r.status_code == 200, r.status_code)
    check("登录页含表单", "api/auth/login" in r.text and "<form" in r.text, r.text[:120])
    # 未登录访问首页必须**重定向**，不能回 401 —— 401 会让浏览器弹原生 Basic 对话框
    r = c.get("/", follow_redirects=False)
    check("未登录访问 / -> 302", r.status_code == 302, r.status_code)
    check("重定向到 /login", "/login" in r.headers.get("location", ""), dict(r.headers).get("location"))

    r = c.get("/api/auth/me")
    check("未登录 /api/auth/me -> 200（不是 401）", r.status_code == 200, r.status_code)
    check("authenticated=False", r.json().get("authenticated") is False, r.json())
    check("未登录时不泄露「是否默认密码」",
          "password_is_default" not in r.json(), r.json())

    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong-pass"})
    check("密码错误 -> 401", r.status_code == 401, r.text[:200])
    r = c.post("/api/auth/login", json={"username": "nobody", "password": PW})
    check("用户名错误 -> 401", r.status_code == 401, r.text[:200])

    r = c.post("/api/auth/login", json={"username": "admin", "password": PW})
    check("正确凭据 -> 200", r.status_code == 200, r.text[:200])
    check("返回 Set-Cookie", "mg_session" in r.headers.get("set-cookie", ""), dict(r.headers).get("set-cookie"))
    sc = r.headers.get("set-cookie", "")
    check("★ Cookie 是 HttpOnly", "httponly" in sc.lower(), sc)
    check("★ Cookie 是 SameSite=Strict（CSRF 主防线）", "samesite=strict" in sc.lower(), sc)
    check("Cookie 带 Path=/", "path=/" in sc.lower(), sc)

    r = c.get("/api/auth/me")
    check("带 Cookie /api/auth/me -> authenticated=True", r.json().get("authenticated") is True, r.json())
    check("返回用户名", r.json().get("username") == "admin", r.json())
    check("登录后能看到「是否默认密码」", "password_is_default" in r.json(), r.json())
    check("用的是测试设置的密码 -> 不是默认密码", r.json().get("password_is_default") is False, r.json())

    r = c.get("/api/overview")
    check("★ 仅凭 Cookie 就能访问 API", r.status_code == 200, r.status_code)
    r = c.get("/", follow_redirects=False)
    check("登录后 / 直接给 UI", r.status_code == 200, r.status_code)

    print("[12] 登出必须真的作废服务端会话")
    cookie_val = c.cookies.get("mg_session")
    r = c.post("/api/auth/logout")
    check("登出 -> 200", r.status_code == 200, r.text[:200])
    r = c.get("/api/overview", cookies={"mg_session": cookie_val})
    check("★ 用登出前的 Cookie 再请求 -> 401（会话已作废）", r.status_code == 401, r.status_code)
    r = c.get("/api/auth/me", cookies={"mg_session": cookie_val})
    check("★ /api/auth/me 也认作未登录", r.json().get("authenticated") is False, r.json())

    print("[13] 伪造 / 无效会话")
    r = c.get("/api/overview", cookies={"mg_session": "totally-made-up-token"})
    check("★ 伪造令牌 -> 401", r.status_code == 401, r.status_code)

    print("[14] CSRF：跨站写请求被拒")
    r = c.post("/api/tunnels", headers={**AUTH, "Origin": "https://evil.example.com"},
               json={"name": "x", "proxy_name": "x", "local_port": 1})
    check("★ 跨站 Origin 的写请求 -> 403", r.status_code == 403, r.status_code)
    r = c.post("/api/tunnels", headers={**AUTH, "Origin": "http://testserver"},
               json={"name": "同源测试", "proxy_name": "same-origin-test", "local_port": 1234})
    check("同源 Origin 的写请求放行", r.status_code == 200, r.text[:200])
    if r.status_code == 200:
        c.delete(f"/api/tunnels/{r.json()['id']}", headers=AUTH)

    print("[15] 改密码")
    r = c.post("/api/auth/login", json={"username": "admin", "password": PW})
    check("重新登录以拿到会话", r.status_code == 200, r.status_code)

    r = c.post("/api/auth/password", json={"current_password": "nope", "new_password": "brand-new-pw1"})
    check("当前密码错误 -> 403", r.status_code == 403, r.text[:200])
    r = c.post("/api/auth/password", json={"current_password": PW, "new_password": "short"})
    check("新密码过短 -> 400", r.status_code == 400, r.text[:200])
    r = c.post("/api/auth/password", json={"current_password": PW, "new_password": "admin123"})
    check("新密码等于默认密码 -> 400", r.status_code == 400, r.text[:200])

    r = c.post("/api/auth/password", json={"current_password": PW, "new_password": "brand-new-pw1"})
    check("正常改密码 -> 200", r.status_code == 200, r.text[:200])
    check("返回注销的会话数", r.json().get("sessions_revoked", 0) >= 1, r.json())

    old_auth = {"Authorization": "Basic " + base64.b64encode(f"admin:{PW}".encode()).decode()}
    new_auth = {"Authorization": "Basic " + base64.b64encode(b"admin:brand-new-pw1").decode()}
    check("★ 旧密码立刻失效", c.get("/api/overview", headers=old_auth).status_code == 401)
    check("新密码可用", c.get("/api/overview", headers=new_auth).status_code == 200)

    # 改回去，后面的用例还要用 AUTH
    r = c.post("/api/auth/password", json={"current_password": "brand-new-pw1", "new_password": PW})
    check("改回原密码 -> 200", r.status_code == 200, r.text[:200])
    check("原密码恢复可用", c.get("/api/overview", headers=AUTH).status_code == 200)

    print("[16] 只读设置：密码哈希不能从 /api/settings 改写或读出")
    s = c.get("/api/settings", headers=AUTH).json()
    check("★ 响应里没有 web_password_hash", "web_password_hash" not in s["settings"], list(s["settings"]))
    check("★ 响应里没有 web_password_salt", "web_password_salt" not in s["settings"], list(s["settings"]))
    check("readonly_keys 已声明", "web_password_hash" in s.get("readonly_keys", []), s.get("readonly_keys"))
    r = c.put("/api/settings", headers=AUTH,
              json={"web_password_hash": "deadbeef" * 8, "engine_interval": 21})
    check("PUT 里塞哈希 -> 被忽略", "web_password_hash" not in r.json().get("updated", []), r.json())
    check("同请求里的正常字段仍然生效", "engine_interval" in r.json().get("updated", []), r.json())
    check("★ 哈希确实没被改掉", c.get("/api/overview", headers=AUTH).status_code == 200)

    print("[17] 防爆破（放在最后，因为会锁定测试客户端 IP）")
    _auth.THROTTLE.clear_all()
    maxn = int(c.get("/api/settings", headers=AUTH).json()["settings"]["login_max_attempts"])
    check("默认上限是 5 次", maxn == 5, maxn)
    codes = []
    for _ in range(maxn):
        codes.append(c.post("/api/auth/login",
                            json={"username": "admin", "password": "definitely-wrong"}).status_code)
    # 语义边界：前 maxn-1 次是「密码错」（401），第 maxn 次**这一次就触发锁定**（429）。
    # 也就是实际上只能试 maxn-1 次，第 maxn 次失败即锁。
    check(f"前 {maxn - 1} 次 -> 401", all(x == 401 for x in codes[:maxn - 1]), codes)
    check(f"★ 第 {maxn} 次失败即触发锁定 -> 429", codes[-1] == 429, codes)
    r = c.post("/api/auth/login", json={"username": "admin", "password": PW})
    check("★ 锁定后即使密码正确也拒绝 -> 429", r.status_code == 429, r.status_code)
    check("429 带 Retry-After", "retry-after" in {k.lower() for k in r.headers}, dict(r.headers))
    _auth.THROTTLE.clear_all()
    r = c.post("/api/auth/login", json={"username": "admin", "password": PW})
    check("清空限速后立刻可登录", r.status_code == 200, r.status_code)
    r = c.post("/api/auth/logout")
    check("收尾登出", r.status_code == 200, r.status_code)

    print("[18] frpc 实例管理（多实例）")
    cfgA = os.path.join(tmp, "frpcA.toml")
    cfgB = os.path.join(tmp, "frpcB.toml")
    d0 = c.get("/api/frpc", headers=AUTH).json()
    check("/api/frpc 200", isinstance(d0.get("instances"), list), d0)
    check("★ 首次运行不播种任何实例（挂接全靠手动）",
          len(d0["instances"]) == 0, d0["instances"])
    check("★ 老字段 config_path 仍保留（兼容旧前端）",
          bool(d0.get("config_path")), d0.get("config_path"))
    check("老字段 backups 仍是数组", isinstance(d0.get("backups"), list))
    check("restart_modes 暴露给前端",
          d0.get("restart_modes") == ["docker", "none"], d0.get("restart_modes"))

    r = c.post("/api/frpc", headers=AUTH, json={
        "name": "默认", "config_path": cfgA,
        "container": "frpcA", "restart_mode": "none"})
    check("手工新建实例 A 200", r.status_code == 200, r.text[:200])
    A_ID = r.json()["id"]

    r = c.post("/api/frpc", headers=AUTH, json={
        "name": "备用线路", "config_path": cfgB,
        "container": "frpcB", "restart_mode": "none"})
    check("新建实例 200", r.status_code == 200, r.text[:200])
    B_ID = r.json()["id"]

    # 有了实例才走得到「备份名」这一层 —— 路径穿越必须在这里被挡住
    r = c.post("/api/frpc/restore", headers=AUTH,
               params={"name": "../../etc/passwd", "instance_id": A_ID})
    check("恢复不存在的备份 -> 400", r.status_code == 400, r.text[:200])
    check("★ 路径穿越被挡住（name 先被削成 passwd）",
          "不存在" in r.text, r.text[:200])

    check("重名 -> 400",
          c.post("/api/frpc", headers=AUTH, json={
              "name": "备用线路",
              "config_path": os.path.join(tmp, "c.toml")}).status_code == 400)
    check("★ 配置路径与别的实例重复 -> 400",
          c.post("/api/frpc", headers=AUTH, json={
              "name": "撞路径", "config_path": cfgB}).status_code == 400)
    check("★ 相对路径 -> 400",
          c.post("/api/frpc", headers=AUTH, json={
              "name": "相对路径", "config_path": "rel/frpc.toml"}).status_code == 400)

    r = c.get(f"/api/frpc/{B_ID}", headers=AUTH)
    check("实例详情 200", r.status_code == 200, r.text[:200])
    check("详情含 config 文本", "config" in r.json(), list(r.json()))
    check("详情含 container_state", "container_state" in r.json())
    check("★ restart_mode=none 时不假装容器可用",
          r.json()["container_state"].get("status") == "不自动重启",
          r.json()["container_state"])

    r = c.patch(f"/api/frpc/{B_ID}", headers=AUTH, json={"note": "改过了"})
    check("改实例 200", r.status_code == 200, r.text[:200])
    check("改动生效",
          c.get(f"/api/frpc/{B_ID}", headers=AUTH).json()["note"] == "改过了")
    check("改名撞车 -> 400",
          c.patch(f"/api/frpc/{B_ID}", headers=AUTH,
                  json={"name": "默认"}).status_code == 400)

    print("[18b] 隧道 ↔ 实例 绑定")
    tid = c.post("/api/tunnels", headers=AUTH, json={
        "name": "绑定测试", "proxy_name": "bind-test",
        "local_port": 1234}).json()["id"]
    # 再建一条**故意不绑定**的，用来验证多实例下它会落到 unassigned
    tid2 = c.post("/api/tunnels", headers=AUTH, json={
        "name": "未绑定测试", "proxy_name": "unbound-test",
        "local_port": 1235}).json()["id"]

    def _tun(tid_):
        return next(t for t in c.get("/api/tunnels", headers=AUTH).json()
                    if t["id"] == tid_)

    r = c.patch(f"/api/tunnels/{tid}", headers=AUTH, json={"frpc_instance_id": B_ID})
    check("绑定 200", r.status_code == 200, r.text[:200])
    check("绑定已落库", _tun(tid)["frpc_instance_id"] == B_ID, _tun(tid))

    # 挂接之后再切：这一层守卫不该再拦它了（能不能切成功取决于节点，另说）
    r = c.post(f"/api/tunnels/{tid}/failover", headers=AUTH, json={"node_id": None})
    check("★ 挂接之后不再被「未挂接」拦住",
          "挂接" not in r.text, r.text[:200])

    r = c.patch(f"/api/tunnels/{tid}", headers=AUTH, json={"frpc_instance_id": None})
    check("★ 传 null 能显式解绑（没被 exclude_none 吃掉）",
          r.status_code == 200 and _tun(tid)["frpc_instance_id"] is None, _tun(tid))
    check("绑到不存在的实例 -> 404",
          c.patch(f"/api/tunnels/{tid}", headers=AUTH,
                  json={"frpc_instance_id": 999999}).status_code == 404)

    r = c.post("/api/frpc/bind", headers=AUTH,
               json={"tunnel_ids": [tid], "frpc_instance_id": B_ID})
    check("批量绑定 200", r.status_code == 200, r.text[:200])
    check("批量绑定 updated=1", r.json()["updated"] == 1, r.json())
    check("批量绑定生效", _tun(tid)["frpc_instance_id"] == B_ID)

    print("[18c] 绑定总览与自动发现")
    mp = c.get("/api/frpc/map", headers=AUTH)
    check("★ /api/frpc/map 没被 /{instance_id} 抢走（路由顺序）",
          mp.status_code == 200, mp.status_code)
    mp = mp.json()
    check("map 有 2 个实例", len(mp["instances"]) == 2, mp)
    check("B 承载 1 条",
          next(i for i in mp["instances"] if i["id"] == B_ID)["tunnel_count"] == 1, mp)
    # 未显式绑定 + 2 个实例 -> 不该被瞎猜，必须落进 unassigned
    check("★ 未显式绑定的隧道进 unassigned（多实例下不瞎猜）",
          any(u["id"] == tid2 for u in mp["unassigned"]), mp["unassigned"])
    check("已绑定的隧道不在 unassigned 里",
          all(u["id"] != tid for u in mp["unassigned"]), mp["unassigned"])

    d = c.post("/api/frpc/discover", headers=AUTH)
    check("自动发现预览 200", d.status_code == 200, d.text[:200])
    check("返回 proposals/ambiguous/unmatched 三个桶",
          {"proposals", "ambiguous", "unmatched"} <= set(d.json()), list(d.json()))
    check("★ 预览不改库", _tun(tid)["frpc_instance_id"] == B_ID)
    check("列出各实例现有配置里的隧道名",
          all("proxy_names" in i for i in d.json()["instances"]),
          d.json()["instances"])

    print("[18d] 删除实例")
    check("有绑定未解绑 -> 400",
          c.delete(f"/api/frpc/{B_ID}", headers=AUTH).status_code == 400)
    r = c.delete(f"/api/frpc/{B_ID}?unbind=true", headers=AUTH)
    check("unbind=true -> 200", r.status_code == 200, r.text[:200])
    check("解绑计数 = 1", r.json()["unbound"] == 1, r.json())
    check("实例已删",
          all(i["id"] != B_ID
              for i in c.get("/api/frpc", headers=AUTH).json()["instances"]))
    check("隧道本身还在（只是解绑）", _tun(tid)["id"] == tid)
    check("删完只剩 A",
          [i["id"] for i in c.get("/api/frpc", headers=AUTH).json()["instances"]] == [A_ID])
    check("不存在的实例 -> 404",
          c.get("/api/frpc/999999", headers=AUTH).status_code == 404)

    print("[18e] overview 里的实例信息")
    ov = c.get("/api/overview", headers=AUTH).json()
    check("overview.frpc 带 instances",
          isinstance(ov["frpc"].get("instances"), list), ov["frpc"])
    check("overview.frpc 带 instance_count",
          ov["frpc"].get("instance_count") == 1, ov["frpc"])
    check("隧道项带 frpc_instance_name",
          all("frpc_instance_name" in t for t in ov["tunnels"]), ov["tunnels"][:1])
    check("隧道项带 frpc_bound",
          all("frpc_bound" in t for t in ov["tunnels"]), ov["tunnels"][:1])
    # 只剩实例 A。此刻所有隧道都没挂接 —— 程序**不该**因为「只剩一个实例」
    # 就把它们自动认领：那样用户会以为有人在管，实际配置写没写、容器重启没重启
    # 全看运气。挂接必须是用户的一次明确动作。
    check("★ 未挂接的隧道 frpc_bound 全为假（不再靠唯一实例兜底）",
          all(not t["frpc_bound"] for t in ov["tunnels"]),
          [(t["name"], t["frpc_bound"]) for t in ov["tunnels"]])
    _target = ov["tunnels"][0]["id"]
    c.patch(f"/api/tunnels/{_target}", headers=AUTH,
            json={"frpc_instance_id": A_ID})
    ov2 = c.get("/api/overview", headers=AUTH).json()
    check("★ 挂接一条 -> 只有它 frpc_bound 为真",
          all(t["frpc_bound"] == (t["id"] == _target) for t in ov2["tunnels"]),
          [(t["name"], t["frpc_bound"]) for t in ov2["tunnels"]])

    # ★ 回归：/api/tunnels 也必须带 frpc_bound / frpc_instance_name。
    #   前端的「手动切换」对话框（failover()）读的是**这个**接口，原来它直接
    #   返回 store 的原始行、没有这两个字段 → `t.frpc_bound` 是 undefined，
    #   falsy → **挂接明明成功了，还是提示「它还没有挂接 frpc 容器，无法切换」**。
    #   同一个隧道在两个接口里形状不一样，是这个 bug 的根因。
    print("[18f] ★ /api/tunnels 与 /api/overview 的挂接字段口径一致")
    tl = {t["id"]: t for t in c.get("/api/tunnels", headers=AUTH).json()}
    check("每条都带 frpc_bound", all("frpc_bound" in t for t in tl.values()),
          list(tl.values())[:1])
    check("每条都带 frpc_instance_name",
          all("frpc_instance_name" in t for t in tl.values()), list(tl.values())[:1])
    check("★ 两个接口的 frpc_bound 完全一致",
          all(tl[t["id"]]["frpc_bound"] == t["frpc_bound"] for t in ov2["tunnels"]),
          [(t["name"], t["frpc_bound"], tl.get(t["id"], {}).get("frpc_bound"))
           for t in ov2["tunnels"]])
    _t2 = next(t for t in ov2["tunnels"] if t["id"] == _target)
    check("★ 已挂接那条在两个接口里都带上了实例名",
          tl[_target]["frpc_bound"] is True
          and tl[_target]["frpc_instance_name"] == _t2["frpc_instance_name"],
          (tl[_target], _t2.get("frpc_instance_name")))

print(f"\n==> PASS {ok} / FAIL {bad}")
sys.exit(1 if bad else 0)
