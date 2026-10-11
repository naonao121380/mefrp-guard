# mefrp-guard · 技术留档

> ⚙️ **这是技术文档**，面向要读懂 / 修改这个项目的人：内部实现、mefrp API 的坑、设计取舍、
> 测试与排错细节。
>
> **只是想装来用？** → 看 **[README.md](README.md)**（简洁版：页面功能 / 使用逻辑 / 部署 / 参数）。

---

mefrp 隧道自愈守护。跑在 frpc 同一台机器上（`docker.sock` 是本地的，跨主机控制不了），
用官方 API 盯着隧道状态，节点挂了就自动换节点、改 frpc 配置、重启容器、同步 Cloudflare DNS，
并把过程推到 Gotify。

## 它解决什么问题

mefrp 的节点会不定期变更（下线、维护、被禁用）。手工处理一次故障要：

1. 上 mefrp 网页看哪个节点挂了、挑一个还活着且带宽够的
2. 手动在那边新建隧道，记下新的公网端口
3. 改本机 `frpc.toml` 的 `serverAddr` / `serverPort` / `remotePort`
4. 重启 frpc 容器
5. 去 Cloudflare 改 DNS 解析记录
6. 如果公网端口变了，还要回头改所有引用这个端口的反代规则

这六步现在由程序自动做完，只在**端口发生变化**时提醒你去改下游。

## 工作原理

### 一轮循环（默认 20 秒）

```
拉全量状态 → 逐隧道对账 → 没判成故障就顺手纠正 DNS → 判成故障就累计失败次数 → 够了就故障转移
```

> 「没判成故障」包括**探测不适用**（udp）这种情况 —— 探不了 ≠ 地址不对，
> DNS 照常同步。详见下文「DNS 同步」。
>
> DNS 那一步是**幂等且便宜**的：内容已经对得上就什么都不写、也不产生事件；真要去问
> Cloudflare 时复用连接池（不再每个请求重新握手），传输层失败还会退避重试 2 次，
> 抖一下只记 `warn`，不会把日志染红。

### 三层健康判定

单看 mefrp 的 `isOnline` 是不够的 —— **节点列表有 5 分钟 Redis 缓存**，状态会滞后。
所以判定分三层，任何一层不过就算异常：

| 层 | 判据 | 说明 |
|---|---|---|
| 1 · proxy | 隧道存在 / 未被封禁 / 未被禁用 / `isOnline` | 抓「隧道被删了」「frpc 没连上」 |
| 2 · node | 节点仍在列表 / 未禁用 / 在线 / status 接口一致 | 抓「节点下线了」 |
| 3 · probe | 真的 TCP connect 一次 `节点地址:公网端口` | **唯一不会骗人的判据** |

第三层是必要的：前两层都依赖 mefrp 自己的状态上报，而缓存和上报都可能滞后。
只有实际连一次，才知道隧道到底通不通。

第三层能不能做，取决于**拿不拿得到节点公网地址**。拿不到时这一层直接判不健康 ——
因为「不知道通不通」和「通了」是两回事，不能默认放行。

### ⚠️ 探测模式（`probe_mode`）—— 别拿 TCP 去探 UDP

`probe_mode` 有三个取值：

| 值 | 行为 |
|---|---|
| `auto`（默认） | TCP / HTTP / HTTPS 隧道做 TCP 探测；**UDP 隧道跳过第三层** |
| `tcp` | 所有隧道都做 TCP 探测（逃生口） |
| `none` | 完全关闭第三层，只用 L1 + L2 判定 |

**为什么 UDP 隧道默认跳过**：mefrp 的 UDP 隧道在节点上监听的是 UDP 端口，
**没有 TCP 监听**。对它做 TCP 三次握手必然失败，于是这条完全健康的隧道会被
永久判成「异常」：

```
fail_streak 一路涨 → 到阈值 → 触发自动切换 → 搬到新节点
  → 新节点上依然是 UDP，依然探不通 → 再切换 …… 无限循环
```

UDP 没有连接语义，「可达」只能靠应用层握手来证明（OpenVPN 的控制通道、
WireGuard 的握手包）。那属于业务侧的事，不是这个工具该做的，
所以这里**诚实地跳过**并在 UI 上标注「不适用」，而不是假装探测失败。

被跳过时 UI 显示为 **「在线 · 不探测」**（中性），不会画成红色「异常」。

### 故障转移流程

```
选新节点 → 逐条「删旧隧道 → 建新隧道」（优先沿用原端口）
        → 重建它所属 frpc 容器的配置 → 重启那个容器
        → 等隧道上线 → 端到端 TCP 验证 → 更新 DNS → 推 Gotify
```

> 模型是「一条隧道 : 一个 frpc 容器」，正常只有一条。万一你把多条挂到了同一个容器上，
> 它们会作为**一组**一起搬 —— 原因见下面两条。

每一步都会写进事件日志。任一步失败都会明确告诉你失败在哪，不会静默吞掉。

⚠️ **没挂接容器的隧道不会切换**：换节点要改本地配置、重启容器，没有归属就无从下手；
硬搬 mefrp 上的 proxy 只会变成「proxy 换了节点、本地没人接」，比不切换更糟。
接口会返回 400 并说明原因。

⚠️ **为什么必须先删旧、再建新**：mefrp 上 `proxyName` 在账号内唯一，**同名隧道不能共存**，
先建会直接撞名失败。代价是这条隧道在中间那几步会**短暂完全不可用** —— 它本来就已经是坏的，
所以可以接受。

⚠️ **组内任一条隧道创建失败 → 整体回滚**：把已经搬走的那些**建回原节点**，并删掉新节点上的 proxy。
「先删后建」之后，只删新建的等于一条都不剩，所以回滚必须真的重建。半搬半不搬会让同一个容器的
隧道分散在两个节点上，配置文件根本没法合并 —— 那比「这次切换失败」更糟，会把一个本来还能跑
的状态变成彻底不能跑。若**回滚本身也没完全成功**，会明确告警并要求人工检查，绝不假装没事。

### 防抖

| 参数 | 默认 | 作用 |
|---|---|---|
| `fail_threshold` | 3 | 连续失败 3 次才判故障，避免网络抖动误切 |
| `failover_cooldown` | 300s | 切换后冷却，避免在多个坏节点间反复横跳 |
| `node_cooldown` | 1800s | 刚被切走的节点一段时间内不再选它 |
| `probe_interval` | 60s | 单隧道端到端探测的最小间隔（不是每轮都探） |
| `probe_mode` | `auto` | 端到端探测模式，见上文「探测模式」 |

### 节点择优规则

依次过滤，再排序：

1. **用户组权限** —— `allowGroup` 不含你的组就跳过（非 VIP 会自动排除 VIP 专属节点）
2. **隧道类型** —— `allowType` 不含 `tcp` 就跳过
3. **区域** —— 默认只留 `cn`
4. **带宽下限** —— 默认 ≥ 25Mbps
5. **负载上限** —— 默认 ≤ 90%
6. **排除名单与冷却期**

排序键：`节点偏好顺位 > 手工优先级 > 带宽大 > 负载低`。

#### 节点偏好（默认「北京」）

「设置 → 节点偏好」是一个**有序列表**，用**包含匹配**去比对节点的
**名称 + 描述 + 区域**，命中第几个关键词就排在第几档：

- 列表里填 `北京`、`上海` → 所有名字含「北京」的节点排在最前，含「上海」的紧随其后。
- **顺序就是优先级**，所以界面上可以上移 / 下移（mefrp 的节点名形如「北京BGP-1」，
  填「北京」两个字就够，不用写全名）。
- 一个关键词都没命中的节点排在**最后**，但**仍然会被选中** —— 偏好是**排序**，
  不是筛选。真想禁掉某类节点用「节点」页的「排除」按钮。
- 列表清空 = 所有节点同权，排序退回带宽 / 负载。
- 设置页里有**即时预览**：直接列出每个关键词各自命中哪些节点、有几个谁都没命中。
  预览走的是后端同一个匹配函数，不会和真正择优的结果跑偏。

> 和「区域（`allow_regions`）」的区别：区域是**筛选**（不符合的直接出局，默认只留 `cn`），
> 节点偏好是**排序**（不符合的只是排后面）。一个是门槛，一个是倾向。

用户组是**运行时自动探测**的（`/auth/user/info` 的 `group` 字段），不需要手工填。

注意这里有两个值，用途不同：

| 字段 | 例子 | 用途 |
|---|---|---|
| `group` | `default` | **机器名**，用来匹配节点的 `allowGroup` |
| `friendlyGroup` | `正式用户` | 展示名，只在 UI 上给人看 |

程序内部一律用 `group` 做权限判断，界面上显示 `friendlyGroup`。

## DNS 同步

一条隧道**填了 DNS 记录名**（「编辑隧道」里的那一栏）之后，程序会在
**导入时 / 每次端到端探测 / 每轮巡检**这三处，把那条记录纠到隧道的当前地址上。

判据只有三件事，**跟隧道协议无关，也跟探测通不通无关**：

1. `dns_record_name` 非空 —— 留空 = 这条隧道的 DNS 你自己管，程序一次都不碰；
2. `auto_dns_sync` 开着，或者调用方传了 `force=True`（用户明确点的动作）；
3. 拿得到地址 —— mefrp 隧道从 `proxy_list` 的 `nodes` 子数组反推，外部节点直接用自己的
   `serverAddr`（不查任何 API，所以外部节点有没有 API 都无所谓）。

地址是 IP 就写 `A`，是域名就写 `CNAME`。zone 按**最长后缀匹配**自动定位
（`resolve_zone`），结果落库，之后不再重复问。记录内容已经对得上就**什么都不写**
（不产生事件、不产生噪音）—— 所以「每轮巡检都调一次」是安全的。

### ⚠️ DNS 记录名必须**全局**唯一（隧道名不是）

这条规则和隧道名正好相反，别搞混：

| | 唯一性范围 | 为什么 |
|---|---|---|
| **隧道名**（`proxy_name`） | **一台 frps 内** | mefrp 的一台 = 整个账号；外部节点的一台 = 那个 `manual_node`。各运营商命名空间互不相干，**跨运营商重名完全合法**。查重一律 `find_tunnel_by_proxy(name, manual_node_id=...)`。 |
| **DNS 记录名** | **全局** | 它不是谁的命名空间，而是 Cloudflare 上一个实实在在的资源。 |

两条 enabled 的隧道填同一个记录名会这样：两边都在健康路径上**每 20 秒**同步一次，
一个把记录改成节点 A 的地址、另一个改成节点 B 的，**互相覆盖、无限抖动**；而事件
日志里只有一行行「DNS 已更新」，完全看不出是在打架。

所以这里是**硬拒绝**（`409` + `code: dns_name_taken` + 占用者的 id/名字/hint），
**没有 overwrite 开关** —— 它不像「同一台 frps 上同名」那种还能说谁先谁后，
这种情况没有任何合理的语义。比对时大小写和首尾空格都归一。

三处写入路径都查：`POST /api/tunnels`、`PATCH /api/tunnels/{id}`（带 `exclude_id=自己`，
否则改别的字段时把记录名原样带上会把自己判成冲突）、`POST /api/orphans/{id}/adopt`。
**导入外部节点时是例外**：撞名只放弃那一条的记录名，隧道照建，结果放在响应的
`dns_clash` 里单独报（混进 `skipped` 是错的 —— 那些隧道**是纳管了的**）。

### 踩过的坑

用户报过「手动添加的隧道好像没有自动进行 cf dns 解析」。查下来**是代码的问题**，
不是忘了填记录名（当然前提还是那条隧道上填了 —— 没填的话按上面第 1 条，
程序本来就不该碰它）。三条独立的路各自把 DNS 那一步漏掉了，另外还有三个连带问题：

- **★ 「不适用探测」不等于「地址不对」** —— udp 隧道在 `auto` 模式下不做 TCP 探测，
  `_probe_cached` 返回 `None`（三态里的「不适用」）。原来 `_reconcile_manual` 在这个分支
  **直接 `return`**，于是 udp 的外部隧道**永远**同步不了 DNS —— 而 udp 恰恰是外部节点上
  最常见的一类（VPN / 游戏服 / DNS）。现在改成：不涨 `fail_streak`、**不写 `last_error`**
  （写了的话前端会把它画成红色「异常」，而这里只是「探不了」），**但照常调 `_sync_dns`**。
- **★ 探测端点要和巡检对齐** —— `POST /api/tunnels/{id}/probe` 里同款分支也一样漏了。
  两条路行为不一致时，用户点一次按钮反而更懵。现在两边都同步，并把结果放进返回值的
  `dns` 字段，弹窗里当场显示成功 / 失败原因。⚠️ 探测**失败**时不动 DNS —— 地址并没有变，
  改它只会把一条本来对的记录改坏。
- **★ 导入时立刻同步，别等下一轮** —— 导入接口原来**从来不碰 DNS**，全靠引擎巡检
  （最长 20 秒）。用户粘完配置站在页面前什么都不发生，只会以为「没生效」。现在导入
  时 `force=True` 逐条同步（用户刚填的记录名 = 明确指令），失败也当场回话。
- **★ `last_error` 里的历史遗留值要能自愈** —— 老版本把「无法探测：…」写进 `last_error`，
  前端把它画成红色「异常」，升级后那条红字会一直挂着。新代码在「不适用」分支顺手清掉它。
- **★ 没配 CF token 时不能每轮记一条错误事件** —— 那是**静态配置问题**，不是「这条隧道
  此刻解析失败了」。照常往下走的话 `CloudflareAuthError` 会被 `except` 抓住、每轮巡检
  记一条 error —— 20 秒一条 × 每条填了记录名的隧道，很快把事件日志刷满，真正的问题
  反而被淹掉。现在 `_sync_dns` 开头就判掉，**只在 `force`（用户明确点的动作）时才记事件**。
  ⚠️ 测试里的假 CF 也得带上 `token` 属性，否则会以 `AttributeError` 炸而不是「跳过 DNS」。
- **CF 的 httpx 异常必须带上类型名** —— 超时类异常 `str()` 常常是空串，只拼 `{exc}` 的话
  事件日志里只剩一句「请求 Cloudflare 失败：」，完全看不出是超时、连不上还是 TLS 出错。
- **★ 每次请求都新建连接池 = 反复重新握手** —— `_request` 原来是
  `async with httpx.AsyncClient(...)`，**每个请求新建一个**。而 `_sync_dns` 的写路径上要打
  **4 个请求**（自己 `list_records` 一次 + `upsert` 内部又查两次 + `PUT` 一次），也就是
  4 次全新的 DNS 解析 + TCP + TLS 握手，彼此不复用；巡检每 20 秒一轮，握手次数直接把
  「握手中途超时」的概率放大了。现在客户端**懒建并复用一个连接池**（一次握手撑很多轮），
  写路径也降到 2 个请求（把刚查到的 `DnsRecord` 通过 `upsert(existing=...)` 传下去，
  别让它再自查两遍）。⚠️ 复用的代价是**必须有人关它**：`reload_clients()` 换客户端时
  走 `_close_client_soon()`（同步方法没法 await，把 `aclose()` 丢给当前事件循环）。
  另外连接池**不能跨事件循环复用** —— 测试里每个用例一次 `asyncio.run()`（一个新循环），
  所以 `_http()` 会比 `self._loop is not loop`，不同就重建。
- **★ 传输层失败要重试，而且要能分类** —— 原来零重试，网络抖一下整条同步就失败。
  现在只对 `httpx.TransportError`（连不上 / 超时 / 连接被重置 / 代理挂了）退避重试 2 次；
  HTTP 状态错误**不重试**（401/403/5xx 是请求本身的问题，再打十次也一样）。
  重试耗尽后抛的 `CloudflareError` 带 `transient=True`，调用方据此决定记 warn 还是 error。
- **★ 瞬时失败不能一律记 error，而且门槛要按「时间」、不是「次数」** —— 巡检每 20 秒
  一轮，每轮都同步一次 DNS。抖一下失败、下一轮立刻就好，而日志里留下的是**红色
  「更新 DNS 失败」** —— 用户会以为 DNS 功能坏了（他确实这么报过）。一开始的修法是
  「连续 `< DNS_FAIL_ESCALATE` 次只记 warn」—— 但 3 次只有 1 分钟，**照样刷屏**：
  实测三天里 mefrp 报了 122 条 error、Cloudflare 64 条，全是 2~9 分钟的短窗口，
  **没有一条是源站真挂了**（根因是移动宽带的间歇性抖动，源站侧只有 10-09 上午那段
  `响应不是合法 JSON` 是真的）。
  现在按**时间**（`alert_after_seconds`，默认 1800 = 30 分钟）：
  · 刚开始失败 → 只留**一条** warn，中间完全安静（原来 90 轮就是 90 条）
  · 连续满阈值 → 升 `error`；之后每再满一个阈值补一条（断一整天也只有 48 条）
  · 恢复 → 状态清零；**告过警的**才记一条恢复事件，短抖自愈不记（前面那条 warn
    已经留过痕了，再来一条纯属噪音）
  成功一次就清零（**清零很重要**：否则抖动会攒起来，隔几分钟突然升级成 error，
  变成另一种误报）。`force`（用户明确点的动作）和**静态问题**（zone 找不到、token
  没权限这类，重试一万次也不会好）不看阈值，第一次就如实记 `error`。
  阈值刻意**不复用** `fail_threshold` —— 那个管的是「连续探测失败几次才触发切换」，
  捆在一起以后调其中一个必然误伤另一个。
- ★ **mefrp 拉取失败与 DNS 同步失败共用同一套口径** —— 见 `ALERT_AFTER_SECONDS` 与
  `_note_mefrp_fail` / `_note_dns_fail`。两处原来各写各的（一处「每轮一条 error」、
  一处「连续 3 次」），调了一个忘了另一个。现在都是「一条 warn + 满阈值才 error」。

### 相关的巡检坑：mefrp 挂了不该连累外部节点

`tick()` 原来在「没配 mefrp Token」和「拉取 mefrp 失败」两处**直接 `return`** ——
外部节点的隧道压根不走 mefrp API，却跟着一起瞎掉（探测不更新、DNS 不解析），
页面上一点线索都没有。现在这两处改成 `remote_ok = False` 后继续跑，
**但只对账外部节点的隧道**：反过来放行 mefrp 隧道是危险的 —— proxy 列表是陈旧的，
`_evaluate` 会拿旧数据判出假故障、一路涨 `fail_streak`，最后触发一次不该发生的切换。

## 前置条件

1. **每条要管的隧道，都有一个自己的 frpc 容器**。本程序不负责创建它，只负责改它的
   配置文件并重启它。
   - 容器名和配置文件路径**在 Web UI 的「frpc 实例」页登记**，不通过环境变量配
   - 宿主机上存放 frpc 配置的**根目录**要挂进本容器（`.env` 的 `FRPC_PATH` → `/frpc`）
2. **mefrp 账号的访问 Token**
3. 要用 DNS 自动同步的话，**Cloudflare API Token**（权限 `Zone.DNS:Edit`）
4. 要推送的话，**Gotify 地址 + App Token**

### ⚠️ 硬约束：一个 frpc 进程只能连一个节点

> **同一个 frpc 容器承载的所有隧道，必须落在同一个节点上。**

本程序在合并配置时会校验 `serverAddr` / `serverPort` 是否一致，不一致就直接报错、
拒绝写出错配置。

本项目的模型是**一条隧道 : 一个 frpc 容器**，所以每条隧道各自守一个节点、互不牵连 ——
隧道分散在多个节点不需要手工收敛。详见 [frpc 容器与隧道挂接](#frpc-容器与隧道挂接)。

程序**不会自动把隧道认领到某个容器上**，必须手动挂接。

## 部署

所有跟宿主机有关的取值都集中在 `.env` 里，`docker-compose.yml` 本身不用改：

```bash
cp .env.example .env
vim .env                 # 至少填 MEFRP_TOKEN、MG_WEB_PASSWORD、FRPC_PATH
docker build -t mefrp-guard:v1.0.2 .
docker compose up -d
```

> 也可以一步做完：`docker compose up -d --build`，两者等价。
>
> 镜像 tag 固定成 `v1.0.2` 而不是 `latest` —— `latest` 会让「现在跑的是哪一版」
> 变成一个回答不了的问题，回滚时也没有可指的目标。改了代码就 build 成 `v1.0.2`
> 之类的新 tag，`docker compose up -d` 会自动用新镜像重建容器。

起来后访问 `http://<宿主机>:<HOST_PORT>`（默认 8080），会先跳到登录页。

`.env` 里跟部署有关的四项：

| 变量 | 作用 |
|---|---|
| `FRPC_PATH` | 宿主机上**存放所有 frpc 配置的根目录**，挂到容器内 `/frpc` |
| `HOST_PORT` | 宿主机上暴露 Web UI 的端口（容器内固定 8080） |
| `CONTAINER_IP` | 接入外部网络时给本容器的静态 IP（可选） |
| `EXTERNAL_NETWORK_NAME` | 要接入的已存在 Docker 网络名，`docker network ls` 里的那个（可选） |

> ⚠️ `FRPC_PATH` 挂的是**一个公共根目录**，不必给每个 frpc 容器单独挂一行 ——
> 容器内看到的是 `/frpc/<子目录>/frpc.toml`。
>
> ⚠️ `CONTAINER_IP` / `EXTERNAL_NETWORK_NAME` 用不到的话，把 compose 里 `services`
> 下的 `networks:` 和文件末尾的顶层 `networks:` 两段一起删掉即可，走默认 bridge
> 一样能跑。这两项在 compose 里写成 `${VAR:?…}`，没填会直接报错并说明缺哪个，
> 不会静默用错值。

`./data/prod` 一般不用改，它是**唯一需要备份的目录**。

> ⚠️ 它刻意跟 `./data/local` 分开：后者是 `run_local.sh` 的沙箱数据。混在一起的话，
> 本地试跑建出来的那条「指向本机路径的 frpc 实例」会被带进容器 —— 容器里没那个
> 路径，直接不可用。

### 登录与鉴权

**默认凭据 `admin` / `admin123`。** 首次启动时自动播种，登录后页面顶部会一直挂着红色警告，
直到你改掉它。

设计要点：

| 项 | 做法 | 为什么 |
|---|---|---|
| 密码存储 | PBKDF2-HMAC-SHA256，300,000 轮，每实例随机盐 | 不落明文；即使库被拖走也反推不出密码 |
| 会话 | 随机 256 位令牌，**库里只存 SHA-256** | 库泄露也拿不到可用会话 |
| Cookie | `HttpOnly` + `SameSite=Strict` + `Path=/` | JS 读不到（XSS 偷不走）；跨站请求不会带上（CSRF 主防线） |
| `Secure` 标志 | 只在确实走 HTTPS 时才加 | 内网是 HTTP，硬加会导致浏览器直接不存 Cookie → 登录完还是未登录 |
| 比较 | 一律 `hmac.compare_digest` | 普通 `==` 会在首个不同字节提前返回，能被计时攻击逐字节猜 |
| 防爆破 | 按来源 IP 计数，默认连错 5 次锁 5 分钟 | 默认密码是公开的，不限速就能被字典刷出来 |
| CSRF | `SameSite=Strict` + 写操作校验 `Origin` | 第二道防线；不带 `Origin` 的（curl/脚本）不受影响 |
| 改密码 | 必须验当前密码；改完**踢掉该用户所有会话** | 否则旧密码泄露期间建立的会话在改密码后依然有效 |

**登录页 `/login`** 是独立的自包含页面（暗色，与主 UI 同风格），带锁定倒计时。

**两套凭据通道**，按顺序尝试：

1. `Authorization: Basic` —— 给脚本 / curl / 自动化用
   ```bash
   curl -u admin:admin123 http://127.0.0.1:8080/api/overview
   ```
2. 会话 Cookie `mg_session` —— 给浏览器用（登录页换来的）

未登录时：`/api/*` 返回 **401**，页面请求（`/`）返回 **302 → /login**。
**故意不弹浏览器原生 Basic 对话框** —— 那个对话框没法登出，正是引入登录页要摆脱的东西。

`/healthz` 和 `/login` 不需要鉴权（前者给容器健康检查，后者是入口本身）。

**改初始密码 / 找回密码**

```bash
# 想用别的初始密码：首次启动前设环境变量（之后以 UI 里改的为准）
MG_WEB_PASSWORD='your-strong-password' docker compose up -d

# 忘了密码：删掉三行凭据再重启，会用默认 admin/admin123 重新播种
sqlite3 <数据目录>/guard.db "DELETE FROM settings WHERE key LIKE 'web_password%';"
```

### ⚠️ 部署到公网前必做

1. **改掉默认密码**（设置 → 账号安全）
2. 在 Lucky / Cloudflare 上加一层访问控制 —— 这个服务的鉴权是给内网设计的，
   不要只靠它挡公网
3. 如果前面有反代，确认它透传了 `X-Forwarded-For`（否则防爆破会把所有人算作同一个 IP）

### 不装 Docker 先试跑

`run_local.sh` 可以在本机直接起一个实例（不依赖 Docker，不碰真实 frpc 配置）：

```bash
PY=<python> ./run_local.sh          # 默认监听 127.0.0.1:18080
PY=<python> PORT=18080 ./run_local.sh
```

区别与取舍：

- 监听 `127.0.0.1`，只在本地可达
- frpc 配置指向 `data/local/sandbox-frpc/frpc.toml`（沙箱目录），**绝不会碰真实配置**
- 数据目录是 `data/local/`，跟 Docker 部署的 `data/prod/` 分开，互不干扰
- **鉴权默认开启**，首次启动用 `admin` / `admin123`
  （想换初始密码：`MG_WEB_PASSWORD='xxx' ./run_local.sh`）
- 没有 `docker.sock` → 「重启 frpc」「看容器日志」会提示不可用，其余功能正常
- 启动时一条 frpc 实例都不建。要验证完整链路，到「frpc 实例」页新增一个，
  配置路径填脚本打印的那个沙箱路径即可（容器名随便填，只有「重启」会失败）

### 首次配置

0. **登录**（`admin` / `admin123`），然后**立刻到「设置 → 账号安全」改掉密码** ——
   总览页顶部会一直挂着红色警告提醒你
1. 打开「设置」页，填 **mefrp Token** → 点「测试」（会显示节点总数、在线数、你的用户组）
2. 填 **Cloudflare Token** → 点「测试」（会列出可管理的 zone）
3. 填 **Gotify 地址和 Token** → 点「发条测试消息」
4. 到「节点」页点「重新拉取」，确认能看到节点列表，并把不想要的节点「排除」
5. 到「隧道」页，把 mefrp 上已有的隧道**纳管**进来；或者「新增隧道」建新的
6. 到「frpc 实例」页，**为每条隧道登记它自己的 frpc 容器**（配置路径 + 容器名）
7. 回到「隧道」页，逐条点 **「挂接 frpc」** 把它挂到对应的容器上

> 第 6、7 步不能省 —— 程序**不会**自动认领隧道。没挂接的隧道不会被写进任何配置，
> 总览页会一直提示「隧道未挂接 frpc」。详见 [frpc 容器与隧道挂接](#frpc-容器与隧道挂接)。
>
> 如果这些隧道**本来就在某个 frpc 配置文件里跑着**，第 6、7 步可以合并：
> 先把那些容器登记好，再点「自动发现绑定」按现有配置一次性把关系录进来。

### 纳管已有隧道

「隧道」页下方会列出 mefrp 上**还没被纳管**的隧道，点「纳管」即可。
本地地址、端口、当前节点都从 mefrp 实读，不用手填。

纳管后要补三项（前两项可选，第三项必做）：

- **挂接的 frpc 容器** —— ⚠️ **必填**。没挂接的话这条隧道不会被写进任何 frpc 配置，
  也就没人帮它改配置、重启容器；故障转移也会被直接拒绝
- **关联的 Cloudflare 记录名** —— 填了才会自动同步 DNS，留空则不管理 DNS
- **下游备忘** —— 端口变了要改什么，会原样出现在告警里

## frpc 容器与隧道挂接

### 模型：一条隧道 : 一个 frpc 容器

一个 frpc 进程只能连**一个** `serverAddr`，也就是只能连一个 mefrp 节点。所以：

> **同一个 frpc 容器上的所有隧道，必然在同一个节点上。**

本项目的做法是**一条隧道配一个 frpc 容器**。这样每条隧道各自守一个节点、互不牵连 ——
一条隧道要换节点，不会拖着别人一起换。

（程序内部仍然按「一组」处理切换，那是为了万一你把两条挂到同一个容器上时不出错，
见下面「切换时会发生什么」。正常用法下这一组永远只有一条。）

### ⚠️ 程序不会自动认领隧道

**首次启动不建任何 frpc 容器，也不会把隧道自动挂到某个容器上。** 理由：

- 自动认领会让「没挂接的隧道」看起来像挂接好了 —— 你以为程序在管它，实际配置写没写、
  容器重启没重启全看运气。
- 它还不稳定：一旦你再加一个容器，这些隧道会**突然集体失去归属**，行为在那一刻突变。

所以挂接必须是**你的一次明确动作**。没挂接的隧道不会被写进任何 frpc 配置，
总览页 / 「frpc 实例」页 / 事件日志三处都会提示。

### ⚠️ 挂接状态是**算出来**的 —— 别让前端读错接口

`frpc_bound` / `frpc_instance_name` **不是数据库里的列**，是
`engine.frpc_for_tunnel()` 现算的。它们原来只在 `/api/overview` 里算，而
`/api/tunnels` 直接 `return store.list_tunnels(...)` 的原始行 ——
**同一个隧道在两个接口里形状不一样**。

代价是一次真实的 bug：前端的「手动切换」对话框（`failover()`）读的是
`/api/tunnels`，`t.frpc_bound` 拿到 `undefined`，而 `undefined` 是假值，
于是**挂接明明成功了，还是提示「它还没有挂接 frpc 容器，无法切换」**。
隧道卡片那边另有 `t.frpc_bound === undefined ? '—'` 兜底，反而显示正常 ——
所以现象看着像「挂接没生效」，实际上数据一直是对的。

现在两个接口都带上这两个字段（`/api/tunnels` 里实例表只查一次，
`engine.frpc_for_tunnel(tunnel, instances=…)` 复用，不在循环里逐条扫）。

> **规则：给 `/api/overview` 加计算字段时，顺手问一句「`/api/tunnels` 要不要也带上」。**
> 同一个实体有两个形状，早晚会有人读错那个缺字段的。

### 第一步：登记 frpc 容器

「frpc 实例」页 → 「新增实例」。每个容器要填：

| 字段 | 说明 |
|---|---|
| 实例名 | 自己认得出就行，如「NAS 面板」「Git 面板」 |
| 配置文件绝对路径 | 这个容器的 `frpc.toml`。**必须是绝对路径**，且不能和别的容器重复 |
| 容器名 | 要重启的 Docker 容器。留空 = 只写文件不重启 |
| 重启方式 | `docker` = 配置变化后重启容器；`none` = 只写文件，由你自己重启 |

两个容器**不能共用一个配置文件** —— 会互相覆盖，接口直接拒绝（400）。

> 容器里跑的话，「配置文件路径」要填**容器内看到的路径**，不是宿主机路径。
> 宿主机 `/srv/frpc/nas/frpc.toml` 在容器里是 `/frpc/nas/frpc.toml` ——
> 前提是 `.env` 的 `FRPC_PATH` 指到了那个根目录（见「部署」一节）。
>
> ⚠️ 填宿主路径时页面上 `config_exists` 会是 `false`，而「自动发现绑定」遇到读不出来
> 的配置是**静默跳过**的 —— 你只会看到「全都匹配不上」，看不出是路径填错了。

### 第二步：把隧道挂接上去

每条隧道挂接一个 frpc 容器。解析规则**只有一级**：

**显式挂接** —— `tunnels.frpc_instance_id`。没填就是「未挂接」，程序不猜。

三种挂接方式：

- 「隧道」页卡片上的 **「挂接 frpc」** 按钮
- 「隧道」页 **「编辑」** 对话框里的「挂接的 frpc 容器」下拉
- 「frpc 实例」页的 **「自动发现绑定」** —— 按各容器现有配置文件里的 `[[proxies]] name` 推断

> ⚠️ 这里**故意不做**「按配置文件里的隧道名自动发现」参与自动解析。
> 发现是启发式规则，一旦参与自动解析就会**覆盖用户的显式操作** —— 你把隧道取消挂接，
> 只要旧容器的配置里还留着那个隧道名，下一轮就会被挂回去，永远改不动。
> 所以发现被做成**一次性动作**：「自动发现绑定」把推断结果**写成显式挂接**，
> 之后完全走上面那一级。它会先给预览（哪些能挂、哪些在多个容器里都出现过、哪些找不到归属），
> 确认后才写库。适合「隧道本来就在某个 frpc 配置文件里跑着、现在要把这套关系录进来」的迁移场景。

### 切换时会发生什么

隧道被判定为故障时：

1. 选一个新节点
2. **删旧隧道 → 建新隧道**（mefrp 上 `proxyName` 唯一，同名不能共存，必须先删旧的）
3. 重建它所属 frpc 容器的配置
4. 重启那个容器
5. 端到端验证 + 更新 DNS

其它容器**完全不受影响**（配置不重写、容器不重启、DNS 不动）。

**没挂接的隧道不会切换。** 换节点要改本地配置、重启容器，没有归属就无从下手；
硬搬 mefrp 上的 proxy 只会变成「proxy 换了节点、本地没人接」，比不切换更糟。
这种情况接口返回 400 并说明原因。

> 为什么内部还是按「一组」处理：万一你把两条隧道挂到了同一个容器上（UI 不拦，
> 排查问题时确实可能临时这么干），只搬一条会让合并配置时 `serverAddr` 不一致 → 直接报错 →
> **一条都写不进去**，触发切换的那条反而彻底断了。成组是安全网，不是常规路径。

### 未挂接的隧道

「已启用但没有挂接任何容器」的隧道**不会被写进任何 frpc 配置**。会在三处提醒你：

- 总览页的统计卡（「隧道未挂接 frpc」）
- 「frpc 实例」页顶部的黄色横幅
- 事件日志（`warn` 级）

连续失败达到阈值时还会额外记一条 `error`，说明它因为没挂接所以无法自动切换。

## Token 获取

| Token | 位置 | 权限 |
|---|---|---|
| mefrp | mefrp.com → 用户设置 → 访问 Token | — |
| Cloudflare | dash.cloudflare.com → My Profile → API Tokens → Create Token | Zone / DNS / Edit |
| Gotify | 你的 Gotify 实例 → Apps → 新建一个 App | — |

## 关于挂载 `docker.sock`

`docker-compose.yml` 里挂了 `/var/run/docker.sock`，**这等于把宿主机 Docker 的完全控制权交给本容器**。
拿到这个 socket 的容器可以起特权容器、挂载宿主机任意目录 —— 也就是等价于宿主机 root。

考虑到本程序的定位（只重启一个指定名字的容器），有三个选择：

1. **接受它**。本程序只在你自己的内网跑，且只调用 `containers.get(name).restart()`。
2. **换成 socket 代理**。用 [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) 只放行
   `POST /containers/{id}/restart` 和 `GET /containers/{id}/json`，然后让本程序连代理而不是真 socket
   （把 `MG_DOCKER_HOST` 改成 `tcp://docker-proxy:2375`）。
3. **不挂**。那「重启 frpc」和「看容器日志」两个功能不可用，其余照常。
   `docker-compose.yml` 里把那一行注释掉即可，程序会自己降级。

另外 `frpc.toml` 所在目录是**读写**挂载的 —— 必须读写，因为要改配置。

## 目录结构

```
mefrp-guard/
├── app/
│   ├── settings.py     双层配置：BOOTSTRAP（环境变量，需重启）+ 运行期设置（存库，UI 可改）
│   ├── auth.py         鉴权原语：PBKDF2 密码哈希 / 会话令牌 / 登录防爆破（纯标准库）
│   ├── store.py        SQLite（WAL）。settings / tunnels / node_prefs / events / sessions /
│   │                   frpc_instances / manual_nodes 七张表 + 启动时自动迁移
│   ├── mefrp.py        mefrp 5.0 API 客户端（含 WAF 检测）
│   ├── cloudflare.py   Cloudflare DNS 客户端
│   ├── notifier.py     Gotify 推送
│   ├── frpc.py         TOML 合并 + 配置读写备份 + 容器管控
│   ├── frpcparse.py    外部 frpc 配置解析（TOML / INI，只读不改）
│   ├── engine.py       自愈引擎（三层判定 / 择优 / 故障转移 / DNS 同步）
│   ├── main.py         FastAPI 后端（含登录 / 登出 / 改密码）
│   └── web/
│       ├── login.html  登录页（自包含）
│       ├── index.html  主单页 UI（自包含，无外部依赖）
│       ├── favicon.svg 站点图标（`/favicon.svg`，不需登录即可取）
│       └── favicon.ico 老浏览器 / Safari / webview 的回落图标（`/favicon.ico`）
├── tests/              十一个测试文件（鉴权 / 纯逻辑 / CF 客户端 / 外部节点逻辑 / API /
│                       外部节点 API / 标签 / 作用域 / 故障转移 / HTTP 隧道 / 多容器挂接），
│                       共 1107 条断言
├── run_local.sh        本地试跑脚本（不依赖 Docker，用沙箱 frpc 配置）
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example        复制成 .env 后填；compose 用 env_file 注入容器
└── data/               （运行时生成，已 gitignore）
    ├── local/          run_local.sh 的沙箱数据 —— 别和 prod 混
    └── prod/           Docker 部署的数据（挂到容器 /data）
```

## mefrp API 的坑

前两个来自官方文档，后两个是实测出来的 —— 都已在代码里处理，但你手工调 API 时一定会踩。

1. **User-Agent 必须规范，且不能以 `MEFrp-Client` 开头**，否则被 CDN / WAF 拦截。
   被拦截时返回的是 **HTML 而不是 JSON** —— 所以解析 JSON 会抛异常，可以拿这个当「是否被拦截」的判据。
   本程序统一检查响应首字符是不是 `<`，是就抛 `MefrpWafBlocked`。
2. **节点列表有 5 分钟 Redis 缓存**。所以 `isOnline` 不能全信，必须配合主动 TCP 探测。
3. **⚠️ `/auth/user/group` 这个端点根本不存在。**
   调它返回 **HTTP 404**，但 `message` 是服务器的通用 banner：

   ```json
   {"code": 404, "message": "ME Frp 5.21 API Server is OK!", "data": null}
   ```

   这个 `message` 极具迷惑性 —— 只看它很容易误判成「服务正常，只是这个账号没组」。
   真实的用户组在 **`/auth/user/info`**：

   ```json
   {"username": "xxx", "group": "default", "friendlyGroup": "正式用户",
    "maxProxies": 10, "usedProxies": 2, "email": "...", "inBound": ..., "outBound": ...}
   ```

4. **⚠️ 非管理员账号下，`/auth/node/list` 的 `hostname` 是空串。**
   45 个节点全部返回 `hostname: ""`，连 `servicePort` 也是 `0`、`token` 是空串。
   真实的节点公网地址只在两个地方出现：

   - **`/auth/proxy/list` 返回的 `nodes` 子数组**（首选，一次拿全）：

     ```json
     {"proxies": [...],
      "nodes": [{"nodeId": 117, "name": "北京 ②",
                 "hostname": "203.0.113.10", "allowGroup": ""}]}
     ```

     注意这个子数组**只覆盖「已经有隧道」的节点**。
   - **`/auth/proxy/config` 生成的 TOML 里的 `serverAddr`**（兜底，需要该节点上有隧道）。

   本程序用三级 fallback 取地址：
   `proxy_list.nodes` → `node_list.hostname`（管理员才有值）→ `proxy_config` 的 `serverAddr`。

   另外**没有批量端点**：`/auth/node/{all,detail,info,address,hostname}` 全部 404。
   `/auth/node/secret` 只返回 `serverPort` 和 `token`，**不含 hostname**。

5. **官方生成的 TOML 用单引号字面量**：`serverAddr = '203.0.113.10'`（不是双引号）。
   写正则去抠这个值时，`"?([^"\n]+)"?` 这种写法对单引号会**把引号一起吞进捕获组**，
   于是同一个地址只因引号风格不同就被判成「跨节点」，`merge_configs` 直接拒绝生成配置。
   正确做法是先把整个值捕获下来再统一剥引号。

6. **★★ HTTP/HTTPS 隧道与 TCP/UDP 只差两个字段，但两个都很反直觉。**

   | 字段 | TCP / UDP | HTTP / HTTPS |
   |---|---|---|
   | `remotePort` | `8000`（必填） | **`null`** —— 必须**显式传 null**，不是「省略这个键」 |
   | `domain` | `''` | **`'["example.com"]'`** —— 一个「**文本化的 JSON 数组**」**字符串** |

   `domain` 这个形状是最大的坑：它是 `str` 类型，内容是 JSON 数组的**文本**。官方 schema
   的原话是「列表被文本化，需要额外处理，如 `["mefrp.com"]`」。**官方自己的 Python SDK
   里 `domain` 也是 `str`** —— 它自己都没解析。照字面 `str(item.get("domain") or "")`
   存下来的话，显示给用户看的是 `["a.com"]` 这种带方括号引号的鬼东西，跟用户填的
   `a.com` 比对永远不相等，故障转移的「域名变没变」判断直接失效。

   本程序的做法：`mefrp.parse_domains()` 做**宽容解析**（JSON 数组 / 逗号分隔 / 分号 /
   空格 / 单个裸域名都认），`mefrp.join_domains()` 严格按官方示例序列化回去。
   两个函数都做了「已经是 JSON 数组文本就归一化」的处理，避免双重编码。

   **`httpPlugin` 的四种组合**（隧道类型 × 内网服务协议）：

   | `proxyType` | 内网服务 | `httpPlugin` | `crtPath` / `keyPath` |
   |---|---|---|---|
   | `http` | HTTP | 留空 | — |
   | `http` | HTTPS | `http2https` | — |
   | `https` | HTTP | `https2http` | **需要** |
   | `https` | HTTPS | `https2https` | **需要** |

   ⚠️ `https` 那两个组合的证书路径是**节点侧**的（示例 `/etc/crt/example.com.crt`），
   免费用户基本拿不到节点文件系统 —— **实用组合是 `http` + Cloudflare 终结 TLS**（橙云）。

   另外 `httpUser`/`httpPassword` 和 `accessKey` **不能同时存在**（后端会拒）。
   spec 里还有本程序尚未支持的字段：`locations`（路径路由，逗号分隔）、`responseHeaders`、
   `transportProtocol` —— 其中 `locations` 已经透传。

7. **`domain` 只对 HTTP/HTTPS 有意义，`remotePort` 只对 TCP/UDP 有意义。**
   互串着传不是「被忽略」而是语义错乱：TCP 隧道带上 `domain`、HTTP 隧道带上端口，
   都是错的。本程序在**两个入口**都做了硬校验（`POST /api/tunnels` 与
   `PATCH /api/tunnels/{id}`）：HTTP 缺域名 → 400、HTTP 填端口 → 400、TCP 绑域名 → 400。
   在 `proxy_create` 里还做了一层强制（TCP 组的 `domain`/`locations`/证书路径一律清空），
   防止调用方漏改。

用到的端点：

| 用途 | 端点 | 方法 | 备注 |
|---|---|---|---|
| 节点列表 | `/auth/node/list` | GET | 非管理员 `hostname` 为空串 |
| 节点状态 | `/auth/node/status` | GET | |
| 隧道列表 | `/auth/proxy/list` | GET | **`nodes` 子数组带真实 hostname** |
| 创建隧道 | `/auth/proxy/create` | POST | **HTTP/S 的 `domain` 是文本化 JSON 数组、`remotePort` 必须显式 null** |
| 删除隧道 | `/auth/proxy/delete` | POST | |
| 生成单隧道配置 | `/auth/proxy/config` | POST | 里面的 `serverAddr` 是节点地址 |
| **当前用户信息 / 用户组** | **`/auth/user/info`** | GET | 用 `group` + `friendlyGroup` |
| ~~当前用户组~~ | ~~`/auth/user/group`~~ | — | **不存在，404** |

官方 Python SDK 里还有几个本程序**没用**的端点，将来可能有用：
`POST /auth/proxy/update`（改隧道）、`/auth/proxy/toggle`（启用禁用）、
`/auth/proxy/kick`（强制下线）、`POST /auth/node/freePort`（`{nodeId, protocol}`
让节点给个空闲端口）、`POST /auth/easyStartup`（`{proxyId}` → `nodeAddr`/`nodePort`/`nodeToken`）、
`GET /auth/node/nameList`、`GET /auth/user/groups`。

## HTTP / HTTPS 隧道（1.0.2）

两类隧道**不是一个东西**，所以从数据模型到择优逻辑到前端表单全部**分了两套**。

### 为什么必须分开

| | TCP / UDP | HTTP / HTTPS |
|---|---|---|
| 对外入口 | **端口**（`节点IP:41234`） | **域名**（`http://nas.example.com`） |
| 节点侧机制 | 裸端口转发 | 节点**反代**，按 Host 头分流到不同后端 |
| 主要限制 | 端口是否被占、节点是否支持该协议 | **域名备案**（大陆节点）、需报备（白名单） |
| 切换节点后 | 端口可能变 → 要去改下游 | **域名不变** → 下游什么都不用动 |
| 可探测性 | 探端口，可靠 | **TCP 层探不出问题**（反代对任何 Host 都握手成功） |

### 两套偏好体系

`settings.PREF_KEYS` 是这套设计的核心 —— 把「隧道类型组」映射到对应的设置键：

```python
PREF_KEYS = {
    "port": {"regions": "allow_regions",      "min_bandwidth": "min_bandwidth_mbps",
             "max_load": "max_load_percent",  "keywords": "prefer_keywords",
             "node_cooldown": "node_cooldown"},
    "http": {"regions": "http_allow_regions", "min_bandwidth": "http_min_bandwidth_mbps",
             "max_load": "http_max_load_percent", "keywords": "http_prefer_keywords",
             "node_cooldown": "http_node_cooldown"},
}
```

`mefrp.kind_of(proxy_type)` 把类型归成 `"port"` / `"http"` 两组，**认不出来的类型一律
当 `port`** —— 那是保守的一侧（旧的默认值就是 TCP 那一套）。`settings.pref_key()` 同理。

⚠️ **冷却表因此是复合键 `(类型组, node_id)`**，不是裸 `node_id`。理由：同一台节点上，
一条 TCP 隧道刚失败不代表一条 HTTP 隧道也要躲开它 —— 两者用到的能力根本不同
（HTTP 靠节点反代 + 域名，TCP 靠裸端口）。只按节点记冷却会让两类互相误伤。

### 默认只用港澳台 + 海外

`http_allow_regions` 的默认值是 **`cnos,oversea`**（`cnos` = 港澳台），**不是随手填的**：
官方文档明说大陆节点建 HTTP/S 站需要**向管理员报备域名**（白名单处理），
腾讯云/阿里云/华为云等节点还要求域名**在服务商处接入备案**。默认避开大陆，
能让新用户第一次建 HTTP 隧道就成功，而不是建完发现打不开。
`rank_nodes(proxy_type="http")` 会给大陆节点挂一条「需先报备」的 **warning**（不是 blocker）
—— 手动锁一个大陆节点是完全合法的选择（域名已经报备过）。

`region` 只有三个值：**`cn` / `cnos`（港澳台）/ `oversea`**。

### 探测：auto 下**故意跳过** HTTP 隧道

`probe_plan(proxy_type, mode)` 返回 `(种类, 原因)`，种类是 `"tcp"` / `"http"` / `"none"`。
两种「不探」的原因**正好相反**，注释里写清楚了：

- **udp** —— 节点上只有 UDP 监听，TCP 握手必然失败 → 探了必**假阴性**。
- **http/https（auto 模式）** —— 节点反代对**任何** Host 都会握手成功，
  TCP 层探出来永远是「通」→ 探了必**假阳性**。要真探得把 `probe_mode` 改成 `http`。

`probe_mode = http` 时，HTTP 隧道走 `http_probe()`：GET 绑定域名，**2xx/3xx 算通**
（本地服务在根路径上 302 跳登录页极常见），4xx/5xx 算不通（多半意味着节点反代没匹配到
这条隧道）。**不跟随重定向**。请求路径由 `http_probe_path` 控制（默认 `/`）——
如果服务在根路径上本来就返回 4xx/5xx，得把这个改成能返回 2xx 的路径。

⚠️ `http_probe` 里的 `import httpx` **放在函数内部**而不是模块顶层 —— engine 被
「纯逻辑测试」导入时会被塞一个假的 httpx。

### DNS：CNAME 到节点入口域名，或退回 A 记录

官方要求「把绑定域名 CNAME 到**节点域名**」，但非管理员账号看不到 `hostname`
（见上面第 4 条），实测能拿到的 `serverAddr` 是 **IP**。所以：

- 节点偏好里的 **`http_entry`**（可选，手填）就是「这个节点的 HTTP 入口域名」。
  填了 → DNS 记录走 **CNAME** 到它（抗节点换 IP）；没填 → 退回节点 **IP 的 A 记录**。
- 实测 A 记录也能通 —— 节点反代按 Host 头分流，不挑地址形式，CNAME 只是更稳。

### 前端

- 隧道对话框按类型**切换字段**：TCP/UDP 显示「期望远程端口」，HTTP/S 显示「绑定域名 +
  内网服务协议（httpPlugin）+ 路径路由」；`https` 才显示节点侧证书路径。
- 设置页把节点择优拆成 **「TCP/UDP」** 和 **「HTTP/HTTPS」** 两块；区域从输入框改成
  **复选框 + 快捷选择**（含「所有海外节点 = `cnos,oversea`」）；节点偏好 chips 编辑器
  上面加了个 **TCP/UDP ↔ HTTP/S 页签**。
- 节点页也加了同样的页签 —— 同一个节点在两套口径下的可用性可能不同。
- ⚠️ 节点列表按类型**分别缓存**（`NODES_BY_KIND`），不能混用，否则会把按 A 口径算出来的
  可用性画到 B 口径的页签上。

## 排错

**「`docker build` 失败，报 `json.decoder.JSONDecodeError: Unterminated string`」**

不是 `requirements.txt` 有问题 —— 是 pip 抓 PyPI 索引页时**响应体被中途截断**了。
`pydantic` 的传递依赖 `pydantic-core` 的索引页有 **9.4 MB**（14,296 个文件，
gzip 后 1.53 MB），pip 必须把整页下完才能挑 wheel；这条长连接被中间设备掐断，
`json.loads()` 就在最后一个不完整的字符串上报错，pip 以 code 2 退出。
报错栈里全是 pip 内部函数，**完全看不出是网络问题**。

**先重跑一次 `docker build`。** 这类截断基本是偶发，重跑一次就过了。
若稳定复现，报错里的 `char N` 就是「收到了多少字节」，跟真实页大小对一下：

```bash
curl -s -o /dev/null -w '%{size_download}\n' \
  -H 'Accept: application/vnd.pypi.simple.v1+json' -H 'Accept-Encoding: identity' \
  https://pypi.org/simple/pydantic-core/
# 完整时输出 9430673
```

稳定复现且明显偏小 → 问题在本地链路。查 Docker 网桥的 MTU：宿主机上行 MTU 小于 1500 时
（PPPoE 是 1492、走 VPN 可能只有 1400 上下），**大响应会在网桥里被截断，小请求却一切正常**，
症状与这里一模一样。用同一页在默认网桥和宿主机网络上各测一次 `size_download`，两个数不一样
就是 MTU —— 在 `/etc/docker/daemon.json` 里加 `{"mtu": 1400}` 后重启 docker，或临时用
`docker build --network=host` 绕过。

> ⚠️ 要换国内源的话**别用清华 TUNA**：它的 `/simple/` 返回的 JSON 缺少 PEP 691 要求的
> `meta.api-version` 字段，pip 会判定「这个包一个可用版本都没有」，报
> `No matching distribution found`（和截断是两回事，同样看不出原因）。
> 实测 2026-10：阿里云 / 腾讯云 / 中科大 / pypi 官方正常，只有清华这样。

**「挂了 frpc，点『手动切换』还说没挂接」**

先分清是哪一种：

1. **隧道卡片上「frpc 容器」那一行显示 `—` 或「未挂接」** → 那是**真没挂上**。
   查 `/api/tunnels` 里这条的 `frpc_instance_id` 是不是空的；如果非空，再看那个实例
   是不是被**停用**了 —— `frpc_for_tunnel()` 只认 `enabled = 1` 的实例，指向一个停用的
   实例会**当作未挂接**（故意的，见 `frpc_for_tunnel` 的注释）。
2. **卡片显示正常（有容器名），只有对话框说没挂接** → 就是本文档「frpc 容器与隧道挂接」
   里那个**两个接口形状不一致**的 bug（1.0.1 已修）。对一下两个接口：

   ```bash
   for p in tunnels overview; do
     echo "== /api/$p"
     curl -s -b cookie.txt "http://127.0.0.1:8080/api/$p" \
       | python -m json.tool | grep -m1 -A1 frpc_bound
   done
   ```

   两边都该是 `true`。**只有 overview 有、tunnels 缺字段** → 你的镜像是旧的，重建即可。

**彻底绕开索引**（离线构建）：在能正常联网的机器上把 wheel 抓下来，随镜像一起打包。

```bash
docker run --rm -v "$PWD:/w" -w /w python:3.12-slim \
  pip download -r requirements.txt -d wheels --only-binary=:all: \
  -i https://mirrors.aliyun.com/pypi/simple/
```

Dockerfile 里加 `COPY wheels /wheels`，安装那行换成
`pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt`。

**「被 CDN / WAF 拦截」**
改「设置」页里的 User-Agent（别用 `MEFrp-Client` 开头），或者降 `engine_interval`。

**「受管隧道不在同一个节点上」**
你的隧道分散在多个节点。先把它们收敛到同一个节点，再重建配置。

**「没有满足条件的节点」**
页面会给出拒因统计（几个离线、几个无权限、几个带宽不够……）。
常见原因是带宽门槛设太高，或者 `allow_regions` 填了但节点 region 不是 `cn`。

**「重启 frpc 失败」**
先看「frpc」页的容器状态。多半是容器名不对（`MG_FRPC_CONTAINER`）或没挂 docker.sock。

**切换后端口变了**
页面顶部会出现黄色横幅提示，并显示你填的「下游备忘」。
改完下游配置后点「已处理」清掉。

**DNS 没同步**
先看隧道卡片上「DNS 记录」那一栏填了没有 —— **留空 = 程序不管这条的 DNS**，
一次都不会去问 Cloudflare（这是设计，不是故障）。填了的话再往下查：

- CF Token 权限是不是 `Zone.DNS:Edit`、记录所在的 zone 在不在授权范围内；
- 节点地址是 IP 就写 A 记录，是域名就写 CNAME —— 程序按节点地址自动判断；
- 如果事件里写「拿不到节点地址」，见上文「已知限制」第二条；
- **记录名是不是被别的隧道占着** —— 两条隧道共用一个记录名会被拒绝（见上文
  「DNS 记录名必须全局唯一」），编辑时会 409，导入时会出现在 `dns_clash` 里。

⚠️ **事件里出现红色的「更新 DNS 失败」不代表功能坏了**：传输层抖动（超时 / 连不上）
现在只记 `warn`，连续 3 次才升 `error`，而且客户端会自动重试 2 次、复用连接池 ——
所以偶尔一条 `warn` 是正常的，下一轮就自己好了。真正需要你去动手的是那些
**反复出现的 `error`**（多半是 token 权限 / zone 找不到 / 记录名撞车）。

导入 / 探测 / 切换之后都会**当场**在弹窗里回报 DNS 的结果（成功 / 找不到 zone /
token 没权限），不必去翻事件日志。判据与设计取舍见上文「DNS 同步」。

**界面上「节点地址」是空的 / 公网入口显示 `—`**
说明这个节点上还没有任何隧道，mefrp 对非管理员不返回它的地址。
在那个节点上建一条隧道之后地址就能反推出来了。事件日志里会有对应记录。

**UDP 隧道一直显示「不探测」，是坏了吗**
不是。这是设计如此 —— 见上文「探测模式」。
UDP 隧道只有 L1（mefrp 状态）+ L2（节点状态）两层判定，
`fail_streak` 不会因为探测而增长。想验证 UDP 服务本身是否正常，
请在业务侧确认（比如 OpenVPN 客户端能不能连上）。

**「用户组」显示未知**
看括号里的原因。常见的是 Token 没填、Token 无效，或网络被 WAF 拦。
如果原因里出现 404 且提示 `/auth/user/group`，说明代码版本太旧 —— 新版本改用 `/auth/user/info` 了。

**登录页一直转 / 登录成功后又跳回登录页**
多半是 Cookie 没存下来。检查是不是通过 HTTPS 访问但 `Secure` 标志没生效，
或者反代改写了 `Host` 导致 CSRF 的 `Origin` 校验失败（会被拒 403，不是这个症状）。
内网 HTTP 直连不会有这个问题。

**被锁定了（429）**
按 IP 计数，默认连错 5 次锁 5 分钟。等一会儿，或者重启容器清空计数
（锁定状态只在内存里，重启即清）。如果反代没透传 `X-Forwarded-For`，
所有客户端会被算作同一个 IP —— 一个人被锁会连累所有人。

**改了 `MG_WEB_PASSWORD` 但密码没变**
正常。环境变量只是**首次启动的种子**，之后以数据库里的为准。
要重新播种就删掉那三行（见上文「改初始密码 / 找回密码」）。

## 测试

```bash
PY=<python>
$PY -m pip install --target .devdeps fastapi httpx pydantic   # 只需装一次
PYTHONPATH=$PWD/.devdeps PY=$PY ./tests/run_all.sh
```

> ⚠️ `run_all.sh` **自己不设 `PYTHONPATH`** —— 不带上的话会在第一个需要依赖的文件上
> 报 `No module named 'fastapi'`。

十一个文件，共 **1107 条断言**（59 + 149 + 22 + 137 + 196 + 183 + 30 + 47 + 75 + 116 + 93）：

| 文件 | 覆盖 | 需要第三方库 |
|---|---|---|
| `tests/test_auth.py` | **密码哈希（随机盐/迭代数/异常输入安全降级）、默认密码识别、会话令牌、登录防爆破、来源 IP 解析** | 否 |
| `tests/test_logic.py` | frpc TOML 合并与跨节点校验、**单引号字面量解析**、配置备份/恢复/路径穿越、SQLite 持久化与字段白名单、Node/Proxy 字段解析、`pick_node` 择优调度、**节点偏好的有序语义与归一化**、**`probe_plan` 探测适用性（四种模式 × 四种隧道类型，含「http 在 auto 下是假阳性」）** | 否 |
| `tests/test_cfclient.py` | **Cloudflare 客户端的 httpx 交互**：传输层退避重试、重试耗尽后 `transient=True` 与异常类型名、非传输层错误不重试、**连接池复用（3 个请求只建 1 个）与跨事件循环重建**、`upsert(existing=…)` 省掉两次自查、没配 token 一个请求都不发 | httpx |
| `tests/test_manual_node.py` | **frpc 配置解析（TOML / INI）、`patch_server` 文本级改写的保真与合法性、外部节点数据层 CRUD、1.0.0 老库补列迁移、引擎对外部隧道的分支（含「不适用探测」的三态、UDP 的 DNS 同步）、★ **mefrp 拉取失败与 DNS 同步失败「满 `alert_after_seconds` 才告警」的完整口径**（一条 warn → 静默 → 满阈值 error → 每再满一个阈值补报 → 恢复 success / 短抖不记 / force 与静态问题立刻报）** | 否 |
| `tests/test_api.py` | FastAPI 全端点：**登录页/会话 Cookie/登出作废/改密码/CSRF/防爆破/只读设置保护**、鉴权、CRUD、密钥打码、错误码、枚举字段校验、引擎生命周期、**frpc 实例 CRUD 与挂接 API**、**`/api/tunnels` 与 `/api/overview` 的挂接字段口径一致**、**节点偏好预览（含路由遮蔽回归）** | fastapi / httpx / pydantic |
| `tests/test_manual_api.py` | 外部节点全部 HTTP 端点：导入 / 更新 / 删除 / 改连 / 探测、token 不回明文、**「地址已导入过」的 409 契约与「覆盖重建空节点」**、**导入时顺手同步 DNS 与 udp 隧道的探测端点**、**DNS 记录名查重的 409 契约（含编辑自己 / 导入时只放弃那一个字段）**、删掉最后一条隧道自动清理空节点 | fastapi / httpx / pydantic |
| `tests/test_tags.py` | 隧道标签：默认打 `mefrp`、归一化与截断、`?tag=` 筛选（**空串 = 筛未打标的**）、`/api/tags` 计数与排序、显式清空、**老库只回填一次** | fastapi / httpx / pydantic |
| `tests/test_scope.py` | **隧道名的唯一性作用域**：同名隧道跨运营商并存、展示名重名不报错、mefrp 作用域内仍唯一、`/api/orphans` 与 `probe` 按作用域分流、**老库整表重建去掉 UNIQUE** | fastapi / httpx / pydantic |
| `tests/test_failover.py` | 完整故障转移流水线（mefrp / CF / Gotify / Docker 全部打桩），含**节点地址取址路径**与 **UDP 跳过探测** | fastapi / httpx / pydantic |
| `tests/test_http_tunnel.py` | **1.0.2 HTTP/HTTPS 隧道**：`domain` 字段的「文本化 JSON 数组」解析与序列化（含畸形输入兜底）、`proxy_create` 两类隧道的请求体差异（`remotePort` 必须显式 null、TCP 侧 domain 强制清空）、**HTTP 探测的 URL 构造与返回码三态（2xx/3xx 通、4xx/5xx 不通）**、**按类型校验（HTTP 缺域名 / 填端口、TCP 绑域名都是 400）**、**两套偏好体系的隔离（同一节点在两组口径下选出不同结果）**、**冷却表的 `(类型组, 节点)` 复合键**、**DNS 走 `http_entry` 时是 CNAME、否则退回节点 IP 的 A 记录** | fastapi / httpx / pydantic |
| `tests/test_frpc_multi.py` | **多容器挂接：不自动播种、只认显式挂接、未挂接拒绝切换、按容器重建、成组切换、跨容器隔离、失败回滚、自动发现** | 否 |

`test_auth` / `test_logic` / `test_failover` / `test_frpc_multi` / `test_manual_node`
用 `sys.modules` 注入假的 `httpx`（或在桩里补齐 `TransportError` 等属性），在
**没装任何依赖**的环境里也能跑。其余六个需要依赖（装到 `.devdeps` 即可，不污染环境）。
⚠️ `test_cfclient` 反过来 —— 它要验的**就是** httpx 交互本身，所以**必须用真的 httpx**。
⚠️ `test_http_tunnel` 是**混合**的：FastAPI 的 `TestClient` 依赖真实的 `httpx.Response`，
所以它**不能**整个替换 `sys.modules["httpx"]`（会在 import 阶段就炸）—— 正确做法是
拿到真模块、只把 `AsyncClient` 换成假的；`engine.http_probe` 在函数内部 `import httpx`，
拿到的就是同一个已打补丁的模块对象。

`test_failover.py` 里最关键的几条用例（都是踩过的坑）：

- 手动指定节点**能突破**带宽/负载/区域/排除/冷却等软偏好，但**不能突破**离线/禁用/无权限等硬约束
- 端到端探测失败时**不去改 DNS**（否则会把解析指向一个不通的地址）
- 端口被占用时自动降级为「服务端分配」，并在端口真的变了时提示检查下游
- 一个可用节点都没有时必须**如实失败**，不能假装切换成功
- 切换失败时**不置**「下游待办」标志（那个标志的含义是「端口变过」，置了就是误报）
- **节点地址取自 `proxy_list` 的 `nodes` 子数组**（假 `node_list` 故意返回空 hostname，还原非管理员视图）
- **UDP 隧道在 `auto` 模式下不被 TCP 探测误判**（假探测桩故意返回失败，验证它压根没被调用）
- 用户组取自 `/auth/user/info` 的 `group`，且 `allowGroup` 匹配用的是机器名而不是展示名
- **登出必须真的删服务端会话**（只清 Cookie 的话旧令牌在过期前仍然可用，「登出」就是个摆设）
- **改密码后旧密码立刻失效**，且其他设备上的会话被全部踢掉
- **密码哈希不能从 `/api/settings` 读出或写入**（否则任何拿到会话的人都能改掉密码）
- **跨站 `Origin` 的写请求被拒**，同源的放行，不带 `Origin` 的（curl）不受影响
- **防爆破的语义边界**：第 N 次失败即触发锁定返回 429，不是第 N+1 次
- **多容器：A 的隧道切换时 B 完全不受影响**（B 的配置文件内容与容器重启计数都不变）
- **成组切换只重建/重启一次**，组内 2 条隧道搬完，重启计数 = 1
- **组内任一条创建失败 → 整体回滚**：已经搬走的隧道被**建回原节点**，新节点上的 proxy 被删
- **切换顺序是「先删旧、再建新」**（假客户端会像真 mefrp 一样对同名创建直接报错，顺序反了就红）
- **首次启动不播种任何实例**，挂接全靠手动
- **未挂接的隧道：不写配置、拒绝切换、`frpc_bound` 为假** —— 哪怕当时只有一个容器
- **显式取消挂接不会被启发式规则挂回去**（旧容器配置里还留着隧道名也不认）
- **空实例重建报错而不是写空配置**（避免把用户手写的 `[[proxies]]` 清掉）
- **两个容器不能共用同一个配置文件**，相对路径也直接拒绝
- **老库迁移**：补 `frpc_instance_id` 列（老库里已有的绑定关系原样保留）

`test_scope` / `test_tags` / `test_manual_api` 里最关键的几条（都是踩过的坑）：

- **★ 隧道名的唯一性只在「同一台 frps 内」** —— 导入一份含同名隧道的外部配置时
  **不能被跳过**，两条同名隧道要能并存，且外部那条的展示名**就是本名**（不许自动加后缀）
- **★ 展示名重名不报错**：新建同名展示名、把名字改成已存在的，都得 200 而不是 500
  （`name` 上的 UNIQUE 已经整表重建摘掉了）
- **★ `find_tunnel_by_proxy` 三向隔离**：mefrp 作用域、某个外部节点、另一个外部节点各查各的
- **★ `/api/orphans` 不被同名的外部隧道干扰** —— `managed` 集合只算 mefrp 作用域，
  否则一条真·未纳管的 mefrp 隧道会被同名的那条外部隧道**藏掉**
- **★ `probe` 按作用域分流** —— 外部隧道拿的是自己节点的地址与端口，
  绝不能拿 `proxy_name` 去 mefrp 的列表里找（会探到一条完全不相干的隧道）
- **★ 老库整表重建**：`name` / `proxy_name` 上的 UNIQUE 都去掉，数据、主键、标签原样保留，
  重建后能插同名；新表 DDL **从 `sqlite_master` 读出来再摘约束**（手写 DDL 会因可空性 /
  默认值不一致而让 `INSERT ... SELECT` 失败）
- **★ DNS 记录名的唯一性**：两条隧道共用同一个记录名会被硬拒（409 / `dns_name_taken`），
  大小写与首尾空格都归一；`PATCH` 自己时带 `exclude_id`（否则改别的字段会被自己判成冲突）；
  导入外部节点时是例外 —— **只放弃那一条的记录名，隧道照建**，结果放 `dns_clash`
  （混进 `skipped` 是错的：那些隧道**是纳管了的**）
- **★ 标签只在「刚加出这一列」的那一次回填** —— 用户手动清空后重启**不能**被打回 `mefrp`
- **`?tag=` 的空串语义**：筛的是「未打标签的」，不是「不过滤」
- **PATCH 不带 `tag` 字段时不能动标签**（要能区分「没传」和「传了空串」）
- **★ 「地址已导入过」是出路不是死路**：409 的结构化 detail 必须带 `existing_id` 与两个计数；
  `overwrite=true` **只对零隧道零实例的残留节点**生效，有隧道挂着的一律拒（且节点与隧道都还在）
- **★ 残留空节点是同名 bug 的产物**：导入时隧道被全局重名判掉 → 只建出节点、零纳管
  （`delete_tunnel` / `switch_instance_to_node` 会自动清理没人引用的空节点）

`test_manual_node` / `test_manual_api` 里还钉了一组 DNS 同步的用例，
设计取舍见上文「[DNS 同步](#dns-同步)」。

## 已知限制

- **一个 frpc 只能连一个节点**，所以**同一个容器上的隧道必须同节点**。
  本项目的模型是**一条隧道一个容器**，各自守一个节点 —— 容器之间互不牵连。
- **隧道必须手动挂接**，程序不做任何自动认领。这是刻意的：自动认领会让
  「没挂接」看起来像「已挂接」，而且新增容器时会突然集体失去归属。
  代价是初次配置多两步（登记容器 + 挂接隧道）。
- **⚠️ 非管理员账号拿不到「没有隧道」的节点的公网地址。**
  `/auth/node/list` 的 `hostname` 被脱敏成空串，而 `/auth/proxy/list` 的 `nodes` 子数组
  只覆盖已经有隧道的节点。所以对一个**此前完全没用过**的新节点，程序拿不到它的地址
  → 无法做端到端探测 → 故障转移到这种节点后，验证这一步会降级为「无法验证」，
  这一轮的 DNS 同步也拿不到地址而跳过（除非该节点上有别的隧道可供反推）。
  ⚠️ 这只影响 **mefrp 隧道** —— 外部节点的 `serverAddr` 就在自己库里，不查任何 API。
  这是 mefrp 侧的权限限制，不是程序缺陷。**想彻底解决就得给账号加管理员权限。**
- **DNS 只在隧道上填了记录名时才管**（判据见上文「DNS 同步」）。记录所在的 zone 必须
  在 API Token 的可见范围内（权限 `Zone.DNS:Edit`），否则 `resolve_zone` 找不到，
  这一轮会如实记一条「找不到 … 所属的 Cloudflare zone」。
- 端到端探测只能证明 **TCP 层可达**，不能证明后端服务健康。要做应用层探测得另加 HTTP 检查。
  同理，**UDP 隧道根本没有可靠的端到端探测手段**（见上文「探测模式」），只能靠 L1 + L2 判定。
  这类隧道在 UI 上显示「在线 · 不探测」—— 是「没探」，不是「探挂了」。
- 隧道被 mefrp 判为 `isBanned` 时不会自动处理 —— 这类问题通常需要人工去申诉，换节点也会继续被封。
- 事件日志默认保留最近 5000 条。
