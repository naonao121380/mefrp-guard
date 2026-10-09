#!/usr/bin/env bash
# 本地试跑 mefrp-guard（不依赖 Docker）。
#
# 与生产部署的区别：
#   * 监听 127.0.0.1，只在本地可达
#   * frpc 配置指向 data/local/sandbox-frpc/frpc.toml（沙箱目录），绝不会碰真实配置
#   * 没有 docker.sock → 「重启 frpc」「看容器日志」会提示不可用，其余功能正常
#
# frpc 容器（模型：**一条隧道 : 一个 frpc 容器**）：
#   * frpc 容器**不在环境变量里配**。程序启动时一条实例都不建，全靠手动登记 ——
#     这样「谁在管哪条隧道」永远是一个明确的、看得见的决定，不存在
#     「程序替你认领了但你没注意」的中间状态。
#   * 起来之后到「frpc 实例」页点「新增实例」，填配置文件路径 + 容器名；
#     再到「隧道」页逐条点「挂接 frpc」把它挂上去。
#   * ⚠️ 没挂接的隧道**不会被写进任何 frpc 配置**，总览页会提示「隧道未挂接 frpc」。
#   * 沙箱试跑时容器名随便填（本机没有那个容器）—— 只有「重启 frpc」会失败，
#     配置读写照常，够验证除容器管控以外的全部功能。
#
# 鉴权：**默认开启**，首次启动用 admin / admin123。
#   * 想用别的初始密码，启动前设 MG_WEB_PASSWORD=<新密码>
#   * 密码存在 data/local/guard.db 里，改过之后 MG_WEB_PASSWORD 不再生效
#     （它只是「首次播种」用的）。忘了密码就删掉 settings 表里的三行：
#       sqlite3 data/local/guard.db "DELETE FROM settings WHERE key LIKE 'web_password%';"
#     然后重启，会用默认密码重新播种。
#
# ⚠️ 数据目录刻意是 data/local（不是 data）—— Docker 部署用的是 data/prod。
#    两者必须分开：沙箱里会建一条指向**本机路径**的 frpc 实例，那条记录一旦
#    被带进容器就完全不可用（容器里没有那个路径）。
#
# 用法：
#   PY=<python> ./run_local.sh          # 前台运行，Ctrl-C 退出
#   PY=<python> PORT=18080 ./run_local.sh
set -eu

PY="${PY:-python3}"
PORT="${PORT:-18080}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

export MG_DATA_DIR="$ROOT/data/local"
export MG_FRPC_CONFIG="$ROOT/data/local/sandbox-frpc/frpc.toml"
export MG_FRPC_CONTAINER="${MG_FRPC_CONTAINER:-frpc}"
export MG_HOST=127.0.0.1
export MG_PORT="$PORT"
# 初始凭据种子。留空 = 用内置默认 admin / admin123。
export MG_WEB_USER="${MG_WEB_USER:-}"
export MG_WEB_PASSWORD="${MG_WEB_PASSWORD:-}"
export PYTHONUNBUFFERED=1

mkdir -p "$MG_DATA_DIR/sandbox-frpc"

echo "----------------------------------------------------------------"
echo " mefrp-guard 本地实例"
echo "   地址      http://127.0.0.1:$PORT"
echo "   登录      ${MG_WEB_USER:-admin} / ${MG_WEB_PASSWORD:-admin123（默认，请登录后修改）}"
echo "   数据目录  $MG_DATA_DIR"
echo "   沙箱 frpc $MG_FRPC_CONFIG"
echo "----------------------------------------------------------------"
echo " 起来之后按这个顺序配："
echo "   1. 「设置」页填 mefrp Token -> 点「测试」"
echo "   2. 「节点」页点「重新拉取」"
echo "   3. 「frpc 实例」页「新增实例」，填："
echo "        配置路径  $MG_FRPC_CONFIG"
echo "        容器名    frpc   （本机没这个容器，只有「重启」会失败，其余照常）"
echo "   4. 「隧道」页纳管隧道，再点「挂接 frpc」挂到刚建的那个实例上"
echo " 说明：一条隧道对应一个 frpc 容器；没挂接的隧道不会被写进任何配置。"
echo "----------------------------------------------------------------"

exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT" --no-access-log
