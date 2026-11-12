#!/usr/bin/env bash
# mefrp-guard 构建脚本：build / verify / pack。
#
# 设计目标：
#   1. 不写死任何机器路径 —— 一切相对仓库根；
#   2. 自动适配 LXC —— 在容器里 docker 新建 netns 会被宿主 AppArmor 拦
#      （CVE-2025-52881 补丁副作用，报 `reopen fd 8: permission denied`），
#      检测到 LXC 就给 docker build / run 加 `--network host`；
#   3. 镜像源默认走官方 —— 国内构建用 `--mirror` 显式打开。
#
# 用法：
#   ./scripts/build-image.sh              # build + verify + pack
#   ./scripts/build-image.sh build        # 只构建
#   ./scripts/build-image.sh verify       # 只验证已有镜像
#   ./scripts/build-image.sh pack         # 只打包 tar
#
#   ./scripts/build-image.sh build --mirror          # 国内镜像源（apt 清华 + pip 清华）
#   ./scripts/build-image.sh build --no-cache        # 全量重建
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 版本号以 app/main.py 为准，别在脚本里再写一份
VERSION="$(sed -n 's/.*version="\([0-9][^"]*\)".*/\1/p' app/main.py | head -1)"
if [ -z "$VERSION" ]; then
  echo "!! 读不到 app/main.py 里的 version" >&2
  exit 1
fi

IMG="mefrp-guard:${VERSION}"
OUT_DIR="${OUT_DIR:-$ROOT/out}"
TAR="$OUT_DIR/mefrp-guard-v${VERSION}.tar"
SMOKE_PORT="${SMOKE_PORT:-18080}"

# ---- LXC 检测 ----
NET_ARGS=()
VIRT="$(systemd-detect-virt 2>/dev/null || echo none)"
if [ "$VIRT" = "lxc" ]; then
  NET_ARGS=(--network host)
  echo "  [env] 检测到 LXC（$VIRT）→ docker build/run 加 --network host"
fi

CMD="${1:-all}"
shift || true

CACHE_ARGS=()
MIRROR_ARGS=()
for a in "$@"; do
  case "$a" in
    --no-cache) CACHE_ARGS=(--no-cache) ;;
    --mirror)   MIRROR_ARGS=(--build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn
                             --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple) ;;
    --no-mirror) MIRROR_ARGS=() ;;
    *) echo "!! 未知参数：$a" >&2; exit 1 ;;
  esac
done

hr() { echo; echo "===== $* ====="; }

do_build() {
  hr "1) docker build  $IMG"
  echo "  源码: $ROOT"
  echo "  版本: $VERSION（读自 app/main.py）"
  # ⚠️ 先删旧 tag：构建失败时不会留下陈旧镜像被误 save
  docker rmi "$IMG" >/dev/null 2>&1 || true
  local t0=$SECONDS
  docker build "${NET_ARGS[@]}" "${CACHE_ARGS[@]}" "${MIRROR_ARGS[@]}" -t "$IMG" . || return 1
  echo "  构建耗时: $((SECONDS - t0))s"
  docker images --format '  {{.Repository}}:{{.Tag}}  {{.ID}}  {{.Size}}' | grep mefrp || true
}

do_verify() {
  hr "2) 镜像信息"
  docker image inspect "$IMG" --format '  Id:      {{.Id}}
  Created: {{.Created}}
  Cmd:     {{.Config.Cmd}}' || return 1

  hr "2.1) 镜像里的代码是不是这次的版本"
  docker run --rm "${NET_ARGS[@]}" --entrypoint sh "$IMG" -c '
    echo -n "  push_tunnel_config: "; grep -c "def push_tunnel_config" /app/app/engine.py
    echo -n "  proxy_update:       "; grep -c "async def proxy_update" /app/app/mefrp.py
    echo -n "  proxy_kick:         "; grep -c "async def proxy_kick" /app/app/mefrp.py
    echo -n "  PUSH_TO_REMOTE:     "; grep -c "PUSH_TO_REMOTE_FIELDS" /app/app/main.py
    echo -n "  _pushNotice(前端):  "; grep -c "_pushNotice" /app/app/web/index.html
    echo -n "  force_restart:      "; grep -c "force_restart" /app/app/engine.py
    echo -n "  normalize_metadatas:"; grep -c "normalize_metadatas" /app/app/frpc.py
    echo -n "  port_candidates:    "; grep -c "def port_candidates" /app/app/engine.py
    echo -n "  pick_free_port:     "; grep -c "def pick_free_port" /app/app/engine.py
    echo -n "  notify dedupe:      "; grep -c "DEDUPE_WINDOWS" /app/app/notifier.py
  ' || return 1

  hr "2.2) 依赖版本"
  docker run --rm "${NET_ARGS[@]}" --entrypoint python "$IMG" -c '
import fastapi, httpx, pydantic, uvicorn, docker
print("  fastapi ", fastapi.__version__)
print("  httpx   ", httpx.__version__)
print("  pydantic", pydantic.VERSION)
print("  uvicorn ", uvicorn.__version__)
print("  docker  ", docker.__version__)
' || return 1

  hr "2.3) 镜像内跑全量测试（挂载宿主的 tests/ 与 app/）"
  # 挂整个仓库根（不含 .env —— 构建机上没有密钥文件）
  local tlog=/tmp/mg-tests.log rc=0
  docker run --rm "${NET_ARGS[@]}" -v "$ROOT:/src:ro" -w /src -e PY=python3 \
      "$IMG" bash tests/run_all.sh >"$tlog" 2>&1 || rc=$?
  tail -25 "$tlog"

  hr "2.4) 起容器打 /healthz（端口 $SMOKE_PORT）"
  docker rm -f mg-smoke >/dev/null 2>&1 || true
  # 用 host 网络时 -p 无效，直接 override 监听端口
  docker run -d --name mg-smoke "${NET_ARGS[@]}" "$IMG" \
      uvicorn app.main:app --host 127.0.0.1 --port "$SMOKE_PORT" --no-access-log >/dev/null || return 1
  local ok=0
  for _ in $(seq 1 30); do
    if curl -fsS -m 2 "http://127.0.0.1:$SMOKE_PORT/healthz" >/tmp/mg-hz.json 2>/dev/null; then
      echo "  healthz -> $(cat /tmp/mg-hz.json)"; ok=1; break
    fi
    sleep 2
  done
  docker rm -f mg-smoke >/dev/null 2>&1 && echo "  容器已清理"
  [ $ok -eq 1 ] || { echo "  !! healthz 没起来"; return 1; }

  [ $rc -eq 0 ] || { echo "  !! 测试有失败项"; return 1; }
}

do_pack() {
  hr "3) docker save"
  mkdir -p "$OUT_DIR"
  rm -f "$TAR"
  time docker save -o "$TAR" "$IMG" || return 1
  ls -l "$TAR"

  hr "3.1) tar 结构"
  echo "  条目数: $(tar -tf "$TAR" | wc -l)"
  tar -xOf "$TAR" manifest.json 2>/dev/null | grep -o '"RepoTags":\[[^]]*\]'

  hr "3.2) sha256"
  ( cd "$OUT_DIR" && sha256sum "mefrp-guard-v${VERSION}.tar" | tee SHA256SUM.txt )

  hr "3.3) 往返校验：rmi 后重新 load，image ID 必须一致"
  local before after
  before=$(docker image inspect "$IMG" --format '{{.Id}}')
  echo "  load 前 Id: $before"
  docker rmi "$IMG" >/dev/null 2>&1
  docker load -i "$TAR" 2>&1 | tail -2
  after=$(docker image inspect "$IMG" --format '{{.Id}}')
  echo "  load 后 Id: $after"
  if [ "$before" = "$after" ]; then
    echo "  ★ 往返一致"
  else
    echo "  !! 不一致"; return 1
  fi
}

case "$CMD" in
  build)  do_build ;;
  verify) do_verify ;;
  pack)   do_pack ;;
  all)    do_build && do_verify && do_pack ;;
  *) echo "用法: $0 [build|verify|pack|all] [--mirror|--no-mirror|--no-cache]" >&2; exit 1 ;;
esac
