#!/usr/bin/env bash
# 跑全部测试。
#
# 纯逻辑测试不需要任何第三方库；API / 故障转移测试需要 fastapi + httpx + pydantic。
# 如果本机没有，可以临时装到隔离目录（不污染环境）：
#
#   PY=<python>
#   $PY -m pip install --target .devdeps fastapi httpx pydantic
#   PYTHONPATH=$PWD/.devdeps $PY tests/test_api.py
#
set -u
PY="${PY:-python3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rc=0
for t in test_auth test_logic test_api test_failover test_frpc_multi; do
  echo "=================== $t ==================="
  "$PY" "tests/$t.py" || rc=1
done
echo
[ $rc -eq 0 ] && echo "全部通过" || echo "有失败项"
exit $rc
