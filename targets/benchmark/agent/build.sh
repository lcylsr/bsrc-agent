#!/usr/bin/env bash
# 构建并导出托管模式镜像
# 用法: bash targets/benchmark/agent/build.sh
# 产物: targets/benchmark/agent/agent.tar.gz（上传到 TSecBench 平台）
set -euo pipefail
cd "$(dirname "$0")"

echo "=== 1/3 构建镜像 ==="
docker build -t agent-solver:latest .

echo "=== 2/3 导出并压缩 ==="
docker save agent-solver:latest | gzip > agent.tar.gz

echo "=== 3/3 完成 ==="
ls -lh agent.tar.gz
echo "上传到平台「制作并上传 Docker 镜像」即可"
