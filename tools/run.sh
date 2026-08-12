#!/usr/bin/env bash
# tools/run.sh — 统一 Python dispatch wrapper / CLI 入口
# 用法:
#   bash tools/run.sh <tool-name> [args...]
#   bash tools/run.sh --list           # 列出所有可用 Python 工具
#   bash tools/run.sh --help / -h      # 显示本帮助
#
# v6.0-slim 说明:
#   本脚本只负责发现可用 Python 工具并转发参数,不替代任何重脚本。
#   旧 v5.x wrapper(status/pending-tick/dispatch/graph/prompt 等)已删除,
#   如需同等能力,由 AI 按 skills/orchestrator.md 直接驱动。

set -u
export PYTHONIOENCODING=utf-8

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 统一 Python 发现(拒绝 Windows Store stub)
# shellcheck source=lib/find-python.sh
source "$(dirname "$0")/lib/find-python.sh"
if ! srccop_require_python; then
  echo "✗ run.sh: 未找到可用 python" >&2
  exit 1
fi

# 扫描 tools/*.py 并提取第一行 docstring/注释作为描述
generate_tool_list() {
  local max_len=0
  local -a names=()
  local -a descs=()
  for py in "$ROOT"/tools/*.py; do
    [ -f "$py" ] || continue
    local name
    name=$(basename "$py" .py)
    local desc=""
    # 优先提取文件内第一行非 shebang 的 # 或 """ 注释
    desc=$("$PY" - "$py" <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path, encoding='utf-8', errors='ignore') as f:
    lines = f.read().splitlines()
desc = ''
for line in lines[:5]:
    s = line.strip().rstrip('\r')
    if not s or s.startswith('#!/usr/bin'):
        continue
    # """...""" 或 # ...
    m = re.match(r'^#\s*(.*)$', s)
    if m:
        desc = m.group(1).strip()
        break
    m = re.match(r'^"""\s*(.*?)\s*"""$', s)
    if m:
        desc = m.group(1).strip()
        break
    m = re.match(r"^'''\s*(.*?)\s*'''$", s)
    if m:
        desc = m.group(1).strip()
        break
print(desc[:80])
PYEOF
)
    [ ${#name} -gt $max_len ] && max_len=${#name}
    names+=("$name")
    descs+=("$desc")
  done

  echo "可用 Python 工具:"
  echo ""
  local i
  for i in "${!names[@]}"; do
    printf "  %-${max_len}s  %s\n" "${names[$i]}" "${descs[$i]}"
  done
}

show_help() {
  cat <<EOF
usage: bash tools/run.sh <tool-name> [args...]
       bash tools/run.sh --list
       bash tools/run.sh --help | -h

统一 Python 工具调度入口。常用示例:
  bash tools/run.sh recon-pipeline targets/xxx <domain>
  bash tools/run.sh space-recon targets/xxx <domain>
  bash tools/run.sh js-recon targets/xxx <url>
  bash tools/run.sh nday-matcher targets/xxx
  bash tools/run.sh scanner-dispatch nuclei targets/xxx <url>
  bash tools/run.sh ssrf-probe targets/xxx "<url>"
  python tools/findings-lint.py targets/xxx/findings.md
  python tools/agent-launch.py recon-agent targets/xxx --roots <domain>

EOF
  generate_tool_list
}

# 无参数 / --help / -h
TOOL="${1:-}"
if [ -z "$TOOL" ] || [ "$TOOL" = "--help" ] || [ "$TOOL" = "-h" ]; then
  show_help
  exit 0
fi

# --list
if [ "$TOOL" = "--list" ] || [ "$TOOL" = "-l" ]; then
  generate_tool_list
  exit 0
fi

shift

# 工具别名(短命令 -> 实际脚本名)
declare -A TOOL_ALIASES=(
  [scanner-dispatch]=scanner-dispatch
  [ssrf-probe]=ssrf-probe
  [nday-matcher]=nday-matcher
  [space-recon]=space-recon
  [recon-pipeline]=recon-pipeline
  [client-recon]=client-recon
  [miniapp-recon]=miniapp-recon
  [android-recon]=android-recon
  [agent-launch]=agent-launch
)
if [ -n "${TOOL_ALIASES[$TOOL]:-}" ]; then
  TOOL="${TOOL_ALIASES[$TOOL]}"
fi

SCRIPT_PY="$ROOT/tools/${TOOL}.py"
SCRIPT_SH="$ROOT/tools/${TOOL}.sh"

if [ -f "$SCRIPT_PY" ]; then
  exec "$PY" "$SCRIPT_PY" "$@"
fi

if [ -f "$SCRIPT_SH" ]; then
  # 兼容旧薄 wrapper:若 .sh 只是 exec 本脚本,则忽略(避免无限循环)
  first=$(sed -n '/^[^#]/p' "$SCRIPT_SH" | head -1)
  if echo "$first" | grep -qE 'exec.*run\.sh|bash.*run\.sh'; then
    echo "✗ run.sh: tools/${TOOL}.py 不存在(旧 wrapper 已失效)" >&2
    echo "  → 运行 bash tools/run.sh --list 查看可用工具" >&2
    exit 3
  fi
  exec bash "$SCRIPT_SH" "$@"
fi

echo "✗ run.sh: tools/${TOOL}.py 或 tools/${TOOL}.sh 均不存在" >&2
echo "  → 运行 bash tools/run.sh --list 查看可用工具" >&2
exit 3
