#!/usr/bin/env bash
# tools/mcp-health.sh — 多 MCP 健康度自检 + 启动命令提示
# 用法: bash tools/mcp-health.sh [<target_dir>]
# 输出: JSON 状态 → stdout (并写到 <target_dir>/mcp-status.json 如果给了 target_dir)
# 退出码: 0=全 healthy / 2=有降级 / 1=全 down
#
# v2 升级:从"进程是否存在"升级为"功能性检查"
#   - js-reverse-mcp: Chrome DevTools /json/list 可返回页面列表
#   - everything-mcp: Python everything_mcp 模块可执行搜索
#   - scrcpy-mcp: adb 可列出设备 + scrcpy-server 文件存在

set -u

TARGET="${1:-}"
NOW=$(date '+%Y-%m-%dT%H:%M:%S%z' | sed 's/\(..\)$/:\1/')
TL=""
[ -n "$TARGET" ] && [ -d "$TARGET" ] && TL="$TARGET/timeline.md"

log_tl() {
  [ -n "$TL" ] && [ -f "$TL" ] && echo "$(date '+%Y-%m-%d %H:%M') $*" >> "$TL"
}

MCP_JSON=".mcp.json"

: ${PY_MCP:=""}

# 统一 Python 发现(与框架一致)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/lib/find-python.sh" ]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/lib/find-python.sh"
  if srccop_require_python 2>/dev/null; then
    PY_MCP="$PY"
  fi
fi
if [ -z "$PY_MCP" ]; then
  for cand in python python3; do
    if command -v "$cand" >/dev/null 2>&1; then
      PY_MCP="$cand"; break
    fi
  done
fi

mcp_script_path() {
  local name="$1"
  if [ -z "$PY_MCP" ] || [ ! -f "$MCP_JSON" ]; then
    echo ""
    return
  fi
  "$PY_MCP" -c "
import json
try:
    d=json.load(open('$MCP_JSON'))
    srv=d.get('mcpServers',{}).get('$name',{})
    args=srv.get('args',[])
    # first positional script argument, if any
    for a in args:
        if a.endswith('.py') and not a.startswith('-'):
            print(a)
            break
except Exception:
    pass
" 2>/dev/null | tr -d '\r' || true
}

list_servers() {
  if [ ! -f "$MCP_JSON" ]; then
    echo ""
    return
  fi
  if [ -z "$PY_MCP" ]; then
    echo ""
    return
  fi
  "$PY_MCP" -c "import json; d=json.load(open('$MCP_JSON')); print('\n'.join(d.get('mcpServers',{}).keys()))" 2>/dev/null | tr -d '\r' || true
}

# --- 功能性健康检测 ---
check_jsreverse() {
  # v1: 仅检查 /json/version
  # v2: 检查 /json/list 能返回页面列表(等价于 list_pages 能力)
  local list_rc
  list_rc=$(curl -s --max-time 3 "http://127.0.0.1:9222/json/list" -o /dev/null -w '%{http_code}' 2>/dev/null || true)
  if [ "$list_rc" = "200" ]; then
    # 进一步确认返回的是 JSON 数组(非空)
    local cnt
    cnt=$(curl -s --max-time 3 "http://127.0.0.1:9222/json/list" 2>/dev/null | "$PY_MCP" -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo 0)
    if [ "${cnt:-0}" -gt 0 ] 2>/dev/null; then
      echo "healthy|0|Chrome DevTools /json/list 返回 $cnt 个页面"
    else
      echo "degraded|1|Chrome 可连但无页面(可能未打开浏览器)"
    fi
  elif curl -s --max-time 2 "http://127.0.0.1:9222/json/version" -o /dev/null -w '%{http_code}' 2>/dev/null | grep -q '^200$'; then
    echo "degraded|1|Chrome 可连但 /json/list 异常"
  elif command -v shuji >/dev/null 2>&1; then
    echo "degraded|1|shuji 可用但 Chrome DevTools 不可连"
  else
    echo "down|2|Chrome DevTools 未启动且无 shuji fallback"
  fi
}

check_everything() {
  # v2: 尝试用 everything_mcp 模块执行一次搜索
  local py_result
  py_result=$("$PY_MCP" -c "
import sys, json
try:
    from everything_mcp.server import search
    # 尝试搜索一个常见词,超时由外部控制
    r = search('test', max_results=1)
    print('healthy|0|Everything 搜索 test 成功')
except Exception as e:
    print('degraded|1|Everything 模块异常: ' + str(e)[:60])
" 2>/dev/null)
  if [ -n "$py_result" ] && echo "$py_result" | grep -q '^healthy'; then
    echo "$py_result"
  elif command -v rg >/dev/null 2>&1; then
    echo "degraded|1|Everything 搜索失败,但 rg 可用作 fallback"
  elif command -v grep >/dev/null 2>&1; then
    echo "degraded|1|Everything 搜索失败,仅有 grep fallback"
  else
    echo "down|2|Everything 不可用且无 fallback"
  fi
}

check_scrcpy() {
  # v2: adb 能列出设备 + scrcpy-server 文件存在
  local server_path
  server_path=$("$PY_MCP" -c "import json; d=json.load(open('.mcp.json')); print(d.get('mcpServers',{}).get('scrcpy-mcp',{}).get('env',{}).get('SCRCPY_SERVER_PATH',''))" 2>/dev/null | tr -d '\r')
  local has_adb_device=0
  if command -v adb >/dev/null 2>&1; then
    if adb devices 2>/dev/null | grep -qE "device$"; then
      has_adb_device=1
    fi
  fi
  local has_server=0
  [ -n "$server_path" ] && [ -f "$server_path" ] && has_server=1

  if [ "$has_adb_device" -eq 1 ] && [ "$has_server" -eq 1 ]; then
    echo "healthy|0|adb 已连接设备且 scrcpy-server 存在"
  elif [ "$has_adb_device" -eq 1 ]; then
    echo "degraded|1|adb 已连接设备但 scrcpy-server 路径无效"
  elif command -v adb >/dev/null 2>&1; then
    echo "degraded|1|adb 可用但无设备连接"
  else
    echo "down|2|adb 不可用"
  fi
}

check_adb() {
  if command -v adb >/dev/null 2>&1; then
    if adb devices 2>/dev/null | grep -qE "device$"; then
      echo "healthy|0|adb 已连接设备"
    else
      echo "degraded|1|adb 可用但无设备"
    fi
  else
    echo "down|2|adb 不可用"
  fi
}

check_file_server() {
  local script_path="$1"
  if [ -f "$script_path" ]; then
    echo "healthy|0|脚本文件存在"
  else
    echo "down|2|脚本文件缺失"
  fi
}

check_idapro() {
  if curl -s --max-time 2 "http://127.0.0.1:13337" -o /dev/null -w '%{http_code}' 2>/dev/null | grep -qE '^(200|401|403)$'; then
    echo "healthy|0|IDA RPC 可连"
  else
    echo "down|2|IDA RPC 未启动"
  fi
}

# --- 根据 .mcp.json 生成启动命令提示 ---
get_startup_hint() {
  local name="$1"
  case "$name" in
    js-reverse-mcp)
      echo "npx -y js-reverse-mcp@latest --isolated  (需 Chrome 9222 端口可连)" ;;
    scrcpy-mcp)
      echo "npx -y scrcpy-mcp@latest  (需 SCRCPY_SERVER_PATH / ADB_PATH 环境变量)" ;;
    adb-mcp)
      echo "npx -y android-debug-bridge-mcp@latest  (需 ANDROID_HOME / ADB_PATH)" ;;
    everything-mcp)
      echo "\$PY_MCP -m everything_mcp  (需 Everything 服务运行)" ;;
    jadx-mcp)
      echo "\$PY_MCP \$(mcp_script_path jadx-mcp)" ;;
    frida-mcp)
      echo "\$PY_MCP \$(mcp_script_path frida-mcp)" ;;
    idapro-mcp)
      echo "需先启动 IDA Pro 并启用 ida_pro_mcp RPC (http://127.0.0.1:13337)" ;;
    *)
      echo "见 .mcp.json 中 $name 配置" ;;
  esac
}

# --- 主检测 ---
SERVERS=$(list_servers)
if [ -z "$SERVERS" ]; then
  echo "⚠️  $MCP_JSON 不存在或无 mcpServers 配置" >&2
  echo '{"checked_at":"'"$NOW"'","error":".mcp.json missing or empty"}'
  exit 1
fi

JSON_PAIRS=()
overall_max_tier=0
any_down=0
any_degraded=0

echo "━━━ MCP 健康检查 ━━━" >&2
for srv in $SERVERS; do
  case "$srv" in
    js-reverse-mcp) result=$(check_jsreverse) ;;
    everything-mcp) result=$(check_everything) ;;
    scrcpy-mcp)     result=$(check_scrcpy) ;;
    adb-mcp)        result=$(check_adb) ;;
    jadx-mcp)       result=$(check_file_server "$(mcp_script_path jadx-mcp)") ;;
    frida-mcp)      result=$(check_file_server "$(mcp_script_path frida-mcp)") ;;
    idapro-mcp)     result=$(check_idapro) ;;
    *)              result="degraded|1|未知服务器类型" ;;
  esac

  status=$(echo "$result" | cut -d'|' -f1)
  tier=$(echo "$result" | cut -d'|' -f2)
  detail=$(echo "$result" | cut -d'|' -f3-)
  [ "$tier" -gt "$overall_max_tier" ] && overall_max_tier=$tier
  [ "$status" = "down" ] && any_down=1
  [ "$status" = "degraded" ] && any_degraded=1

  hint=$(get_startup_hint "$srv")
  JSON_PAIRS+=("\"$srv\":{\"status\":\"$status\",\"tier\":$tier,\"detail\":\"$detail\",\"startup_hint\":\"$hint\"}")

  echo "  $srv: $status (tier-$tier) — $detail" >&2
  if [ "$status" = "down" ]; then
    echo "    ↳ 启动: $hint" >&2
  fi
  log_tl "[mcp-health] $srv $status tier-$tier — $detail"
done

# 构造 JSON
json_body=$(printf '%s,' "${JSON_PAIRS[@]}")
json_body=${json_body%,}
JSON=$(cat << EOF
{
  "checked_at": "$NOW",
  "overall_max_tier": $overall_max_tier,
  "servers": {
    $json_body
  }
}
EOF
)

echo "$JSON"

# 写 target 状态文件
if [ -n "$TARGET" ] && [ -d "$TARGET" ]; then
  echo "$JSON" > "$TARGET/mcp-status.json"
fi

if [ "$overall_max_tier" -eq 0 ]; then
  exit 0
elif [ "$any_down" -eq 1 ] && [ "$any_degraded" -eq 0 ] && [ "$overall_max_tier" -eq 2 ]; then
  exit 1
else
  exit 2
fi
