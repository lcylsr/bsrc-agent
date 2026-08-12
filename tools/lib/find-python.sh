#!/usr/bin/env bash
# tools/lib/find-python.sh — 全框架统一 Python 解释器发现
#
# 问题背景(v5.2.2):
#   Windows App Execution Aliases 会把 `python3` 指到
#   %LOCALAPPDATA%/Microsoft/WindowsApps/python3.exe(Store 占位),
#   exit code 常为 49,导致 poc-replay.sh 等 wrapper "假跑通"。
#
# 用法:
#   source "$(dirname "$0")/lib/find-python.sh"   # 从 tools/*.sh
#   source "$(cd "$(dirname "$0")" && pwd)/find-python.sh"  # 从 tools/lib/*.sh
#   PY=$(srccop_find_python) || exit 3
#   srccop_require_python || exit 3   # 设 $PY,找不到则打印错误并返回 1
#
# 优先级:
#   1) $SRCOOP_PYTHON / $PYTHON / $GATE_PYTHON(显式覆盖)
#   2) 已知本机路径(D:/python3.12 等)
#   3) PATH 中的 `python`(过滤 WindowsApps 占位)
#   4) PATH 中的 `python3`(过滤 WindowsApps)
#   5) `py -3` launcher 解析出的真实 exe
#   6) 通配扫描 C:/D:/Python* 与 %LOCALAPPDATA%/Programs/Python
#
# 环境:
#   SRCOOP_PYTHON / PYTHON / GATE_PYTHON — 强制指定解释器

# 返回 0 若路径像 Windows Store 占位(不可用)
_srccop_is_store_stub() {
  local p="$1"
  case "$p" in
    *[Ww]indows[Aa]pps*) return 0 ;;
    *) return 1 ;;
  esac
}

# 候选可执行且 --version 成功(过滤 stub)
_srccop_python_ok() {
  local cand="$1"
  [ -n "$cand" ] || return 1
  if [ -f "$cand" ] || [ -x "$cand" ]; then
    :
  elif ! command -v "$cand" >/dev/null 2>&1; then
    return 1
  fi
  # resolve to real path when possible
  local resolved
  resolved=$(command -v "$cand" 2>/dev/null || true)
  [ -n "$resolved" ] || resolved="$cand"
  if _srccop_is_store_stub "$resolved"; then
    return 1
  fi
  # smoke: print version, ignore stdout noise
  if "$cand" -c "import sys; assert sys.version_info >= (3, 8)" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# 打印一个可用 python 路径到 stdout;失败返回 1
srccop_find_python() {
  local env_override="${SRCOOP_PYTHON:-${PYTHON:-${GATE_PYTHON:-}}}"
  if [ -n "$env_override" ]; then
    if _srccop_python_ok "$env_override"; then
      printf '%s' "$env_override"
      return 0
    fi
    # 显式指定但不可用:仍尝试继续搜索,并在 stderr 提示
    echo "⚠ find-python: SRCOOP_PYTHON/PYTHON='$env_override' 不可用,继续搜索" >&2
  fi

  local cand
  # 已知实装路径(本机约定 + 常见安装)
  for cand in \
    /d/python3.12/python.exe \
    /d/python3.12/python \
    /c/Python312/python.exe \
    /c/Python311/python.exe \
    /c/Python310/python.exe \
    "${LOCALAPPDATA:-}/Programs/Python/Python312/python.exe" \
    "${LOCALAPPDATA:-}/Programs/Python/Python311/python.exe"
  do
    [ -n "$cand" ] || continue
    if [ -f "$cand" ] || [ -x "$cand" ]; then
      if _srccop_python_ok "$cand"; then
        printf '%s' "$cand"
        return 0
      fi
    fi
  done

  # PATH: 优先 python,再 python3(避免 Store stub 抢先)
  for cand in python python3; do
    if command -v "$cand" >/dev/null 2>&1; then
      if _srccop_python_ok "$cand"; then
        # 输出 command -v 解析后的路径,避免 hash 别名
        local r
        r=$(command -v "$cand")
        if ! _srccop_is_store_stub "$r"; then
          printf '%s' "$r"
          return 0
        fi
      fi
    fi
  done

  # py -3 launcher
  if command -v py >/dev/null 2>&1; then
    local pyexe
    pyexe=$(py -3 -c "import sys; print(sys.executable)" 2>/dev/null || true)
    if [ -n "$pyexe" ] && _srccop_python_ok "$pyexe"; then
      printf '%s' "$pyexe"
      return 0
    fi
  fi

  # 通配扫描
  local g
  for g in /c/Python*/python.exe /d/Python*/python.exe \
           "${LOCALAPPDATA:-}/Programs/Python/Python*/python.exe"; do
    for cand in $g; do
      [ -f "$cand" ] || continue
      if _srccop_python_ok "$cand"; then
        printf '%s' "$cand"
        return 0
      fi
    done
  done

  return 1
}

# 设全局 PY;失败打印错误返回 1
srccop_require_python() {
  local found
  found=$(srccop_find_python) || {
    echo "✗ find-python: 未找到可用 Python ≥3.8" >&2
    echo "  请安装 Python 或设置 SRCOOP_PYTHON=/path/to/python.exe" >&2
    echo "  并关闭 Windows「应用执行别名」中的 python/python3" >&2
    return 1
  }
  PY="$found"
  export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"
  return 0
}

# 兼容 gate-common 旧名
gate_find_python() {
  srccop_find_python
}
