#!/bin/bash
# tools/playbook/run.sh
# 用法: bash tools/playbook/run.sh <target_dir> [--mock <fixture_dir>] [--audit-only]
#
# v6.0-slim: 仅保留 match + quickcheck 两阶段。audit/upgrade 已随 gate 体系移除，
# 命中后的深度验证由 AI 按 skills/orchestrator.md 阶段 3 直接驱动。
#
# 参数:
#   --mock <dir>     传给 quickcheck.py 用 fixture 而非真实请求
#   --audit-only     已废弃: audit.sh 已删除,保留参数仅输出 no-op 提示

set -uo pipefail

if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; B=$'\033[34m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; C=""; B=""; N=""
fi

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "用法: $0 <target_dir> [--mock <dir>] [--audit-only]" >&2; exit 1; }
[ ! -d "$TARGET" ] && { echo "${R}✗ 目录不存在: $TARGET${N}" >&2; exit 1; }

shift
MOCK_ARGS=()
AUDIT_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --mock)
      MOCK_ARGS=(--mock "$2")
      shift 2
      ;;
    --audit-only)
      AUDIT_ONLY=1
      shift
      ;;
    *)
      echo "${R}✗ 未知参数: $1${N}" >&2
      exit 1
      ;;
  esac
done

DIR="$(cd "$(dirname "$0")" && pwd)"

# 定位仓库根并 cd(match.py/quickcheck.py 依赖相对路径 memory/playbooks/)
ROOT="$(git -C "$DIR" rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$DIR")/..")"
cd "$ROOT" || { echo "✗ 无法进入仓库根: $ROOT" >&2; exit 1; }

# TARGET 相对路径转绝对(cd 根之后相对路径会失效)
case "$TARGET" in
  /*|[A-Za-z]:*) ;;
  *) TARGET="$(cd "$(pwd)/$TARGET" 2>/dev/null && pwd || echo "$TARGET")" ;;
esac

if [ $AUDIT_ONLY -eq 1 ]; then
  echo "${Y}⚠ --audit-only 已废弃: audit.sh 已随 gate 体系删除。" >&2
  echo "  命中后的深度验证请直接读 skills/orchestrator.md 阶段 3 并由 AI 驱动。${N}" >&2
fi

echo "${C}╔══════════════════════════════════════════════════╗${N}"
echo "${C}║${N}  playbook 子系统 — v6.0-slim forward loop        ${C}║${N}"
echo "${C}║${N}  match.py → quickcheck.py                        ${C}║${N}"
echo "${C}╚══════════════════════════════════════════════════╝${N}"
echo

# ── 1. match ──
echo "${B}[1/2] match.py${N}"
if ! python "$DIR/match.py" "$TARGET"; then
  echo "${R}✗ match.py 失败${N}"
  exit 1
fi
echo

# ── 2. quickcheck (仅命中时跑) ──
if grep -qE "^playbooks_match:[[:space:]]*\\[\".*\"\\]" "$TARGET/scope.md" 2>/dev/null; then
  echo "${B}[2/2] quickcheck.py${N}"
  if ! python "$DIR/quickcheck.py" "$TARGET" "${MOCK_ARGS[@]}"; then
    echo "${R}✗ quickcheck.py 失败${N}"
    exit 1
  fi
  echo
else
  echo "${Y}[2/2] 跳过 quickcheck (无 playbook 命中)${N}"
  echo
  echo "${G}━━━ 完成(无命中,目标不属于已知 playbook)━━━${N}"
  exit 0
fi

echo "${G}━━━ 子系统流程完成 ━━━${N}"
echo
echo "下一步:"
echo "  - 读 scope.md ## playbook 件状态,由 AI 按 skills/orchestrator.md 阶段 3 做深度验证"
echo "  - verified 后写 findings.md;无实证则保持 phenomenon/candidate"
