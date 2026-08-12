#!/usr/bin/env bash
# tools/state-checkpoint-hook.sh — PostToolUse hook（防失忆强制提醒）
#
# 作用：AI 写 targets/ 下文件时，检查对应【当日 rounds 卷】与【_STATE.md 摘要行】是否同步；
#       v4 P0-2 分卷后：叙事进 output/rounds/<当日日期>.md，_STATE 只存摘要行（7 段，<30KB）。
#       提醒条件：
#         写非 rounds/ 卷文件 → 当日卷缺失或更旧 → 提醒补写轮次段；
#         _STATE.md 比刚写文件旧（含刚写完卷本身）→ 提醒更新摘要行+时间戳。
# 触发：settings.json PostToolUse Write|Edit
# 输入：stdin 收到 Claude Code 的 hook JSON
# 原理：_STATE.md + 当日卷是唯一续接依据；每次有进展的写入后立即同步，保证突然退出/compaction 不失忆。

set -u
export PYTHONIOENCODING=utf-8

input=$(cat)

# 提取 file_path（优先 python 解析，失败则 grep fallback）
file_path=$(printf '%s' "$input" | python -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ti = d.get('tool_input', {})
    print(ti.get('file_path', '') or ti.get('filePath', ''))
except Exception:
    pass
" 2>/dev/null)

if [ -z "$file_path" ]; then
  file_path=$(printf '%s' "$input" | grep -oE '"file_?[Pp]ath"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
fi

# 只关心 targets/ 下的写入，且不是 _STATE.md 本身
case "$file_path" in
  */targets/*|*\\targets\\*)
    fname="${file_path##*/}"
    fname="${fname##*\\}"
    [ "$fname" = "_STATE.md" ] && exit 0

    # 向上找 _STATE.md 所在的 target 根目录
    dir=$(dirname "$file_path")
    state=""
    while [ "$dir" != "." ] && [ "$dir" != "/" ] && [ -n "$dir" ]; do
      if [ -f "$dir/_STATE.md" ]; then
        state="$dir/_STATE.md"
        break
      fi
      ndir=$(dirname "$dir")
      [ "$ndir" = "$dir" ] && break
      dir="$ndir"
    done

    if [ -z "$state" ]; then
      echo "⚠️ [防失忆] 检测到 target 目录写入($fname)但无 _STATE.md。请立即创建 _STATE.md（cp targets/_template/_STATE.md），否则会话中断后无法续接。" >&2
      exit 0
    fi

    # v4 P0-2 分卷：当日卷 + _STATE 摘要行双检查
    state_dir=$(dirname "$state")
    day_volume="$state_dir/output/rounds/$(date +%F).md"
    is_volume=false
    case "$file_path" in
      */rounds/*|*\\rounds\\*) is_volume=true ;;
    esac

    if [ "$is_volume" = false ]; then
      # 非卷文件（findings/lifecycle/探针产物…）→ 检查当日卷是否已同步
      if [ ! -f "$day_volume" ]; then
        echo "⚠️ [防失忆] 你刚写了 $fname，但当日轮次卷缺失（$day_volume）。请立即追加轮次段 \`## P-<NNN> <主题>（$(date +%F)）\`，叙事只进卷，_STATE 不存长文。" >&2
      elif [ "$file_path" -nt "$day_volume" ]; then
        echo "⚠️ [防失忆] 你刚写了 $fname，比当日卷 $day_volume 新。请立即把进展追加进当日卷（新探针/新 finding/新死路/阶段切换都算）。" >&2
      fi
    fi

    # _STATE 摘要行检查（卷写完也提醒：摘要行+时间戳必须同步）
    if [ "$day_volume" -nt "$state" ] || { [ "$is_volume" = true ] && [ "$file_path" -nt "$state" ]; }; then
      echo "⚠️ [防失忆] 轮次卷已更新但 _STATE.md 落后。请立即更新 _STATE.md 的「当前阶段/下一步」摘要行 +「最后更新」时间戳（叙事勿进 _STATE，>30KB 即违规）。" >&2
    fi
    ;;
esac
exit 0
