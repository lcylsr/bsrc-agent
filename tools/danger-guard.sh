#!/usr/bin/env bash
# tools/danger-guard.sh — PreToolUse 危险命令拦截 hook
#
# 由 settings.json 的 PreToolUse(matcher: Bash)调用,从 stdin 读 hook JSON,
# 提取将要执行的 Bash 命令,匹配"灾难性不可逆"模式 → exit 2 硬阻断(Claude Code
# 对 PreToolUse 的 exit 2 = 拦截工具调用并把 stderr 回灌给 LLM)。
#
# 设计原则(guardrails-not-rails):只拦"几乎一定是灾难"的少数模式,宁可漏拦
# 不可滥拦。法律红线 §危险命令 的工程兜底。非危险命令一律放行(exit 0)。
#
# 拦截清单:
#   1. fork bomb            :(){ :|:& };:
#   2. rm 递归强删危险根     rm -rf / | /* | ~ | ~/ | $HOME | . | ./ | 裸 *
#   3. 磁盘擦除             mkfs.* / dd of=/dev/sdX / > /dev/sdX
#   4. SQL 摧毁数据         DROP TABLE|DATABASE|SCHEMA / TRUNCATE TABLE(红线"不动他人数据")
#   5. 重武器 payload       RCE / 反序列化 / 文件上传 / JNDI 注入等(红线"重武器先请示")
#   6. 业务破坏意图(语义)  tools/lib/business_impact.py
#      — 按 HTTP method × path 动作 × body 字段角色 判定改密/删数据/资金提交/SQL 写
#      — 不是纯关键词:POST /login + password 放行;POST /resetPassword + newPassword 拦截
#
# 设计说明:
#   - 重武器拦截匹配命令字符串中的真实 payload,不拦 echo/grep/文档中的关键词
#   - 命中后 exit 2 硬阻断,要求用户显式确认或临时移除 hook
#   - 法律红线 §4.1 的自动化兜底,不是替代 AI 自律
#   - 显式放行: SRCOOP_DANGER_ALLOW=1 (须用户确认后临时设置,并写 timeline)
#
# 退出码: 0 = 放行(默认) / 2 = 拦截

set -uo pipefail

# 读 stdin(hook JSON);非阻塞,空输入直接放行
INPUT=""
if [ ! -t 0 ]; then
  INPUT="$(cat 2>/dev/null || true)"
fi
[ -z "$INPUT" ] && exit 0

# 强制放行逃生口(用户拍板后临时开;business_impact 同步尊重此 env)
if [ "${SRCOOP_DANGER_ALLOW:-}" = "1" ] || [ "${SRCOOP_DANGER_ALLOW:-}" = "true" ] || [ "${SRCOOP_DANGER_ALLOW:-}" = "yes" ]; then
  exit 0
fi

# 只关心 Bash 工具(matcher 已限定,但双保险)
echo "$INPUT" | grep -qE '"tool_name"[[:space:]]*:[[:space:]]*"Bash"' || exit 0

# 提取"命令位置"内容:JSON 里 "command":" 之后到第一个引号为止 = 真正要执行的命令头部。
# 引号内的参数/payload(echo "rm -rf /" / grep "DROP TABLE")会被自然截掉 → 不误拦。
# (guardrails-not-rails:渗透场景频繁 echo/grep 危险字符串,只拦真正执行位的灾难命令。)
CMDVAL=$(echo "$INPUT" | sed -E 's/.*"command"[[:space:]]*:[[:space:]]*"//')
CMDPOS=$(echo "$CMDVAL" | sed -E 's/".*//')

reason=""

# ── 1. fork bomb ──(命令位)
if echo "$CMDPOS" | grep -qE ':[[:space:]]*\(\)[[:space:]]*\{[[:space:]]*:[[:space:]]*\|[[:space:]]*:'; then
  reason="fork bomb(:(){ :|:& };:)"
fi

# ── 2. rm 递归强删危险根目录 ──(命令位)
if [ -z "$reason" ] && echo "$CMDPOS" | grep -qE 'rm[[:space:]]+([^|;&]*[[:space:]])?-([[:alnum:]]*[rR][[:alnum:]]*[fF][[:alnum:]]*|[[:alnum:]]*[fF][[:alnum:]]*[rR][[:alnum:]]*)'; then
  if echo "$CMDPOS" | grep -qE 'rm[[:space:]]+[^|;&]*([[:space:]]|=)(/|/\*|~|~/|\$HOME|\$\{HOME\}|\.|\./|\*)([[:space:]"'\''\\]|$)'; then
    reason="rm 递归强删危险根目录(/ ~ \$HOME . 或裸 *)"
  elif echo "$CMDPOS" | grep -qE 'rm[[:space:]]+[^|;&]*[[:space:]]/(etc|usr|var|bin|boot|lib|home|root|sys|proc)([[:space:]/"'\''\\]|$)'; then
    reason="rm 递归强删系统顶层目录(/etc /usr /var ...)"
  fi
fi

# ── 3. 磁盘擦除 ──(命令位)
if [ -z "$reason" ]; then
  if echo "$CMDPOS" | grep -qE '\bmkfs(\.[a-z0-9]+)?[[:space:]]'; then
    reason="mkfs 格式化"
  elif echo "$CMDPOS" | grep -qE '\bdd[[:space:]]+[^|;&]*of=/dev/(sd|nvme|hd|vd|disk)'; then
    reason="dd 写裸磁盘设备"
  elif echo "$CMDPOS" | grep -qE '>[[:space:]]*/dev/(sd|nvme|hd|vd)[a-z]'; then
    reason="重定向覆写裸磁盘设备"
  fi
fi

# ── 4. SQL 摧毁数据(红线:不动他人数据)──
# 用整条命令值(SQL 通常在 -e "..." 引号内),但必须同时出现 DB 客户端调用才判定,
# 避免 echo/grep/散文里的 "drop schema" 误报。
# 更细的 INSERT/UPDATE/DELETE 由 §6 business_impact 语义层覆盖。
if [ -z "$reason" ] && echo "$CMDVAL" | grep -qiE '\b(mysql|mariadb|psql|sqlite3?|sqlcmd|sqlplus|mongosh?|clickhouse-client)\b'; then
  if echo "$CMDVAL" | grep -qiE '\bDROP[[:space:]]+(TABLE|DATABASE|SCHEMA)\b'; then
    reason="SQL DROP TABLE/DATABASE/SCHEMA(红线:不动他人数据)"
  elif echo "$CMDVAL" | grep -qiE '\bTRUNCATE[[:space:]]+TABLE\b'; then
    reason="SQL TRUNCATE TABLE(红线:不动他人数据)"
  fi
fi

# ── 5. 重武器 payload(红线:重武器先请示)──
# 匹配真实执行场景中的 RCE / 反序列化 / 文件上传 / JNDI 等 payload。
# 白名单:grep/echo/cat 等纯文本查看/输出命令中的危险字符串不拦截(散文/文档/搜索)。
if [ -z "$reason" ]; then
  is_text_viewer=0
  if echo "$CMDPOS" | grep -qE '^(grep|egrep|fgrep|echo|printf|cat|head|tail|sed|awk|wc|sort|uniq|tr|cut|tee|xxd|od|base64)[[:space:]]'; then
    is_text_viewer=1
  fi

  if [ "$is_text_viewer" -eq 0 ]; then
    # JNDI 注入
    if echo "$CMDVAL" | grep -qiE '\bjndi:(ldap|dns|rmi|iiop|nis|corba)://'; then
      reason="JNDI 注入 payload(jndi:xxx://) — 重武器先请示"
    # 反序列化 gadget / ysoserial
    elif echo "$CMDVAL" | grep -qiE '\bysoserial\b|CommonsCollections[0-9]|ObjectInputStream|readObject[[:space:]]*\('; then
      reason="反序列化 payload / ysoserial / CommonsCollections — 重武器先请示"
    # 反弹 shell / 命令执行
    elif echo "$CMDVAL" | grep -qiE '\bbash[[:space:]]+(-i|--interactive)\b|bash[[:space:]]+.*>&[[:space:]]*/dev/tcp|/bin/sh[[:space:]]+-i\b|\becho[[:space:]]+[^|]*\|[[:space:]]*/bin/bash|\bnc[[:space:]]+(-e|-c)\b|\bpython[0-9]?[[:space:]]+-c[[:space:]]+.*socket'; then
      reason="反弹 shell / 远程命令执行 payload — 重武器先请示"
    # powershell 编码执行
    elif echo "$CMDVAL" | grep -qiE '\bpowershell\.[a-z]+|powershell[[:space:]]+(-enc|-encodedcommand|-e[[:space:]]|-ep[[:space:]]bypass)\b'; then
      reason="PowerShell 编码/绕过执行 — 重武器先请示"
    # WebShell / eval
    elif echo "$CMDVAL" | grep -qiE '<\?(php|asp)[[:space:]]+@?(eval|assert|system|exec|passthru|shell_exec)|<%@?\s*(eval|Execute|Response\.Write|Request\.Item)|\beval\s*\(|\bassert\s*\('; then
      reason="WebShell / eval 执行 payload — 重武器先请示"
    # Java 命令执行
    elif echo "$CMDVAL" | grep -qiE 'Runtime\.getRuntime\s*\(\s*\)\.exec|ProcessBuilder\s*\(|java\.lang\.Runtime'; then
      reason="Java 命令执行 payload — 重武器先请示"
    # 文件上传: multipart -F 配合危险后缀
    elif echo "$CMDVAL" | grep -qiE '\b(curl|wget)[[:space:]]+.*-[fF][[:space:]]+[^;|]*[\"\047]?[^;|]*\.(jsp|jspx|php|php3|php5|phtml|asp|aspx|ashx|asmx|cer|war|sh|bat|cmd|ps1|vbs|py|pl)\b'; then
      reason="multipart 文件上传危险后缀 — 重武器先请示"
    # 云上元数据 SSRF 批量探测(非单包验证)
    elif echo "$CMDVAL" | grep -qiE '169\.254\.169\.254.*(latest|meta-data)|metadata\.google\.internal|instance-data|aliyun\.com/metadata'; then
      reason="云元数据 SSRF 批量探测 — 重武器先请示"
    fi
  fi
fi

if [ -n "$reason" ]; then
  echo "🛑 [danger-guard] 已拦截危险命令: $reason" >&2
  echo "   命中法律红线 / 灾难性不可逆操作。如确属授权且必要,请用户在 ! 前缀手动执行,或临时 SRCOOP_DANGER_ALLOW=1。" >&2
  exit 2
fi

# ── 6. 业务破坏意图(语义分类,非纯关键词)──
# method × path 动作 × body 字段角色。登录/只读放行;改密/DELETE/资金/SQL 写拦截。
# 解析失败 fail-open(exit 0),避免 hook 误杀整条链路。
_DG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$_DG_DIR/lib/find-python.sh" ] && [ -f "$_DG_DIR/lib/business_impact.py" ]; then
  # shellcheck source=lib/find-python.sh
  source "$_DG_DIR/lib/find-python.sh"
  if PY="$(srccop_find_python 2>/dev/null)" && [ -n "$PY" ]; then
    _BI_ERR="$("$PY" "$_DG_DIR/lib/business_impact.py" <<<"$INPUT" 2>&1 >/dev/null)"
    _BI_RC=$?
    if [ "$_BI_RC" -eq 2 ]; then
      echo "🛑 [danger-guard] 业务破坏意图拦截: ${_BI_ERR:-business_impact deny}" >&2
      echo "   按接口语义判定(改密/删数据/资金写/SQL 写等)。授权测试请用户确认后 SRCOOP_DANGER_ALLOW=1 并 timeline 留痕。" >&2
      echo "   判据见 tools/lib/business_impact.py;自测: python tools/lib/business_impact.py --selftest" >&2
      exit 2
    fi
  fi
fi

exit 0
