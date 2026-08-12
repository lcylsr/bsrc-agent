#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""business_impact.py — 按接口实际情况判定业务破坏意图(非纯关键词)

供 danger-guard PreToolUse 调用。核心原则:
  - 不看"命令里有没有 password 字符串"，而看 **HTTP 方法 × 路径动作 × body 字段角色**
  - 登录/鉴权探测(POST /login + password)允许；改密/重置/删用户/资金提交拦截
  - SQL: 有 DB 客户端时只允许 SELECT 类只读；DDL/DML 写破坏一律拦
  - 设计: guardrails-not-rails — 宁可漏拦不可滥拦鉴权/只读 POC

退出码(作为脚本主入口时):
  0 = 放行
  2 = 拦截(业务破坏/灾难意图)
  1 = 解析失败(fail-open: danger-guard 应视为放行,避免 hook 误杀整条链路)

环境:
  SRCOOP_DANGER_ALLOW=1  → 强制放行(须调用方留痕)
  SRCOOP_BI_DEBUG=1      → stderr 打印判定细节
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ── 路径动作词(segment / camel / snake) ──────────────────────────
# 高危写动作:出现在 path 且 method∈写方法 → 默认拦截
PATH_MUTATION_ACTIONS = {
    # 删除/销毁
    "delete", "remove", "destroy", "drop", "purge", "wipe", "truncate",
    "disable", "ban", "block", "kick", "unbind", "revoke", "invalidate",
    # 改密/凭据变更(非登录)
    "resetpassword", "resetpwd", "reset_password", "reset-password",
    "changepassword", "changepwd", "change_password", "change-password",
    "updatepassword", "updatepwd", "update_password", "update-password",
    "modifypassword", "setpassword", "setpwd", "set_password",
    "forgotpassword", "forgot_password",  # 触发真实短信/邮件改密流
    # 用户/账号写
    "createuser", "adduser", "registeradmin", "deluser", "deleteuser",
    "updateuser", "edituser", "modifyuser", "saveuser",
    # 资金/订单写提交
    "pay", "payment", "checkout", "transfer", "withdraw", "refund",
    "recharge", "purchase", "order/submit", "submitorder", "confirmorder",
    "cancelorder", "closeorder", "void",
    # 权限提升
    "grant", "setrole", "assignrole", "promote", "setadmin",
}

# 鉴权入口:写方法 + password 字段 = 允许(测登录/默认凭据)
AUTH_PATH_HINTS = {
    "login", "signin", "sign-in", "sign_in", "auth", "authenticate",
    "oauth", "token", "gettoken", "access_token", "jwt", "sso",
    "passport", "session", "captcha", "sms/login", "mobile/login",
}

# body 字段角色
PASSWORD_MUTATION_KEYS = {
    "newpassword", "new_password", "newpwd", "new_pwd", "passwordnew",
    "oldpassword", "old_password", "oldpwd", "old_pwd", "passwordold",
    "confirmpassword", "confirm_password", "password2", "repassword",
    "passwordconfirm", "pwdnew", "pwd_new",
}
PASSWORD_AUTH_KEYS = {
    "password", "passwd", "pwd", "pass", "userpassword", "user_password",
    "loginpassword", "login_password",
}
# 资金/破坏性业务字段(与写方法叠加)
MONEY_KEYS = {
    "amount", "money", "price", "payamount", "transferamount", "balance",
    "cardno", "bankcard", "accountno", "toaccount", "fromaccount",
}
DESTRUCTIVE_BODY_KEYS = {
    "drop", "truncate", "force", "harddelete", "permanent", "purge",
}

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
READ_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

DB_CLIENTS = {
    "mysql", "mariadb", "psql", "postgres", "postgresql", "sqlite3", "sqlite",
    "sqlcmd", "sqlplus", "mongosh", "mongo", "clickhouse-client", "redis-cli",
}

# SQL 写/毁
SQL_DESTRUCTIVE = re.compile(
    r"\b(DROP|TRUNCATE|ALTER|CREATE|REPLACE|RENAME|GRANT|REVOKE|ATTACH|DETACH)\b",
    re.I,
)
SQL_DML_WRITE = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|UPSERT|REPLACE\s+INTO)\b",
    re.I,
)
SQL_SELECTISH = re.compile(
    r"\b(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|WITH)\b",
    re.I,
)


@dataclass
class Operation:
    kind: str  # http | sql | shell_disaster | unknown
    method: str = ""
    url: str = ""
    path: str = ""
    body: str = ""
    content_type: str = ""
    sql: str = ""
    raw: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    action: str  # allow | deny
    reason: str
    risk: str = "none"  # none|low|medium|high|critical
    rule: str = ""
    op: Optional[Dict[str, Any]] = None
    signals: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


# ── 命令预处理 ──────────────────────────────────────────────────

def _cmd_position(cmd: str) -> str:
    """命令位:第一个未转义双引号前(与 danger-guard CMDPOS 一致,防 echo 误杀)."""
    # 简化:按未转义 " 切
    out = []
    i, n, esc = 0, len(cmd), False
    while i < n:
        c = cmd[i]
        if esc:
            out.append(c)
            esc = False
        elif c == "\\":
            out.append(c)
            esc = True
        elif c == '"':
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _is_text_viewer(cmdpos: str) -> bool:
    return bool(re.match(
        r"^(grep|egrep|fgrep|echo|printf|cat|head|tail|sed|awk|wc|sort|uniq|tr|cut|tee|xxd|od|base64|less|more)\b",
        cmdpos.strip(),
        re.I,
    ))


# ── HTTP 解析 ───────────────────────────────────────────────────

def _split_commands(cmd: str) -> List[str]:
    """按 shell 管道/串接粗分(保留 curl 主体)."""
    # 不完美但够用: ; && || \n 分割,管道右侧若是 curl 也单独看
    parts = re.split(r"\s*(?:&&|\|\||;|\n)\s*", cmd)
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # 管道:只分析含 http 客户端的段
        for seg in re.split(r"\s*\|\s*", p):
            seg = seg.strip()
            if seg:
                out.append(seg)
    return out


def _extract_curl_ops(segment: str) -> List[Operation]:
    ops: List[Operation] = []
    if not re.search(r"(?:^|[\s/`])curl(?:\.exe)?\b", segment, re.I):
        # httpie / wget 写
        if re.search(r"(?:^|[\s/`])wget(?:\.exe)?\b", segment, re.I):
            return _extract_wget_ops(segment)
        if re.search(r"(?:^|[\s])http(?:ie)?\b", segment):
            return _extract_httpie_ops(segment)
        return ops

    # 用 shlex 失败时 fallback 正则
    try:
        # Windows 路径下 curl 参数常含中文;用 posix=False 对引号更友好
        tokens = shlex.split(segment, posix=os.name != "nt")
    except ValueError:
        tokens = segment.split()

    method = "GET"
    url = ""
    headers: List[str] = []
    data_parts: List[str] = []
    form_parts: List[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        tl = t.lower()
        if t in ("curl", "curl.exe") or t.endswith("\\curl") or t.endswith("/curl"):
            i += 1
            continue
        if tl in ("-x", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
            continue
        if re.fullmatch(r"-(get|head|post|put|patch|delete|options)", tl):
            method = tl[1:].upper()
            i += 1
            continue
        # curl -XPOST 粘连
        m = re.fullmatch(r"-x(get|head|post|put|patch|delete|options)", tl)
        if m:
            method = m.group(1).upper()
            i += 1
            continue
        if tl in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json") and i + 1 < len(tokens):
            data_parts.append(tokens[i + 1])
            if tl == "--json":
                headers.append("Content-Type: application/json")
            # -d 隐含 POST
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if tl in ("-f", "--form") and i + 1 < len(tokens):  # -F form
            form_parts.append(tokens[i + 1])
            if method == "GET":
                method = "POST"
            i += 2
            continue
        # -F without long opt (curl uses -F)
        if t == "-F" and i + 1 < len(tokens):
            form_parts.append(tokens[i + 1])
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if tl in ("-h", "--header") and i + 1 < len(tokens):
            headers.append(tokens[i + 1])
            i += 2
            continue
        if tl.startswith("http://") or tl.startswith("https://") or tl.startswith("ws://"):
            url = t.strip("'\"")
            i += 1
            continue
        # 无 scheme 但像 path/host 且未设 url
        if not url and (t.startswith("/") or "://" in t) and not t.startswith("-"):
            url = t.strip("'\"")
        i += 1

    body = "&".join(data_parts + form_parts)
    ct = ""
    for h in headers:
        if re.match(r"content-type\s*:", h, re.I):
            ct = h.split(":", 1)[1].strip()
    if not url and data_parts:
        # 可能 URL 在后面被引号吞了
        m = re.search(r"https?://[^\s\"']+", segment)
        if m:
            url = m.group(0)

    if url or body or method != "GET":
        path = _url_path(url)
        ops.append(Operation(
            kind="http", method=method, url=url, path=path, body=body,
            content_type=ct, raw=segment[:500],
            meta={"headers": headers[:20]},
        ))
    return ops


def _extract_wget_ops(segment: str) -> List[Operation]:
    method = "GET"
    if re.search(r"--(post-data|post-file|method=POST)", segment, re.I):
        method = "POST"
    m = re.search(r"https?://[^\s\"']+", segment)
    url = m.group(0) if m else ""
    body = ""
    pm = re.search(r"--post-data=([^\s]+)", segment)
    if pm:
        body = pm.group(1).strip("'\"")
    return [Operation(kind="http", method=method, url=url, path=_url_path(url), body=body, raw=segment[:500])]


def _extract_httpie_ops(segment: str) -> List[Operation]:
    # http POST url key=value
    m = re.search(r"\bhttp(?:ie)?\s+(GET|POST|PUT|PATCH|DELETE)\s+(\S+)", segment, re.I)
    if not m:
        return []
    method, url = m.group(1).upper(), m.group(2)
    return [Operation(kind="http", method=method, url=url, path=_url_path(url), body=segment, raw=segment[:500])]


def _url_path(url: str) -> str:
    if not url:
        return ""
    try:
        if "://" not in url and url.startswith("/"):
            return url.split("?", 1)[0]
        p = urllib.parse.urlparse(url)
        return p.path or "/"
    except Exception:
        return url


def _path_tokens(path: str) -> List[str]:
    raw = path.lower().replace("\\", "/")
    parts = re.split(r"[/\-_.]+", raw)
    tokens = []
    for p in parts:
        if not p:
            continue
        tokens.append(p)
        # camelCase split: resetPassword → reset, password
        for w in re.findall(r"[a-z]+|[A-Z][a-z]*", p):
            tokens.append(w.lower())
    # 也放整段 compact
    compact = re.sub(r"[^a-z0-9]", "", raw)
    if compact:
        tokens.append(compact)
    return tokens


def _path_has_auth(path: str) -> bool:
    low = path.lower()
    for h in AUTH_PATH_HINTS:
        if h in low:
            return True
    toks = set(_path_tokens(path))
    return bool(toks & {"login", "signin", "auth", "token", "oauth", "session", "passport"})


def _path_mutation_hits(path: str) -> List[str]:
    low = path.lower()
    hits = []
    compact = re.sub(r"[^a-z0-9]", "", low)
    for act in PATH_MUTATION_ACTIONS:
        act_c = re.sub(r"[^a-z0-9]", "", act)
        if act in low or (act_c and act_c in compact):
            hits.append(act)
    return hits


def _parse_body_keys(body: str, content_type: str = "") -> Dict[str, str]:
    """返回 lower_key → value(截断)."""
    keys: Dict[str, str] = {}
    if not body:
        return keys
    b = body.strip()
    # JSON
    if b.startswith("{") or "json" in (content_type or "").lower():
        try:
            # 可能被 shell 包了引号
            b2 = b
            if (b2.startswith("'") and b2.endswith("'")) or (b2.startswith('"') and b2.endswith('"')):
                b2 = b2[1:-1]
            # 处理 shell 里的 \"
            b2 = b2.replace('\\"', '"').replace("\\'", "'")
            obj = json.loads(b2)
            def walk(o, prefix=""):
                if isinstance(o, dict):
                    for k, v in o.items():
                        kk = f"{prefix}.{k}" if prefix else str(k)
                        if isinstance(v, (dict, list)):
                            walk(v, kk)
                        else:
                            keys[str(k).lower()] = str(v)[:80]
                            keys[kk.lower()] = str(v)[:80]
                elif isinstance(o, list) and o:
                    walk(o[0], prefix)
            walk(obj)
            return keys
        except Exception:
            pass
    # form / query
    try:
        # 去包裹引号
        b2 = b.strip("'\"")
        pairs = urllib.parse.parse_qsl(b2, keep_blank_values=True)
        for k, v in pairs:
            keys[k.lower()] = v[:80]
    except Exception:
        pass
    # 兜底: key=value 扫描
    for m in re.finditer(r'["\']?([A-Za-z_][\w\-\.]*)["\']?\s*[:=]\s*["\']?([^&"\'\s,}]{0,80})', b):
        keys[m.group(1).lower()] = m.group(2)[:80]
    return keys


def _body_role(keys: Dict[str, str]) -> Dict[str, Any]:
    kl = set(keys.keys())
    # 展平: user.password → 也检查 password
    flat = set()
    for k in kl:
        flat.add(k)
        if "." in k:
            flat.add(k.split(".")[-1])
    has_auth_pwd = bool(flat & PASSWORD_AUTH_KEYS)
    has_mut_pwd = bool(flat & PASSWORD_MUTATION_KEYS)
    # 同时有 old+new 也算改密
    if ("oldpassword" in flat or "old_password" in flat or "oldpwd" in flat) and (
        "newpassword" in flat or "new_password" in flat or "password" in flat or "newpwd" in flat
    ):
        has_mut_pwd = True
    has_money = bool(flat & MONEY_KEYS)
    has_destructive = bool(flat & DESTRUCTIVE_BODY_KEYS)
    return {
        "has_auth_password": has_auth_pwd,
        "has_mutation_password": has_mut_pwd,
        "has_money": has_money,
        "has_destructive_flag": has_destructive,
        "keys": sorted(flat)[:40],
    }


# ── SQL 解析 ────────────────────────────────────────────────────

def _extract_sql_ops(cmd: str) -> List[Operation]:
    ops = []
    low = cmd.lower()
    client = None
    for c in DB_CLIENTS:
        if re.search(rf"(?:^|[\s/`]){re.escape(c)}\b", low):
            client = c
            break
    if not client:
        return ops
    # -e / -c / -q 后的 SQL
    sql = ""
    m = re.search(r"(?:-e|--execute|-c)\s+(['\"])(.*?)\1", cmd, re.I | re.S)
    if m:
        sql = m.group(2)
    else:
        m = re.search(r"(?:-e|--execute|-c)\s+(\S+)", cmd, re.I)
        if m:
            sql = m.group(1)
    #  heredoc 或整段
    if not sql:
        m = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b.+", cmd, re.I)
        if m:
            sql = m.group(0)[:500]
    ops.append(Operation(kind="sql", sql=sql or cmd[:300], raw=cmd[:500], meta={"client": client}))
    return ops


# ── 判定 ────────────────────────────────────────────────────────

def classify_http(op: Operation) -> Verdict:
    method = (op.method or "GET").upper()
    path = op.path or _url_path(op.url)
    keys = _parse_body_keys(op.body, op.content_type)
    roles = _body_role(keys)
    mut_hits = _path_mutation_hits(path)
    is_auth_path = _path_has_auth(path)
    signals = [
        f"method={method}",
        f"path={path[:120]}",
        f"auth_path={is_auth_path}",
        f"path_mut={mut_hits[:5]}",
        f"body_roles={ {k: roles[k] for k in roles if k != 'keys'} }",
    ]

    # 1) 纯读方法 → 放行(IDOR/遍历/目录)
    if method in READ_METHODS and not op.body:
        return Verdict("allow", "只读 HTTP 方法,视为探测", "none", "http.read", asdict(op), signals)

    # DELETE 方法:默认业务删除
    if method == "DELETE":
        # 清理自建测试资源的弱放行: path 含 test/poc/srccop 且非用户批量
        if re.search(r"(test|poc|srccop|dummy|sample)", path, re.I):
            return Verdict(
                "deny",  # 仍 deny:删除即写,需 SRCOOP_DANGER_ALLOW 或 PENDING
                f"HTTP DELETE 删除资源 path={path[:80]} (自测资源也须显式放行,防误删)",
                "high",
                "http.delete",
                asdict(op),
                signals,
            )
        return Verdict(
            "deny",
            f"HTTP DELETE 可能删除业务数据 path={path[:80]}",
            "critical",
            "http.delete",
            asdict(op),
            signals,
        )

    # 2) 改密/重置:路径动作 或 body 改密字段
    pwd_path = any(
        x in re.sub(r"[^a-z0-9]", "", path.lower())
        for x in (
            "resetpassword", "changepassword", "updatepassword", "modifypassword",
            "setpassword", "forgotpassword", "resetpwd", "changepwd", "updatepwd",
        )
    ) or any(h in mut_hits for h in (
        "resetpassword", "changepassword", "updatepassword", "modifypassword",
        "setpassword", "forgotpassword", "resetpwd", "changepwd", "updatepwd",
        "reset_password", "change_password", "update_password",
    ))

    if method in WRITE_METHODS and (pwd_path or roles["has_mutation_password"]):
        return Verdict(
            "deny",
            f"改密/重置密码意图 method={method} path={path[:80]} "
            f"mutation_pwd={roles['has_mutation_password']} path_hit={pwd_path}",
            "critical",
            "http.password_mutation",
            asdict(op),
            signals,
        )

    # 3) 登录鉴权:写方法 + 鉴权路径 + 仅 auth 密码字段(无 new/old) → 放行
    if method in WRITE_METHODS and is_auth_path and roles["has_auth_password"] and not roles["has_mutation_password"]:
        return Verdict(
            "allow",
            f"鉴权/登录探测 path={path[:80]}",
            "low",
            "http.auth_probe",
            asdict(op),
            signals,
        )

    # 4) 非鉴权路径却只带 password 单字段 — 可能是弱口令撞库入口或隐藏改密
    #    若路径含 user/account/admin/profile/member 且非 login → 偏危险,拦
    if method in WRITE_METHODS and roles["has_auth_password"] and not is_auth_path:
        if re.search(r"/(user|users|account|admin|profile|member|employee|staff)(/|$)", path, re.I):
            # 无 new/old 但在用户资源上 POST password → 可能是注册或改密;注册可放行若路径 register
            if re.search(r"register|signup|sign-up|create", path, re.I):
                return Verdict("allow", "用户注册类接口(自测账号)", "low", "http.register", asdict(op), signals)
            return Verdict(
                "deny",
                f"用户资源上的写密码字段且非登录路径,疑似改密/设密 path={path[:80]}",
                "high",
                "http.user_password_write",
                asdict(op),
                signals,
            )

    # 5) 资金类提交
    if method in WRITE_METHODS and (
        any(h in mut_hits for h in ("pay", "payment", "transfer", "withdraw", "refund", "recharge", "checkout", "purchase"))
        or (roles["has_money"] and re.search(r"/(pay|payment|order|trade|transfer|wallet|billing)", path, re.I))
    ):
        return Verdict(
            "deny",
            f"资金/支付类写提交 path={path[:80]} money_fields={roles['has_money']}",
            "critical",
            "http.money",
            asdict(op),
            signals,
        )

    # 6) 路径级删除/禁用/销毁动作
    destructive_acts = {
        "delete", "remove", "destroy", "drop", "purge", "wipe", "truncate",
        "disable", "ban", "block", "kick", "unbind", "revoke",
    }
    if method in WRITE_METHODS and any(h in destructive_acts or h.startswith("delete") or h.startswith("remove") for h in mut_hits):
        return Verdict(
            "deny",
            f"路径含删除/禁用等破坏动作 path={path[:80]} hits={mut_hits[:6]}",
            "high",
            "http.path_destructive",
            asdict(op),
            signals,
        )

    # 7) 用户/权限写(非注册)
    user_write = {"createuser", "adduser", "updateuser", "edituser", "modifyuser", "deluser", "deleteuser",
                  "grant", "setrole", "assignrole", "promote", "setadmin", "registeradmin"}
    if method in WRITE_METHODS and any(h in user_write for h in mut_hits):
        return Verdict(
            "deny",
            f"用户/权限写操作 path={path[:80]} hits={mut_hits[:6]}",
            "high",
            "http.user_admin_write",
            asdict(op),
            signals,
        )

    # 8) 通用业务写:PUT/PATCH 整资源更新 — 中风险,默认拦(防改正常业务数据)
    if method in {"PUT", "PATCH"}:
        return Verdict(
            "deny",
            f"{method} 更新资源可能修改业务数据 path={path[:80]} (显式放行: SRCOOP_DANGER_ALLOW=1)",
            "medium",
            "http.put_patch",
            asdict(op),
            signals,
        )

    # 9) POST 无明确危险信号 → 放行(大量 API 探测/弱信号需要 POST)
    #    但 body 含 hard delete 标志仍拦
    if roles["has_destructive_flag"] and method in WRITE_METHODS:
        return Verdict(
            "deny",
            f"body 含破坏性标志字段 path={path[:80]}",
            "high",
            "http.body_destructive_flag",
            asdict(op),
            signals,
        )

    return Verdict(
        "allow",
        f"未识别为业务破坏意图 method={method} path={path[:80]}",
        "low",
        "http.default_allow",
        asdict(op),
        signals,
    )


def classify_sql(op: Operation) -> Verdict:
    sql = op.sql or ""
    signals = [f"client={op.meta.get('client')}", f"sql={sql[:160]}"]
    if not sql.strip():
        # 仅启动客户端交互壳 — 中风险,放行但提示(拦会误伤)
        return Verdict("allow", "DB 客户端无显式 SQL(交互壳)", "low", "sql.shell", asdict(op), signals)
    if SQL_DESTRUCTIVE.search(sql):
        return Verdict("deny", f"SQL DDL/破坏语句: {sql[:120]}", "critical", "sql.ddl", asdict(op), signals)
    if SQL_DML_WRITE.search(sql):
        # DELETE/UPDATE/INSERT
        return Verdict("deny", f"SQL 写语句(INSERT/UPDATE/DELETE): {sql[:120]}", "critical", "sql.dml", asdict(op), signals)
    if SQL_SELECTISH.search(sql):
        return Verdict("allow", "SQL 只读查询", "none", "sql.select", asdict(op), signals)
    return Verdict("deny", f"未能识别为只读 SQL,默认拦截: {sql[:120]}", "high", "sql.unknown", asdict(op), signals)


def classify_command(cmd: str) -> Verdict:
    if os.environ.get("SRCOOP_DANGER_ALLOW", "").strip() in ("1", "true", "yes", "YES"):
        return Verdict("allow", "SRCOOP_DANGER_ALLOW=1 强制放行", "none", "env.allow", None, [])

    cmd = cmd or ""
    cmdpos = _cmd_position(cmd)

    # 纯文本查看 → 放行(文档/grep 里的危险串)
    if _is_text_viewer(cmdpos):
        return Verdict("allow", "文本查看命令,不执行业务写", "none", "shell.viewer", None, [])

    ops: List[Operation] = []
    for seg in _split_commands(cmd):
        ops.extend(_extract_curl_ops(seg))
        ops.extend(_extract_sql_ops(seg))

    # python -c 内嵌请求:粗提取
    if re.search(r"\bpython[0-9.]*\b.*-c\b", cmd) or re.search(r"\bnode\b.*-e\b", cmd):
        if re.search(r"\b(requests\.(post|put|patch|delete)|httpx\.(post|put|patch|delete)|fetch\()", cmd, re.I):
            # 尝试从字符串字面量捞 URL 与方法
            method = "POST"
            if re.search(r"\.(delete|DELETE)\(|method\s*=\s*['\"]DELETE", cmd):
                method = "DELETE"
            elif re.search(r"\.(put|PUT)\(|method\s*=\s*['\"]PUT", cmd):
                method = "PUT"
            elif re.search(r"\.(patch|PATCH)\(", cmd):
                method = "PATCH"
            um = re.search(r"https?://[^\s\"']+", cmd)
            url = um.group(0) if um else ""
            # body 字面量
            bm = re.search(r"""(?:json|data)\s*=\s*(\{.*?\}|['\"].*?['\"])""", cmd)
            body = bm.group(1) if bm else cmd
            ops.append(Operation(kind="http", method=method, url=url, path=_url_path(url), body=body, raw=cmd[:500], meta={"embedded": True}))

    if not ops:
        return Verdict("allow", "未解析出 HTTP/SQL 业务操作", "none", "noop", None, [])

    # 多 op:任一 deny 则 deny(最严重优先)
    denials: List[Verdict] = []
    allows: List[Verdict] = []
    for op in ops:
        if op.kind == "http":
            v = classify_http(op)
        elif op.kind == "sql":
            v = classify_sql(op)
        else:
            v = Verdict("allow", "unknown op", "none", "unknown", asdict(op), [])
        if v.action == "deny":
            denials.append(v)
        else:
            allows.append(v)

    if denials:
        # critical > high > medium
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        denials.sort(key=lambda x: order.get(x.risk, 9))
        return denials[0]

    return allows[0] if allows else Verdict("allow", "ok", "none", "ok", None, [])


def main(argv: List[str]) -> int:
    # 用法:
    #   echo '{"tool_input":{"command":"..."}}' | python business_impact.py
    #   python business_impact.py --cmd 'curl ...'
    #   python business_impact.py --selftest
    if "--selftest" in argv:
        return _selftest()

    cmd = ""
    if "--cmd" in argv:
        i = argv.index("--cmd")
        cmd = argv[i + 1] if i + 1 < len(argv) else ""
    else:
        raw = sys.stdin.read()
        if raw.strip():
            try:
                d = json.loads(raw)
                if isinstance(d, dict):
                    ti = d.get("tool_input") or {}
                    cmd = ti.get("command") or d.get("command") or ""
                else:
                    cmd = raw
            except json.JSONDecodeError:
                cmd = raw

    v = classify_command(cmd)
    if os.environ.get("SRCOOP_BI_DEBUG") or "--json" in argv:
        print(v.to_json(), file=sys.stderr if v.action == "deny" else sys.stdout)
    else:
        if v.action == "deny":
            print(f"business_impact:{v.rule}:{v.reason}", file=sys.stderr)
        elif os.environ.get("SRCOOP_BI_DEBUG"):
            print(f"allow:{v.rule}:{v.reason}", file=sys.stderr)

    return 2 if v.action == "deny" else 0


def _selftest() -> int:
    cases: List[Tuple[str, str, str]] = [
        # cmd, expect allow|deny, rule_substr
        ('curl -s http://x/api/user/1', "allow", "http.read"),
        ('curl -s -X POST http://x/api/login -d \'{"username":"a","password":"b"}\'', "allow", "http.auth"),
        ('curl -s -X POST http://x/api/user/resetPassword -d \'{"newPassword":"x"}\'', "deny", "password_mutation"),
        ('curl -s -X POST http://x/api/user/change-password -H "Content-Type: application/json" -d \'{"oldPassword":"a","newPassword":"b"}\'', "deny", "password_mutation"),
        ('curl -s -X DELETE http://x/api/user/123', "deny", "http.delete"),
        ('curl -s -X POST http://x/api/pay/submit -d \'{"amount":100}\'', "deny", "http.money"),
        ('curl -s -X PUT http://x/api/order/1 -d \'{"status":"ok"}\'', "deny", "http.put_patch"),
        ('curl -s -X POST http://x/api/search -d \'{"q":"test"}\'', "allow", "default_allow"),
        ('mysql -e "SELECT 1"', "allow", "sql.select"),
        ('mysql -e "DROP TABLE users"', "deny", "sql.ddl"),
        ('mysql -e "DELETE FROM users WHERE id=1"', "deny", "sql.dml"),
        ('echo "curl -X DELETE http://x/api/user/1"', "allow", "viewer"),
        ('curl -s -X POST http://x/api/auth/token -d "username=a&password=b"', "allow", "auth"),
        ('curl -s -X POST http://x/api/user/profile -d \'{"password":"new"}\'', "deny", "user_password"),
    ]
    # force no allow env
    os.environ.pop("SRCOOP_DANGER_ALLOW", None)
    failed = 0
    for cmd, expect, rule_sub in cases:
        v = classify_command(cmd)
        ok = v.action == expect and (rule_sub in v.rule or rule_sub in v.reason or rule_sub in (v.rule + v.reason))
        # viewer case: rule shell.viewer
        if rule_sub == "viewer":
            ok = v.action == "allow"
        if rule_sub == "auth":
            ok = v.action == "allow" and "auth" in v.rule
        mark = "OK" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  {mark} expect={expect} got={v.action}/{v.rule} :: {cmd[:70]}")
    print(f"selftest failed={failed}/{len(cases)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace") if hasattr(sys.stdout, "reconfigure") else None
    sys.stderr.reconfigure(encoding="utf-8", errors="replace") if hasattr(sys.stderr, "reconfigure") else None
    sys.exit(main(sys.argv[1:]))
