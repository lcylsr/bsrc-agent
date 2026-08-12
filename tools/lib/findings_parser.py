#!/usr/bin/env python3
# tools/lib/findings-parser.py — findings.md frontmatter 公共解析器
#
# 支持两种 frontmatter 包裹:
#   1. ```yaml\n---\n...\n---\n```   (推荐,与 internal-10.0.0.1 一致)
#   2. 裸 ---\n...\n---            (历史兼容)
#
# 被 findings-lint 统一调用,避免各工具解析口径不一致。

import re
from pathlib import Path


def parse_yaml_simple(block):
    """简单 YAML 解析 — 支持 1 级嵌套 dict + nest 内 list(upgrade_path.missing_artifacts 等)。"""
    # Windows Git Bash 下文件可能是 \r\n,统一为 \n
    block = block.replace("\r\n", "\n").replace("\r", "\n")
    out = {}
    cur_key = None
    cur_val_lines = []
    nest_key = None
    nest_dict = None
    pending_list_key = None  # nest 内 key: 空后接  - item
    for line in block.split("\n"):
        if line.strip() in ("---", ""):
            continue
        # 嵌套 dict 子字段: 两个空格缩进
        if nest_key is not None:
            # nest 内 list item: "  - foo" 或 "    - foo"(YAML 常见 2/4 空格)
            m_list = re.match(r"^  +-\s+(.*?)\s*$", line)
            if m_list and pending_list_key:
                val = m_list.group(1).strip().strip('"').strip("'")
                cur = nest_dict.get(pending_list_key)
                if not isinstance(cur, list):
                    nest_dict[pending_list_key] = []
                nest_dict[pending_list_key].append(val)
                continue
            m_nest = re.match(r"^  ([a-z_]+):\s*(.*?)\s*$", line)
            if m_nest:
                k_n, v_n = m_nest.group(1), m_nest.group(2)
                if v_n == "" or v_n is None:
                    # 空值: 后续 list 归属此 key
                    pending_list_key = k_n
                    nest_dict[k_n] = []
                else:
                    pending_list_key = None
                    nest_dict[k_n] = v_n.strip().strip('"').strip("'")
                continue
            # 嵌套结束
            out[nest_key] = nest_dict
            nest_key = None
            nest_dict = None
            pending_list_key = None
            # fall through 处理本行

        m = re.match(r"^([a-z_]+):\s*\|\s*$", line)
        if m:
            if cur_key:
                out[cur_key] = "\n".join(cur_val_lines).strip()
            cur_key = m.group(1)
            cur_val_lines = []
            continue
        if cur_key and (line.startswith("  ") or line.startswith("\t")):
            cur_val_lines.append(line)
            continue
        m = re.match(r"^([a-z_]+):\s*(.*?)\s*$", line)
        if m:
            if cur_key:
                out[cur_key] = "\n".join(cur_val_lines).strip()
                cur_key = None
                cur_val_lines = []
            k, v = m.group(1), m.group(2)
            if v == "" or v is None:
                # 可能是嵌套 dict 起始
                nest_key = k
                nest_dict = {}
                pending_list_key = None
            else:
                out[k] = v.strip().strip('"').strip("'")
    if cur_key:
        out[cur_key] = "\n".join(cur_val_lines).strip()
    if nest_key is not None:
        out[nest_key] = nest_dict
    return out


def parse_yaml_block(block):
    """优先用 yaml.safe_load 解析,失败退回到简单解析器。"""
    try:
        import yaml
        # 去掉首尾的 --- 分隔符,yaml.safe_load 才能正确解析
        cleaned = re.sub(r"^---\s*\n", "", block)
        cleaned = re.sub(r"\n---\s*$", "", cleaned)
        d = yaml.safe_load(cleaned)
        if isinstance(d, dict):
            return d
    except Exception:
        pass
    return parse_yaml_simple(block)


def extract_frontmatter_blocks(text):
    """返回 [(raw_block_text, start_pos), ...],同时识别 ```yaml 块和裸 --- 块。"""
    # Windows Git Bash 下文件可能是 \r\n,统一为 \n
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    seen_starts = set()  # 按 start_pos 去重,避免 ```yaml 和裸 --- 重复收录
    covered_ranges = []  # 记录 ```yaml 块覆盖的完整区间,避免内部 --- 被裸匹配
    blocks = []

    # 1) ```yaml 块,块内以 --- 开始和结束
    for m in re.finditer(r"```yaml\s*\n(---\n.*?\n---)\n```", text, re.DOTALL):
        seen_starts.add(m.start())
        covered_ranges.append((m.start(), m.end()))
        blocks.append((m.group(1), m.start()))

    # 2) 裸 --- 块(块内含 id: F- 表示是 finding frontmatter)
    for m in re.finditer(r"---\n(.*?)\n---", text, re.DOTALL):
        if m.start() in seen_starts:
            continue  # 已被 ```yaml 块覆盖,跳过
        # 跳过落在 ```yaml 块区间内的裸 --- 匹配(解决内部 --- 被重复收录)
        if any(start <= m.start() < end for start, end in covered_ranges):
            continue
        raw = m.group(1)
        if re.search(r"^id:\s*F-", raw, re.M):
            blocks.append((raw, m.start()))

    # 按 start_pos 排序,保持文档原序
    blocks.sort(key=lambda b: b[1])
    return blocks


def parse_findings(path):
    """解析 findings.md,返回 [{id, yaml_dict, title_line, start_pos}, ...]。"""
    src = Path(path).read_text(encoding="utf-8", errors="ignore")

    results = []
    for raw, pos in extract_frontmatter_blocks(src):
        d = parse_yaml_block(raw)
        if not isinstance(d, dict):
            continue
        fid = d.get("id", "")
        if not isinstance(fid, str) or not fid.startswith("F-"):
            continue
        title = str(d.get("title", "<no title>")).strip().strip('"').strip("'")
        # 找标题行
        title_line = ""
        for line in src.splitlines():
            if line.startswith(f"### {fid}"):
                title_line = line
                break
        results.append({
            "id": fid,
            "title": title,
            "yaml": d,
            "title_line": title_line,
            "start_pos": pos,
        })
    return results


def findings_count(path):
    """返回解析到的 finding 数量(用于 lint 快速判断)。"""
    return len(parse_findings(path))


def count_by_status(path):
    """返回 {status: count} 字典。"""
    counts = {}
    for item in parse_findings(path):
        st = str(item.get("yaml", {}).get("status", "unknown") or "unknown")
        counts[st] = counts.get(st, 0) + 1
    return counts


# 叙事标题: ### F-001 | title  /  #### F-007 [HIGH] title  /  ### F-007：title
_ORPHAN_HEADING_RE = re.compile(
    r"^(#{2,4})\s+(F-\d+)\b(?:\s*[|：:\-—]\s*|\s+)(.*)$",
    re.M,
)


def scan_orphan_headers(path):
    """
    扫描 narrative `### F-xxx` 标题中,尚未被 frontmatter 收录的 id。

    返回 [{id, title, line, level}, ...]。
    用于 status/lint 阻断「文件非空但 parser 为 0」的静默失明。
    """
    p = Path(path)
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n").replace("\r", "\n")
    known = {item["id"] for item in parse_findings(path)}
    orphans = []
    seen = set()
    for i, line in enumerate(text.split("\n"), 1):
        m = _ORPHAN_HEADING_RE.match(line)
        if not m:
            continue
        fid = m.group(2)
        if fid in known:
            continue
        if fid in seen:
            continue
        seen.add(fid)
        title = (m.group(3) or "").strip()
        # 去掉 markdown 残留
        title = re.sub(r"^\[.*?\]\s*", "", title).strip()
        orphans.append({
            "id": fid,
            "title": title[:80],
            "line": i,
            "level": len(m.group(1)),
        })
    return orphans


# ── readiness / 真洞闸门共享判定 ──────────────────────────

_GENERIC_EVIDENCE_BLACKLIST = (
    "http/1.1 200", "200 ok", "success:true", '"success":true',
    "code:200", '"code":200', '"result":true', "result:null",
    "http 200", "unauthorizedrequest:false",
)

_TRASH_TITLE_KEYWORDS = (
    "CORS", "Self-XSS", "安全头", "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "版本号", "Sourcemap", "SourceMap", ".git 暴露",
    "Rate limit", "速率限制", "点击劫持", "Clickjacking", "tabnabbing",
    "TLS 弱", "TLS 版本", "弱套件", "HTTPS 降级", "开放重定向(无链)",
    "robots.txt", ".env 403", "404 信息", ".svn 暴露",
)

_CHAINS_SECTION_RE = re.compile(
    r"^##\s+Chains\b.*?(?=^##\s|\Z)",
    re.M | re.S | re.I,
)
_CHAIN_NODE_RE = re.compile(r"nodes:\s*\[([^\]]+)\]", re.I)
_CHAIN_HEAD_RE = re.compile(r"^###\s+(C-\d+)\b", re.M)


# 业务锚点: 长证据剥离 blacklist 后需命中其一(或中文/路径特征),防 a×40 注水
_BUSINESS_ANCHORS = (
    "vendor", "vendors", "blob", "upload", "uuid", "multipart", "cdn",
    "swagger", "enumerat", "password", "token", "secret", "getvendors",
    "供应商", "未授权", "邮箱", "密钥", "路径", "源码", "对象可读",
    "environment", "partner", "appxite", "rethink", "portal",
    "leak", "disclosure", "unauthorized", "idor", "ssrf", "rce",
    "file://", "169.254", "admin", "config", "api-key", "accesskey",
)


def is_generic_business_evidence(be) -> bool:
    """
    判定 business_evidence 是否仅为「HTTP 200 / success:true」类现象句。

    v2 规则:
      1. 空/<10 字 / 含「需补充」「待补充」→ generic
      2. 剥离 blacklist → cleaned
      3. 多样性: cleaned 唯一字符种类 < 8 且无中文 → generic(挡 a×40)
      4. cleaned ≥ 40:
           含业务锚点 OR 中文≥6 OR 路径/域名特征 → 非 generic
           否则仍 generic(防注水)
      5. cleaned < 40: 含 blacklist → generic; cleaned < 10 → generic; 否则非 generic
    """
    if not be or len(str(be).strip()) < 10:
        return True
    raw = str(be)
    if "需补充" in raw or "待补充" in raw:
        return True
    low = raw.lower()
    cleaned = low
    for bad in _GENERIC_EVIDENCE_BLACKLIST:
        cleaned = cleaned.replace(bad, " ")
    cleaned = re.sub(r"[\s\W_]+", " ", cleaned, flags=re.UNICODE).strip()

    # 多样性: 注水重复字符
    compact = re.sub(r"\s+", "", cleaned)
    if compact:
        unique_n = len(set(compact))
        has_cjk = bool(re.search(r"[一-鿿]", raw))
        if unique_n < 8 and not has_cjk:
            return True

    def _has_anchor(text: str) -> bool:
        t = text.lower()
        for a in _BUSINESS_ANCHORS:
            if a in t:
                return True
        # 路径/域名/UUID 特征
        if re.search(r"/[a-z0-9_\-]{3,}/", t):
            return True
        if re.search(r"\b[0-9a-f]{8}-[0-9a-f]{4}-", t):
            return True
        if re.search(r"\b\d{2,}\s*(vendors?|blob|host|user|record)", t):
            return True
        cjk_n = len(re.findall(r"[一-鿿]", raw))
        if cjk_n >= 6:
            return True
        return False

    if len(cleaned) >= 40:
        return not _has_anchor(cleaned)

    for bad in _GENERIC_EVIDENCE_BLACKLIST:
        if bad in low:
            return True
    return len(cleaned) < 10


# severity 排序: critical 最前
SEV_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "?": 9,
    "": 9,
}


def sort_readiness(rows, *, money_first: bool = False):
    """
    按 severity 排序 readiness 行; money_first=True 时 money_ready 整组置顶。
    同级按 id 字母序。
    """
    def key(r):
        sev = SEV_RANK.get(str(r.get("severity") or "").lower(), 9)
        money_bit = 0 if (money_first and r.get("money_ready")) else 1
        rid = str(r.get("id") or "")
        return (money_bit, sev, rid)

    return sorted(list(rows or []), key=key)


def is_shell_verified(row_or_item) -> bool:
    """
    空壳 verified: title 空 / <no title> 或 severity 非法。
    接受 readiness row 或 parse_findings item。
    """
    if not isinstance(row_or_item, dict):
        return True
    d = row_or_item.get("yaml") if "yaml" in row_or_item else row_or_item
    title = str(
        row_or_item.get("title")
        or (d or {}).get("title")
        or ""
    ).strip().strip('"').strip("'")
    if not title or title in ("<no title>", "no title", "?", "-"):
        return True
    sev = str(
        row_or_item.get("severity")
        or (d or {}).get("severity")
        or ""
    ).strip().lower()
    if sev and sev not in ("critical", "high", "medium", "low", "info", "?"):
        return True
    if not sev or sev == "?":
        # readiness 可能 severity='?'; shell 仅 title 空时严格
        if not title or title == "<no title>":
            return True
    return False


def is_generic_signature(sig) -> bool:
    if not sig or len(str(sig).strip()) < 3:
        return True
    low = str(sig).lower().strip()
    if low in ("true", "false", "null", "ok", "200"):
        return True
    for bad in _GENERIC_EVIDENCE_BLACKLIST:
        if bad in low:
            return True
    return False


def trash_hit(title_or_line: str) -> str:
    """返回命中的垃圾洞关键词,未命中返回空串。"""
    s = title_or_line or ""
    for kw in _TRASH_TITLE_KEYWORDS:
        if kw in s:
            return kw
    return ""


def load_replay_status(findings_path) -> dict:
    """读取 findings 同目录 .replay-status.json → {F-id: {verdict, at}}。"""
    p = Path(findings_path)
    rp = p.parent / ".replay-status.json"
    if not rp.is_file():
        return {}
    try:
        import json
        data = json.loads(rp.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _parse_missing_artifacts_field(raw) -> list:
    """upgrade_path.missing_artifacts → ['reproduction','impact',...]。支持 list / 逗号串。"""
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [str(x).strip().lower() for x in raw if str(x).strip()]
    s = str(raw).strip().strip("[]")
    if not s:
        return []
    parts = re.split(r"[,|\s]+", s)
    return [p.strip().lower().strip("'\"") for p in parts if p.strip()]


def derive_missing_artifacts(has_poc, has_impact, has_signature, replay_ok, status, trash) -> list:
    """由证据位推导缺什么。missing_artifacts 展示真相永远走此函数(声明仅作 plan/stale)。"""
    miss = []
    if trash:
        return ["trash_chain"]  # 需链式才可能升
    if not has_poc:
        miss.append("reproduction")
    if not has_impact:
        miss.append("impact")
    if status in ("verified", "deliverable", "submitted") and not has_signature:
        miss.append("signature")
    if status in ("verified", "deliverable") and not replay_ok:
        miss.append("replay")
    # candidate 证据齐但仍未升 verified: 视同缺 replay(待 AI 写 PoC 并运行验证后人工升)
    if (
        status in ("candidate", "verifying")
        and has_poc
        and has_impact
        and has_signature
        and not replay_ok
        and "replay" not in miss
    ):
        miss.append("replay")
    return miss


def gate_for(status, money_ready, blockers, trash, has_poc, mode="src") -> str:
    """
    分级 gate 语言(只提示,不改 findings 状态):
      pass | soft_fail | pivot | blocked

    签名保留 blockers/has_poc/mode 兼容调用方;gate 本体只看 trash/money/status。
    trash: src/redteam 一律 blocked(与无链不报一致)。
    """
    status = (status or "").lower()
    if trash:
        return "blocked"
    if money_ready or status == "submitted":
        return "pass"
    if status == "phenomenon":
        return "pivot"
    return "soft_fail"


def compute_readiness(item, replay_map=None, findings_path=None, mode="src") -> dict:
    """
    计算单条 finding 的投递 readiness(计算字段,不写回 YAML)。

    返回:
      {
        id, status, severity, title,
        has_poc, has_impact, has_signature, replay_ok, trash,
        money_ready,  # verified + 三真 + 非 trash
        blockers: [str, ...],
        missing_artifacts: [reproduction|impact|signature|replay|...],
        missing_artifacts_declared: bool,  # YAML 是否显式写了 missing_artifacts
        gate: pass|soft_fail|pivot|blocked,
        upgrade_hint: str,
      }
    """
    d = item.get("yaml") or {}
    fid = item.get("id") or d.get("id") or "?"
    status = str(d.get("status") or "")
    title = str(d.get("title") or item.get("title") or "")
    title_line = item.get("title_line") or title
    sev = str(d.get("severity") or "?")
    mode = (mode or "src").lower()

    poc_curl = str(d.get("poc_curl") or "").strip()
    replay_script = str(d.get("replay_script") or "").strip()
    has_poc = bool(poc_curl or replay_script)

    be = d.get("business_evidence") or ""
    has_impact = not is_generic_business_evidence(be)

    sig = d.get("replay_signature") or ""
    has_signature = not is_generic_signature(sig)

    if replay_map is None and findings_path:
        replay_map = load_replay_status(findings_path)
    elif replay_map is None:
        replay_map = {}

    # frontmatter last_replay 优先,否则 .replay-status.json
    last = str(d.get("last_replay") or "").strip().lower()
    if not last and isinstance(replay_map.get(fid), dict):
        last = str(replay_map[fid].get("verdict") or "").lower()
    elif not last and isinstance(replay_map.get(fid), str):
        last = replay_map[fid].lower()

    if last in ("passed", "pass", "ok", "true"):
        replay_ok = True
    elif last in ("failed", "degraded", "fail"):
        replay_ok = False
    else:
        # 未跑过: candidate 不算 ok; verified 也未 ok(需重放)
        replay_ok = False

    th = trash_hit(title_line) or trash_hit(title)

    blockers = []
    if th:
        blockers.append(f"trash:{th}")
    if not has_poc:
        blockers.append("no_poc")
    if not has_impact:
        blockers.append("no_impact")
    if status in ("verified", "deliverable", "submitted") and not has_signature:
        blockers.append("no_signature")
    if status in ("verified", "deliverable") and not replay_ok:
        blockers.append("need_replay")

    money_ready = (
        status in ("verified", "deliverable")
        and has_poc
        and has_impact
        and has_signature
        and replay_ok
        and not th
    )

    # missing_artifacts: 永远证据推导;YAML 声明仅作 plan + stale 检测
    upath = d.get("upgrade_path") if isinstance(d.get("upgrade_path"), dict) else {}
    declared_raw = upath.get("missing_artifacts") if upath else None
    declared = _parse_missing_artifacts_field(declared_raw)
    missing_artifacts_declared = declared_raw is not None and str(declared_raw).strip() != ""
    missing_artifacts = derive_missing_artifacts(
        has_poc, has_impact, has_signature, replay_ok, status, th
    )
    _KNOWN_MISS = ("reproduction", "impact", "signature", "replay", "trash_chain")
    stale = []
    if missing_artifacts_declared:
        for x in declared:
            if x in _KNOWN_MISS and x not in missing_artifacts:
                stale.append(x)

    gate = gate_for(status, money_ready, blockers, th, has_poc, mode=mode)

    # upgrade hint for candidates
    if status in ("candidate", "verifying", "phenomenon"):
        if th:
            hint = f"垃圾洞模式({th}) — 无链不报"
        elif not has_poc and not has_impact:
            hint = "补 PoC + 业务影响句" if mode != "redteam" else "补最小可重放(reproduction)"
        elif not has_poc:
            hint = "补 poc_curl/replay_script"
        elif not has_impact:
            hint = "补真实 business_evidence(非 HTTP 200)" if mode != "redteam" else "有 repro 可写 Kill Chain hop;转 src 再补 impact"
        elif not has_signature:
            hint = "补具体 replay_signature"
        elif "replay" in missing_artifacts:
            hint = "AI 写 output/poc-<finding_id>.py 并运行验证后人工升 verified / 确认 money_ready"
        else:
            hint = "证据齐 — 人工升 verified"
    elif status in ("verified", "deliverable") and not money_ready:
        if blockers == ["need_replay"] or (blockers and set(blockers) <= {"need_replay"}):
            hint = "AI 写 output/poc-<finding_id>.py 并运行验证后才 money_ready(非缺 PoC)"
        else:
            hint = "补: " + ",".join(blockers) if blockers else "AI 写 PoC 并运行验证"
    elif status == "submitted":
        hint = "已交单"
    else:
        hint = ""
    if stale:
        stale_s = ",".join(stale)
        extra = f"⚠ plan stale: {stale_s}(证据已满足,勿再补)"
        hint = f"{hint}; {extra}" if hint else extra

    return {
        "id": fid,
        "status": status,
        "severity": sev,
        "title": title[:80],
        "has_poc": has_poc,
        "has_impact": has_impact,
        "has_signature": has_signature,
        "replay_ok": replay_ok,
        "trash": th,
        "money_ready": money_ready,
        "blockers": blockers,
        "missing_artifacts": missing_artifacts,
        "missing_artifacts_declared": missing_artifacts_declared,
        "missing_artifacts_plan": declared,
        "missing_artifacts_stale": stale,
        "gate": gate,
        "upgrade_hint": hint,
    }


def readiness_report(path, mode="src") -> list:
    """对 findings.md 全部 finding 返回 readiness 列表。mode 影响 gate/hint 措辞。"""
    replay_map = load_replay_status(path)
    return [compute_readiness(it, replay_map=replay_map, findings_path=path, mode=mode)
            for it in parse_findings(path)]


# ── multi-subdomain / program-target rollup ──────────────────
# 程序级 target(如 targets/acme)顶层 findings.md 常是 markdown 索引表,
# 权威 YAML 在子目录 */findings.md。status/board 必须聚合子域,否则 V/C=0。


def list_findings_files(target_dir, max_depth=2):
    """
    列出 target 下 findings.md 路径。

    - depth 0: <target>/findings.md
    - depth 1: <target>/<host>/findings.md
    - depth 2: <target>/<a>/<b>/findings.md(少见,默认仍扫)

    返回 [Path, ...] 按路径排序;不存在的跳过。
    """
    root = Path(target_dir)
    if not root.is_dir():
        return []
    out = []
    root_f = root / "findings.md"
    if root_f.is_file():
        out.append(root_f)
    if max_depth < 1:
        return out
    try:
        children = sorted(root.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return out
    for child in children:
        if not child.is_dir():
            continue
        name = child.name
        if name.startswith(".") or name in ("output", "recon", "probes", "tmp", "archive"):
            continue
        f1 = child / "findings.md"
        if f1.is_file():
            out.append(f1)
        if max_depth >= 2:
            try:
                for sub in sorted(child.iterdir(), key=lambda p: p.name.lower()):
                    if not sub.is_dir() or sub.name.startswith("."):
                        continue
                    f2 = sub / "findings.md"
                    if f2.is_file():
                        out.append(f2)
            except OSError:
                pass
    return out


def collect_findings(target_dir, max_depth=2):
    """
    聚合 target 根 + 子域 findings.md 的 frontmatter 条目。

    每条附加:
      source: 相对 target 的 findings 路径(posix)
      source_host: 子目录名;根文件则为 ""
      display_id: host/F-xxx 或 F-xxx(根)

    同 host 内同 id 只保留首次;跨 host 同 id 并存(靠 source 区分)。
    """
    root = Path(target_dir).resolve()
    results = []
    seen = set()  # (source_host, id)
    for fpath in list_findings_files(root, max_depth=max_depth):
        try:
            rel = fpath.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = fpath.name
        parent = fpath.parent
        if parent.resolve() == root:
            host = ""
        else:
            try:
                host = parent.resolve().relative_to(root).as_posix()
            except ValueError:
                host = parent.name
        try:
            items = parse_findings(str(fpath))
        except Exception:
            continue
        for it in items:
            fid = it.get("id") or ""
            key = (host, fid)
            if key in seen:
                continue
            seen.add(key)
            row = dict(it)
            row["source"] = rel
            row["source_host"] = host
            row["source_path"] = str(fpath)
            row["display_id"] = f"{host}/{fid}" if host else fid
            results.append(row)
    return results


def count_by_status_tree(target_dir, max_depth=2) -> dict:
    """聚合 count_by_status: {status: n} 跨根+子域。"""
    counts = {}
    for item in collect_findings(target_dir, max_depth=max_depth):
        st = str(item.get("yaml", {}).get("status", "unknown") or "unknown")
        counts[st] = counts.get(st, 0) + 1
    return counts


def readiness_report_tree(target_dir, mode="src", max_depth=2) -> list:
    """
    对 collect_findings 结果逐条 compute_readiness。
    replay 状态按各自 source findings 目录的 .replay-status.json。
    返回列表在 compute_readiness 字段上附加 source/source_host/display_id。
    """
    out = []
    # cache replay maps per findings path
    replay_cache = {}
    for it in collect_findings(target_dir, max_depth=max_depth):
        sp = it.get("source_path") or ""
        if sp not in replay_cache:
            replay_cache[sp] = load_replay_status(sp) if sp else {}
        r = compute_readiness(
            it,
            replay_map=replay_cache[sp],
            findings_path=sp,
            mode=mode,
        )
        r["source"] = it.get("source", "")
        r["source_host"] = it.get("source_host", "")
        r["display_id"] = it.get("display_id") or r.get("id")
        # 展示用: 程序级 TODO/列表优先 display_id
        r["id_local"] = r.get("id")
        r["id"] = r["display_id"]
        out.append(r)
    return out


def is_program_target(target_dir, max_depth=2) -> bool:
    """根 findings 可解析为 0,但子域至少 1 个 findings.md → 程序级索引目标。"""
    root = Path(target_dir)
    root_f = root / "findings.md"
    root_n = 0
    if root_f.is_file():
        try:
            root_n = len(parse_findings(str(root_f)))
        except Exception:
            root_n = 0
    files = list_findings_files(root, max_depth=max_depth)
    child_files = [f for f in files if f.parent.resolve() != root.resolve()]
    return root_n == 0 and len(child_files) > 0


def parse_chains(path) -> list:
    """
    解析 findings.md 文末 ## Chains 段。
    返回 [{id, nodes: [F-..], raw_head}, ...]。无段则 []。
    """
    p = Path(path)
    if not p.is_file():
        return []
    text = p.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")
    m = _CHAINS_SECTION_RE.search(text)
    if not m:
        return []
    section = m.group(0)
    chains = []
    # split by ### C-
    parts = re.split(r"(?=^###\s+C-\d+)", section, flags=re.M)
    for part in parts:
        hm = _CHAIN_HEAD_RE.search(part)
        if not hm:
            continue
        cid = hm.group(1)
        nodes = []
        nm = _CHAIN_NODE_RE.search(part)
        if nm:
            nodes = re.findall(r"F-\d+", nm.group(1))
        else:
            nodes = re.findall(r"\bF-\d+\b", part)
        # de-dup preserve order
        seen = set()
        uniq = []
        for n in nodes:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        chains.append({"id": cid, "nodes": uniq, "raw": part[:200]})
    return chains


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print(
            "usage: python tools/lib/findings_parser.py <findings.md|target_dir> [--tree] [--gate soft_fail]",
            file=sys.stderr,
        )
        sys.exit(2)
    path = sys.argv[1]
    tree = "--tree" in sys.argv[2:]
    gate_filter = None
    for i, a in enumerate(sys.argv[2:], 2):
        if a == "--gate" and i + 1 < len(sys.argv):
            gate_filter = sys.argv[i + 1]
    p = Path(path)
    if tree or (p.is_dir()):
        target = path if p.is_dir() else str(p.parent)
        if gate_filter:
            rows = readiness_report_tree(target)
            rows = [r for r in rows if r.get("gate") == gate_filter]
            rows = sort_readiness(rows, money_first=True)
            for r in rows:
                print(json.dumps(r, ensure_ascii=False, default=str))
            print(f"# gate={gate_filter} n={len(rows)}", file=sys.stderr)
        else:
            for item in collect_findings(target):
                print(json.dumps({
                    "id": item["id"],
                    "display_id": item.get("display_id"),
                    "source": item.get("source"),
                    "title": item["title"],
                    "status": item["yaml"].get("status"),
                    "severity": item["yaml"].get("severity"),
                }, ensure_ascii=False))
            print(
                f"# tree total={len(collect_findings(target))} "
                f"by_status={count_by_status_tree(target)}",
                file=sys.stderr,
            )
    else:
        for item in parse_findings(path):
            print(json.dumps({
                "id": item["id"],
                "title": item["title"],
                "status": item["yaml"].get("status"),
                "severity": item["yaml"].get("severity"),
            }, ensure_ascii=False))
        orphans = scan_orphan_headers(path)
        if orphans:
            print("--- orphans ---", file=sys.stderr)
            for o in orphans:
                print(json.dumps(o, ensure_ascii=False), file=sys.stderr)
