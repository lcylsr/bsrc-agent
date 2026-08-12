#!/usr/bin/env python3
# tools/nday-matcher.py — N-day / 历史漏洞指纹识别器
#
# 用途: 读取目标指纹信号(scope + raw probe + recon 结果),
#       与 skills/fingerprint/nday-fingerprints.yaml 中 curated N-day 指纹匹配,
#       输出高置信攻击面提示和可执行的安全 GET 检查报告。
#
# 设计原则:
#   - 零外部依赖(纯 Python + curl),与 tech-fuzz.py / ssrf-probe.sh 风格一致
#   - 只做安全 GET 探测,不投写操作/RCE payload(重武器仍要走 scanner-dispatch + 请示)
#   - 命中 ≠ verified;报告只给“下一步该按哪个 playbook/skill 打”
#
# 用法:
#   bash tools/run.sh nday-matcher <target_dir>                # 自动发现 base_url,跑检查
#   bash tools/run.sh nday-matcher <target_dir> --dry-run      # 只匹配本地信号,不联网
#   bash tools/run.sh nday-matcher <target_dir> --base-url https://target.com

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "skills" / "fingerprint" / "nday-fingerprints.yaml"


def log(msg):
    print(msg, flush=True)


def err(msg):
    print(f"❌ {msg}", file=sys.stderr, flush=True)


def warn(msg):
    print(f"⚠️  {msg}", flush=True)


def read_text(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def parse_frontmatter(text):
    """简易 frontmatter 解析。"""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                import yaml
                return yaml.safe_load(parts[1]) or {}
            except Exception:
                pass
    m = re.search(r"```yaml\s*\n(.*?)\n```", text, re.S)
    if m:
        try:
            import yaml
            return yaml.safe_load(m.group(1)) or {}
        except Exception:
            pass
    return {}


def load_fingerprints(db_path=DB_PATH):
    """加载 YAML 指纹库。"""
    if not db_path.is_file():
        err(f"指纹库不存在: {db_path}")
        return []
    try:
        import yaml
        data = yaml.safe_load(db_path.read_text(encoding="utf-8", errors="ignore")) or {}
        return data.get("fingerprints", [])
    except Exception as exc:
        err(f"指纹库解析失败: {exc}")
        return []


def _extract_paths(text):
    """从文本里抽路径/URL。"""
    paths = set()
    # HTTP 请求行
    for m in re.finditer(r"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)", text, re.I):
        paths.add(m.group(1))
    # 绝对 URL
    for m in re.finditer(r"https?://[^\s\"'<>]+", text, re.I):
        paths.add(m.group(0))
    # /开头路径
    for m in re.finditer(r"(?:^|[^a-zA-Z0-9_./-])(/[a-zA-Z0-9_./-]{2,})", text):
        paths.add(m.group(1))
    return paths


def collect_signals(target_dir):
    """收集目标指纹信号,返回按类别组织的字典(全小写)。"""
    target_dir = Path(target_dir)
    signals = {
        "text": "",
        "headers": "",
        "body": "",
        "paths": set(),
        "titles": "",
        "cookies": "",
        "server": "",
    }

    # 1) scope.md
    scope_path = target_dir / "scope.md"
    if scope_path.is_file():
        scope_text = read_text(scope_path)
        signals["text"] += scope_text + "\n"
        signals["paths"] |= _extract_paths(scope_text)
        fm = parse_frontmatter(scope_text)
        for k in ("target", "domain", "vendor", "厂商", "甲方", "stack", "fingerprint", "vuln_focus", "tags"):
            v = fm.get(k)
            if isinstance(v, str):
                signals["text"] += v + "\n"
            elif isinstance(v, list):
                signals["text"] += "\n".join(str(x) for x in v) + "\n"
        # 显式字段行
        for line in scope_text.splitlines():
            if re.match(r"(?i)^(SRC|甲方|vendor|厂商|target|资产|范围|域名|domain|stack|fingerprint):", line):
                signals["text"] += re.sub(r"^[^:]*:", "", line) + "\n"

    # 2) raw/ 目录
    raw_dir = target_dir / "raw"
    if raw_dir.is_dir():
        for f in sorted(raw_dir.rglob("*")):
            if f.is_file() and f.stat().st_size < 5 * 1024 * 1024:
                txt = read_text(f).lower()
                signals["text"] += txt + "\n"
                # 简单分离 headers/body(以第一个空行)
                if "\n\n" in txt:
                    hdrs, body = txt.split("\n\n", 1)
                    signals["headers"] += hdrs + "\n"
                    signals["body"] += body + "\n"
                else:
                    signals["body"] += txt + "\n"
                signals["paths"] |= _extract_paths(txt)

    # 3) recon/probe-results.txt
    probe_path = target_dir / "recon" / "probe-results.txt"
    if probe_path.is_file():
        txt = read_text(probe_path).lower()
        signals["text"] += txt + "\n"
        signals["paths"] |= _extract_paths(txt)

    # 4) surface.md
    surface_path = target_dir / "surface.md"
    if surface_path.is_file():
        txt = read_text(surface_path).lower()
        signals["text"] += txt + "\n"
        signals["paths"] |= _extract_paths(txt)

    # 5) 提取 title / server / cookie
    all_text = (signals["text"] + "\n" + signals["headers"] + "\n" + signals["body"]).lower()
    for line in (signals["headers"] + signals["text"]).splitlines():
        low = line.lower()
        if low.startswith("server:"):
            signals["server"] += line.split(":", 1)[1].strip() + "\n"
        if low.startswith("set-cookie:") or low.startswith("cookie:"):
            signals["cookies"] += line.split(":", 1)[1].strip() + "\n"
    for m in re.finditer(r"<title[^>]*>(.*?)</title>", all_text, re.I | re.S):
        signals["titles"] += re.sub(r"<[^>]+>", " ", m.group(1)).strip() + "\n"

    signals["text"] = signals["text"].lower()
    signals["headers"] = signals["headers"].lower()
    signals["body"] = signals["body"].lower()
    signals["titles"] = signals["titles"].lower()
    signals["cookies"] = signals["cookies"].lower()
    signals["server"] = signals["server"].lower()
    signals["paths"] = {p.lower() for p in signals["paths"]}
    return signals


def _get_signal_bucket(signals, trigger_type):
    """把 trigger_type 映射到 signals 桶。"""
    t = trigger_type.lower()
    if t == "path":
        return signals["paths"]
    if t == "header":
        return signals["headers"]
    if t == "body":
        return signals["body"]
    if t == "title":
        return signals["titles"]
    if t == "server":
        return signals["server"]
    if t == "cookie":
        return signals["cookies"]
    return signals["text"]


def _condition_match(condition, signals):
    """匹配单个条件 {type, value}。"""
    t = condition.get("type", "text").lower()
    val = str(condition.get("value", "")).lower().strip()
    if not val:
        return False
    bucket = _get_signal_bucket(signals, t)
    if isinstance(bucket, set):
        return any(val in p for p in bucket)
    return val in bucket


def _trigger_match(trigger, signals):
    """匹配一个 trigger 对象(可能是 all_of/any_of/直接条件);支持递归。"""
    if "all_of" in trigger:
        return all(_trigger_match(sub, signals) for sub in trigger["all_of"])
    if "any_of" in trigger:
        return any(_trigger_match(sub, signals) for sub in trigger["any_of"])
    return _condition_match(trigger, signals)


def match_fingerprints(signals, fingerprints):
    """返回命中的指纹列表,每个元素带 matched_triggers。"""
    hits = []
    for fp in fingerprints:
        matched = []
        for trig in fp.get("triggers", []):
            if _trigger_match(trig, signals):
                matched.append(trig)
        if matched:
            hits.append({"fp": fp, "matched_triggers": matched})
    return hits


def read_scope(scope_path):
    """读取 scope,返回 domains/ips/mode/base_url 候选。"""
    text = read_text(scope_path)
    fm = parse_frontmatter(text)
    domains = []
    ips = []
    mode = ""
    base_url = ""

    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("mode:"):
            mode = line.split(":", 1)[1].strip().lower()
        for m in re.finditer(r"(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,})", line, re.I):
            domains.append(m.group(1).lower())
        for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?\b", line):
            ips.append(m.group(1))

    # 优先从 frontmatter target/domain 取 base_url
    tgt = fm.get("target") or fm.get("domain") or fm.get("域名")
    if isinstance(tgt, str) and tgt.strip():
        t = tgt.strip()
        if not re.match(r"^https?://", t, re.I):
            t = f"https://{t}"
        base_url = t
    return {"domains": list(set(domains)), "ips": list(set(ips)), "mode": mode, "text": text, "base_url": base_url}


def _host_in_scope(host, scope):
    """host 小写,检查是否在 scope 域名/IP 内。"""
    host = host.lower().strip()
    for ip in scope["ips"]:
        if ip in host:
            return True
    for d in scope["domains"]:
        d = d.lower().strip()
        if d in host:
            return True
        root = ".".join(d.split(".")[-2:]) if d.count(".") >= 1 else d
        if root and root in host:
            return True
    return False


def target_in_scope(base_url, scope):
    try:
        host = urlparse(base_url).hostname or ""
        return _host_in_scope(host, scope)
    except Exception:
        return False


def find_base_urls(target_dir, scope, max_bases=8):
    """收集 in-scope base_url 列表(去重、上限 max_bases)。

    来源优先级:
      1) scope frontmatter target/domain
      2) scope 正文 https? URL
      3) recon/probe-results.txt / surface.md / recon/*.md 中的 URL
      4) scope domains/ips 拼 https/http(兜底)
    """
    target_dir = Path(target_dir)
    scope = scope or {}
    seen = []
    seen_set = set()

    def _add(url):
        if not url:
            return
        u = url.strip().rstrip("/")
        if not re.match(r"^https?://", u, re.I):
            return
        # strip path for host-level base when path is just /
        try:
            p = urlparse(u)
            if not p.hostname:
                return
            # keep scheme://host[:port] only (checks append their own paths)
            base = f"{p.scheme}://{p.netloc}".rstrip("/")
        except Exception:
            return
        key = base.lower()
        if key in seen_set:
            return
        # scope filter when domains/ips present
        if scope.get("domains") or scope.get("ips"):
            if not target_in_scope(base, scope):
                return
        seen_set.add(key)
        seen.append(base)

    # 1) frontmatter base
    if scope.get("base_url"):
        _add(scope["base_url"])

    # 2) scope text URLs
    for m in re.finditer(r"https?://[^\s\"'`<>\]]+", scope.get("text") or "", re.I):
        _add(m.group(0))

    # 3) recon / surface
    candidates_files = []
    probe = target_dir / "recon" / "probe-results.txt"
    if probe.is_file():
        candidates_files.append(probe)
    surface = target_dir / "surface.md"
    if surface.is_file():
        candidates_files.append(surface)
    recon_dir = target_dir / "recon"
    if recon_dir.is_dir():
        for p in sorted(recon_dir.glob("*.md"))[:20]:
            candidates_files.append(p)
    for fp in candidates_files:
        text = read_text(fp)
        for m in re.finditer(r"https?://[^\s\"'`<>\]]+", text, re.I):
            _add(m.group(0))
            if len(seen) >= max_bases:
                return seen[:max_bases]

    # 4) domains / ips fallback
    for d in scope.get("domains") or []:
        _add(f"https://{d}")
        if len(seen) >= max_bases:
            break
    for ip in scope.get("ips") or []:
        _add(f"http://{ip}")
        if len(seen) >= max_bases:
            break

    return seen[:max_bases]


def find_base_url(target_dir, scope):
    """兼容旧 API:返回第一个 base_url 或空串。"""
    bases = find_base_urls(target_dir, scope)
    return bases[0] if bases else ""


def run_curl(url, method="GET", headers=None, timeout=10):
    """用 curl 做安全 GET,返回 (status, body_text, err)。"""
    method = method.upper()
    cmd = ["curl", "-sk", "-m", str(timeout), "-D", "-", "-o", "-", "-L", "--max-redirs", "0"]
    if method != "GET":
        cmd += ["-X", method]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout + 5)
        out = r.stdout or ""
        # 分离 headers/body
        if "\r\n\r\n" in out:
            hdr, body = out.split("\r\n\r\n", 1)
        elif "\n\n" in out:
            hdr, body = out.split("\n\n", 1)
        else:
            hdr, body = out, ""
        status = "000"
        for line in hdr.splitlines():
            if line.startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status = parts[1]
        return status, body, ""
    except subprocess.TimeoutExpired:
        return "000", "", "timeout"
    except Exception as exc:
        return "ERR", "", str(exc)


def _format_trigger(trig):
    """把 trigger 对象格式化为可读字符串。"""
    if "all_of" in trig:
        return "(all: " + " + ".join(_format_trigger(t) for t in trig["all_of"]) + ")"
    if "any_of" in trig:
        return "(any: " + " / ".join(_format_trigger(t) for t in trig["any_of"]) + ")"
    return f"{trig.get('type','?')}:{trig.get('value','?')}"


def run_checks(base_url, fp, timeout=10):
    """对单个指纹跑 checks,返回每个 check 结果列表。"""
    results = []
    for chk in fp.get("checks", []):
        path = chk.get("path", "/")
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        method = chk.get("method", "GET")
        headers = chk.get("headers") or {}
        status, body, error = run_curl(url, method=method, headers=headers, timeout=timeout)

        hit = False
        fixed = False
        status_ok = False
        expected = chk.get("status")
        if expected is None:
            status_ok = status[0].isdigit() and status != "000" and status != "ERR"
        else:
            status_ok = status in [str(s) for s in expected]

        hit_pat = chk.get("hit_grep", "")
        fixed_pat = chk.get("fixed_grep", "")
        if status_ok and hit_pat:
            hit = bool(re.search(hit_pat, body, re.I))
        if fixed_pat:
            fixed = bool(re.search(fixed_pat, body, re.I))

        if fixed:
            state = "fixed"
        elif hit:
            state = "confirmed"
        elif status_ok:
            state = "suspected"
        else:
            state = "miss"

        results.append({
            "name": chk.get("name", "check"),
            "url": url,
            "status": status,
            "state": state,
            "hit": hit,
            "fixed": fixed,
            "note": chk.get("note", ""),
            "command": chk.get("command", ""),
            "scanner_tags": chk.get("scanner_tags", ""),
            "error": error,
        })
    return results


def merge_playbooks_match(scope_path, playbook_paths):
    """Union-append playbook basenames into scope.md playbooks_match (no deletes).

    playbook_paths: list of paths like memory/playbooks/playbook-xxx.md
    Returns number of newly added names, or 0.
    """
    if not playbook_paths or not scope_path or not Path(scope_path).is_file():
        return 0
    names = []
    for p in playbook_paths:
        if not p:
            continue
        base = Path(str(p)).name
        if base.endswith(".md"):
            base = base[:-3]
        if base and base not in names:
            names.append(base)
    if not names:
        return 0

    scope_path = Path(scope_path)
    text = read_text(scope_path)
    existing = []
    m = re.search(r"^playbooks_match:\s*\[(.*?)\]\s*$", text, re.M)
    if m:
        existing = [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]
    before = set(existing)
    for n in names:
        if n not in existing:
            existing.append(n)
    added = len(existing) - len(before)
    if added == 0 and m:
        return 0
    list_yaml = "playbooks_match: [" + ", ".join(f'"{x}"' for x in existing) + "]"
    if m:
        new_text = re.sub(r"^playbooks_match:\s*\[.*?\]\s*$", list_yaml, text, count=1, flags=re.M)
    else:
        # insert before second --- if frontmatter, else append
        lines = text.splitlines()
        fm_end = None
        c = 0
        for i, ln in enumerate(lines):
            if ln.strip() == "---":
                c += 1
                if c == 2:
                    fm_end = i
                    break
        if fm_end is not None:
            lines.insert(fm_end, list_yaml)
            new_text = "\n".join(lines)
            if text.endswith("\n"):
                new_text += "\n"
        else:
            new_text = text.rstrip() + "\n\n" + list_yaml + "\n"
    scope_path.write_text(new_text, encoding="utf-8")
    return added


def render_markdown(target_dir, base_url, hits, dry_run, out_path, base_urls=None):
    """写 nday-matches.md 报告。base_urls 为 multi-base 列表;base_url 兼容单值。"""
    bases = list(base_urls or [])
    if not bases and base_url:
        bases = [base_url]
    lines = []
    lines.append(f"# N-day 指纹匹配报告\n")
    lines.append(f"- target: `{target_dir}`")
    if len(bases) <= 1:
        lines.append(f"- base_url: `{(bases[0] if bases else base_url) or '未提供'}`")
    else:
        lines.append(f"- base_urls: {len(bases)} 个")
        for b in bases:
            lines.append(f"  - `{b}`")
    lines.append(f"- dry_run: `{dry_run}`")
    lines.append(f"- generated_at: `{time.strftime('%Y-%m-%d %H:%M:%S')}`")
    lines.append(f"- 命中指纹数: {len(hits)}\n")

    if not hits:
        lines.append("未匹配到已知 N-day 指纹。")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return

    confirmed_total = sum(1 for h in hits if any(c["state"] == "confirmed" for c in h.get("results", [])))
    suspected_total = sum(1 for h in hits if any(c["state"] == "suspected" for c in h.get("results", [])))
    lines.append(f"- 已确认检查项: {confirmed_total}")
    lines.append(f"- 疑似检查项: {suspected_total}\n")
    lines.append("> ⚠️ **命中 ≠ verified**。下面只是「该产品有公开 N-day,建议按对应 playbook/skill 深入取证」。\n")
    lines.append("> 下一刀: `bash tools/playbook/run.sh <target>`(有 playbook 时) → 人工 PoC → findings candidate\n")

    primary_base = bases[0] if bases else (base_url or "https://target.com")

    for h in hits:
        fp = h["fp"]
        results = h.get("results", [])
        lines.append(f"## {fp.get('name', fp.get('id'))} ({fp.get('severity', 'unknown')})\n")
        lines.append(f"- id: `{fp.get('id')}`")
        lines.append(f"- product: {fp.get('product', '')}")
        lines.append(f"- severity: {fp.get('severity', '')}")
        lines.append(f"- tags: {', '.join(fp.get('tags', []))}")
        if fp.get("playbook"):
            lines.append(f"- playbook: `{fp.get('playbook')}`")
        if fp.get("skill"):
            lines.append(f"- skill: `{fp.get('skill')}`")
        lines.append(f"- 触发条件: " + "; ".join(_format_trigger(t) for t in h["matched_triggers"]))
        lines.append("")
        if not results:
            lines.append("- 检查: (dry-run / scope 外,未执行网络探测)")
        else:
            lines.append("| base | 检查 | 状态码 | 判定 | 备注 |")
            lines.append("|------|------|--------|------|------|")
            icon = {"confirmed": "🟢", "fixed": "🔴", "suspected": "🟡", "miss": "⚪"}
            for c in results:
                note = c["note"]
                if c["error"]:
                    note += f" (error: {c['error']})"
                b = c.get("base") or primary_base
                lines.append(
                    f"| `{b}` | {c['name']} | {c['status']} | {icon.get(c['state'], '?')} {c['state']} | {note} |"
                )
            for c in results:
                if c["command"]:
                    b = c.get("base") or primary_base
                    cmd = c["command"].replace("{base}", b)
                    lines.append(f"\n```bash\n{cmd}\n```")
                    if c["scanner_tags"]:
                        lines.append(
                            f"\n重武器扫描(需授权): `bash tools/run.sh scanner-dispatch nuclei {target_dir} {b} --tags {c['scanner_tags']} --confirm`"
                        )
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def print_summary(hits, base_url, dry_run, target_dir, base_urls=None):
    """打印简洁 stdout 摘要。"""
    bases = list(base_urls or [])
    if not bases and base_url:
        bases = [base_url]
    if not hits:
        log("🎯 N-day 指纹: 未命中已知 N-day 产品")
        if bases:
            log(f"   base_urls({len(bases)}): " + ", ".join(bases[:4]) + ("..." if len(bases) > 4 else ""))
        return
    log(f"🎯 N-day 指纹命中 {len(hits)} 个(按 severity 排序):")
    if bases:
        log(f"   base_urls({len(bases)}): " + ", ".join(bases[:4]) + ("..." if len(bases) > 4 else ""))
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_hits = sorted(hits, key=lambda h: sev_order.get(h["fp"].get("severity", "").lower(), 99))
    for h in sorted_hits[:8]:
        fp = h["fp"]
        sev = fp.get("severity", "?")
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
        confirmed = [c for c in h.get("results", []) if c["state"] == "confirmed"]
        state_tag = f"[确认 {len(confirmed)} 项]" if confirmed else "[待验证]"
        log(f"   {icon} {fp.get('name')} {state_tag}")
        log(f"      触发: {'; '.join(_format_trigger(t) for t in h['matched_triggers'])}")
        if fp.get("playbook"):
            log(f"      → Read {fp.get('playbook')}")
        elif fp.get("skill"):
            log(f"      → Read {fp.get('skill')}")
    if dry_run:
        log("   (dry-run,未做网络检查;跑 `bash tools/run.sh nday-matcher <target>` 验证)")
    else:
        log(f"   详细报告: {Path(target_dir) / 'recon' / 'nday-matches.md'}")
        log(f"   下一刀: bash tools/playbook/run.sh {target_dir}  # 有 playbook 时;命中≠verified")


def main():
    parser = argparse.ArgumentParser(description="N-day / 历史漏洞指纹识别器")
    parser.add_argument("target_dir", help="target 目录,如 targets/example")
    parser.add_argument("--base-url", help="强制指定单个 base URL(关闭 multi-base)")
    parser.add_argument("--dry-run", action="store_true", help="只匹配本地信号,不联网")
    parser.add_argument("--timeout", type=int, default=10, help="单条 curl 超时(秒)")
    parser.add_argument("--db", help="自定义指纹库 YAML 路径")
    parser.add_argument("--max-bases", type=int, default=8, help="multi-base 上限(默认 8)")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.is_dir():
        err(f"target_dir 不存在: {target_dir}")
        return 2

    db_path = Path(args.db) if args.db else DB_PATH
    fingerprints = load_fingerprints(db_path)
    if not fingerprints:
        err("指纹库为空,无法匹配")
        return 2

    signals = collect_signals(target_dir)
    hits = match_fingerprints(signals, fingerprints)

    scope = None
    scope_path = target_dir / "scope.md"
    if scope_path.is_file():
        scope = read_scope(scope_path)

    if args.base_url:
        base_urls = [args.base_url.rstrip("/")]
    elif scope:
        base_urls = find_base_urls(target_dir, scope, max_bases=args.max_bases)
    else:
        base_urls = find_base_urls(target_dir, {}, max_bases=args.max_bases)

    # scope filter for forced --base-url
    if not args.dry_run and base_urls and scope and args.base_url:
        if not target_in_scope(base_urls[0], scope):
            warn(f"base_url {base_urls[0]} 不在 scope.md 内,跳过网络检查")
            base_urls = []

    if not args.dry_run and base_urls and hits:
        for h in hits:
            all_results = []
            for b in base_urls:
                for r in run_checks(b, h["fp"], timeout=args.timeout):
                    r["base"] = b
                    all_results.append(r)
            h["results"] = all_results

    # bridge: confirmed/suspected → union playbooks_match
    if hits and scope_path.is_file():
        to_merge = []
        for h in hits:
            results = h.get("results") or []
            # dry-run or no checks: still enqueue playbook from trigger hit
            useful = (not results) or any(
                c.get("state") in ("confirmed", "suspected") for c in results
            )
            if useful and h["fp"].get("playbook"):
                to_merge.append(h["fp"]["playbook"])
        if to_merge:
            n = merge_playbooks_match(scope_path, to_merge)
            if n:
                log(f"📎 scope.playbooks_match += {n} (union,命中≠verified)")

    out_dir = target_dir / "recon"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "nday-matches.md"
    primary = base_urls[0] if base_urls else ""
    render_markdown(str(target_dir), primary, hits, args.dry_run, out_path, base_urls=base_urls)

    print_summary(hits, primary, args.dry_run, target_dir, base_urls=base_urls)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("用户中断")
        sys.exit(130)
    except Exception as exc:
        err(f"未预期错误: {exc}")
        sys.exit(1)
