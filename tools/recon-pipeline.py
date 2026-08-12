#!/usr/bin/env python3
# tools/recon-pipeline.py — 大范围资产发现流水线(v4.3.5)
#
# 用途: 输入一个或多个根域,输出可挖的攻击面清单(子域 + 分类 + 存活探测)。
#       输出与 skills/orchestrator.md 阶段 1/2 对齐,供 Commander 选择 Top N 后 spawn agent 深挖。
#
# 设计原则:
#   - 去掉外部工具硬依赖,优先 subfinder + httpx
#   - OneForAll / amass / assetfinder 可选,缺失时降级 crt.sh + Wayback
#   - 全部 OSINT 源均为被动/公开,不触法律红线
#   - 输出 schema 与 skills/orchestrator.md 对齐
#
# 用法:
#   bash tools/run.sh recon-pipeline <target_dir> <root1> [<root2>...] [--dry-run]
#
# 输出:
#   <target_dir>/recon/sources/            原始 OSINT 数据
#   <target_dir>/recon/all-subdomains.txt  去重后子域
#   <target_dir>/recon/subdomain-classified.md  反射准则视角分类
#   <target_dir>/recon/probe-results.txt   httpx/curl 存活探测结果
#   <target_dir>/recon/nday-matches.md     N-day / 历史漏洞指纹匹配报告
#
# 退出码: 0=正常 / 2=部分工具缺失但仍跑 / 3=用法错

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.target_paths import workspace_path
from tools.lib.tool_resolve import resolve as resolve_tool, load_yaml

# Windows 控制台默认 GBK,强制 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def _load_nday_matcher():
    """动态加载 tools/nday-matcher.py(文件名含连字符,无法直接 import)。"""
    path = ROOT / "tools" / "nday-matcher.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("nday_matcher", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_nday_matcher(target_dir, timeout=10):
    """在 recon 完成后跑 N-day 指纹快查,只发安全 GET 请求(multi-base ≤8)。"""
    mod = _load_nday_matcher()
    if mod is None:
        warn("nday-matcher.py 不存在,跳过 N-day 指纹快查")
        return

    target_dir = Path(target_dir)
    try:
        fingerprints = mod.load_fingerprints()
        if not fingerprints:
            return
        signals = mod.collect_signals(target_dir)
        hits = mod.match_fingerprints(signals, fingerprints)

        scope_path = target_dir / "scope.md"
        scope = mod.read_scope(scope_path) if scope_path.is_file() else {}
        find_bases = getattr(mod, "find_base_urls", None)
        if find_bases:
            base_urls = find_bases(target_dir, scope or {}, max_bases=8)
        else:
            b = mod.find_base_url(target_dir, scope) if scope else ""
            base_urls = [b] if b else []

        if hits and base_urls:
            for h in hits:
                all_results = []
                for b in base_urls:
                    for r in mod.run_checks(b, h["fp"], timeout=timeout):
                        r["base"] = b
                        all_results.append(r)
                h["results"] = all_results

        if hits and scope_path.is_file() and hasattr(mod, "merge_playbooks_match"):
            to_merge = [h["fp"].get("playbook") for h in hits if h["fp"].get("playbook")]
            if to_merge:
                n = mod.merge_playbooks_match(scope_path, to_merge)
                if n:
                    log(f"📎 scope.playbooks_match += {n}")

        if not hits:
            log("🎯 N-day 指纹: 未命中已知 N-day 产品")

        out_path = target_dir / "recon" / "nday-matches.md"
        primary = base_urls[0] if base_urls else ""
        dry = not bool(base_urls)
        try:
            mod.render_markdown(
                target_dir, primary, hits, dry_run=dry, out_path=out_path, base_urls=base_urls
            )
        except TypeError:
            mod.render_markdown(target_dir, primary, hits, dry_run=dry, out_path=out_path)
        try:
            mod.print_summary(hits, primary, dry_run=dry, target_dir=target_dir, base_urls=base_urls)
        except TypeError:
            mod.print_summary(hits, primary, dry_run=dry, target_dir=target_dir)
    except Exception as exc:
        warn(f"N-day 指纹快查失败: {exc}")


def log(msg):
    print(msg, flush=True)


def err(msg):
    print(f"❌ {msg}", file=sys.stderr, flush=True)


def warn(msg):
    print(f"⚠️  {msg}", flush=True)


def which(cmd):
    """优先 external-tools.yaml / tool_resolve,再退回 PATH。"""
    cfg = load_yaml()
    registered = set((cfg.get("tools") or {}).keys())
    if cmd in registered or cmd.replace("-", "_") in registered:
        p = resolve_tool(cmd)
        if p is not None:
            return str(p)
    return shutil.which(cmd)


def run(cmd, timeout=60, shell=False, check=False, cwd=None, capture=True):
    """运行外部命令,返回 (rc, stdout, stderr)。"""
    try:
        kwargs = {
            "shell": shell,
            "cwd": cwd,
            "timeout": timeout,
            "text": True,
        }
        if capture:
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.PIPE
        result = subprocess.run(cmd, **kwargs)
        if check and result.returncode != 0:
            return result.returncode, result.stdout or "", result.stderr or ""
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return 127, "", "command not found"
    except Exception as e:
        return 1, "", str(e)


def fetch_crtsh(root):
    """crt.sh 被动 SSL 证书透明日志。"""
    url = f"https://crt.sh/?q=%25.{quote(root)}&output=json"
    rc, out, _ = run(["curl", "-sk", "-m", "60", url], timeout=70)
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
        subs = set()
        for item in data:
            name = item.get("name_value", "") or item.get("common_name", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line and "*" not in line and line.endswith(f".{root}") or line == root:
                    subs.add(line)
        return sorted(subs)
    except Exception:
        return []


def fetch_wayback(root):
    """Wayback Machine 历史 URL,常含已下线子域。"""
    url = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{quote(root)}&output=text&fl=original"
        "&collapse=urlkey&limit=5000"
    )
    rc, out, _ = run(["curl", "-sk", "-m", "60", url], timeout=70)
    if rc != 0:
        return []
    subs = set()
    for line in out.splitlines():
        m = re.search(r"https?://([^/?:\s]+)", line)
        if not m:
            continue
        host = m.group(1).lower().strip(".")
        if host.endswith(f".{root}") or host == root:
            subs.add(host)
    return sorted(subs)


def fetch_otx(root):
    """AlienVault OTX 被动 DNS(免费,无需 key)。"""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(root)}/passive_dns"
    rc, out, _ = run(["curl", "-sk", "-m", "30", url], timeout=40)
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
        subs = set()
        for item in data.get("passive_dns", []):
            h = (item.get("hostname") or "").lower().strip()
            if h and (h.endswith(f".{root}") or h == root):
                subs.add(h)
        return sorted(subs)
    except Exception:
        return []


def run_subfinder(roots, out_file):
    """subfinder 经 tool_resolve 解析后跑,否则返回 False。"""
    subfinder = which("subfinder")
    if not subfinder:
        return False
    roots_file = out_file.parent / "roots.txt"
    roots_file.write_text("\n".join(roots) + "\n", encoding="utf-8")
    rc, out, errtxt = run(
        [subfinder, "-dL", str(roots_file), "-all", "-silent"],
        timeout=300,
    )
    if rc == 0:
        subs = sorted(set(line.strip().lower() for line in out.splitlines() if line.strip()))
        out_file.write_text("\n".join(subs) + "\n", encoding="utf-8")
        return True
    return False


def run_oneforall(roots, sources_dir):
    """OneForAll 经 tool_resolve / 天狐解析后跑。无 key 也能跑部分源。"""
    p = resolve_tool("oneforall")
    oneforall_py = str(p) if p else None
    if not oneforall_py:
        # 兼容旧 env / 本地副本
        for c in [
            os.environ.get("ONEFORALL_PY", ""),
            "tools/oneforall/oneforall.py",
        ]:
            if c and Path(c).is_file():
                oneforall_py = c
                break
    if not oneforall_py:
        return False
    oneforall_dir = str(Path(oneforall_py).parent)
    python = shutil.which("python") or shutil.which("python3") or sys.executable
    if not python:
        return False
    for root in roots:
        run(
            [python, "oneforall.py", "--target", root, "--brute", "false", "run"],
            timeout=300,
            cwd=oneforall_dir,
        )
    results_dir = Path(oneforall_dir) / "results"
    if results_dir.is_dir():
        for csv in results_dir.glob("*.csv"):
            shutil.copy(csv, sources_dir / csv.name)
    return True


def run_amass(roots, out_file):
    amass = which("amass")
    if not amass:
        return False
    roots_file = out_file.parent / "roots.txt"
    roots_file.write_text("\n".join(roots) + "\n", encoding="utf-8")
    rc, out, _ = run([amass, "enum", "-passive", "-df", str(roots_file), "-silent"], timeout=300)
    if rc == 0:
        subs = sorted(set(line.strip().lower() for line in out.splitlines() if line.strip()))
        out_file.write_text("\n".join(subs) + "\n", encoding="utf-8")
        return True
    return False


def run_assetfinder(roots, out_file):
    af = which("assetfinder")
    if not af:
        return False
    subs = set()
    for root in roots:
        rc, out, _ = run([af, "--subs-only", root], timeout=120)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip().lower()
                if line:
                    subs.add(line)
    if subs:
        out_file.write_text("\n".join(sorted(subs)) + "\n", encoding="utf-8")
        return True
    return False


def run_httpx(in_file, out_file):
    # tool_resolve 已做 PD identity 校验,杜绝 Python httpx 冒充
    httpx = which("httpx")
    if not httpx:
        return False
    rc, _, _ = run(
        [
            httpx,
            "-l", str(in_file),
            "-silent",
            "-timeout", "8",
            "-threads", "20",
            "-status-code",
            "-title",
            "-tech-detect",
            "-no-color",
            "-o", str(out_file),
        ],
        timeout=600,
    )
    return rc == 0 and out_file.is_file()


def run_curl_fallback(in_file, out_csv):
    """无 httpx 时用 curl 并行探测,输出 CSV。"""
    hosts = [line.strip() for line in in_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    out_csv.write_text("host,scheme,http_code,size,server,title\n", encoding="utf-8")

    def probe(host):
        for scheme in ("https", "http"):
            rc, out, _ = run(
                ["curl", "-sik", "-m", "8", "-L", "--max-redirs", "3", f"{scheme}://{host}/"],
                timeout=15,
            )
            if rc != 0:
                continue
            first = out.splitlines()[0] if out else ""
            code_m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first)
            code = code_m.group(1) if code_m else ""
            if not code or code == "000":
                continue
            server = ""
            for line in out.splitlines():
                if re.match(r"(?i)^server:", line):
                    server = re.sub(r"(?i)^server:\s*", "", line).strip().replace(",", "_")
                    break
            title = ""
            m = re.search(r"<title>([^<]*)</title>", out, re.IGNORECASE)
            if m:
                title = m.group(1).strip().replace(",", "_").replace("\n", " ")
            size = len(out.encode("utf-8", errors="ignore"))
            return f"{host},{scheme},{code},{size},{server},{title}\n"
        return ""

    with ThreadPoolExecutor(max_workers=10) as ex:
        for row in ex.map(probe, hosts):
            if row:
                with out_csv.open("a", encoding="utf-8") as f:
                    f.write(row)
    return True


def classify_subdomains(subdomains, roots):
    """按反射准则视角分类,生成 markdown。"""
    lines = ["# Subdomain 分类(反射准则视角)", f"总数: {len(subdomains)}", ""]

    categories = [
        ("🔥 高 ROI 关键字命中", None),
        ("A. 开放平台 / 开发者 / API", r"^(developer|open|api|dev|console|sdk|push)\.|developer\.|openapi|opensdk"),
        ("B. 支付 / 钱包 / 资金 ⚠️ §2", r"^(pay|wallet|payment|fund|bill|cashier)\.|paycashier"),
        ("C. 商城 / 应用 / 游戏", r"^(mall|shop|store|app|game)\.|appstore|gamecenter"),
        ("D. 测试 / 预发 / dev(SRC 经典金矿)", r"\.(test|dev|stage|sit|uat|pre|qa)\.|^test|^dev|^stage|xhprof"),
        ("E. 内部 / 管理 / 工具", r"^(admin|manage|console|inner|internal|backend|ops|jenkins|grafana|gitlab|nacos|consul|swagger|druid|h2)\."),
        ("F. 反射准则第一层(参数级 SSRF/任意文件读)关键字", r"proxy|cloud|cdn|forward|gateway|relay|file|upload|download"),
        ("G. 第三方业务区", r"fenxiao|chuancan|terminal|distrib|gd-|partner|agent"),
    ]

    for title, pattern in categories:
        lines.append(f"## {title}")
        lines.append("")
        if pattern is None:
            lines.append("下表按关键字聚类,快速定位高 ROI 子域。")
            lines.append("")
            continue
        matched = [s for s in subdomains if re.search(pattern, s, re.IGNORECASE)]
        if matched:
            for s in matched[:30]:
                lines.append(f"- {s}")
            if len(matched) > 30:
                lines.append(f"- ... 共 {len(matched)} 条,省略剩余")
        else:
            lines.append("- (无)")
        lines.append("")

    return "\n".join(lines)


def summarize_client_recon(target_dir):
    """读取 client-recon / miniapp-recon / android-recon 的 manifest.json,返回 markdown 行列表。"""
    manifests = [
        ("client-recon", Path(target_dir) / "recon" / "client-recon" / "manifest.json"),
        ("miniapp-recon", Path(target_dir) / "recon" / "miniapp-recon" / "manifest.json"),
        ("android-recon", Path(target_dir) / "recon" / "android-recon" / "manifest.json"),
    ]
    lines = []
    for label, path in manifests:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        findings = data.get("findings", {})
        ctype = data.get("client_type", label)
        asset = data.get("asset_path", "")
        lines.append(
            f"| {ctype} 客户端资产 | API {findings.get('api_paths', 0)} | baseURL {findings.get('base_urls', 0)} | "
            f"secret {findings.get('secrets', 0)} | `{asset}` |"
        )
    return lines


def append_pending(target_dir, roots, total, recon_dir):
    pending = Path(target_dir) / "_PENDING.md"
    sources = ["crt.sh", "Wayback", "OTX"]
    if (recon_dir / "sources" / "subfinder.txt").is_file():
        sources.append("subfinder")
    if (recon_dir / "sources" / "amass.txt").is_file():
        sources.append("amass")
    if list((recon_dir / "sources").glob("*.csv")):
        sources.append("OneForAll")

    client_lines = summarize_client_recon(target_dir)
    client_block = ""
    if client_lines:
        client_block = """
**客户端资产(来自阶段 0 / client-recon)**:

| 类型 | API 路径 | baseURL | 敏感关键词 | 资产 |
|---|---|---|---|---|
""" + "\n".join(client_lines) + """
"""

    block = f"""

---

## ⚡ recon-pipeline {time.strftime('%Y-%m-%d %H:%M')} — 大范围资产发现完成

| 指标 | 数据 |
|---|---|
| 输入根域 | {' '.join(roots)} |
| 唯一子域(多源去重) | {total} |
| 分类输出 | {recon_dir}/subdomain-classified.md |
| 存活探测 | {recon_dir}/probe-results.txt |
| 数据源 | {' + '.join(sources)} |
{client_block}
**强制动作**: Read `{recon_dir}/subdomain-classified.md` 看高 ROI 候选 → 选 Top 5-10 用 multi-agent 并行深挖(`skills/orchestrator.md` 阶段 3)。

**反 velox 教训**: 不要单 agent 串行打存活子域,应该 5 个 Explore agent 同时各打一个。
"""
    with pending.open("a", encoding="utf-8") as f:
        f.write(block)


def main():
    parser = argparse.ArgumentParser(
        description="大范围资产发现流水线",
        usage="%(prog)s <target_dir> <root1> [<root2>...] [--dry-run]",
    )
    parser.add_argument("target_dir", help="目标目录,如 targets/velox/recon 或 targets/velox")
    parser.add_argument("roots", nargs="+", help="一个或多个根域,如 velox.com")
    parser.add_argument("--dry-run", action="store_true", help="只检查工具可用性和目录结构,不联网")
    args = parser.parse_args()

    target_dir = Path(args.target_dir)
    roots = [r.lower().strip() for r in args.roots]

    if not target_dir.is_dir():
        err(f"target_dir 不存在: {target_dir}")
        return 3

    recon_dir = target_dir / "recon"
    sources_dir = workspace_path(target_dir, "recon/sources")
    sources_dir.mkdir(parents=True, exist_ok=True)

    log(f"━━━ recon-pipeline v2 ━━━")
    log(f"target_dir: {target_dir}")
    log(f"roots: {' '.join(roots)}")
    log("")

    # ── 工具可用性检查 ──
    has_subfinder = which("subfinder") is not None
    has_httpx = which("httpx") is not None
    missing_tools = []
    if not has_subfinder:
        missing_tools.append("subfinder")
    if not has_httpx:
        missing_tools.append("httpx")

    if missing_tools:
        warn(f"工具缺失,将用 fallback: {', '.join(missing_tools)}")
        partial_rc = 2
    else:
        partial_rc = 0

    if args.dry_run:
        log("[dry-run] 不联网,仅检查结构与工具")
        log(f"  recon_dir: {recon_dir} (exists={recon_dir.is_dir()})")
        log(f"  sources_dir: {sources_dir} (exists={sources_dir.is_dir()})")
        log(f"  subfinder: {'✅' if has_subfinder else '❌'}")
        log(f"  httpx: {'✅' if has_httpx else '❌'}")
        log("  roots: " + " ".join(roots))
        # dry-run 只报告可用性,不视为失败
        return 0

    # 实际运行时才因工具缺失返回 2
    partial_rc = 2 if missing_tools else 0

    # ── 阶段 1: 被动 OSINT ──
    log("[1/4] 被动 OSINT 多源并发...")
    all_subs = set()

    def fetch_one(source_name, func, root):
        try:
            subs = func(root)
            return source_name, root, subs
        except Exception as e:
            return source_name, root, []

    tasks = []
    for root in roots:
        tasks.append(("crt.sh", fetch_crtsh, root))
        tasks.append(("wayback", fetch_wayback, root))
        tasks.append(("otx", fetch_otx, root))

    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(fetch_one, name, func, root): (name, root) for name, func, root in tasks}
        for fut in as_completed(futures):
            name, root, subs = fut.result()
            if subs:
                all_subs.update(subs)
                (sources_dir / f"{name}-{root}.txt").write_text(
                    "\n".join(subs) + "\n", encoding="utf-8"
                )
            log(f"  ✓ {name}:{root} → {len(subs)} 子域")

    # 可选工具
    if has_subfinder:
        sf_out = sources_dir / "subfinder.txt"
        if run_subfinder(roots, sf_out):
            all_subs.update(sf_out.read_text(encoding="utf-8").splitlines())
            log(f"  ✓ subfinder → {len([l for l in sf_out.read_text().splitlines() if l.strip()])} 子域")
    else:
        log("  ⚠ subfinder 未找到,跳过(可用 crt.sh+Wayback fallback)")

    if run_oneforall(roots, sources_dir):
        log("  ✓ OneForAll(部分源无需 key)")
        for csv in sources_dir.glob("*.csv"):
            try:
                text = csv.read_text(encoding="utf-8", errors="ignore")
                for line in text.splitlines()[1:]:
                    parts = line.split(",")
                    if len(parts) > 5:
                        host = parts[5].strip().strip('"').lower()
                        if host:
                            all_subs.add(host)
            except Exception:
                pass

    amass_out = sources_dir / "amass.txt"
    if run_amass(roots, amass_out):
        all_subs.update(amass_out.read_text(encoding="utf-8").splitlines())
        log(f"  ✓ amass → {len([l for l in amass_out.read_text().splitlines() if l.strip()])} 子域")

    af_out = sources_dir / "assetfinder.txt"
    if run_assetfinder(roots, af_out):
        all_subs.update(af_out.read_text(encoding="utf-8").splitlines())
        log(f"  ✓ assetfinder → {len([l for l in af_out.read_text().splitlines() if l.strip()])} 子域")

    # 过滤:只保留以 roots 结尾或等于 roots 的域,去掉通配符和脏数据
    filtered = set()
    for s in all_subs:
        s = s.strip().lower().rstrip(".")
        if not s or "*" in s or " " in s or len(s) > 253:
            continue
        if any(s == r or s.endswith(f".{r}") for r in roots):
            filtered.add(s)

    subdomains = sorted(filtered)
    all_file = recon_dir / "all-subdomains.txt"
    all_file.write_text("\n".join(subdomains) + "\n", encoding="utf-8")
    log(f"  唯一子域(去重后): {len(subdomains)}")
    log("")

    # ── 阶段 2: 分类 ──
    log("[2/4] 子域去重 + 分类...")
    classified = classify_subdomains(subdomains, roots)
    classified_file = recon_dir / "subdomain-classified.md"
    classified_file.write_text(classified, encoding="utf-8")
    log(f"  分类输出: {classified_file}")
    log("")

    # ── 阶段 3: 存活探测 ──
    log("[3/4] 存活探测...")
    probe_file = recon_dir / "probe-results.txt"
    if len(subdomains) == 0:
        probe_file.write_text("", encoding="utf-8")
        log("  无子域,跳过存活探测")
    elif run_httpx(all_file, probe_file):
        live = [l for l in probe_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        log(f"  ✓ httpx 存活探测 → {len(live)} 条")
    else:
        warn("httpx 未装或不是 ProjectDiscovery 版本,用 curl 并行 fallback")
        csv_file = workspace_path(target_dir, "recon/probe-results.csv")
        csv_file.parent.mkdir(parents=True, exist_ok=True)
        run_curl_fallback(all_file, csv_file)
        live = [l for l in csv_file.read_text(encoding="utf-8").splitlines() if l.strip()][1:]
        log(f"  ✓ curl fallback 存活探测 → {len(live)} 条")
    log("")

    # ── 阶段 3.5: N-day 指纹快查 ──
    log("[3.5/4] N-day 指纹快查(只发安全 GET)...")
    run_nday_matcher(target_dir)
    log("")

    # ── 阶段 4: 输出摘要 + _PENDING ──
    log("[4/4] 输出最终摘要...")
    pending_file = target_dir / "_PENDING.md"
    if pending_file.is_file():
        append_pending(target_dir, roots, len(subdomains), recon_dir)
        log(f"  ✓ 追加 {pending_file}")

    log("")
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log("✅ recon-pipeline 完成")
    log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log("")
    log("下一步:")
    log(f"  1. cat {classified_file}  # 看分类")
    log(f"  2. cat {recon_dir / 'nday-matches.md'}  # 看 N-day 命中与推荐 playbook")
    log("  3. Read skills/orchestrator.md  # 看编排与 multi-agent 触发条件")
    log("  4. 选 Top 5-10 子域,启动 5 个 Explore subagent 并行深挖")

    return partial_rc


if __name__ == "__main__":
    sys.exit(main())
