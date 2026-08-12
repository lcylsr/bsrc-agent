#!/usr/bin/env python3
# tools/space-recon.py — 空间测绘统一封装(Fofa / Hunter / Quake)
#
# 用途: 把被动 OSINT(crt.sh/Wayback)漏掉的内部业务域、IP 资产通过空间测绘 API 补全。
#       输出与 skills/orchestrator.md 阶段 1/2 对齐。
#
# API key 来源(优先级从高到低,统一经 tools.lib.tool_resolve.load_keys):
#   1. 环境变量: FOFA_EMAIL/FOFA_KEY, HUNTER_KEY, QUAKE_TOKEN
#   2. ~/.config/srccop/keys.env 或 keys.json
#   3. ~/.config/space-recon/keys.env 或 keys.json
#   4. tools/keys.env(本地,勿提交 git;见 tools/keys.env.example)
#
# 用法:
#   bash tools/run.sh space-recon <target_dir> <domain>
#
# 退出码:
#   0 = 至少一个 API 成功返回
#   1 = 全部 API 无 key 或失败
#   3 = 用法错

import argparse
import base64
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.tool_resolve import load_keys


def log(msg):
    print(msg, flush=True)


def warn(msg):
    print(f"⚠️  {msg}", flush=True)


DEFAULT_FOFA_BASE = "https://bdziyi.com/hygj/ssyq.html"


def is_custom_proxy(base):
    """bdziyi 代理: 非官方 API 路径,走自定义 POST 协议。"""
    return "bdziyi.com" in base or "ssyq" in base


def decode_body(raw):
    """代理响应编码不一(utf-8/gbk 混用),带回退。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", errors="replace")


def post_form(url, data, headers=None, timeout=60):
    """POST form-urlencoded,返回 (rc, body)。"""
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, decode_body(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, decode_body(body)
    except Exception as e:
        return 0, str(e)


def parse_fofa_results(body):
    """解析 FOFA 兼容 JSON {"error": bool, "results": [[host,ip,...]]}。"""
    try:
        data = json.loads(body)
        if data.get("error"):
            return False, data.get("errmsg", "unknown")
        results = data.get("results", [])
        assets = []
        for r in results:
            if isinstance(r, list) and len(r) >= 2:
                host, ip = r[0], r[1]
                assets.append({"host": host, "ip": ip, "source": "fofa"})
        return True, assets
    except Exception as e:
        return False, str(e)


def fetch(url, headers=None, timeout=30):
    """简单 GET,返回 (rc, body)。rc 为 HTTP 状态码或 0(网络错误)。"""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


def fofa_query(domain, email, key, size=100, base=None, cookie=None):
    """FOFA 搜索。
    - bdziyi.com 自定义代理: POST <dir>/ssyqapi.php?action=fofa_cx&fofa_yf=<domain>&fofa_ts=<rows>,需登录 cookie(FOFA_COOKIE)
    - 官方/兼容 API: GET {base}/api/v1/search/all(需 email+key)
    """
    base = (base or os.environ.get("FOFA_BASE") or DEFAULT_FOFA_BASE).rstrip("/")
    if is_custom_proxy(base):
        api = base[: base.rfind("/") + 1] + "ssyqapi.php"
        data = f"action=fofa_cx&fofa_yf={quote(domain)}&fofa_ts={size}".encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": base,
        }
        if cookie:
            headers["Cookie"] = cookie
        rc, body = post_form(api, data, headers)
        if rc != 200:
            return False, f"HTTP {rc}: {body[:200]}"
        return parse_fofa_results(body)
    query = f'domain="{domain}"'
    b64 = base64.b64encode(query.encode("utf-8")).decode("utf-8")
    params = f"key={quote(key)}&qbase64={quote(b64)}&size={size}&fields=host,ip,port,title"
    if email:
        params = f"email={quote(email)}&{params}"
    url = f"{base}/api/v1/search/all?{params}"
    rc, body = fetch(url)
    if rc != 200:
        return False, f"HTTP {rc}: {body[:200]}"
    return parse_fofa_results(body)


def hunter_query(domain, key, page_size=100):
    query = f'domain="{domain}"'
    b64 = base64.b64encode(query.encode("utf-8")).decode("utf-8")
    url = f"https://hunter.qianxin.com/openApi/search?api-key={quote(key)}&search={quote(b64)}&page=1&page_size={page_size}"
    rc, body = fetch(url)
    if rc != 200:
        return False, f"HTTP {rc}: {body[:200]}"
    try:
        data = json.loads(body)
        if data.get("code") != 200:
            return False, data.get("message", "unknown")
        results = data.get("data", {}).get("arr", [])
        assets = []
        for r in results:
            assets.append({"host": r.get("url", ""), "ip": r.get("ip", ""), "source": "hunter"})
        return True, assets
    except Exception as e:
        return False, str(e)


def quake_query(domain, token, size=100):
    query = f'domain:"{domain}"'
    url = "https://quake.360.net/api/v3/search/quake_service"
    headers = {
        "X-QuakeToken": token,
        "Content-Type": "application/json",
    }
    payload = json.dumps({"query": query, "start": 0, "size": size}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if data.get("code") != 0:
                return False, data.get("message", "unknown")
            results = data.get("data", [])
            assets = []
            for r in results:
                service = r.get("service", {})
                host = service.get("http", {}).get("host", "")
                ip = r.get("ip", "")
                assets.append({"host": host, "ip": ip, "source": "quake"})
            return True, assets
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return False, f"HTTP {e.code}: {body[:200]}"
    except Exception as e:
        return False, str(e)


def extract_hosts(assets):
    """从资产列表中提取唯一 host。"""
    hosts = set()
    for a in assets:
        h = a.get("host", "").strip().lower()
        if h and h.startswith("http"):
            # 去掉 scheme
            h = h.split("://", 1)[-1].split("/")[0]
        if h:
            hosts.add(h)
    return sorted(hosts)


def main():
    parser = argparse.ArgumentParser(description="空间测绘统一封装")
    parser.add_argument("target_dir", help="目标目录")
    parser.add_argument("domain", help="根域")
    args = parser.parse_args()

    target_dir = Path(args.target_dir)
    if not target_dir.is_dir():
        print(f"❌ target_dir 不存在: {target_dir}", file=sys.stderr)
        return 3

    recon_dir = target_dir / "recon"
    recon_dir.mkdir(exist_ok=True)

    log(f"━━━ space-recon: {args.domain} → {recon_dir} ━━━")

    keys = load_keys()
    fofa_email = keys.get("FOFA_EMAIL") or os.environ.get("FOFA_EMAIL", "")
    fofa_key = keys.get("FOFA_KEY") or os.environ.get("FOFA_KEY", "")
    fofa_base = keys.get("FOFA_BASE") or os.environ.get("FOFA_BASE", "") or None
    fofa_cookie = keys.get("FOFA_COOKIE") or os.environ.get("FOFA_COOKIE", "")
    hunter_key = keys.get("HUNTER_KEY") or os.environ.get("HUNTER_KEY", "")
    quake_token = keys.get("QUAKE_TOKEN") or os.environ.get("QUAKE_TOKEN", "")

    all_assets = []
    reports = []

    # FOFA: 官方/兼容 API 需 FOFA_KEY;bdziyi 自定义代理仅需 FOFA_COOKIE
    if fofa_key or is_custom_proxy(fofa_base or DEFAULT_FOFA_BASE):
        log(f"[Fofa] 查询中... base={fofa_base or DEFAULT_FOFA_BASE}")
        ok, res = fofa_query(args.domain, fofa_email, fofa_key, base=fofa_base, cookie=fofa_cookie)
        if ok:
            all_assets.extend(res)
            reports.append(f"Fofa: {len(res)} 条")
            log(f"  → Fofa {len(res)} 条")
        else:
            warn(f"Fofa 失败: {res}")
            if "调用次数" in str(res):
                warn("提示: bdziyi 代理今日配额已用完,次日或续费后重试;临时可用 FOFA_BASE=https://fofa.icu 走兼容代理")
    else:
        reports.append("Fofa: 未配置 FOFA_KEY（官方 API）且无自定义代理可用")
        warn("Fofa: 未配置 FOFA_KEY")

    if hunter_key:
        log("[Hunter] 查询中...")
        ok, res = hunter_query(args.domain, hunter_key)
        if ok:
            all_assets.extend(res)
            reports.append(f"Hunter: {len(res)} 条")
            log(f"  → Hunter {len(res)} 条")
        else:
            warn(f"Hunter 失败: {res}")
    else:
        reports.append("Hunter: 未配置 HUNTER_KEY")
        warn("Hunter: 未配置 HUNTER_KEY")

    if quake_token:
        log("[Quake] 查询中...")
        ok, res = quake_query(args.domain, quake_token)
        if ok:
            all_assets.extend(res)
            reports.append(f"Quake: {len(res)} 条")
            log(f"  → Quake {len(res)} 条")
        else:
            warn(f"Quake 失败: {res}")
    else:
        reports.append("Quake: 未配置 QUAKE_TOKEN")
        warn("Quake: 未配置 QUAKE_TOKEN")

    hosts = extract_hosts(all_assets)

    # 输出文件
    hosts_file = recon_dir / "space-subdomains.txt"
    hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    report_file = recon_dir / "space-assets.md"
    report_lines = [
        "# 空间测绘资产报告",
        "",
        f"**目标**: {args.domain}",
        f"**生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**总资产**: {len(all_assets)}",
        f"**唯一 host**: {len(hosts)}",
        "",
        "## API 状态",
        "",
    ]
    for r in reports:
        report_lines.append(f"- {r}")
    report_lines.extend([
        "",
        "## 唯一 Host 列表",
        "",
    ])
    for h in hosts[:200]:
        report_lines.append(f"- {h}")
    if len(hosts) > 200:
        report_lines.append(f"- ... 共 {len(hosts)} 条,显示前 200")
    report_lines.extend([
        "",
        "## 输出文件",
        "",
        f"- 唯一 host: `{hosts_file}`",
        f"- 本报告: `{report_file}`",
        "",
        "## 下一步",
        "",
        "1. 把 `space-subdomains.txt` 与 `recon/all-subdomains.txt` 合并",
        "2. 跑 httpx 探活: `httpx -l recon/space-subdomains.txt -o recon/space-live.txt`",
        "3. 用 `bash tools/run.sh nday-matcher <target_dir>` 做 N-day 指纹匹配,再按 skills/orchestrator.md 阶段 3 深挖",
        "",
    ])
    report_file.write_text("\n".join(report_lines), encoding="utf-8")

    log(f"输出: {hosts_file} ({len(hosts)} host)")
    log(f"       {report_file}")

    if not all_assets:
        warn("全部 API 未配置或失败,未拿到空间测绘数据")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
