#!/usr/bin/env python3
# tools/sign-extract.py — 客户端签名/加密函数自动提取 + Python 重放模板
#
# 用法:
#   bash tools/run.sh sign-extract <target_dir> <source_dir_or_file> [--lang js|java|cs|py]
#
# 输出:
#   <target_dir>/recon/sign-extract/sign-functions.json
#   <target_dir>/recon/sign-extract/sign-hits.txt
#   <target_dir>/recon/sign-extract/replay_templates/*.py

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.target_paths import ensure_parent

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── 配置 ──
SIGN_KEYWORDS = re.compile(
    r'\b(sign|signature|sig|hmac|md5|sha1|sha256|sha512|aes|rsa|encrypt|decrypt|cipher|crypto|hash|encode|decode)\b',
    re.IGNORECASE,
)

ALGO_PATTERNS = [
    ("MD5", re.compile(r'\bmd5\b', re.IGNORECASE)),
    ("SHA1", re.compile(r'\bsha-?1\b', re.IGNORECASE)),
    ("SHA256", re.compile(r'\bsha-?256\b', re.IGNORECASE)),
    ("SHA512", re.compile(r'\bsha-?512\b', re.IGNORECASE)),
    ("HMAC", re.compile(r'\bhmac\b', re.IGNORECASE)),
    ("AES", re.compile(r'\baes\b', re.IGNORECASE)),
    ("RSA", re.compile(r'\brsa\b', re.IGNORECASE)),
    ("Base64", re.compile(r'\bbase64\b', re.IGNORECASE)),
    ("SortedParams", re.compile(r'\bsort\b', re.IGNORECASE)),
]

# 按语言匹配函数/方法签名
FUNC_RE = {
    "js": re.compile(
        r'(?:function\s+(\w+)\s*\(([^)]*)\))'
        r'|(?:const\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\))'
        r'|(?:const\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>)'
        r'|(?:(\w+)\s*:\s*(?:async\s+)?function\s*\(([^)]*)\))'
        r'|(?:(\w+)\s*:\s*(?:async\s+)?\(([^)]*)\)\s*=>)',
        re.IGNORECASE,
    ),
    "java": re.compile(
        r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*\{',
        re.IGNORECASE,
    ),
    "cs": re.compile(
        r'(?:public|private|protected|internal|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*\{',
        re.IGNORECASE,
    ),
    "py": re.compile(
        r'def\s+(\w+)\s*\(([^)]*)\)\s*:',
        re.IGNORECASE,
    ),
}

EXT_BY_LANG = {
    "js": [".js", ".ts", ".jsx", ".tsx", ".vue"],
    "java": [".java", ".kt"],
    "cs": [".cs"],
    "py": [".py"],
}

SECRET_RE = re.compile(
    r'\b(secret|salt|key|iv|private|password|token)\b',
    re.IGNORECASE,
)


def log(msg, level="INFO"):
    icon = {"INFO": "ℹ️", "OK": "✅", "WARN": "⚠️", "HIT": "🚨", "STEP": "▶️"}.get(level, "•")
    print(f"{icon} {msg}", flush=True)


def err(msg):
    print(f"❌ {msg}", file=sys.stderr, flush=True)


def safe_name(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)[:80]


def dedupe_candidates(candidates: list) -> list:
    """按 (file, function) 去重,保留包含算法关键字的命中行。"""
    keep = {}
    for c in candidates:
        key = (c["file"], c["function"])
        existing = keep.get(key)
        if existing is None:
            keep[key] = c
            continue
        # 若当前 snippet 含算法名而旧的不含,则替换
        has_algo_current = any(pat.search(c["snippet"]) for _, pat in ALGO_PATTERNS)
        has_algo_existing = any(pat.search(existing["snippet"]) for _, pat in ALGO_PATTERNS)
        if has_algo_current and not has_algo_existing:
            keep[key] = c
    return list(keep.values())


def detect_lang(path: Path) -> str:
    suffix = path.suffix.lower()
    for lang, exts in EXT_BY_LANG.items():
        if suffix in exts:
            return lang
    return "js"


def find_source_files(src: Path, lang: str):
    if src.is_file():
        return [src]
    exts = EXT_BY_LANG.get(lang, [".js"])
    files = []
    for ext in exts:
        files.extend(src.rglob(f"*{ext}"))
    # 排除 node_modules / jadx lib
    files = [f for f in files if "node_modules" not in f.parts and "/lib/" not in str(f)]
    return files


def extract_function_name(lines: list, hit_idx: int, lang: str) -> str:
    """从命中行附近向上查找函数/方法名。"""
    func_re = FUNC_RE.get(lang)
    if not func_re:
        return ""
    window_start = max(0, hit_idx - 20)
    for i in range(hit_idx, window_start - 1, -1):
        line = lines[i]
        m = func_re.search(line)
        if m:
            # 取第一个非空组作为函数名
            groups = [g for g in m.groups() if g]
            return groups[0].strip() if groups else ""
    return ""


def guess_algorithms(context: str) -> list:
    algos = []
    for name, pat in ALGO_PATTERNS:
        if pat.search(context):
            algos.append(name)
    return algos


def is_noise_line(line: str) -> bool:
    """过滤 import / require / 注释等噪音。"""
    s = line.strip()
    if not s:
        return True
    if s.startswith(("//", "/*", "*", "#", "import ", "from ", "using ", "package ", "@")):
        return True
    if "console." in s or "Log." in s or "print(" in s:
        return True
    return False


def scan_file(file_path: Path, lang: str) -> list:
    """扫描单个文件,返回候选列表。"""
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    lines = text.splitlines()
    candidates = []
    seen_keys = set()

    for i, line in enumerate(lines):
        if not SIGN_KEYWORDS.search(line):
            continue
        if is_noise_line(line):
            continue

        func_name = extract_function_name(lines, i, lang)
        if not func_name:
            func_name = "anonymous"

        # 上下文:命中行前后各 6 行
        start = max(0, i - 6)
        end = min(len(lines), i + 7)
        context = "\n".join(lines[start:end])

        algos = guess_algorithms(context)
        confidence = "high" if algos and SECRET_RE.search(context) else ("medium" if algos else "low")

        rel = str(file_path)
        key = (rel, func_name, i)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        snippet = line.strip()
        if len(snippet) > 180:
            snippet = snippet[:180] + "..."

        candidates.append({
            "file": rel,
            "line": i + 1,
            "function": func_name,
            "snippet": snippet,
            "algorithms": algos,
            "confidence": confidence,
            "context": context,
        })

    return candidates


def build_template(candidate: dict, lang: str) -> str:
    """为候选生成 Python 重放脚本模板。"""
    func = safe_name(candidate["function"])
    file_base = safe_name(Path(candidate["file"]).stem) + "_" + func
    algos = candidate["algorithms"] or ["UNKNOWN"]
    algo = algos[0].upper()

    template = f'''#!/usr/bin/env python3
# Auto-generated by tools/sign-extract.py
# Source: {candidate["file"]}:{candidate["line"]} {candidate["function"]}
# Algorithm candidate: {" / ".join(algos)}
# Confidence: {candidate["confidence"]}

import hashlib
import hmac
import base64
import json
import urllib.parse
from urllib.parse import urlencode

# TODO: 通过 js-reverse-mcp / frida 断点回填以下值
SECRET = "__FILL_SECRET__"
SALT = "__FILL_SALT__"
SALT_ORDER = ["param1", "param2", "timestamp"]  # TODO: 确认参数顺序

def {func}(params: dict) -> str:
    """
    复刻 {candidate["function"]} 的签名/加密逻辑。
    当前实现基于静态扫描猜测,需要在断点中观察实际输入/输出后校准。
    """
    # 示例:按 SALT_ORDER 排序 + secret 后做 {algo}
    sorted_params = sorted((k, params.get(k, "")) for k in SALT_ORDER if k in params)
    payload = urlencode(sorted_params)
    if SALT:
        payload += SALT
    if SECRET:
        payload += SECRET

    # TODO: 根据实际算法选择以下分支之一
'''
    if "MD5" in algos:
        template += '''    sig = hashlib.md5(payload.encode()).hexdigest()
'''
    elif "SHA1" in algos:
        template += '''    sig = hashlib.sha1(payload.encode()).hexdigest()
'''
    elif "SHA256" in algos:
        template += '''    if SECRET:
        sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    else:
        sig = hashlib.sha256(payload.encode()).hexdigest()
'''
    elif "HMAC" in algos:
        template += '''    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
'''
    elif "AES" in algos:
        template += '''    # AES 加密需要额外确认模式/填充/IV,这里仅做占位
    from cryptography.fernet import Fernet  # pip install cryptography
    raise NotImplementedError("AES 分支需要断点观察后实现")
'''
    elif "RSA" in algos:
        template += '''    # RSA 签名需要私钥/公钥,这里仅做占位
    raise NotImplementedError("RSA 分支需要断点观察后实现")
'''
    else:
        template += '''    # 未识别算法,默认 MD5 占位
    sig = hashlib.md5(payload.encode()).hexdigest()
'''

    template += f'''
    return sig


if __name__ == "__main__":
    # TODO: 替换为真实请求参数,验证输出与断点一致
    params = {{"param1": "value1", "param2": "value2", "timestamp": "1234567890"}}
    print({func}(params))

'''
    return file_base, template


def main():
    parser = argparse.ArgumentParser(description="客户端签名/加密函数自动提取 + Python 重放模板")
    parser.add_argument("target_dir", help="target 目录")
    parser.add_argument("source", help="源码文件或目录")
    parser.add_argument("--lang", default="auto", choices=["auto", "js", "java", "cs", "py"],
                        help="源码语言,auto 按后缀识别")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    source = Path(args.source).resolve()

    if not target_dir.is_dir():
        err(f"target_dir 不存在: {target_dir}")
        return 1
    if not source.exists():
        err(f"source 不存在: {source}")
        return 1

    lang = args.lang
    if lang == "auto":
        lang = detect_lang(source) if source.is_file() else "js"

    out_dir = target_dir / "recon" / "sign-extract"
    tpl_dir = out_dir / "replay_templates"
    ensure_parent(out_dir / ".keep")

    log(f"━━━ sign-extract: {target_dir.name} (lang={lang}) ━━━")
    files = find_source_files(source, lang)
    log(f"扫描 {len(files)} 个 {lang} 源文件...")

    candidates = []
    for f in files:
        hits = scan_file(f, lang)
        candidates.extend(hits)

    # 同一函数多行命中时去重
    candidates = dedupe_candidates(candidates)

    # 按置信度排序,高 → 中 → 低
    order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: (order.get(c["confidence"], 3), c["file"], c["line"]))

    log(f"发现 {len(candidates)} 个 sign/crypto 候选函数")
    high = sum(1 for c in candidates if c["confidence"] == "high")
    med = sum(1 for c in candidates if c["confidence"] == "medium")
    low = sum(1 for c in candidates if c["confidence"] == "low")
    log(f"  high={high} medium={med} low={low}")

    # 写入 JSON
    summary = {
        "lang": lang,
        "source": str(source),
        "scanned_files": len(files),
        "candidates": candidates,
    }
    (out_dir / "sign-functions.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 写入 sign-hits.txt
    hits_lines = []
    for c in candidates:
        hits_lines.append(
            f"[{c['confidence']}] {c['file']}:{c['line']} {c['function']} "
            f"algo={'/'.join(c['algorithms'])} snippet={c['snippet'][:80]}"
        )
    (out_dir / "sign-hits.txt").write_text("\n".join(hits_lines) + "\n", encoding="utf-8")

    # 生成 Python 模板
    generated = []
    for c in candidates[:20]:  # 最多生成 20 个模板,避免噪音
        name, tpl = build_template(c, lang)
        tpl_path = tpl_dir / f"{name}.py"
        ensure_parent(tpl_path)
        tpl_path.write_text(tpl, encoding="utf-8")
        generated.append(str(tpl_path.name))

    if generated:
        log(f"生成 {len(generated)} 个 Python 重放模板")
        for g in generated[:5]:
            log(f"  → {g}")
        if len(generated) > 5:
            log(f"  ... 共 {len(generated)} 个")

    log(f"输出: {out_dir}")
    log("━━━ sign-extract 完成 ━━━")
    return 0


if __name__ == "__main__":
    sys.exit(main())
