#!/usr/bin/env python3
# tools/js-recon.py — JS 攻击面自动提取(v4.3.5 Python 版)
#
# 相比旧 bash 版改进:
#   - 更好的正则覆盖(路由配置、axios/fetch 调用、运行时配置对象)
#   - 自动检测 window._config / window.urls / axios.defaults.baseURL 等运行时 baseURL
#   - 统一去重与上下文截断,减少噪音
#   - 标准库实现,无外部依赖
#
# 用法:
#   python tools/js-recon.py <target_dir> <url_or_file>

import hashlib
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.target_paths import workspace_path, ensure_parent

# ── 配置 ──
API_RE = re.compile(
    r'["\047](/[A-Za-z0-9_./@-]+)["\047]'           # 普通字符串路径
    r'|(?:path|routePath|url|pathname)\s*[:=]\s*["\047](/[A-Za-z0-9_./@-]+)["\047]'  # 路由配置
    r'|(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax))\s*\(\s*["\047](/[A-Za-z0-9_./@-]+)["\047]',  # 调用地址
    re.IGNORECASE,
)

# 运行时 baseURL / 全局 API 配置对象
BASEURL_RE = re.compile(
    r'(?:axios\.defaults\.baseURL|baseURL|baseUrl|apiBaseUrl|serverUrl|apiHost|gateway|publicPath|apiPrefix)\s*[:=]\s*["\047]([^"\047]+)["\047]',
    re.IGNORECASE,
)

RUNTIME_OBJ_RE = re.compile(
    r'(?:window\.(?:_config|config|urls|URLS|api|API|gateway|GLOBAL_CONFIG)|__INITIAL_STATE__|process\.env)\s*=\s*(\{[\s\S]*?\})',
    re.IGNORECASE,
)

SECRET_KEYWORDS = re.compile(
    r'\b(api[_-]?key|secret[_-]?key|app[_-]?secret|client[_-]?id|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|aws[_-]?access[_-]?key|aliyun[_-]?access[_-]?key|tencent[_-]?secret|baidu[_-]?api|map[_-]?key|ak|sk|jwt|signature|salt|encrypt[_-]?key|decrypt[_-]?key)\b',
    re.IGNORECASE,
)

SOURCEMAP_RE = re.compile(r'sourceMappingURL\s*=\s*(\S+)')
SOURCEMAP_URL_RE = re.compile(r'https?://[^"\047\s]+\.map')

LOW_VALUE_PREFIXES = (
    '/node_modules/', '/static/', '/assets/', '/images/', '/css/', '/js/',
    '/fonts/', '/favicon', '/robots', '/sitemap', '/uploads/', '/downloads/',
)

HIGH_VALUE_KEYWORDS = (
    'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'gateway', 'service', 'services',
    'open', 'auth', 'oauth', 'admin', 'manage', 'proxy', 'upload', 'download',
    'file', 'export', 'jdx', 'sentry', 'cas', 'sso', 'webhook', 'callback',
    'payment', 'order', 'user', 'account', 'system', 'config', 'decision',
)


def safe_filename(url: str) -> str:
    """把 URL 转成可安全做文件名的字符串。"""
    name = re.sub(r'[^a-zA-Z0-9._-]', '_', url)
    name = re.sub(r'_+', '_', name)
    name = name[:120]
    if not name.endswith(('.js', '.mjs', '.json', '.ts', '.jsx')):
        name += '.js'
    return name


def download(url: str, dest: Path) -> bool:
    """下载 URL 到 dest,返回是否成功。"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status != 200:
                return False
            data = resp.read()
        dest.write_bytes(data)
        return True
    except Exception as e:
        print(f"    ⚠️ 下载失败: {e}")
        return False


def collect_urls(input_arg: str) -> list:
    """输入是文件或单个 URL,返回 URL 列表。"""
    p = Path(input_arg)
    if p.is_file():
        return [line.strip() for line in p.read_text(encoding='utf-8', errors='ignore').splitlines() if line.strip()]
    if input_arg.startswith(('http://', 'https://', 'file://')):
        return [input_arg]
    print(f"❌ INPUT 既不是文件也不是 http(s)/file URL: {input_arg}")
    sys.exit(1)


def is_low_value(path: str) -> bool:
    lower = path.lower()
    if lower.startswith(LOW_VALUE_PREFIXES):
        return True
    if lower.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                       '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.webm',
                       '.json', '.xml', '.txt', '.html', '.htm')):
        return True
    return False


def is_high_value(path: str) -> bool:
    lower = path.lower()
    return any(kw in lower for kw in HIGH_VALUE_KEYWORDS)


def extract_api_paths(text: str) -> set:
    """从 JS 文本中提取 API 路径。"""
    paths = set()
    for m in API_RE.finditer(text):
        for g in m.groups():
            if g and g.startswith('/') and not is_low_value(g):
                paths.add(g)
    return paths


def extract_base_urls(text: str) -> set:
    """提取运行时 baseURL / 全局 API 前缀。"""
    found = set()
    for m in BASEURL_RE.finditer(text):
        found.add(m.group(1))
    # 对 window._config 等对象做浅层字符串提取
    for m in RUNTIME_OBJ_RE.finditer(text):
        obj = m.group(1)
        # 提取对象内 "api": "/foo" / baseURL: "..." 等键值
        for km in re.finditer(r'["\047]([^"\047]*(?:api|url|host|base|gateway|prefix)[^"\047]*)["\047]\s*:\s*["\047]([^"\047]+)["\047]', obj, re.IGNORECASE):
            found.add(km.group(2))
    return found


def extract_secrets(text: str) -> list:
    """返回 (行号, 上下文) 列表,最多 200 条。"""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if SECRET_KEYWORDS.search(line):
            # 截断到 180 字符并去重尾部
            snippet = line.strip()
            if len(snippet) > 180:
                snippet = snippet[:180] + '...'
            hits.append((i, snippet))
            if len(hits) >= 200:
                break
    return hits


def extract_sourcemaps(text: str) -> set:
    found = set()
    for m in SOURCEMAP_RE.finditer(text):
        found.add(m.group(1))
    for m in SOURCEMAP_URL_RE.finditer(text):
        found.add(m.group(0))
    return found


def main():
    if len(sys.argv) < 3:
        print("用法: python tools/js-recon.py <target_dir> <url_or_file>")
        sys.exit(1)

    target_dir = sys.argv[1]
    input_arg = sys.argv[2]

    # 与 recon-pipeline/nday-matcher/space-recon 约定一致:传入 targets/<甲方>/<目标> 完整路径。
    # 兼容旧式不带前缀调用 (js-recon acme <url>)。
    target_path = Path(target_dir) if target_dir.startswith('targets') else Path('targets') / target_dir

    out_dir = target_path / 'recon' / 'js-recon'
    dl_dir = workspace_path(target_path, 'recon/js-recon/downloaded')
    out_dir.mkdir(parents=True, exist_ok=True)
    dl_dir.mkdir(parents=True, exist_ok=True)

    urls = collect_urls(input_arg)
    (out_dir / 'urls.txt').write_text('\n'.join(urls) + '\n', encoding='utf-8')

    print(f"━━━ js-recon: {target_dir} ━━━")
    print("[1/4] 下载 JS 文件...")
    downloaded = []
    for url in urls:
        local_path = None
        if url.startswith('file://'):
            local_path = Path(url[7:])
        elif Path(url).is_file():
            local_path = Path(url)

        if local_path is not None:
            if local_path.is_file():
                dest = dl_dir / safe_filename(str(local_path))
                dest.write_bytes(local_path.read_bytes())
                downloaded.append(dest)
                print(f"  → {url}")
            else:
                print(f"    ⚠️ 本地文件不存在: {local_path}")
            continue

        dest = dl_dir / safe_filename(url)
        print(f"  → {url}")
        if download(url, dest):
            downloaded.append(dest)
        else:
            dest.unlink(missing_ok=True)

    # 过滤空/过小文件
    downloaded = [f for f in downloaded if f.is_file() and f.stat().st_size > 50]
    print(f"      → {len(downloaded)} 个有效 JS 文件")

    if not downloaded:
        print("❌ 没有可处理的 JS 文件")
        sys.exit(1)

    print("[2/4] 提取 API 路径 / baseURL / 运行时配置...")
    api_paths = set()
    base_urls = set()
    for f in downloaded:
        text = f.read_text(encoding='utf-8', errors='ignore')
        api_paths |= extract_api_paths(text)
        base_urls |= extract_base_urls(text)

    api_list = sorted(api_paths, key=lambda x: (not is_high_value(x), x))
    (out_dir / 'api-paths.txt').write_text('\n'.join(api_list) + '\n', encoding='utf-8')
    print(f"      → {len(api_list)} 条 API 路径")
    if base_urls:
        (out_dir / 'base-urls.txt').write_text('\n'.join(sorted(base_urls)) + '\n', encoding='utf-8')
        print(f"      → {len(base_urls)} 个 baseURL / 运行时配置")

    print("[3/4] 提取敏感关键词...")
    all_hits = []
    for f in downloaded:
        text = f.read_text(encoding='utf-8', errors='ignore')
        all_hits.extend(extract_secrets(text))
    # 按文件+行号去重并截断
    seen = set()
    uniq = []
    for f in downloaded:
        text = f.read_text(encoding='utf-8', errors='ignore')
        for i, snippet in extract_secrets(text):
            key = (f.name, i, snippet)
            if key not in seen:
                seen.add(key)
                uniq.append((f.name, i, snippet))
                if len(uniq) >= 200:
                    break
        if len(uniq) >= 200:
            break
    (out_dir / 'secrets.txt').write_text(
        '\n'.join(f"{name}:{line}: {snippet}" for name, line, snippet in uniq) + '\n',
        encoding='utf-8'
    )
    print(f"      → {len(uniq)} 条敏感关键词命中")

    print("[4/4] 提取 sourcemap...")
    sourcemaps = set()
    for f in downloaded:
        text = f.read_text(encoding='utf-8', errors='ignore')
        sourcemaps |= extract_sourcemaps(text)
    (out_dir / 'sourcemaps.txt').write_text('\n'.join(sorted(sourcemaps)) + '\n', encoding='utf-8')
    print(f"      → {len(sourcemaps)} 个 sourcemap")

    # 生成报告
    report = out_dir / 'js-attack-surface.md'
    lines = [
        '# JS 攻击面提取报告',
        '',
        f'**目标目录**: {target_dir}',
        f'**输入**: {input_arg}',
        f'**生成时间**: {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        '',
        '## 统计',
        '',
        f'| 类别 | 数量 | 文件 |',
        f'|---|---|---|',
        f'| 有效 JS 文件 | {len(downloaded)} | downloaded/ |',
        f'| API 路径 | {len(api_list)} | api-paths.txt |',
        f'| 敏感关键词 | {len(uniq)} | secrets.txt |',
        f'| Sourcemap | {len(sourcemaps)} | sourcemaps.txt |',
    ]
    if base_urls:
        lines.append(f'| baseURL / 运行时配置 | {len(base_urls)} | base-urls.txt |')
    lines += [
        '',
        '## 高关注 API 路径',
        '',
    ]
    for p in [x for x in api_list if is_high_value(x)][:150]:
        lines.append(f'- `{p}`')
    if len(api_list) > len([x for x in api_list if is_high_value(x)]):
        lines.append('')
        lines.append('## 其他 API 路径(前 100 条)')
        lines.append('')
        for p in [x for x in api_list if not is_high_value(x)][:100]:
            lines.append(f'- `{p}`')
    if base_urls:
        lines += [
            '',
            '## 运行时 baseURL / 全局配置',
            '',
        ]
        for u in sorted(base_urls)[:100]:
            lines.append(f'- `{u}`')
    lines += [
        '',
        '## 敏感关键词命中(前 50 条)',
        '',
    ]
    for name, line, snippet in uniq[:50]:
        lines.append(f'- `{name}:{line}` {snippet}')
    if sourcemaps:
        lines += [
            '',
            '## Sourcemap 列表',
            '',
        ]
        for sm in sorted(sourcemaps):
            lines.append(f'- `{sm}`')
    lines += [
        '',
        '## 下一步建议',
        '',
        '1. 对 `/open/*`、`/api/*`、`/admin/*`、`/upload/*` 等高价值路径做定向探测。',
        '2. 对 sourcemap 列表尝试下载,可能还原完整源码。',
        '3. 对 `base-urls.txt` 中的全局 baseURL 做服务边界确认。',
        '4. 对 secrets.txt 中的命中项手动复核上下文,确认是否为真实硬编码密钥。',
        '5. 将 api-paths.txt 喂给 `tools/ssrf-probe.sh` 或 `scanner-dispatch.py dirsearch` 做后续测试。',
    ]
    report.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    print("")
    print("━━━ 输出文件 ━━━")
    for f in sorted(out_dir.iterdir()):
        print(f"  {f.name}/" if f.is_dir() else f"  {f.name}")
    print("")
    print(f"汇总报告: {report}")


if __name__ == '__main__':
    main()
