#!/usr/bin/env python3
# tools/client-recon.py — 统一客户端攻击面识别与静态提取入口
#
# 用法:
#   bash tools/run.sh client-recon <target_dir> <asset_path> [--type auto|apk|ipa|wxapkg|asar|electron|pe|macho] [--out-dir <dir>]
#
# 输出:
#   <target_dir>/recon/client-recon/client-attack-surface.md
#   <target_dir>/recon/client-recon/manifest.json
#   <target_dir>/recon/client-recon/api-paths.txt
#   ...
#   E:/claude-artifacts/tmp/<target_key>/recon/client-recon/extracted/

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.target_paths import workspace_path, ensure_parent, target_key

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── 正则 ──
URL_RE = re.compile(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=-]+?(?=[\'"\s,)>}\]]|$)')

SECRET_RE = re.compile(
    r'\b(api[_-]?key|secret[_-]?key|app[_-]?secret|client[_-]?id|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|password|passwd|private[_-]?key|aws[_-]?access[_-]?key|aliyun[_-]?access[_-]?key|tencent[_-]?secret|baidu[_-]?api|map[_-]?key|ak|sk|jwt|signature|salt|encrypt[_-]?key|decrypt[_-]?key|session[_-]?key|openid|unionid)\b',
    re.IGNORECASE,
)

API_RE = re.compile(
    r'["\047](/[A-Za-z0-9_./@-]+)["\047]'
    r'|(?:path|routePath|url|pathname)\s*[:=]\s*["\047](/[A-Za-z0-9_./@-]+)["\047]'
    r'|(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax)|wx\.request)\s*\(\s*["\047](/[A-Za-z0-9_./@-]+)["\047]',
    re.IGNORECASE,
)

BASEURL_RE = re.compile(
    r'(?:axios\.defaults\.baseURL|baseURL|baseUrl|apiBaseUrl|serverUrl|apiHost|gateway|publicPath|apiPrefix)\s*[:=]\s*["\047]([^"\047]+)["\047]',
    re.IGNORECASE,
)

MINIPROGRAM_ROUTE_RE = re.compile(
    r'(?:wx\.(?:navigateTo|redirectTo|reLaunch|switchTab)|uni\.(?:navigateTo|redirectTo|reLaunch|switchTab)|wx\.navigateToMiniProgram)\s*\(\s*\{[^}]*url\s*:\s*["\047](/[^"\047]+)["\047]',
    re.IGNORECASE,
)

MINIPROGRAM_URL_RE = re.compile(
    r'["\047]((?:wx|alipay|tt)://[a-zA-Z0-9_-]+/?[^"\047]*)["\047]',
    re.IGNORECASE,
)

WEBVIEW_RE = re.compile(r'<web-view[^>]+src\s*=\s*["\047]([^"\047]+)["\047]', re.IGNORECASE)

NAVIGATOR_RE = re.compile(r'<navigator[^>]+url\s*=\s*["\047]([^"\047]+)["\047]', re.IGNORECASE)

WX_API_RE = re.compile(
    r'\b(wx\.(?:login|request|getUserInfo|getPhoneNumber|downloadFile|uploadFile|connectSocket|'
    r'chooseImage|scanCode|getLocation|openLocation|navigateToMiniProgram|openEmbeddedMiniProgram|'
    r'getStorage|setStorage|removeStorage|clearStorage|getSetting|openSetting|checkSession|'
    r'requestSubscribeMessage|requestPayment|login|getAccountInfoSync))\b',
    re.IGNORECASE,
)

CRYPTO_RE = re.compile(
    r'\b(MD5|SHA-?1|SHA-?256|SHA-?512|HMAC|AES|RSA|DES|Blowfish|CryptoJS|javax\.crypto|Cipher|MessageDigest|Mac|SecretKey|KeyStore|SharedPreferences|okhttp3|retrofit2|firebase|crashlytics)\b',
    re.IGNORECASE,
)

LOW_VALUE_PREFIXES = (
    '/node_modules/', '/static/', '/assets/', '/images/', '/css/', '/js/',
    '/fonts/', '/favicon', '/robots', '/sitemap', '/uploads/', '/downloads/',
)

HIGH_VALUE_KEYWORDS = (
    'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'gateway', 'service', 'services',
    'open', 'auth', 'oauth', 'admin', 'manage', 'proxy', 'upload', 'download',
    'file', 'export', 'jdx', 'sentry', 'cas', 'sso', 'webhook', 'callback',
    'payment', 'order', 'user', 'account', 'system', 'config', 'decision',
    'pay', 'coupon', 'member', 'address', 'card', 'wallet', 'invoice',
    'login', 'register', 'verify', 'send', 'sms', 'email', 'push',
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def log(msg, level="INFO"):
    icon = {"INFO": "ℹ️", "OK": "✅", "WARN": "⚠️", "HIT": "🚨", "STEP": "▶️", "SKIP": "⏭️"}.get(level, "•")
    print(f"{icon} {msg}", flush=True)


def err(msg):
    print(f"❌ {msg}", file=sys.stderr, flush=True)


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
    return any(kw in path.lower() for kw in HIGH_VALUE_KEYWORDS)


def read_text(path: Path, limit_mb=5):
    """安全读取文本,过大返回空。"""
    try:
        if path.stat().st_size > limit_mb * 1024 * 1024:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def find_source_files(root: Path, exts):
    """按扩展名递归收集文件,并排除 node_modules / .git 干扰。"""
    if not root.is_dir():
        return []
    files = []
    for ext in exts:
        files.extend(root.rglob(ext))
    return [f for f in files if "node_modules" not in f.parts and ".git" not in f.parts]


def scan_js_source(src_dir: Path):
    """通用 JS / 小程序 / Android / 源码扫描,返回攻击面提取字段。"""
    api_paths = set()
    base_urls = set()
    secrets = []
    routes = set()
    webviews = set()
    wx_api_hits = set()
    miniapp_urls = set()
    navigator_hits = set()
    crypto_refs = set()
    seen_secret = set()
    seen_crypto = set()

    exts = ("*.js", "*.ts", "*.jsx", "*.vue", "*.json", "*.wxml", "*.wxss", "*.acss", "*.axml", "*.html")
    for f in find_source_files(src_dir, exts):
        text = read_text(f)
        if not text:
            continue
        # API 路径
        for m in API_RE.finditer(text):
            for g in m.groups():
                if g and g.startswith('/') and not is_low_value(g):
                    api_paths.add(g)
        # baseURL
        for m in BASEURL_RE.finditer(text):
            base_urls.add(m.group(1))
        # URL
        for u in URL_RE.findall(text):
            if not u.lower().startswith(('http://localhost', 'http://127.0.0.1', 'https://servicewechat.com', 'https://mp.weixin.qq.com')):
                base_urls.add(u)
        # Secrets / crypto refs
        for i, line in enumerate(text.splitlines(), 1):
            if SECRET_RE.search(line):
                snippet = line.strip()
                if len(snippet) > 180:
                    snippet = snippet[:180] + '...'
                key = (f.name, i, snippet)
                if key not in seen_secret:
                    seen_secret.add(key)
                    secrets.append((str(f.relative_to(src_dir)), i, snippet))
            if CRYPTO_RE.search(line):
                snippet = line.strip()[:120]
                key = (f.name, i, snippet)
                if key not in seen_crypto:
                    seen_crypto.add(key)
                    crypto_refs.add((str(f.relative_to(src_dir)), i, snippet))
        # 小程序路由 / navigator
        for m in MINIPROGRAM_ROUTE_RE.finditer(text):
            routes.add(m.group(1))
        for m in NAVIGATOR_RE.finditer(text):
            navigator_hits.add(m.group(1))
        # webview / 小程序 URL
        for m in WEBVIEW_RE.finditer(text):
            webviews.add(m.group(1))
        for m in MINIPROGRAM_URL_RE.finditer(text):
            miniapp_urls.add(m.group(1))
        # 微信小程序 API 调用
        for m in WX_API_RE.finditer(text):
            wx_api_hits.add(m.group(1))

    return {
        "api_paths": sorted(api_paths, key=lambda x: (not is_high_value(x), x)),
        "base_urls": sorted(base_urls)[:200],
        "secrets": secrets[:200],
        "routes": sorted(routes | navigator_hits),
        "webviews": sorted(webviews),
        "deep_links": sorted({d for d in (webviews | miniapp_urls) if '{{' not in d and '}}' not in d})[:100],
        "wx_api_calls": sorted(wx_api_hits),
        "crypto_refs": sorted(crypto_refs)[:200],
    }


def detect_type(asset_path: Path, force: str):
    if force and force != "auto":
        return force
    if not asset_path.exists():
        return "unknown"
    suffix = asset_path.suffix.lower()
    name = asset_path.name.lower()
    if suffix == ".apk":
        return "android"
    if suffix == ".ipa":
        return "ios"
    if suffix == ".wxapkg":
        return "miniprogram"
    if suffix == ".asar":
        return "electron"
    if suffix in (".exe", ".dll"):
        return "pe"
    if asset_path.is_dir():
        # 目录类型启发
        if (asset_path / "app.json").is_file() and (asset_path / "app.js").is_file():
            return "miniprogram"
        if (asset_path / "AndroidManifest.xml").is_file():
            return "android"
        if any((asset_path / "Payload").glob("*.app") if (asset_path / "Payload").exists() else []):
            return "ios"
        if (asset_path / "package.json").is_file():
            return "electron"
        return "unknown"
    # 文件头 magic
    try:
        header = asset_path.open("rb").read(4)
    except Exception:
        return "unknown"
    if header[:2] == b"PK":
        # zip, maybe apk/ipa
        with zipfile.ZipFile(asset_path, "r") as z:
            names = z.namelist()
            if any(n.startswith("Payload/") and n.endswith(".app/") for n in names):
                return "ios"
            if "AndroidManifest.xml" in names or "classes.dex" in names:
                return "android"
        return "unknown"
    if header[:4] == b"\xcf\xfa\xed\xfe" or header[::-1][:4] == b"\xcf\xfa\xed\xfe":
        return "macho"
    return "unknown"


def resolve_executable(name: str) -> str:
    """跨平台解析可执行文件路径,处理 Windows .CMD/.EXE 扩展名。"""
    path = shutil.which(name)
    if path:
        return path
    if sys.platform == "win32":
        for ext in (".cmd", ".bat", ".exe"):
            path = shutil.which(name + ext)
            if path:
                return path
    return name


def run_cmd(cmd, timeout=120, cwd=None):
    """运行外部命令,返回 (ok, stdout, stderr)。"""
    if not cmd:
        return False, "", "empty command"
    resolved = [resolve_executable(cmd[0])] + cmd[1:]
    try:
        result = subprocess.run(
            resolved, capture_output=True, text=True, timeout=timeout, cwd=cwd,
            encoding="utf-8", errors="replace"
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def tool_available(name):
    return shutil.which(name) is not None


def aapt_badging(apk_path: Path):
    """返回 (package, version, launchable_activities[])。"""
    if not tool_available("aapt"):
        return "", "", []
    ok, out, _ = run_cmd(["aapt", "dump", "badging", str(apk_path)], timeout=60)
    pkg = ""
    version = ""
    launchable = []
    if not ok:
        return pkg, version, launchable
    for line in out.splitlines():
        if line.startswith("package:"):
            m = re.search(r"name='([^']+)'", line)
            if m:
                pkg = m.group(1)
            m = re.search(r"versionName='([^']+)'", line)
            if m:
                version = m.group(1)
        elif "launchable-activity" in line:
            m = re.search(r"name='([^']+)'", line)
            if m:
                launchable.append(m.group(1))
    return pkg, version, launchable


def aapt_permissions(apk_path: Path):
    if not tool_available("aapt"):
        return []
    ok, out, _ = run_cmd(["aapt", "dump", "permissions", str(apk_path)], timeout=60)
    if not ok:
        return []
    perms = []
    for line in out.splitlines():
        m = re.search(r"'([^']+)'", line)
        if m:
            perms.append(m.group(1))
    return perms


def parse_manifest(manifest_path: Path):
    """解析文本 AndroidManifest.xml;返回 package、version、components、deep_links、dangerous、permissions、sdk。"""
    result = {
        "package": "",
        "version": "",
        "min_sdk": "",
        "target_sdk": "",
        "permissions": [],
        "components": [],
        "deep_links": [],
        "dangerous_configs": [],
    }
    if not manifest_path.is_file():
        return result

    text = manifest_path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r'package="([^"]+)"', text)
    if m:
        result["package"] = m.group(1)
    m = re.search(r'android:versionName="([^"]+)"', text)
    if m:
        result["version"] = m.group(1)
    m = re.search(r'android:minSdkVersion="(\d+)"', text)
    if m:
        result["min_sdk"] = m.group(1)
    m = re.search(r'android:targetSdkVersion="(\d+)"', text)
    if m:
        result["target_sdk"] = m.group(1)

    if 'android:allowBackup="true"' in text:
        result["dangerous_configs"].append("allowBackup=true")
    if 'android:debuggable="true"' in text:
        result["dangerous_configs"].append("debuggable=true")
    if 'android:usesCleartextTraffic="true"' in text:
        result["dangerous_configs"].append("usesCleartextTraffic=true")
    if 'android:networkSecurityConfig' in text:
        result["dangerous_configs"].append("networkSecurityConfig 存在(需检查是否信任用户证书)")

    result["permissions"] = re.findall(r'<uses-permission[^/]*android:name="([^"]+)"', text)

    try:
        ET.register_namespace("android", ANDROID_NS)
        root = ET.fromstring(text.encode("utf-8"))
    except Exception:
        return result

    ns = {"android": ANDROID_NS}

    def attr(elem, name, default=""):
        return elem.attrib.get(f"{{{ANDROID_NS}}}{name}") or elem.attrib.get(name, default)

    def parse_intent_filters(parent, comp_name):
        exported = attr(parent, "exported")
        deep = []
        browsable = False
        view_action = False
        for intent in parent.findall("intent-filter"):
            for action in intent.findall("action"):
                if attr(action, "name") == "android.intent.action.VIEW":
                    view_action = True
            for cat in intent.findall("category"):
                if attr(cat, "name") == "android.intent.category.BROWSABLE":
                    browsable = True
            for data in intent.findall("data"):
                scheme = attr(data, "scheme") or "http"
                host = attr(data, "host") or ""
                port = attr(data, "port") or ""
                path = attr(data, "path") or ""
                path_prefix = attr(data, "pathPrefix") or ""
                path_pattern = attr(data, "pathPattern") or ""
                chosen = path or path_prefix or path_pattern or "/"
                if host:
                    uri = f"{scheme}://{host}{':' + port if port else ''}{chosen}"
                else:
                    uri = f"{scheme}://{chosen}"
                deep.append(uri)
        if view_action and browsable:
            result["deep_links"].append({"component": comp_name, "uris": deep})
        is_exported = False
        if exported.lower() == "true":
            is_exported = True
        elif exported.lower() != "false" and parent.findall("intent-filter"):
            is_exported = True
        return is_exported

    for tag in ("activity", "service", "receiver", "provider"):
        for elem in root.findall(f"application/{tag}"):
            name = attr(elem, "name")
            if not name:
                continue
            exported = parse_intent_filters(elem, name)
            comp = {
                "type": tag,
                "name": name,
                "exported": exported,
                "permission": attr(elem, "permission"),
                "read_permission": attr(elem, "readPermission"),
                "write_permission": attr(elem, "writePermission"),
                "authorities": attr(elem, "authorities"),
            }
            result["components"].append(comp)

    seen = set()
    uniq = []
    for d in result["deep_links"]:
        key = (d["component"], tuple(d["uris"]))
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    result["deep_links"] = uniq
    return result


def extract_miniprogram(src_dir: Path, out_dir: Path, extracted_dir: Path):
    log("识别为微信小程序源码目录", "OK")
    findings = scan_js_source(src_dir)

    # app.json 路由
    app_json_path = src_dir / "app.json"
    pages = []
    tab_bar = []
    sub_packages = []
    plugins = []
    functional_pages = False
    permission = {}
    appid = ""
    if app_json_path.is_file():
        try:
            data = json.loads(app_json_path.read_text(encoding="utf-8", errors="ignore"))
            pages = data.get("pages", [])
            tab_bar = [item.get("pagePath", "") for item in data.get("tabBar", {}).get("list", [])]
            sub_packages = [sp.get("root", "") for sp in data.get("subpackages", []) + data.get("subPackages", [])]
            plugins = list(data.get("plugins", {}).keys())
            functional_pages = data.get("functionalPages", False) is True
            permission = data.get("permission", {})
        except Exception:
            pass

    # project.config.json 中的 appid
    project_path = src_dir / "project.config.json"
    if project_path.is_file():
        try:
            pdata = json.loads(project_path.read_text(encoding="utf-8", errors="ignore"))
            appid = pdata.get("appid", pdata.get("setting", {}).get("appid", ""))
            if not appid and "projectname" in pdata:
                appid = pdata.get("projectname", "")
        except Exception:
            pass

    findings["pages"] = pages
    findings["tab_bar"] = tab_bar
    findings["sub_packages"] = sub_packages
    findings["plugins"] = plugins
    findings["functional_pages"] = functional_pages
    findings["permission"] = permission
    findings["appid"] = appid
    findings["routes"] = sorted(set(findings["routes"]) | set(pages) | set(tab_bar) | set(sub_packages))
    findings["package_name"] = ""
    findings["version"] = ""
    findings["dangerous_configs"] = []
    findings["exported_components"] = []
    findings["deep_links"] = sorted(findings.get("deep_links", []))[:100]

    # 反编译产物引用,不复制
    extracted = str(src_dir.resolve())
    return findings, extracted, []


def strings_extract(file_path: Path):
    if not tool_available("strings"):
        return []
    ok, out, _ = run_cmd(["strings", str(file_path)], timeout=60)
    return out.splitlines() if ok else []


def extract_apk(apk_path: Path, out_dir: Path, extracted_dir: Path):
    log("识别为 Android APK", "OK")
    warnings = []
    findings = scan_js_source(Path())  # 空扫描
    findings["pages"] = []
    findings["tab_bar"] = []
    findings["sub_packages"] = []
    findings["webviews"] = []

    # 基础解压
    unzip_dir = extracted_dir / "apk_unzip"
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            z.extractall(unzip_dir)
        log("APK 解压完成", "OK")
    except Exception as e:
        log(f"解压 APK 失败: {e}", "WARN")
        warnings.append("APK 解压失败")

    # 优先用 jadx 反编译
    extracted = str(extracted_dir / "apk")
    jadx_dir = Path(extracted)
    if tool_available("jadx"):
        log("使用 jadx 反编译 APK...", "STEP")
        ok, out, errtxt = run_cmd(["jadx", "-d", extracted, str(apk_path)], timeout=300)
        if ok:
            log("jadx 反编译完成", "OK")
            src = Path(extracted) / "sources"
            if src.is_dir():
                findings = scan_js_source(src)
                # 同步 reset 小程序/无关字段
                findings["pages"] = []
                findings["tab_bar"] = []
                findings["sub_packages"] = []
                findings["webviews"] = []
        else:
            log(f"jadx 失败: {errtxt[:120]}", "WARN")
            warnings.append("jadx 反编译失败,已降级为 unzip + strings")
    else:
        log("jadx 未安装,降级为 unzip + strings", "WARN")
        warnings.append("jadx 未安装,Android 静态提取能力受限")

    # 解析 AndroidManifest.xml
    log("解析 AndroidManifest.xml...", "STEP")
    manifest_candidates = [
        jadx_dir / "resources" / "AndroidManifest.xml",
        jadx_dir / "AndroidManifest.xml",
        unzip_dir / "AndroidManifest.xml",
    ]
    manifest_path = next((p for p in manifest_candidates if p.is_file()), None)
    manifest_data = parse_manifest(manifest_path) if manifest_path else {}
    if not manifest_data.get("package"):
        pkg, version, launchable = aapt_badging(apk_path)
        manifest_data.setdefault("package", pkg)
        manifest_data.setdefault("version", version)
        if launchable:
            manifest_data.setdefault("launchable_activities", launchable)
    if not manifest_data.get("permissions"):
        manifest_data["permissions"] = aapt_permissions(apk_path)

    # 源码扫描(若 jadx 失败则退到 unzip)
    source_dir = jadx_dir / "sources" if (jadx_dir / "sources").is_dir() else unzip_dir
    source_findings = scan_js_source(source_dir)
    for key in ("api_paths", "base_urls", "secrets", "crypto_refs"):
        if key in source_findings:
            findings[key] = source_findings[key]

    # dex strings 补充 URL / secret / crypto
    dex_files = list(unzip_dir.glob("*.dex"))[:5]
    all_strings = []
    for dex in dex_files:
        all_strings.extend(strings_extract(dex))
    url_hits = sorted({u for u in URL_RE.findall("\n".join(all_strings)) if not u.startswith(('http://schemas.android', 'http://www.w3.org'))})[:100]
    secret_hits = []
    crypto_hits = []
    seen = set()
    seen_crypto = set()
    for i, line in enumerate(all_strings):
        if SECRET_RE.search(line):
            snippet = line.strip()[:180]
            key = (i, snippet)
            if key not in seen:
                seen.add(key)
                secret_hits.append(("dex_strings", i, snippet))
        if CRYPTO_RE.search(line):
            snippet = line.strip()[:120]
            key = (i, snippet)
            if key not in seen_crypto:
                seen_crypto.add(key)
                crypto_hits.append(("dex_strings", i, snippet))

    findings["base_urls"] = sorted(set(findings.get("base_urls", [])) | set(url_hits))[:200]
    findings["secrets"] = (findings.get("secrets", []) + secret_hits)[:200]
    findings["crypto_refs"] = (findings.get("crypto_refs", []) + crypto_hits)[:200]

    # 合并 Manifest 输出
    components = manifest_data.get("components", [])
    exported_components = [c for c in components if c.get("exported")]
    deep_links = manifest_data.get("deep_links", [])
    permissions = manifest_data.get("permissions", [])

    findings["package_name"] = manifest_data.get("package", "")
    findings["version"] = manifest_data.get("version", "")
    findings["min_sdk"] = manifest_data.get("min_sdk", "")
    findings["target_sdk"] = manifest_data.get("target_sdk", "")
    findings["permissions"] = permissions
    findings["exported_components"] = exported_components
    findings["deep_links"] = deep_links
    findings["dangerous_configs"] = manifest_data.get("dangerous_configs", [])
    findings["components"] = components
    findings["api_paths"] = sorted(set(findings.get("api_paths", [])), key=lambda x: (not is_high_value(x), x))

    return findings, extracted, warnings


def extract_ipa(ipa_path: Path, out_dir: Path, extracted_dir: Path):
    log("识别为 iOS IPA", "OK")
    warnings = []
    extracted = str(extracted_dir / "ipa")
    unzip_dir = Path(extracted)
    try:
        with zipfile.ZipFile(ipa_path, "r") as z:
            z.extractall(unzip_dir)
    except Exception as e:
        log(f"解压 IPA 失败: {e}", "WARN")
        return {}, extracted, ["IPA 解压失败"]

    findings = scan_js_source(Path())
    findings["pages"] = []
    findings["tab_bar"] = []
    findings["sub_packages"] = []
    findings["webviews"] = []

    app_dirs = list((unzip_dir / "Payload").glob("*.app")) if (unzip_dir / "Payload").is_dir() else []
    app_dir = app_dirs[0] if app_dirs else None
    pkg = ""
    version = ""
    deep_links = []
    dangerous = []
    if app_dir:
        # 解析 Info.plist
        plist_path = app_dir / "Info.plist"
        if plist_path.is_file():
            try:
                with plist_path.open("rb") as f:
                    plist = plistlib.load(f)
                pkg = plist.get("CFBundleIdentifier", "")
                version = plist.get("CFBundleShortVersionString", "")
                url_types = plist.get("CFBundleURLTypes", [])
                for ut in url_types:
                    for scheme in ut.get("CFBundleURLSchemes", []):
                        deep_links.append(f"{scheme}://")
                ats = plist.get("NSAppTransportSecurity", {})
                if ats.get("NSAllowsArbitraryLoads"):
                    dangerous.append("NSAllowsArbitraryLoads=true")
                for domain, cfg in ats.get("NSExceptionDomains", {}).items():
                    if cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
                        dangerous.append(f"ATS 明文例外: {domain}")
            except Exception as e:
                log(f"解析 Info.plist 失败: {e}", "WARN")
                warnings.append("Info.plist 解析失败")

        # strings 提取
        exec_files = [f for f in app_dir.iterdir() if f.is_file() and not f.name.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".plist", ".json", ".xml", ".car", ".nib"))]
        all_strings = []
        for ef in exec_files[:3]:
            ok, out, _ = run_cmd(["strings", str(ef)], timeout=60)
            if ok:
                all_strings.extend(out.splitlines())
        url_hits = sorted({u for u in URL_RE.findall("\n".join(all_strings)) if not u.startswith("http://schemas")})[:100]
        secret_hits = []
        seen = set()
        for i, line in enumerate(all_strings):
            if SECRET_RE.search(line):
                snippet = line.strip()
                if len(snippet) > 180:
                    snippet = snippet[:180] + "..."
                key = (i, snippet)
                if key not in seen:
                    seen.add(key)
                    secret_hits.append(("macho_strings", i, snippet))

        # JS/HTML in bundle
        web_assets = list(app_dir.rglob("*.js")) + list(app_dir.rglob("*.html")) + list(app_dir.rglob("*.json"))
        js_findings = scan_js_source(app_dir)
        findings["api_paths"] = sorted(set(js_findings["api_paths"]) | set(findings["api_paths"]), key=lambda x: (not is_high_value(x), x))
        findings["base_urls"] = sorted(set(js_findings["base_urls"]) | set(url_hits))[:200]
        findings["secrets"] = (js_findings["secrets"] + secret_hits)[:200]

    findings["package_name"] = pkg
    findings["version"] = version
    findings["deep_links"] = sorted(deep_links)
    findings["dangerous_configs"] = dangerous
    findings["exported_components"] = []

    return findings, extracted, warnings


def extract_asar(asar_path: Path, out_dir: Path, extracted_dir: Path):
    log("识别为 Electron asar", "OK")
    warnings = []
    extracted = str(extracted_dir / "asar")
    src = Path(extracted)
    if tool_available("npx"):
        log("使用 npx asar 提取...", "STEP")
        ok, out, errtxt = run_cmd(["npx", "asar", "extract", str(asar_path), extracted], timeout=300)
        if ok:
            log("asar 提取完成", "OK")
        else:
            log(f"asar 提取失败: {errtxt[:120]}", "WARN")
            warnings.append("npx asar 提取失败")
    else:
        log("npx 不可用,无法自动提取 asar", "WARN")
        warnings.append("npx 不可用,asar 提取失败")

    if src.is_dir():
        findings = scan_js_source(src)
        # package.json
        pkg_json = src / "package.json"
        pkg = ""
        version = ""
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                pkg = data.get("name", "")
                version = data.get("version", "")
            except Exception:
                pass
        # 检测 nodeIntegration / contextIsolation
        dangerous = []
        for f in find_source_files(src, ("*.js", "*.ts", "*.json")):
            text = read_text(f)
            if "nodeIntegration:" in text or '"nodeIntegration"' in text:
                dangerous.append(f"nodeIntegration 可能启用: {f.relative_to(src)}")
            if "contextIsolation:" in text or '"contextIsolation"' in text:
                dangerous.append(f"contextIsolation 配置存在: {f.relative_to(src)}")
        findings["package_name"] = pkg
        findings["version"] = version
        findings["dangerous_configs"] = dangerous[:50]
        findings["exported_components"] = []
        findings["deep_links"] = []
        findings["pages"] = []
        findings["tab_bar"] = []
        findings["sub_packages"] = []
        return findings, extracted, warnings

    return {}, extracted, warnings + ["asar 提取后目录不存在"]


def extract_generic(asset_path: Path, out_dir: Path, extracted_dir: Path):
    log(f"未知/通用文件: {asset_path.name}", "WARN")
    warnings = [f"未识别的客户端类型,仅做 strings 提取: {asset_path.name}"]
    extracted = str(extracted_dir / "generic")
    # 通用类型不做 JS 目录扫描,避免扫描当前工作目录
    findings = {
        "api_paths": [],
        "base_urls": [],
        "secrets": [],
        "routes": [],
        "webviews": [],
        "package_name": "",
        "version": "",
        "dangerous_configs": [],
        "exported_components": [],
        "deep_links": [],
        "pages": [],
        "tab_bar": [],
        "sub_packages": [],
    }

    if asset_path.is_file():
        ok, out, _ = run_cmd(["strings", str(asset_path)], timeout=60)
        if ok:
            url_hits = sorted({u for u in URL_RE.findall(out) if not u.startswith("http://schemas")})[:100]
            secret_hits = []
            seen = set()
            for i, line in enumerate(out.splitlines()):
                if SECRET_RE.search(line):
                    snippet = line.strip()
                    if len(snippet) > 180:
                        snippet = snippet[:180] + "..."
                    key = (i, snippet)
                    if key not in seen:
                        seen.add(key)
                        secret_hits.append(("strings", i, snippet))
            findings["base_urls"] = url_hits
            findings["secrets"] = secret_hits[:200]

    return findings, extracted, warnings


def build_findings(client_type: str, asset_path: Path, findings: dict, extracted: str, warnings: list):
    """整理 findings 并生成 next_steps 与 manifest。"""
    next_steps = []
    if client_type == "miniprogram":
        next_steps.append("bash tools/run.sh sign-extract <target_dir> <source_dir> --lang js")
        next_steps.append("对提取的 API 端点按 skills/api-logic/fuzz.md 做参数级 fuzz")
        next_steps.append("spawn client-agent for manual mini-program audit")
    elif client_type == "android":
        next_steps.append("bash tools/run.sh android-recon <target_dir> <apk>（深度反编译）")
        next_steps.append("bash tools/run.sh frida-template <target_dir> <package> --hook ssl")
        next_steps.append("spawn client-agent for Android exported component / local storage audit")
    elif client_type == "ios":
        next_steps.append("使用 Burp + Frida/SSL Kill Switch 抓包")
        next_steps.append("bash tools/run.sh sign-extract <target_dir> <extracted_dir> --lang js")
        next_steps.append("spawn client-agent for iOS Keychain / URL Scheme audit")
    elif client_type == "electron":
        next_steps.append("bash tools/run.sh sign-extract <target_dir> <extracted_dir> --lang js")
        next_steps.append("检查 nodeIntegration / contextIsolation 配置")
        next_steps.append("spawn client-agent for Electron main preload audit")
    else:
        next_steps.append("手动确认客户端类型后,跑对应专用脚本")

    if findings.get("api_paths"):
        next_steps.insert(0, "对 client-recon 提取的 API 走 skills/orchestrator.md 阶段 3 主动测试")

    manifest_finding_keys = {
        "api_paths", "base_urls", "secrets", "routes", "deep_links",
        "exported_components", "dangerous_configs", "wx_api_calls",
        "crypto_refs", "permissions",
    }
    findings_summary = {}
    for k in manifest_finding_keys:
        v = findings.get(k)
        if isinstance(v, list):
            if k == "dangerous_configs":
                findings_summary[k] = v
            else:
                findings_summary[k] = len(v)
        elif isinstance(v, int):
            findings_summary[k] = v
        else:
            findings_summary[k] = 0

    result = {
        "client_type": client_type,
        "asset_path": str(asset_path.resolve()),
        "package_name": findings.get("package_name", ""),
        "version": findings.get("version", ""),
        "appid": findings.get("appid", ""),
        "min_sdk": findings.get("min_sdk", ""),
        "target_sdk": findings.get("target_sdk", ""),
        "extracted_to": extracted,
        "findings": findings_summary,
        "next_steps": next_steps,
        "warnings": warnings,
    }
    # Android 追加完整 manifest 数据供后续工具链使用
    if client_type == "android":
        result["manifest"] = {
            "package": findings.get("package_name", ""),
            "version": findings.get("version", ""),
            "min_sdk": findings.get("min_sdk", ""),
            "target_sdk": findings.get("target_sdk", ""),
            "permissions": findings.get("permissions", []),
            "components": findings.get("components", []),
            "deep_links": findings.get("deep_links", []),
            "dangerous_configs": findings.get("dangerous_configs", []),
        }
    # miniprogram 追加 app_meta
    if client_type == "miniprogram":
        result["app_meta"] = {
            "appid": findings.get("appid", ""),
            "pages": findings.get("pages", []),
            "tab_bar": findings.get("tab_bar", []),
            "sub_packages": findings.get("sub_packages", []),
            "plugins": findings.get("plugins", []),
            "functional_pages": findings.get("functional_pages", False),
            "permission": findings.get("permission", {}),
        }
    return result


def write_outputs(out_dir: Path, findings: dict, manifest: dict):
    ensure_parent(out_dir / "manifest.json")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if findings.get("api_paths"):
        (out_dir / "api-paths.txt").write_text("\n".join(findings["api_paths"]) + "\n", encoding="utf-8")
    if findings.get("base_urls"):
        (out_dir / "base-urls.txt").write_text("\n".join(findings["base_urls"]) + "\n", encoding="utf-8")
    if findings.get("secrets"):
        (out_dir / "secrets.txt").write_text(
            "\n".join(f"{loc}:{line}: {snippet}" for loc, line, snippet in findings["secrets"]) + "\n",
            encoding="utf-8",
        )
    if findings.get("routes"):
        (out_dir / "routes.txt").write_text("\n".join(findings["routes"]) + "\n", encoding="utf-8")
    if findings.get("deep_links"):
        (out_dir / "deep-links.txt").write_text("\n".join(findings["deep_links"]) + "\n", encoding="utf-8")
    if findings.get("wx_api_calls"):
        (out_dir / "wx-api-calls.txt").write_text("\n".join(findings["wx_api_calls"]) + "\n", encoding="utf-8")
    if findings.get("crypto_refs"):
        (out_dir / "crypto-refs.txt").write_text(
            "\n".join(f"{loc}:{line}: {snippet}" for loc, line, snippet in findings["crypto_refs"]) + "\n",
            encoding="utf-8",
        )
    if findings.get("permissions"):
        (out_dir / "permissions.txt").write_text("\n".join(findings["permissions"]) + "\n", encoding="utf-8")
    if findings.get("exported_components"):
        # Android exported 组件带结构化信息,其它类型按字符串处理
        comps = findings["exported_components"]
        if comps and isinstance(comps[0], dict):
            (out_dir / "exported-components.txt").write_text(
                "\n".join(f"{c['type']}|{c['name']}|exported={c['exported']}|permission={c.get('permission','')}" for c in comps) + "\n",
                encoding="utf-8",
            )
        else:
            (out_dir / "exported-components.txt").write_text("\n".join(comps) + "\n", encoding="utf-8")

    # 报告
    lines = [
        "# 客户端攻击面提取报告",
        "",
        f"**客户端类型**: {manifest['client_type']}",
        f"**资产路径**: {manifest['asset_path']}",
        f"**包名**: {manifest['package_name'] or '(未知)'}",
        f"**版本**: {manifest['version'] or '(未知)'}",
    ]
    if manifest.get("appid"):
        lines.append(f"**AppID**: {manifest['appid']}")
    if manifest.get("min_sdk") or manifest.get("target_sdk"):
        lines.append(f"**minSdk / targetSdk**: {manifest.get('min_sdk', '')} / {manifest.get('target_sdk', '')}")
    lines += [
        f"**提取目录**: {manifest['extracted_to']}",
        f"**生成时间**: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 统计",
        "",
        "| 类别 | 数量 | 文件 |",
        "|---|---|---|",
        f"| API 路径 | {manifest['findings'].get('api_paths', 0)} | api-paths.txt |",
        f"| baseURL | {manifest['findings'].get('base_urls', 0)} | base-urls.txt |",
        f"| 敏感关键词 | {manifest['findings'].get('secrets', 0)} | secrets.txt |",
        f"| 路由/Deep Link | {manifest['findings'].get('deep_links', 0) + manifest['findings'].get('routes', 0)} | routes.txt / deep-links.txt |",
        f"| 微信 API 调用 | {manifest['findings'].get('wx_api_calls', 0)} | wx-api-calls.txt |",
        f"| 加密/网络库引用 | {manifest['findings'].get('crypto_refs', 0)} | crypto-refs.txt |",
        f"| Exported 组件 | {manifest['findings'].get('exported_components', 0)} | exported-components.txt |",
        f"| 权限 | {manifest['findings'].get('permissions', 0)} | permissions.txt |",
        "",
        "## 危险配置",
        "",
    ]
    if manifest["findings"]["dangerous_configs"]:
        for cfg in manifest["findings"]["dangerous_configs"]:
            lines.append(f"- {cfg}")
    else:
        lines.append("- 未发现明显危险配置")
    lines.append("")

    if findings.get("api_paths"):
        lines += ["## API 路径(前 50 条)", ""]
        for p in findings["api_paths"][:50]:
            lines.append(f"- `{p}`")
        lines.append("")

    if findings.get("base_urls"):
        lines += ["## baseURL / 后端地址(前 30 条)", ""]
        for u in findings["base_urls"][:30]:
            lines.append(f"- `{u}`")
        lines.append("")

    if findings.get("secrets"):
        lines += ["## 敏感关键词命中(前 30 条)", ""]
        for loc, line, snippet in findings["secrets"][:30]:
            lines.append(f"- `{loc}:{line}` {snippet}")
        lines.append("")

    if findings.get("routes"):
        lines += ["## 路由表", ""]
        for r in findings["routes"][:50]:
            lines.append(f"- `{r}`")
        lines.append("")

    if findings.get("deep_links"):
        lines += ["## Deep Link / URL Scheme / Webview 入口", ""]
        for d in findings["deep_links"][:50]:
            lines.append(f"- `{d}`")
        lines.append("")

    if findings.get("wx_api_calls"):
        lines += ["## 微信 API 调用", ""]
        for a in findings["wx_api_calls"][:50]:
            lines.append(f"- `{a}`")
        lines.append("")

    if findings.get("crypto_refs"):
        lines += ["## 加密/网络库引用", ""]
        for loc, line, snippet in findings["crypto_refs"][:30]:
            lines.append(f"- `{loc}:{line}` {snippet}")
        lines.append("")

    if findings.get("permissions"):
        lines += ["## 权限列表", ""]
        for p in findings["permissions"][:50]:
            lines.append(f"- `{p}`")
        lines.append("")

    if client_type == "miniprogram" and manifest.get("app_meta"):
        lines += ["## app.json 关键配置", ""]
        app_meta = manifest["app_meta"]
        if app_meta.get("pages"):
            lines.append(f"- **pages**: {len(app_meta['pages'])} 个")
        if app_meta.get("tab_bar"):
            lines.append(f"- **tabBar**: {', '.join(app_meta['tab_bar'])}")
        if app_meta.get("sub_packages"):
            lines.append(f"- **subpackages**: {', '.join(app_meta['sub_packages'])}")
        if app_meta.get("plugins"):
            lines.append(f"- **plugins**: {', '.join(app_meta['plugins'])}")
        if app_meta.get("functional_pages"):
            lines.append("- **functionalPages**: true (可能存在插件/跳转攻击面)")
        if app_meta.get("permission"):
            lines.append(f"- **permission**: {json.dumps(app_meta['permission'], ensure_ascii=False)}")
        lines.append("")

    lines += [
        "## 本地存储检查清单",
        "",
        "- [ ] SharedPreferences / UserDefaults / localStorage 是否存 token/secret",
        "- [ ] SQLite / CoreData / IndexedDB 是否存敏感数据",
        "- [ ] 外部存储 / iCloud / Application Support 是否暴露文件",
        "- [ ] 日志 / crash 日志是否泄露密钥",
        "",
        "## 下一步",
        "",
    ]
    for step in manifest["next_steps"]:
        lines.append(f"1. {step}")
    if manifest["warnings"]:
        lines += ["", "## 警告", ""]
        for w in manifest["warnings"]:
            lines.append(f"- ⚠️ {w}")

    (out_dir / "client-attack-surface.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="统一客户端攻击面识别与静态提取入口")
    parser.add_argument("target_dir", help="target 目录,如 targets/xxx")
    parser.add_argument("asset_path", help="本地客户端资产文件或目录")
    parser.add_argument("--type", default="auto", choices=["auto", "apk", "ipa", "wxapkg", "miniprogram", "asar", "electron", "pe", "macho"],
                        help="强制指定客户端类型")
    parser.add_argument("--out-dir", help="报告输出目录,默认 <target_dir>/recon/client-recon")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    asset_path = Path(args.asset_path).resolve()

    if not target_dir.is_dir():
        err(f"target_dir 不存在: {target_dir}")
        return 1
    if not asset_path.exists():
        err(f"asset_path 不存在: {asset_path}")
        return 1

    out_dir = Path(args.out_dir) if args.out_dir else target_dir / "recon" / "client-recon"
    extracted_dir = workspace_path(target_dir, "recon/client-recon/extracted")

    log(f"━━━ client-recon: {target_key(target_dir)} ━━━")
    client_type = detect_type(asset_path, args.type)
    if client_type == "unknown" and args.type == "auto":
        log("无法自动识别客户端类型,请使用 --type 强制指定", "WARN")
        return 1

    log(f"[1/3] 识别客户端类型... {client_type}")

    if client_type in ("miniprogram", "wxapkg"):
        # 若输入文件 .wxapkg,目前只反编译能力有限;直接按目录处理
        src_dir = asset_path if asset_path.is_dir() else extracted_dir / "wxapkg"
        if asset_path.is_file():
            log(".wxapkg 文件自动反编译能力将在 miniapp-recon.py 中补齐,当前按通用 JS 扫描处理", "WARN")
        findings, extracted, warnings = extract_miniprogram(src_dir, out_dir, extracted_dir)
    elif client_type == "android":
        findings, extracted, warnings = extract_apk(asset_path, out_dir, extracted_dir)
    elif client_type == "ios":
        findings, extracted, warnings = extract_ipa(asset_path, out_dir, extracted_dir)
    elif client_type in ("electron", "asar"):
        findings, extracted, warnings = extract_asar(asset_path, out_dir, extracted_dir)
    else:
        findings, extracted, warnings = extract_generic(asset_path, out_dir, extracted_dir)

    log("[2/3] 整理发现...")
    manifest = build_findings(client_type, asset_path, findings, extracted, warnings)
    for k, v in manifest["findings"].items():
        if isinstance(v, int) and v > 0:
            log(f"  → {k}: {v}", "OK")
        elif isinstance(v, list) and v:
            log(f"  → {k}: {len(v)} 项", "OK")

    log("[3/3] 生成报告...")
    write_outputs(out_dir, findings, manifest)
    log(f"  报告: {out_dir / 'client-attack-surface.md'}")
    log(f"  清单: {out_dir / 'manifest.json'}")

    if warnings:
        for w in warnings:
            log(w, "WARN")

    log("━━━ client-recon 完成 ━━━")
    return 0


if __name__ == "__main__":
    sys.exit(main())
