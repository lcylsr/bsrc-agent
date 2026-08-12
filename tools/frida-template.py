#!/usr/bin/env python3
# tools/frida-template.py — 生成可直接运行的 Frida 脚本模板
#
# 用法:
#   bash tools/run.sh frida-template <target_dir> <package_name> [--hook ssl|cipher|root|sign] [--class <class>] [--method <method>]
#
# 输出:
#   E:/claude-artifacts/tmp/<target_key>/recon/frida-scripts/<pkg>_<hook>.js

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.target_paths import workspace_path, ensure_parent, target_key

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(msg, level="INFO"):
    icon = {"INFO": "ℹ️", "OK": "✅", "WARN": "⚠️"}.get(level, "•")
    print(f"{icon} {msg}", flush=True)


def err(msg):
    print(f"❌ {msg}", file=sys.stderr, flush=True)


def safe_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)[:80]


TEMPLATES = {
    "ssl": """// Android SSL Pinning Bypass — Frida script
// Target: {{PACKAGE}}
// Usage: frida -U -f {{PACKAGE}} -l {{FILENAME}} --no-pause

Java.perform(function() {
    console.log("[*] SSL pinning bypass hook start");

    // TrustManager 通杀
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManager = Java.registerClass({
        name: "com.claude.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        "[Ljavax/net/ssl/KeyManager;",
        "[Ljavax/net/ssl/TrustManager;",
        "Ljava/security/SecureRandom;"
    );
    SSLContext_init.implementation = function(km, tm, random) {
        console.log("[*] SSLContext.init() hooked");
        SSLContext_init.call(this, km, TrustManagers, random);
    };

    // OkHttp HostnameVerifier
    try {
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function() {
            console.log("[*] OkHostnameVerifier.verify() bypassed");
            return true;
        };
    } catch(e) {}

    // WebView SSL error handler
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[*] WebViewClient.onReceivedSslError bypassed");
            handler.proceed();
        };
    } catch(e) {}

    console.log("[*] SSL bypass ready");
});
""",

    "cipher": """// Android Crypto Hook — Frida script
// Target: {{PACKAGE}}
// Usage: frida -U -f {{PACKAGE}} -l {{FILENAME}} --no-pause

Java.perform(function() {
    console.log("[*] Crypto hook start");

    // Cipher
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "Ljava/security/Key;").implementation = function(opmode, key) {
            console.log("[Cipher.init] opmode=" + opmode + " key=" + key);
            this.init(opmode, key);
        };
        Cipher.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            console.log("[Cipher.doFinal] in=" + bytesToHex(input) + " out=" + bytesToHex(result));
            return result;
        };
    } catch(e) {}

    // MessageDigest
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.update.overload("[B").implementation = function(input) {
            console.log("[MessageDigest.update] input=" + bytesToHex(input));
            return this.update(input);
        };
        MessageDigest.digest.overload("[B").implementation = function(input) {
            var result = this.digest(input);
            console.log("[MessageDigest.digest] in=" + bytesToHex(input) + " out=" + bytesToHex(result));
            return result;
        };
    } catch(e) {}

    // Mac (HMAC)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            console.log("[Mac.doFinal] in=" + bytesToHex(input) + " out=" + bytesToHex(result));
            return result;
        };
    } catch(e) {}

    function bytesToHex(bytes) {
        if (!bytes) return "";
        var result = "";
        for (var i = 0; i < bytes.length; i++) {
            result += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return result;
    }

    console.log("[*] Crypto hook ready");
});
""",

    "root": """// Android Root Detection Bypass — Frida script
// Target: {{PACKAGE}}
// Usage: frida -U -f {{PACKAGE}} -l {{FILENAME}} --no-pause

Java.perform(function() {
    console.log("[*] Root detection bypass start");

    // Build.TAGS check
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
    } catch(e) {}

    // File.exists for /su/bin/su etc.
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var blacklist = ["/su", "/magisk", "/superuser", "/sbin/su", "/system/bin/su", "/system/xbin/su"];
            for (var i = 0; i < blacklist.length; i++) {
                if (path.indexOf(blacklist[i]) !== -1) {
                    console.log("[File.exists] bypass: " + path);
                    return false;
                }
            }
            return this.exists();
        };
    } catch(e) {}

    // Runtime.exec
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            console.log("[Runtime.exec] " + cmd);
            return this.exec(cmd);
        };
    } catch(e) {}

    console.log("[*] Root detection bypass ready");
});
""",

    "sign": """// Android Sign/Method Hook — Frida script
// Target: {{PACKAGE}}
// Usage: frida -U -f {{PACKAGE}} -l {{FILENAME}} --no-pause

Java.perform(function() {
    console.log("[*] Sign method hook start");

    var targetClass = "{{CLASS}}";
    var targetMethod = "{{METHOD}}";

    try {
        var clazz = Java.use(targetClass);
        var overloads = clazz[targetMethod].overloads;
        overloads.forEach(function(overload) {
            overload.implementation = function() {
                var args = [];
                for (var i = 0; i < arguments.length; i++) {
                    args.push(arguments[i]);
                }
                console.log("[" + targetClass + "." + targetMethod + "] input=" + JSON.stringify(args));
                var result = this[targetMethod].apply(this, arguments);
                console.log("[" + targetClass + "." + targetMethod + "] output=" + result);
                return result;
            };
        });
        console.log("[*] Hooked " + targetClass + "." + targetMethod);
    } catch(e) {
        console.log("[!] Hook failed: " + e);
    }
});
""",
}


def render(template_name: str, package: str, class_name: str = "", method_name: str = ""):
    tpl = TEMPLATES.get(template_name)
    if not tpl:
        return None
    filename = f"{safe_filename(package)}_{template_name}.js"
    return tpl.replace("{{PACKAGE}}", package) \
              .replace("{{FILENAME}}", filename) \
              .replace("{{CLASS}}", class_name) \
              .replace("{{METHOD}}", method_name)


def main():
    parser = argparse.ArgumentParser(description="生成可直接运行的 Frida 脚本模板")
    parser.add_argument("target_dir", help="target 目录")
    parser.add_argument("package_name", help="应用包名,如 com.target.app")
    parser.add_argument("--hook", default="ssl",
                        choices=["ssl", "cipher", "root", "sign"],
                        help="Hook 类型")
    parser.add_argument("--class", dest="class_name", default="",
                        help="sign 模式下要 hook 的完整类名")
    parser.add_argument("--method", dest="method_name", default="",
                        help="sign 模式下要 hook 的方法名")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    package = args.package_name.strip()

    if not target_dir.is_dir():
        err(f"target_dir 不存在: {target_dir}")
        return 1
    if not package:
        err("package_name 不能为空")
        return 1

    if args.hook == "sign" and (not args.class_name or not args.method_name):
        err("sign 模式必须同时提供 --class 和 --method")
        return 1

    out_dir = workspace_path(target_dir, "recon/frida-scripts")
    filename = f"{safe_filename(package)}_{args.hook}.js"
    out_path = out_dir / filename

    script = render(args.hook, package, args.class_name, args.method_name)
    if script is None:
        err(f"未知 hook 类型: {args.hook}")
        return 1

    ensure_parent(out_path)
    out_path.write_text(script, encoding="utf-8")

    log(f"━━━ frida-template: {target_key(target_dir)} ━━━")
    log(f"生成 {args.hook} 脚本", "OK")
    log(f"  输出: {out_path}")
    log(f"运行命令: frida -U -f {package} -l {out_path} --no-pause")
    log("━━━ frida-template 完成 ━━━")
    return 0


if __name__ == "__main__":
    sys.exit(main())
