# Android APP 渗透

## Triggers (何时用)

- 目标提供 APK 下载 / 应用市场可搜到
- scope 含 Android 包名(`com.xxx.xxx`)
- Web 端 API 有签名/加密,需要从 APP 逆向算法
- 需要绕 SSL Pinning 才能抓包

## Coverage points (查什么)

**铁律**:
- **jadx 反编译是第一步**(成本 0 包,信息量最大)— 不要先抓包
- **SSL Pinning 绕不过 = 先看静态** — 硬编码密钥/组件暴露都在静态分析里
- **抓到包后回归 Web 测试** — APP 的 API 和 Web 的 API 通常同一套后端
- **exported 组件 = 免费入口** — 不需要登录就能调用的功能

**AndroidManifest.xml 必看项**:`exported="true"` 组件 / Deep Link(`android:scheme`)/ `uses-permission` / `debuggable="true"` / `allowBackup="true"` / `networkSecurityConfig`(证书锁定配置)。

**静态源码搜索**:硬编码密钥(api_key/secret/password) / API 地址 / 加密函数(MD5/SHA/AES/DES/RSA/sign) / SharedPreferences key。

**动态抓包**:常规代理(Android 7+ 需系统证书)/ SSL Pinning 绕过 / mTLS 客户端证书。

**组件安全**:exported Activity 直接启动 / Deep Link 测试 / Content Provider 查询 / Broadcast 发送。

**本地存储**:SharedPreferences(token/session) / SQLite 数据库 / 外部存储(全局可读) / logcat 日志泄露。

**Frida Hook**:加密函数读明文 / 签名函数读入参输出 / 绕过 root 检测。

抓到 API 流量后,回归 Web 测试全流程(`doctrine/coverage-audit.md` 62+10 项),重点 IDOR(替换 userId)/ 未授权(去 token)/ 注入。

## Common misses (AI 常忘)

- 先抓包再反编译 → 反了,jadx 0 包信息量最大,先静态
- SSL Pinning 绕不过就卡住 → 静态分析里有硬编码密钥/组件暴露,不依赖抓包
- exported 组件当信息泄露看 → 它是免费入口,不需要登录就能调用功能(可绕登录)
- hardcoded key 不分公开/私有 → Bugly AppID / 高德 Key / 微信 AppID 是设计公开的
- exported Activity 启动了但白屏/崩溃就放弃 → 需要额外参数才工作 ≠ 漏洞,但可试传参
- allowBackup=true 只报配置问题 → 若应用数据无敏感内容,SRC 低危/拒
- 日志里的 token 直接报 → 需证明是当前有效 token,过期的没用
- debuggable=true → 生产包才算漏洞,debug 包不算

## Verification (verified 标准)

1. **hardcoded key 是第三方 SDK 的公钥**(Bugly AppID / 高德 Key / 微信 AppID)— 设计公开,不算
2. **exported Activity 但需要额外参数才能正常工作** — 启动了但白屏/崩溃 ≠ 漏洞
3. **allowBackup=true 但应用数据无敏感内容** — 仅配置问题,SRC 低危/拒
4. **日志里的 token 是过期的** — 需要证明可利用当前有效 token
5. **debuggable=true 在 debug 包** — 生产包才算

## Related playbooks

- 加密逆向 → `skills/js-reverse/crypto-sign.md`(思路相通)
- API 越权 → `skills/api-logic/idor-bola.md`
- 路径遍历 → `skills/api-logic/ssrf-arbitrary-file.md`
- 组件安全详细 → OWASP MSTG(Mobile Security Testing Guide)

## Reference (深度参考 — AI 可能不会的细节)

### 静态分析命令

```bash
# APK 获取
adb shell pm path com.target.app
adb pull /data/app/<path>/base.apk ./target.apk

# jadx 反编译(命令行或 GUI)
jadx -d ./target_src ./target.apk
```

AndroidManifest grep:

```bash
grep -n 'exported="true"' AndroidManifest.xml
grep -A5 'android.intent.action.VIEW' AndroidManifest.xml
grep -n 'android:scheme' AndroidManifest.xml
grep 'uses-permission' AndroidManifest.xml
grep 'android:debuggable="true"' AndroidManifest.xml
grep 'android:allowBackup="true"' AndroidManifest.xml
grep 'networkSecurityConfig' AndroidManifest.xml
```

### SSL Pinning 绕过

```bash
# Frida(推荐,覆盖面最广)
frida -U -l ssl_pinning_bypass.js -f com.target.app

# Objection(更简单)
objection -g com.target.app explore
# 进入后:
android sslpinning disable

# 特殊场景:OkHttp CertificatePinner → Frida hook OkHttp3.CertificatePinner.check()
```

**双向认证(mTLS)**:从 APK 找客户端证书 + 密码:

```bash
find target_src -name "*.p12" -o -name "*.bks" -o -name "*.pfx" -o -name "*.keystore"
grep -rn "KeyStore\|loadKeyStore\|PKCS12" --include="*.java" | head -10
# 导入 Burp → Project Options → TLS → Client TLS Certificates
```

### 组件安全测试命令

```bash
# Activity 直接启动(绕过登录)
adb shell am start -n com.target.app/.activity.AdminActivity
adb shell am start -n com.target.app/.activity.PaymentActivity

# Deep Link 测试
adb shell am start -a android.intent.action.VIEW -d "targetapp://payment?amount=0.01&order_id=12345"
adb shell am start -a android.intent.action.VIEW -d "targetapp://user/profile?id=OTHER_USER_ID"

# Content Provider 查询
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/files

# Broadcast 发送
adb shell am broadcast -a com.target.app.ACTION_UPDATE -e "cmd" "id"
```

### 本地存储检查(需 root)

```bash
PKG="com.target.app"
DATA="/data/data/$PKG"

# SharedPreferences(最常见泄露点)
adb shell "cat $DATA/shared_prefs/*.xml" 2>/dev/null | grep -iE "token|session|password|key|secret"

# SQLite 数据库
adb shell "ls $DATA/databases/"
adb pull "$DATA/databases/app.db" ./
sqlite3 app.db ".tables"

# 外部存储(全局可读!)
adb shell "ls /sdcard/Android/data/$PKG/"

# 日志泄露
adb logcat -d | grep -iE "token|password|key|secret|api" | head -20
```

### Frida Hook 脚本模板

```javascript
// hook 加密函数(读取明文参数和密钥)
Java.perform(function() {
    var cipher = Java.use("javax.crypto.Cipher");
    cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("[*] Cipher.doFinal input: " + Java.use("java.lang.String").$new(input));
        var result = this.doFinal(input);
        console.log("[*] Cipher.doFinal output: " + bytesToHex(result));
        return result;
    };
});

// hook 签名函数
Java.perform(function() {
    var signClass = Java.use("com.target.app.utils.SignUtil");
    signClass.generateSign.implementation = function(params) {
        console.log("[*] Sign params: " + params);
        var result = this.generateSign(params);
        console.log("[*] Sign result: " + result);
        return result;
    };
});

// 绕过 root 检测
Java.perform(function() {
    var rootCheck = Java.use("com.target.app.security.RootDetector");
    rootCheck.isRooted.implementation = function() {
        console.log("[*] Root check bypassed");
        return false;
    };
});
```

**Frida 启动**:

```bash
# 附加已运行进程
frida -U -n "Target App" -l hook.js

# spawn 模式(从启动开始 hook,绕过初始化检测)
frida -U -f com.target.app -l hook.js --no-pause
```
