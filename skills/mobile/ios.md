# iOS APP 渗透

## Triggers (何时用)

- scope 含 `ipa` / `Payload/xxx.app` / iOS 包名 `com.xxx.xxx`
- 目标提供 TestFlight / App Store 下载链接
- Android 端 API 有签名,需要对比 iOS 端实现是否一致
- 需要审计企业签 / 超级签分发的 IPA

## Coverage points (查什么)

**铁律**:
- **IPA 解压 = 第一步** — 成本 0 包,信息量最大(`unzip -q app.ipa -d ./ipa_src`)
- **Info.plist 必看** — Bundle ID、URL Types、ATS 例外、后台模式
- **IPA 无完整源码**,但可能有:embedded.mobileprovision、Frameworks、资源文件中的 JS/HTML(混合应用)
- **静态分析优先于越狱设备** — 没有越狱设备时,抓包 + 静态同样能发现大量问题
- **抓到包后回归 Web 测试** — iOS 后端与 Web/Android 通常共用

**Info.plist**:Bundle ID / URL Scheme / ATS 明文例外 / 后台模式 / 加密声明。
**字符串提取**:Mach-O 中的 URL、密钥、token;资源 JS/HTML(混合应用)。
**SSL Pinning**:常规代理(iOS 装系统 CA)/ SSL Kill Switch 2(越狱)/ Frida / Objection。
**mTLS**:IPA 中找 `.p12` / `.pfx` 客户端证书。
**本地数据**:Keychain 导出 / 沙盒 / iTunes 备份(无需越狱,默认密码 0000/1234)。
**IPC**:URL Scheme fuzz / Universal Links / Share Extension 越界。
**API 层**:抓到包后回归 `doctrine/coverage-audit.md`,重点 IDOR(替换 userId)/ 未授权(去 token)/ 注入。

## Common misses (AI 常忘)

- 先抓包再解 IPA → 反了,IPA 解压 0 成本信息量最大,先静态
- ATS 例外指向内部测试域名就报 → 生产环境未启用才算
- Keychain 里的 token 直接报 → 必须证明当前有效,过期的没用
- URL Scheme 需要用户手动触发 → 单点钓鱼/信息泄露才构成影响
- AppID / AppSecret 是 Apple/Google 官方 SDK 公钥 → 默认公开,不算漏洞
- 备份数据加密且有强密码 → 无法离线读取不算
- embedded.mobileprovision 里有开发者证书就报 → 仅证明签名来源,非漏洞

## Verification (verified 标准)

1. **AppID / AppSecret 是 Apple/Google 官方 SDK 公钥** — 默认公开,不算漏洞
2. **URL Scheme 需要用户手动触发** — 单点钓鱼/信息泄露才构成影响
3. **Keychain 里的 token 已过期** — 必须能证明当前有效
4. **ATS 例外指向内部测试域名** — 生产环境未启用才算
5. **备份数据加密且有强密码** — 无法离线读取不算

## Related playbooks

- API 越权 → `skills/api-logic/idor-bola.md`
- 加密逆向 → `skills/js-reverse/crypto-sign.md`
- Android 对比 → `skills/mobile/android.md`
- 小程序 → `skills/mobile/miniprogram.md`

## Reference (深度参考 — AI 可能不会的细节)

### Info.plist 必看项

| 字段 | 含义 | 风险 |
|---|---|---|
| `CFBundleIdentifier` | Bundle ID | 与 API 签名/证书关联 |
| `CFBundleURLTypes` | URL Scheme | URL Scheme 注入 / 越界回调 |
| `NSExceptionAllowsInsecureHTTPLoads` | ATS 明文传输例外 | 中间人攻击面 |
| `NSExceptionDomains` | ATS 域名例外 | 指定域名明文传输 |
| `UIBackgroundModes` | 后台模式 | 后台下载/定位/VoIP 滥用 |
| `ITSAppUsesNonExemptEncryption` | 加密声明 | 合规性提示 |

### 静态提取命令

```bash
# 解压 + 定位主 bundle
unzip -q target.ipa -d ./ipa_src
APP_DIR=$(find ./ipa_src/Payload -name "*.app" -maxdepth 1 | head -1)

# 读取 Info.plist(macOS)
plutil -p "$APP_DIR/Info.plist"

# 转换为 XML 查看(Linux/Windows)
plutil -convert xml1 "$APP_DIR/Info.plist" -o Info.xml
# Linux 无 plutil:plistutil -i Info.plist -o Info.xml(libplist)

# Mach-O 可执行文件字符串
EXEC=$(find "$APP_DIR" -maxdepth 1 -type f -perm +111 | head -1)
strings -a "$EXEC" | grep -iE "https?://[a-zA-Z0-9._/-]+" | sort -u
strings -a "$EXEC" | grep -iE "(api_key|api_secret|secret|token|password|salt|iv|aes_key)" | head -30

# 资源文件中的 JS/HTML(混合应用)
find "$APP_DIR" -name "*.js" -o -name "*.html" -o -name "*.json" | head -20
```

### SSL Pinning 绕过

```bash
# 已越狱:SSL Kill Switch 2(Cydia 安装,设置中启用 target app)

# Frida(需开发者证书/越狱)
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Objection
objection -g com.target.app explore
ios sslpinning disable
```

**mTLS 客户端证书提取**:

```bash
find "$APP_DIR" -name "*.p12" -o -name "*.pfx" -o -name "*.p12.enc"
strings "$EXEC" | grep -iE "clientcert|clientCert|p12|pfx|identity"
# 导入 Burp → Project Options → TLS → Client TLS Certificates
```

### 本地数据提取

```bash
# Keychain 导出(越狱,keychain_dumper)
keychain_dumper -d > keychain_dump.txt
grep -iE "password|token|secret|key|session" keychain_dump.txt

# 应用沙盒定位(越狱)
APP_UUID=$(ls /var/mobile/Containers/Data/Application | while read uuid; do
  if [ -d "/var/mobile/Containers/Data/Application/$uuid/Documents" ]; then
    plutil -p "/var/mobile/Containers/Data/Application/$uuid/.com.apple.mobile_container_manager.metadata.plist" 2>/dev/null | grep -q "com.target.app" && echo "$uuid"
  fi
done | head -1)
ls -la "/var/mobile/Containers/Data/Application/$APP_UUID/"

# iTunes 备份分析(无需越狱)
# 备份加密时尝试默认密码 0000 / 1234
# 使用 iBackupBot / 3uTools / libimobiledevice 读取
idevicebackup2 backup --full ./ios_backup/
```

### URL Scheme / Universal Links 测试

```bash
# 从 Info.plist 提取 URL Schemes
plutil -p "$APP_DIR/Info.plist" | grep -A 20 "CFBundleURLTypes"

# URL Scheme fuzz(模拟器)
xcrun simctl openurl booted "targetapp://action?param=value"
# 真机:构造 HTML 触发
# <a href="targetapp://action?param=value">open</a>

# Universal Links:检查 entitlements / apple-app-site-association
find "$APP_DIR" -name "*.entitlements" -o -name "apple-app-site-association"

# Share Extension 越界:分享文件到 target app,观察是否读取预期外路径
```
