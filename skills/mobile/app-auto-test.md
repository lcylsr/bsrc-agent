---
name: app-auto-test
domain: mobile|app|dynamic-analysis
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# App 自动渗透测试方法论（动静结合 · 信号驱动螺旋）

> **定位**：`android.md` / `ios.md` / `miniprogram.md` 是各栈的技能卡（查什么/怎么验）。本 skill 补**端到端自动测试流程**——从拿到 APK 到产出 finding，4 轮螺旋怎么推进、信号怎么驱动、失败怎么 pivot。
>
> **与 app-agent.md 的关系**：app-agent 是 agent 定义（权限/工作流/stop conditions），本 skill 是方法论（每步具体操作/判断标准/pivot）。

## Domain

- 目标提供 APK/IPA/wxapkg 或应用市场可搜到
- Web 端 API 有签名/加密，需要从 App 逆向算法
- 需要 SSL Pinning 绕过才能抓包验证
- 需要测试 exported 组件 / Deep Link / 本地存储
- modes: src/pentest/redteam 均适用——App 是 Web API 的另一入口

## Boundaries

- 静态分析 = 离线，合规
- adb install / 启动 App = 授权测试合规
- Frida hook = 重武器，须 scope 授权（`_PENDING.md` 如需）
- 不登录真实账号 / 不操作他人数据 / 不批量拉取
- 抓包后 API 回归走 law.md（GET 只读免请示 / POST 写须请示）

---

## 4 轮信号驱动螺旋

```
轮1: 快速双开（5min）      静态初扫 + 动态准备 同时启动
轮2: 抓包突破（10-20min）   抓包优先，签名逆向服务抓包
轮3: 信号驱动深挖（20-40min） 哪里有信号打哪里，回静态取弹药
轮4: 覆盖+链式+汇总（10-20min） 补覆盖 + 组合拳 + return
```

**核心原则**：
- 静态不是独立阶段，是动态的**弹药库**——动态打到哪需要什么，回静态取
- 抓包优先于深度静态——流量里的洞最多（IDOR/未授权/越权）
- 签名逆向服务抓包——抓到包发现签名拦着，回去逆向，拿到后立刻重放
- 抓到第一个 API 就开始业务深挖——不等"API 回归阶段"
- 组件测试和 API 测试并行——不是串行

---

## 轮 1：快速双开（5 分钟）

**同时启动静态初扫 + 动态准备**。并行方式：在一个消息里发多个工具调用（jadx-mcp grep + Bash adb install），不靠 shell `&`（ZCode Bash 工具同步等返回，`&` 后台进程可能被超时杀掉）。

### 静态侧（30 秒一眼扫）

用 jadx-mcp 快速 grep（不跑完整反编译，完整反编译按需在轮 2/3 启动）：

```
# Android:
#   get_android_manifest → exported 组件 / deep link（一眼看）
#   search "api_key|secret|password|token" → 硬编码密钥初表
#   search "http://|https://|baseurl|api/" → API 地址初表
# iOS:
#   strings Info.plist → ATS 例外 / URL Scheme
#   strings Binary → api_key/secret/baseurl
# 小程序:
#   app.json → 路由 + API
#   grep appKey/secret/签名盐
```

### 动态侧（同时装 App）

```bash
adb install -r <apk_path>
adb shell monkey -p <pkg> -c LAUNCHER 1
adb logcat | grep -iE "token|password|error|exception|sql"  # logcat 监控（前台跑,有输出就记）
```

### 轮 1 产出

硬编码密钥初表 + API 地址初表 + exported 组件清单 + App 运行状态 + logcat 初始信号。

**关键**：不追求静态跑完，30 秒拿到初表就进轮 2。完整反编译在后台继续跑，轮 3/4 用。

---

## 轮 2：抓包突破（10-20 分钟）

**抓包是第一优先级**——流量里的洞最多。不是"先跑完静态再抓包"。

### 抓包流程

```bash
# 1. 配置代理（Burp/mitmproxy）+ 启动 App → 看能不能直接抓到包
# 2. SSL Pinning 拦着？→ Frida/Objection 绕过（具体方法见 android.md「SSL Pinning 绕过」段）
#    frida-template 生成脚本 → frida-mcp spawn 注入 → scrcpy screenshot 确认 App 正常

# 3. 绕过了 → 操作 App 触发 API → 抓第一个请求
#    → 拿到第一个 API 立刻进轮3业务深挖（不等抓完所有流量）

# 4. 绕不过？→ 见下方 pivot
```

### SSL Pinning 绕不过的 pivot（回静态取弹药）

绕不过不是卡住——静态有弹药可以直接打 API：

```bash
# 弹药1: sign-extract 提取签名算法 → 用 replay 模板直接打 API（不需要抓包）
bash tools/run.sh sign-extract <target_dir> <jadx_output_dir> --lang java
python <target_dir>/recon/sign-extract/replay_templates/hmac_sha256.py --url <api_url> --param userId=1

# 弹药2: get_class_source 读 SSL Pinning 实现 → 针对性 hook
```

3 种绕过方法都失败 → 标 Dead End B（物料门：需 root + Magisk + 自定义证书）。但此时已有静态发现（硬编码/组件/签名），不是空手而归。

### 轮 2 产出

API 流量样本（或签名 replay 模板）+ 签名算法（如提取到）。

**关键**：抓到第一个 API 请求后**立刻进入轮 3**，不等抓完所有流量。边抓边打。

---

## 轮 3：信号驱动深挖（20-40 分钟）

**根据轮 1/2 的信号决定深挖方向**，不是固定流程。每个方向遇到"需要静态信息"就回去取，取完回来继续打——螺旋推进。

### 信号 → 深挖方向 → 回静态取弹药

| 信号 | 深挖方向 | 回静态取什么 |
|---|---|---|
| API 有签名 | 逆向签名 → replay 重放去签名 | sign-extract + get_class_source 读实现 |
| 抓到 ID 类参数 | IDOR 替换 → 去签名重放 | 签名 replay 模板 |
| API 去 token 仍 200 | 未授权 → 枚举同前缀接口 | api-guessing.md CRUD 矩阵 |
| exported 组件 | adb am start 触发 → 看数据/操作 | manifest 权限分析 |
| WebView + JS 接口 | 深审 JS bridge → RCE 链 | get_class_source 读 WebView 配置 |
| 硬编码私有密钥 | 证明可利用（解密/越权） | 代码上下文确认用途 |
| logcat 泄露 token | 证明 token 有效 + 越权 | API 地址配对 |
| 加壳 | Frida dump dex → 回 jadx 重新静态 | 脱壳后重新反编译 |

### 并行原则

- 组件测试（adb am start）和 API 测试（curl 重放）**同时进行**——不串行
- 抓包继续挂着，新 API 请求自动捕获 → 边抓边打
- logcat 持续监控 → 有泄露立即取证

### 业务逻辑深挖（抓到第一个 API 就开始）

```bash
# IDOR: 替换 userId → 去签名重放
python <target_dir>/recon/sign-extract/replay_templates/hmac_sha256.py --url <api> --param userId=<other_id>

# 未授权: 去 token
curl <api_url>  # 不带 Authorization

# 注入: 参数级反射（按 doctrine/reflexes.md 第一层）
curl "<api_url>?q=' UNION SELECT 1"

# Mass assignment: 加 role/isAdmin
curl -X POST <api_url> -d '{"userId":1,"role":"admin"}'

# 越权: 低权限 token 调管理接口
curl -H "Authorization: Bearer <low_priv_token>" <admin_api_url>
```

### exported 组件动态触发（与 API 测试并行）

```bash
# Activity
adb shell am start -n <package>/<activity> --es param value
# Deep Link
adb shell am start -a android.intent.action.VIEW -d "scheme://host/path?param=value"
# Content Provider
adb shell content query --uri content://<provider>/path
# Broadcast Receiver
adb shell am broadcast -a <action> --es param value
# 验证: scrcpy screenshot 看 UI / adb logcat 看日志
```

### 运行时监控（持续）

```bash
# logcat 日志泄露（持续挂着）
adb logcat | grep -iE "token|password|session|error|exception|sql|secret"

# 本地存储
adb shell run-as <package> ls -la /data/data/<package>/
# SharedPreferences: shared_prefs/*.xml
# SQLite: sqlite3 databases/*.db ".tables"
# 外部存储: /sdcard/Android/data/<package>/
```

### 螺旋示例

```
抓到 /api/v1/user/info?userId=100&sign=xxx
→ 发现 sign 拦着 → 回静态 sign-extract 提取 HMAC-SHA256
→ 用 replay 模板去签名重放 userId=101 → 返回他人数据 = IDOR candidate
→ 同时去 token 重放 → 200 = 未授权 candidate
→ 回静态 grep 同前缀 API → 试 /api/v1/user/list /api/v1/user/export
→ 链式: IDOR + 未授权 + 批量接口 = 批量数据泄露
```

---

## 轮 4：覆盖 + 链式 + 汇总（10-20 分钟）

### 补覆盖

- `doctrine/coverage-audit.md` #56-65 客户端项逐条标注
- 静态反编译（轮 1 后台跑的）此时应已完成 → 补查之前没搜到的
- 补查清单：WebView 配置 / 自动更新 / 第三方 SDK 已知漏洞 / debuggable / allowBackup

### 链式组合

- 硬编码密钥 + API 路径 + 签名绕过 = 完整 API 接管
- exported 组件 + Deep Link = 0click/1click 入口
- WebView + JS bridge = RCE 链
- logcat token + API 地址 = 越权链
- 详见 `skills/chain-playbook.md`

### 静态产出格式

`recon/app-static-report.md`：
```markdown
# App 静态分析报告 — <app_name> v<version>
## 硬编码密钥（区分公开 SDK key vs 私有密钥）
## API 路径列表
## exported 组件清单（Activity/Service/Receiver/Provider）
## Deep Link / URL Scheme
## 签名算法 + replay 模板路径
## 加密函数位置
```

---

## Pivot Hints

- jadx 反编译乱码 → 加壳，走线2.4 脱壳
- SSL Pinning 绕不过 → 静态已有签名算法，直接用 replay 模板打 API（不需要抓包）
- exported Activity 白屏 → 传参不对，试 `--es` / `--ei` / `--ez` 不同类型
- API 去签名后 403 → 签名可能有时间戳/nonce，检查 replay 模板是否生成正确
- App 闪退 → Frida hook 可能被检测，试 frida-gadget 或反检测脚本
- 无设备 → 静态线已能出 finding（硬编码/组件/API），动态标 Dead End B

## Common misses

- **等静态跑完才启动动态** → 浪费时间，轮 1 静态动态同时启动
- **抓包跑完才开始业务深挖** → 抓到第一个 API 就开始替换 ID/去 token
- **SSL Pinning 绕不过就卡住** → 静态有签名算法，用 replay 模板直接打 API
- **exported 组件当信息泄露** → 它是免费入口，不需登录就能调用功能
- **硬编码 key 不分公开/私有** → Bugly/高德/微信 AppID 是设计公开的
- **抓到包不回归 Web** → App API 和 Web API 同一套后端
- **不看 logcat** → token/password 常泄露到日志
- **不查本地存储** → SharedPreferences/SQLite 常明文存 token
- **组件测试和 API 测试串行** → 应该并行，adb am start 和 curl 重放同时做

## Verification

- **硬编码密钥 verified**：私有密钥 + 证明可用于越权/解密（不只是暴露）
- **exported 组件 verified**：动态触发 + 返回数据/执行操作
- **IDOR verified**：替换 userId + 返回他人数据 + 反事实校验
- **未授权 verified**：去 token + 200 + 业务数据
- **phenomenon**：公开 SDK key / exported 但需参数且无法利用 / logcat 泄露过期 token

## ⚠️ 红线

- Frida hook = 重武器，须 scope 授权
- 不登录真实账号 / 不操作他人数据
- 抓包后 API 回归：GET 只读免请示 / POST 写须请示
- 脱壳后不批量下载源码，只读关键文件

## Related

- `android.md` / `ios.md` / `miniprogram.md` — 各栈技能卡
- `app-agent.md` — Agent 定义（权限/工作流/stop conditions）
- `skills/chain-playbook.md` — 链式利用（硬编码+签名+API 组合拳）
- `skills/api-logic/fuzz.md` — API fuzz 方法论
- `skills/js-reverse/crypto-sign.md` — 签名逆向
- `doctrine/coverage-audit.md` #56-65 — 客户端审计项
