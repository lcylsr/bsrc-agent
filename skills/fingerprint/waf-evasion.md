---
name: waf-evasion
domain: waf-bypass|rate-adaptive
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# WAF 对抗与速率自适应（防封禁探测）

> **实战来源**：demo-bank 第 6 次全封（7 探针触发 uproxy 封全资产），靠 `var a=alert;a(1)` 变量别名绕过。

## Domain

- 目标有 WAF（响应头/拦截页/行为特征）：Cloudflare/阿里云/长亭 RaySec/腾讯云/安全狗/F5
- 探针被批量封禁：多个探针后全资产 timeout（IP 黑名单）
- payload 被规则匹配拦截：返回拦截页/403/连接重置
- modes: 全模式适用——WAF 是所有攻击面的前置障碍

## Boundaries

- WAF 绕过验证用无害 payload（`waf-test-xxx`），不用真实攻击 payload
- **不灌流量压测 WAF**（DoS = 违法）
- 被封后**不绕 IP 封禁**（换代理/换 IP 打 = 规避安全措施，灰色地带）
- 封禁后等自然解封，不持续重试触发更严封禁

## Pivot Hints

- 规则匹配 `alert(` → 变量别名 `var a=alert;a(1)`（demo-bank 实战验证）
- 规则匹配 `on*=` → 事件处理器拆分 / DOM 操作绕过
- 规则匹配 `document.` → `window['doc'+'ument']`
- 规则匹配 `<script>` → `<svg onload>` / `<img onerror>` / `<body onload>`
- SQL 关键词被拦 → 大小写混合 / 注释拆分 `UN/**/ION` / 编码
- 路径关键词被拦 → URL 编码 / 双重编码 / Unicode / `../` 变形

## Exit Evidence

### src
- E2: 绕过 payload 可重放 + 响应含预期内容（非拦截页）
- E3: 绕过后证明实际漏洞（XSS 触发/SQL 回显/上传成功）

## Tactics

### 1. WAF 指纹识别（2-3 包）

```bash
# 触发拦截看拦截页特征
curl -s "https://target.com/?id=1' UNION SELECT 1" | head -50
# Cloudflare: "Sorry, you have been blocked" / CF-Ray header
# 阿里云: "您的请求带有不合法参数" / Request-ID
# 长亭: 特定拦截页 / 无 header 线索（需行为判断）
# 腾讯云: "您的请求有安全风险"
```

探针 3 类无害 payload（SQLi / 路径穿越 / XSS）读响应判 WAF 状态：

| 响应 | 判定 |
|---|---|
| `200 + 业务正常` | 无 WAF / 后端处理 |
| `403 + 拦截页` | WAF 命中 |
| `5xx` | 后端崩（可能注入，可能仅类型错） |
| `200 + Body 是验证码页` | 弱 WAF / 风控 |

**WAF 分类特征与绕过策略**：

| 类型 | 特征 | 主要策略 |
|---|---|---|
| 云 WAF（阿里云/腾讯云/CF/AWS WAF/七牛） | 拦截页有厂商标识；`cf-ray` / `X-Cache: HIT` / `Server: Tengine`；status 405/403 | 找真实 IP（历史 DNS / 子域 dev/staging / 邮件头 SPF / 证书 Censys）；URL 双编码 / Unicode / HTML 实体；HPP 只看首参；`%0a` 换行截断；Query→POST Body 切换 |
| 硬/软 WAF（安全狗/雷池/长亭/ModSecurity/D盾） | `X-Powered-By-Anquanbao` / `Server: nginx+雷池`；403 页带"网站管理员"中文 logo | XFF 白名单伪装；chunked 分块传输；HTTP 走私（TE+CL 双头）；HTTP/2↔1.1 协议变换；垃圾参数填充；慢速发送 |
| 无 WAF / 自研弱 WAF | 直接 500 / 数据库报错原文；原样回显 payload | 直接上标准 payload，不浪费时间变形 |

**框架指纹 → 打法速查**：

| 指纹 | 框架 | 后续打法 |
|---|---|---|
| `JSESSIONID=...` | Java Tomcat/Jetty | `skills/api-logic/auth-bypass.md` 的 `..;` / 大小写绕过 |
| `Set-Cookie: PHPSESSID` | PHP | 试 `?-d allow_url_include=1` / `phpinfo()` |
| `X-Powered-By: Express` | Node.js | `skills/injection/nosql-graphql.md` |
| `X-AspNet-Version` / `__VIEWSTATE` | .NET WebForms | 试 `~/` 路径绕 / Web.config 泄露 / VIEWSTATE 反序列化 |
| `wp-content` / `wp-json` | WordPress | WPScan + 插件版本 |
| `/druid/` `/actuator/` `/api-docs` | Spring Boot 监控面 | 探针协议已硬卡，几乎必爆 |
| `Server: Tengine` | 阿里 / 阿里云 | 云 WAF 几乎必有，转 WAF 绕过策略 |
| `X-Powered-By: <小写厂商名>`、客户化目录、全大写字段、标准框架+强业务领域 | 二开栈 | 跳 `recon-product-fingerprint.md` |

### 2. 速率自适应（防封核心，全程执行）

```
规则：
- 单 host 探针间隔 ≥ 3 秒（政企 ≤ 2 RPS 保守）
- 同一 payload 变体不超过 3 次连续（换 payload 也是一种"休息"）
- 5 包后暂停 30 秒（防累计触发）
- 被封立即停，不重试（重试 = 加重封禁）
- 多资产轮换：A 封了切 B，B 封了切 C，不盯着一个打
```

### 3. 被封后恢复策略

```
1. 立即停所有探针（不重试 = 不加重封禁）
2. 记录封禁时间到 _STATE.md（推算解封周期）
3. 切换到其他攻击面（不同 host / 不同资产）
4. 等 30-60 分钟后单包探测解封状态（1 包，不连续）
5. 解封后降频继续（间隔从 10 秒起，逐步降到 3 秒）
```

### 4. 内容规则绕过矩阵（XSS 场景）

demo-bank 实战逐项对比表（每项 1 包验证）：

| 被拦模式 | 绕过方式 | demo-bank 验证 |
|---|---|---|
| `alert(` 被拦 | `var a=alert;a(1)` | ✅ 通过 |
| `on*=` 被拦 | DOM 操作 `createElement` | 待验证 |
| `document.` 被拦 | `window['doc'+'ument']` | 待验证 |
| `eval(` 被拦 | `Function('code')()` | 待验证 |
| `new Image()` 被拦 | `document.createElement('img')` | 待验证 |
| `<script>` 被拦 | `<svg onload>` / `<iframe src=javascript:>` | ✅ 通过 |
| 纯 HTML 表单 | 无 JS 完全不检测 | ✅ 通过 |

**核心洞察**：WAF 常检测"危险函数名+括号"模式，但不检测"变量赋值后再调用"——`var a=alert; a(1)` 绕过 `alert(` 模式匹配。

### 5. 协议层绕过

- HTTP/2 降级 HTTP/1.1（解析差异）
- 分块传输 `Transfer-Encoding: chunked`（打乱 payload 关键词）
- 大量 padding（padding 到 WAF 检测缓冲区外，通常 8KB+）
- `Content-Type` 混淆（`application/json` vs `text/plain`）

## Common misses

- **只试编码绕过** → 编码对现代 WAF 基本无效，语义层绕过（变量别名/DOM 操作）更有效
- **被封后立即重试** → 加重封禁，正确做法是停+等+切面
- **盯着一个 host 打** → 多资产轮换是防封的关键
- **不识别 WAF 类型** → 不同 WAF 绕过策略不同（Cloudflare vs 阿里云 vs 长亭）
- **速率不自适应** → 固定速率容易触发累计封禁

## Verification

- **WAF 绕过 verified**：绕过 payload + 响应非拦截页 + 证明实际漏洞
- **WAF 存在 phenomenon**：识别到 WAF 但无法绕过 → 切换攻击面（IDOR/逻辑类 WAF 不拦）
- **rejected**：无 WAF / WAF 不拦截该攻击面

## ⚠️ 红线

- 不灌流量压测 WAF（DoS = 违法）
- 被封后不绕 IP 封禁（换代理打 = 灰色地带）
- 绕过验证用无害 payload，不用真实攻击 payload
- 封禁恢复后降频，不恢复原速率

## Related

- `auth-bypass.md` — WAF 不拦路径/Header 维度绕过
- `recon-product-fingerprint.md` — 二开框架指纹下游确认
- `doctrine/reflexes.md` 认证绕过 8 大头 — 路径变形绕 WAF
- demo-bank timeline — WAF 封禁/解封/绕过实战记录
