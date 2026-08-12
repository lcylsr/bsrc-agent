---
name: js-deep-analysis
domain: js-analysis|reverse|api-discovery
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# JS 深度分析方法论（从页面资源到隐藏攻击面）

> **定位**：`js-recon.py` 做批量正则提取（适合扫一批目标），本 skill 讲对单个目标的 JS 深入分析思路——拿到一个 JS bundle，从哪些维度分析，怎么从 JS 里挖出隐藏 API / 密钥 / 签名算法 / 内部域名 / 调试接口。MCP 工具调用决策见本文"何时用 MCP 工具 vs 离线 grep"段。

## Domain

- 前端 SPA 应用（Vue/React/Nuxt/Next/Angular）
- API 路径不在 HTML 里（只在 JS 里拼接）
- 有签名/加密但不知道算法（在 JS 里实现）
- 有隐藏管理接口 / 内部域名 / 调试开关
- sourcemap 可能有效（能还原源码）
- modes: 全模式——JS 分析是攻击面发现的核心手段

## Boundaries

- JS 文件下载落盘 TEMP（`$CLAUDE_TARGET_TEMP/probes/js/`），不回灌大 body 到对话
- 大 JS（>500KB）用 MCP `save_script_source` 存本地再离线 grep，不在对话里读
- sourcemap 还原后源码只提取关键文件，不下载全部
- 硬编码密钥截图证明，不批量导出

---

## 分析思路：6 个维度

### 维度 1：JS 文件发现与分层

**核心思路：不只看首页引用的 JS，要找到全部 JS 文件。**

```
首页 HTML
  └─ 主 bundle（app.js / main.js / index.js）
      └─ chunk JS（懒加载模块，含业务 API）
          └─ vendor chunk（第三方库，通常无业务 API 但有版本信息）
              └─ sourcemap（.map 文件，可能还原源码）
```

分析思路：
- 从首页 HTML 提取 `<script src>` → 主 bundle
- 从主 bundle 里提取 chunk 文件名（webpack/jsonp 格式：`chunk-xxx.js` `app.hash.js`）
- 优先分析业务 chunk（含 `/api/` `axios` `fetch`），跳过 vendor chunk（`react` `vue` `element-ui` 等库）
- 如果 JS 太大（>1MB），用 MCP `save_script_source` 存本地，再离线 grep
- 如果有 sourcemap（`.map` 文件），还原后能看到完整变量名和注释

### 维度 2：API 路径提取

**核心思路：API 不一定以 `/api/` 出现，可能在对象属性、字符串拼接、或运行时变量里。**

提取思路：
- 直接字符串：`"/api/v1/user/list"` / `"/enterprise-server/address/getUserAddressList"`
- axios/fetch 调用：`axios.get(url)` / `fetch(url)` / `this.$http.post(path)` → 提取 url/path 变量
- 运行时拼接：`baseURL + "/" + path` → 分别提取 baseURL 和 path
- 对象属性映射：`{user: "/api/user", order: "/api/order"}` → 提取 key 和 value
- 枚举/常量定义：`const API = { LOGIN: "/login", ...}` → 提取全部常量
- 反向追踪：知道接口名（如 `/login`）→ grep 上下文看它被谁调用、传什么参数

### 维度 3：baseURL 与域名发现

**核心思路：前端 API 可能走多个不同域名，每个域名可能有不同权限配置。**

提取思路：
- `baseURL: "https://..."` / `baseUrl: "..."` / `BASE_URL = "..."`
- `axios.defaults.baseURL = "..."`
- `window._config` / `window.__NUXT__` / `window.__INITIAL_STATE__` → 运行时注入的配置
- `process.env.API_URL` / `process.env.VUE_APP_BASE_API` → 环境变量
- `https://xxx.acme.com` / `https://xxx.southwind.com.cn` → 硬编码域名
- `https://xxx.uds.acme.com` / `https://xxx.uds-dev.acme.com` → dev/prod 差异

分析思路：同一个 API 路径在不同 baseURL 下可能有不同权限——prod 域名 403，dev 域名可能 200。

### 维度 4：密钥与凭据提取

**核心思路：前端硬编码的东西不只有 api_key，还有签名盐、加密密钥、第三方 token、内部配置。不只盯 `password`，还要看 `appKey`/`appSecret`/`aesKey`/`rsaKey`/`oauth2`/`sso`/`wx`。**

提取思路（按类型扫关键词）：
- 账号口令：`password`/`pwd`/`admin`/`demo/123456` → 默认口令、测试账号
- API 密钥：`appKey`/`appSecret`/`accessKey`/`secretKey`/`apiKey` → 调内部/第三方接口
- 加密密钥：`aes`/`AES`/`rsa`/`RSA`/`iv`/`key`/`privateKey`/`publicKey`/`sm2`/`sm4` → 解密/伪造请求
- Token 端点：`token`/`sso/login`/`oauth2`/`refresh_token`/`/login` → 拿 token 的入口
- SSO/OAuth2：`sso`/`oauth2`/`cas`/`saml`/`redirect_uri`/`client_id`/`client_secret` → 认证绕过
- 微信生态：`wx`/`wechat`/`corpId`/`agentId`/`jsapi_ticket`/`signature` → 企微/公众号
- 内部地址：`baseUrl`/`apiUrl`/`gateway`/`oa.`/`admin.`/`internal.` → 内网/管理入口
- 调试配置：`debug`/`devMode`/`mock`/`proxy` → 开发模式可能开更多面
- 云凭据：`AKIA`/`aws_access_key`/`oss_bucket`/`cdn_domain` → 云服务接管

**区分公开 vs 私有**：
- 公开 SDK key（Bugly AppID/高德 Key/微信 AppID/Stripe pk_live）= 设计公开，不报
- OAuth2 `client_secret` 在前端 = 可直接 client_credentials 换 token（值钱）
- `openApis` 白名单数组里的接口 = 无需 token，重点测未授权/凭据固定

**实战模式识别**（真实代码样本）：
- AES 硬编码：`enc.Utf8.parse("5214567890123125")` → key/iv → 加密任意 userId → 调 SSO 登录 → 拿 token
- RSA 公钥：`-----BEGIN PUBLIC KEY-----` → 一般加密敏感字段，同时拿到私钥或后端不验签可伪造
- OAuth2 client_secret：`{client_id:"xxx",client_secret:"yyy"}` → 直接 client_credentials 换 token
- SSO appKey/appSecret：`appKey === "DT-xxx" && appSecret === "e6190bb..."` → 构造 /sso/login 请求
- openApis 白名单：`openApis: ["/api_v1/token","/api_v1/sso/login"]` → 这些接口无需 token，重点测

**验证思路**：拿到密钥后必须验证可用性——AES 加密任意 userId 调 SSO 登录拿 token（200+有效 token=verified），OAuth2 client_credentials 换 token（200+access_token=verified），公开值不算漏洞。

### 维度 5：签名与加密算法

**核心思路：如果有签名/加密拦截，算法实现就在 JS 里。**

提取思路：
- 找加密函数：`encrypt` / `decrypt` / `sign` / `hmac` / `aes` / `rsa` / `sm2` / `sm4` / `md5` / `sha256`
- 找签名逻辑：`timestamp + nonce + sign` / `HMAC-SHA256(key, data)` / `RSA-SHA256`
- 找参数顺序：`sign = md5(param1 + param2 + key)` → 参数拼接顺序很重要
- 找密钥来源：密钥可能硬编码 / 从后端获取 / 从用户 token 派生
- 用 `sign-extract.py` 自动提取 → 生成 replay 模板

分析思路：拿到签名算法后，可以去掉签名/改参数/重放——不需要抓包也能打 API。

### 维度 6：sourcemap 与源码还原

**核心思路：sourcemap 是最大的信息源——能还原变量名、注释、完整源码。**

提取思路：
- 找 sourcemap：JS 文件尾 `//# sourceMappingURL=app.js.map` → 请求 `.map` 文件
- 常见路径：`app.js.map` / `main.js.map` / `chunk-xxx.js.map` / `/_next/static/xxx.map`
- 还原工具：`npx shuji -i app.js.map -o app-src/` / `npx sorcery` / 手动解析
- 还原后分析：变量名恢复（从 `a.b.c` → `user.info.address`）/ 注释恢复 / 完整文件结构

分析思路：还原后能看到开发者写的注释和原始变量名——API 名/参数名/加密逻辑都更清晰。即使 sourcemap 关了，混淆后的 JS 仍可分析（只是更费力）。

---

## 分析流程思路

```
1. 发现全部 JS 文件（首页→chunk→sourcemap）
   ↓ 优先分析业务 chunk，跳过 vendor
2. 提取 API 路径（不只 /api/，还看对象属性/拼接/常量）
   ↓ 有 API 路径 → 逐个测未授权/IDOR
3. 提取 baseURL（可能多个域名，每个域名权限不同）
   ↓ 不同域名测同一 API → 找权限差异
4. 提取密钥（区分公开 SDK key vs 私有密钥）
   ↓ 私有密钥 → 证明可利用
5. 提取签名算法（sign-extract + 手动分析参数顺序）
   ↓ 生成 replay 模板 → 去签名重放
6. 如果有 sourcemap → 还原源码（变量名/注释/结构）
   ↓ 还原后重新跑 1-5（信息更丰富）
```

## 何时用 MCP 工具 vs 离线 grep

**核心思路：不要从"先做什么"想，从"症状是什么"反查该用什么工具。**

| 症状 | 工具/方法 |
|---|---|
| 全新进场 / 不知道入口在哪 | sourcemap 探针（零成本 4-6 包） |
| sourcemap 404 + 不知道接口在 JS 哪段 | `search_in_sources('axios\|fetch\|baseURL')` |
| 接口拼接被混淆，看不出最终 URL | `break_on_xhr(url=<接口片段>)` 断在请求发出处看拼好的真实 URL |
| 知道某接口想反查是哪段 JS 发的 | `list_network_requests` 拿 reqid → `get_request_initiator` 看调用栈 |
| 知道函数名，想看入参/返回值 | `set_breakpoint_on_text(text=<name>)` → `get_paused_info` 读 scope → `step` 看返回 |
| 怀疑某行代码有问题，想抓现场 | `search_in_sources` 定位 → `set_breakpoint_on_text` 下断 |
| 想看真实跑过的网络 | `list_network_requests` |
| 想读整份压缩 JS | `save_script_source`（自动 beautify 存本地）再离线 grep |
| MCP 起不来 | curl 拉全部 JS + 离线正则盲扫 |

**大小判断**：
- 小 JS（<100KB）：直接读或 grep
- 中 JS（100KB-1MB）：`save_script_source` 存本地 + 离线 grep
- 大 JS（>1MB，如 vendor bundle）：跳过或只提取版本信息
- sourcemap 还原：`save_script_source`（format=true）或 `npx shuji`

## Pivot Hints

- JS 文件被 WAF 拦截 → 换 UA / 加 Referer / 从 CDN 域名下载
- sourcemap 404 → 看 `/_next/static/` `/static/js/` `/_nuxt/` 下的 .map
- 混淆严重看不出 API → 不是看变量名，是看字符串（API 路径是硬编码字符串不会被混淆）
- chunk 文件名带 hash → 从主 bundle 的 webpack manifest 里提取 chunk 列表
- 有多个 baseURL → 每个域名都测同一组 API（dev 域名可能没鉴权）
- 签名算法被混淆 → `break_on_xhr` 在签名请求发出处断点 → 读 scope 里的签名函数

## Common misses

- **只看首页引用的 JS** → chunk JS 里才有业务 API，首页只有框架代码
- **只 grep `/api/`** → API 可能在对象属性/常量定义/字符串拼接里
- **只测一个 baseURL** → 同一 API 在不同域名可能权限不同
- **忽略 sourcemap** → 还原后变量名/注释/结构全恢复，信息量大增
- **混淆就放弃** → API 路径是字符串不会被混淆，密钥也不会被混淆
- **不提取签名算法** → 拿到算法 = 不用抓包也能打 API
- **vendor chunk 也深挖** → 第三方库通常无业务 API，浪费时间
- **在对话里读大 JS** → 大 body 回灌对话浪费 token，存本地离线 grep

## Verification

- **隐藏 API verified**：从 JS 提取 + curl 重放 200 + 返回业务数据
- **密钥泄露 verified**：从 JS 提取 + 证明可用于越权/解密/重放
- **签名绕过 verified**：提取算法 + 去签名改参数重放 + API 仍接受
- **phenomenon**：公开 SDK key / 无法利用的密钥 / sourcemap 关闭

## ⚠️ 红线

- JS 文件下载落盘 TEMP，不回灌大 body 到对话
- sourcemap 还原后只提取关键文件，不下载全部源码
- 硬编码密钥截图证明，不批量导出
- 不用密钥实际连接 DB / 调用云 API（只证明可利用）

## Related

- `crypto-sign.md` — 签名/加密逆向
- `js-recon.py` — 批量正则提取工具（扫一批目标）
- `sign-extract.py` — 签名算法自动提取 + replay 模板
- `fuzz.md` — 批量探测后选目标深挖（JS 分析是深度模式的核心）
- `authed-deep-dive.md` — 拿到 token 后深挖（JS 分析提供 API 清单）
