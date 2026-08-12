---
name: cn-auth
domain: cn-auth|sms|wework|dingtalk|sso
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# CN 特有认证流程漏洞

## Domain

- 短信码/微信扫码/企微/钉钉/政务 SSO/U 盾/生物/MFA
- 参数 mobile/code/openid/corpid/appKey/sign
- 通用 JWT/OAuth 见 auth-bypass,本文不重复

## Boundaries

- 不轰炸真实手机号验证码;用测试号
- 不接管真实企微/钉钉租户做破坏
- code 重放仅证明,不持久劫持他人会话做写操作
- 法律:不下载通讯录全量 PII

## Pivot Hints

- 短信无果 → 扫码 code 重放 / state 缺失
- 企微 → corpid+secret / userid 跨应用
- 网关签名 → 无 nonce 重放 / 弱拼接
- MFA → 跳过第二因素路径
- 与 auth-bypass / cn-crypto 交叉

## Exit Evidence

### src
- E2: 可重放登录/换票成功
- E3: 进入真实用户或管理身份 + 业务数据
- 仅「验证码 4 位」无打通 → 不报

### redteam
- E2: 拿到可用 session/token 即 foothold hop
- 优先打通讯录/管理 API 最小读证明

## Tactics

> 原 Triggers / Coverage / Common misses / Verification 压缩如下;深度细节见文末 Reference(若有)。

> **定位**:手机号+验证码 / 微信扫码 / 企业微信 / 钉钉 / 政务 SSO / 数字证书 / 生物认证 / MFA 等 CN 场景特有的认证流程漏洞。通用 OAuth2/JWT 绕过见 `skills/api-logic/auth-bypass.md`,本文不重复。

## Triggers (何时用)

- 看到 `/sms/login` `/code/login` `/wx/qr` `/qrcode/login` `/sso/callback` `/oauth/dingtalk` `/oauth/wework`
- 请求参数含 `mobile` `phone` `code` `verifyCode` `openid` `unionid` `corpid` `userid` `appKey` `sign`
- 政务 / 金融 / 央企 / 集团型目标,有"统一身份认证"或"数字证书登录"入口
- 客户端有 USB Key / U 盾 / 客户端证书 / 人脸识别 / 指纹登录
- 抓包看到 `state` `nonce` `timestamp` `sign` 组合的网关签名

## Coverage points (查什么)

- **手机号 + 短信验证码登录**:4位 vs 6位 / 时效 / 次数限制逻辑 / 默认码 `000000` `123456`
- **微信扫码登录**:`code` 重放(5 分钟内)/ `state` 缺失 / `openid` 跨应用越权 / `unionid` 跨租户
- **企业微信 SSO**:`corpid + corpsecret` 拿 token / `userid` 跨应用 / 通讯录 API 越权
- **钉钉 SSO**:微应用免登授权码越权 / `dingtalk` 签名算法坑 / `unionid` 跨应用
- **政务网关 SSO**:`appKey` 白名单绕过 / 弱签名(简单拼接)/ 签名重放(无 nonce 或 nonce 可复用)
- **集团内部 SSO**:跨子公司越权(token 加密但子节点解密后信任所有字段,`userId` 可改)
- **数字证书登录**:U 盾 / CA 证书 / 客户端证书提取 / 证书绑定 IP 不严 / SSL Pinning 客户端绕过
- **国密 SM2 证书登录**:签名值可重放(服务端不校 nonce)
- **生物认证**:客户端校验(可篡改)/ 后端不二次校验
- **MFA 绕过**:第二因素可预测 / 登录成功后强制添加 MFA 时无需 MFA / session 固定

## Common misses (AI 常忘)

- 短信验证码只测爆破,漏了 **次数限制逻辑漏洞**(按手机号限 5 次 vs 按 IP 限 5 次,用多 IP 爆破单手机号)
- 微信扫码只测 code 重放,漏了 **openid 跨应用越权**(同一企业不同应用复用 openid,改 appid 即可)
- 企业微信只测登录,漏了 **通讯录 API 越权**(拿到 token 后调 `/user/list` 拉全员)
- 政务网关只测签名逆出来,漏了 **签名算法降级**(支持 `signType=md5` 和 `signType=sm3`,客户端选 md5 = 弱签名)
- 集团 SSO 只测主登录,漏了 **子节点解密后信任所有字段**(token 用集团公钥加密,子公司私钥解密后直接信任 `userId`,可改)
- 数字证书登录只测证书伪造,漏了 **证书可被中间人劫持**(客户端不校验服务端证书 / SSL Pinning 在客户端可绕)
- 国密 SM2 登录只测签名伪造,漏了 **签名值可重放**(若服务端不校 nonce/时间戳,同签名多次登录)
- 生物认证只测活体检测,漏了 **后端不二次校验**(前端传 `faceVerified=true` 后端就信)
- MFA 只测第二因素爆破,漏了 **登录成功后加 MFA 的时序漏洞**(已登录 session 存在,加 MFA 接口可不带 MFA 直接过)
- `unionid` 当 `openid` 用 → unionid 是企业维度,openid 是应用维度,搞混越权判断会错

## Verification (verified 标准)

- 短信码爆破:N 次错误后仍可继续 / 锁定后换 IP 继续 = 真;锁定且换 IP 也锁 = 已防
- code 重放:同 code 第二次 `/token` 换出 token = 真;服务端拒 = 已防
- openid 跨应用:用 A 应用 openid 调 B 应用接口返回数据 = 真;B 应用拒 = 已隔离
- 通讯录越权:拿到 token 后 `/user/list` 返回全员 = 真;接口需额外权限 = 已防
- 签名重放:同签名 N 秒后仍成功(>时效窗口)= 真;服务端拒 = 已防
- userId 篡改:解密 token 后改 `userId`,子节点接受并返回对应用户数据 = 真;子节点重验签名 = 已防
- 证书重放:同客户端证书 + 同签名值多次登录 = 真;服务端要 nonce = 已防
- 生物认证绕过:前端传 `faceVerified=true` 后端登录成功 = 真;后端调生物特征 API 二次校验 = 已防
- MFA 时序:已登录 session 直接访问受保护资源无需 MFA = 真;强制 MFA 检查 = 已防

## Related playbooks

- 通用 OAuth2/JWT 绕过 → `skills/api-logic/auth-bypass.md`(§五 OAuth2 / §六 SSO userId 回退)
- 鉴权字段绕过 → `skills/api-logic/auth-bypass.md` §八
- IDOR/BOLA 通用 → `skills/api-logic/idor-bola.md`
- 国密 SM2 证书签名 → `skills/cn-specific/cn-crypto.md`
- 微信小程序完整流程 → `skills/mobile/miniprogram.md`
- 自研加密/签名逆向 → `skills/js-reverse/crypto-sign.md`
- 前端硬编码 appKey/appSecret 提取 → `skills/js-reverse/js-deep-analysis.md`

## Reference (深度参考 — AI 可能不会的细节)

### 短信验证码登录常见坑

| 维度 | 坑点 | 利用 |
|---|---|---|
| 长度 | 4 位(老系统)/ 6 位(主流) | 4 位 = 1 万次,6 位 = 100 万次;4 位可爆破 |
| 时效 | 60s / 300s / 永久 | 永久 = 可重放;300s 配 6 位 = 爆破窗口大 |
| 次数限制 | 按手机号 vs 按 IP vs 按设备 | 按手机号限 5 次 → 换 IP 继续爆破;按 IP 限 5 次 → 换 IP 爆破单手机号 |
| 默认码 | `000000` `123456` `888888` | 测试遗留 / 短信网关故障时的 fallback |
| 验证码回显 | 响应里直接返回 `code` | 抓登录响应看是否带 code |
| 万能码 | 服务端写死 `if(code=="123456")` | 测常见万能码 |

```bash
# 爆破(限频防风控):for code in $(seq -w 0000 9999); do curl -sk -X POST 'https://target.com/api/sms/login' -d "mobile=13800138000&code=$code" | grep -o '"token":"[^"]*"'; done
# 测默认码:for c in 000000 123456 888888 111111 666666; do curl -sk -X POST 'https://target.com/api/sms/login' -d "mobile=13800138000&code=$c"; done
```

### 微信扫码登录坑

```
流程:前端 /wx/qr/get 拿 ticket → 用户扫码 → 微信回调 /wx/qr/callback?code=xxx&state=xxx → 前端轮询 /wx/qr/status?ticket=xxx 拿 token
漏洞:
  - code 5 分钟有效可重放(部分实现不查重)→ 同 code 多次换 token
  - state 缺失/固定 → CSRF(攻击者诱导受害者扫自己的码)
  - openid 跨应用:同企业 appid-A 和 appid-B,若后端用 openid 做映射不绑 appid → A 的 openid 可登 B
  - unionid 跨租户:unionid 是企业维度,若后端用 unionid 做租户映射不校企业 → 跨租户越权
  - ticket 可枚举:若 ticket 是短整型,可枚举他人登录态
```

### 企业微信(WeWork/WeCom)SSO

```
拿 token:GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=CORPID&corpsecret=CORPSECRET → access_token
通讯录 API(常越权):/user/list(全员) /user/getuserid?mobile=xxx /department/list
漏洞:
  - corpid + corpsecret 前端硬编码 → 直接拿 token
  - userid 跨应用:企业内多应用复用 userid,若不校应用维度 → 跨应用越权
  - 通讯录 API 权限:corpsecret 是通讯录密钥时,可拉全员(信息泄露)
  - 网页授权:oauth2/authorize 拿 code → code 换 userid,若 state 不校 → CSRF
```

### 钉钉(DingTalk)SSO

```
免登:前端 dd.runtime.permission.requestAuthCode 拿 authCode → 后端 /user/getuserinfo 换 userid → 生成登录态
漏洞:
  - authCode 可越权:部分实现 authCode 不绑用户,可枚举他人
  - dingtalk signing 算法:timestamp + nonce + body,签名 secret 前端硬编码 → 可伪造请求
  - unionid 跨应用:同企业多应用,unionid 复用,若不校 appid → 跨应用
  - 通讯录 API:拿到 token 后可拉全员(类似企业微信)
```

### 政务网关 SSO 签名坑

```
常见格式:
  appKey=xxx&timestamp=xxx&nonce=xxx&body=xxx&sign=xxx

签名算法降级:
  服务端支持 signType=md5 / signType=sm3 / signType=rsa
  → 客户端选 md5 = 弱签名(可爆破 secret)
  → 测:把 signType 从 sm3 改 md5,重算 sign,看是否接受

appKey 白名单绕过:
  - appKey=test / appKey=default / appKey=guest 弱默认
  - 同一 appKey 多系统复用 → 拿到 A 系统 appKey 可调 B 系统
  - appKey 校验只判存在不判有效 → 任意值过

签名重放:
  - 无 nonce → 同签名永久可重放
  - nonce 可复用 → 同 nonce 多次成功
  - timestamp 偏移不校 → 老签名永久有效
```

### 集团内部 SSO 跨子公司越权

```
架构:集团 SSO 中心 → 颁发 token(集团公钥加密)→ 子公司各自私钥解密 → 信任内部字段
漏洞:
  - 子节点解密后信任所有字段(userId/role/companyId 都可改)
  - 子节点不重验签名 → 改 token 内部字段后子节点接受
  - 跨子公司:A 公司 token 在 B 公司也接受(若 SSO 不绑子公司)
利用:拿 A 公司普通 token → 解密改 userId=admin,companyId=B → 调 B 公司接口
```

### 数字证书登录(U 盾/CA/客户端证书)

类型:USB Key(私钥不可导出)/ 软证书(PFX/P12,可导出)/ 客户端证书(mTLS)。漏洞点:

```
- 证书绑定 IP/会话不严 → 中间人重放(截获一次签名,重放到另一会话)
- SSL Pinning 在客户端绕过 → 移动端 hook 可绕证书校验
- 证书可被中间人劫持 → 客户端不校验服务端证书 → MITM
- 签名值可重放 → 服务端不校 nonce/timestamp,同签名多次登录
- 证书吊销不检查 → OCSP/CRL 未启用,吊销证书仍可用
- 私钥导出 → 软证书 PFX 密码弱,可爆破导出私钥
```

### 国密 SM2 证书登录签名重放

```
SM2 签名:hash = SM3(ZA || M), sign = SM2_SIGN(hash, privateKey), ZA = 用户 ID(默认 1234567812345678)+ 公钥编码哈希
漏洞:
  - 服务端不校 nonce → 同签名值可重放登录
  - 服务端不校 timestamp → 老签名永久有效
  - 用户 ID 默认值 → 部分实现用空串/固定值,降低签名熵
  - 签名编码混乱 → DER vs 裸 R‖S,服务端解析不严可绕
```

### 生物认证(人脸/指纹)绕过

类型:客户端本地校验 / 服务端调生物特征 API(微信 faceid / 阿里人脸核身)/ 设备级(硬件隔离)。漏洞点:

```
- 客户端校验:前端传 faceVerified=true / fingerprintVerified=true,后端就信
- 后端不二次校验:不调 faceid API,直接信任前端 flag
- 生物特征数据可重放:截获一次 faceid 返回值,重放到另一会话
- 设备级绕过:hook 指纹传感器返回值(Android Xposed/Frida)
- 人脸静态图:部分实现不校活体,照片可过
```

### MFA 绕过模式

| 模式 | 坑点 | 利用 |
|---|---|---|
| 第二因素可预测 | 备份码短 / TOTP 种子弱 | 爆破备份码 / 重置 TOTP 种子 |
| 时序漏洞 | 登录成功后强制加 MFA | 已登录 session 存在,加 MFA 接口可不带 MFA 直接过 |
| session 固定 | MFA 前后 session 不变 | 登录后拿到 session,绕过 MFA 直接用 |
| MFA 跳过 | `?mfa=skip` / `?step=bypass` 参数 | 测常见跳过参数 |
| 重置流程无 MFA | 改密码 / 改手机号不校 MFA | 改手机号后用短信登录绕过原 MFA |
| 记住设备 | "记住此设备" token 可伪造 | 伪造 rememberDeviceToken 跳 MFA |
| OTP 接受窗口 | TOTP ±1 窗口(30s × 3) | 实时爆破 90s 内有效码 |

