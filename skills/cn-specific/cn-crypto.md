# 国密算法与 CN 框架特有加密签名

> **定位**:国密 SM2/SM3/SM4 与国产 OA/ERP/政务/金融场景的"非标准"加密签名模式。通用 AES/RSA/MD5 逆向见 `skills/js-reverse/crypto-sign.md`,本文只讲 AI 容易踩坑的 CN-specific 细节。

## Triggers (何时用)

- 请求/响应里出现 `SM2` `SM3` `SM4` `国密` `gm` `sm2` 字样或参数名
- 密文/签名长度异常:64 字节签名 / 32 字节哈希但不是 SHA256 / 16 字节块但分组行为像分组密码
- 政务 / 金融 / 银联 / 央企目标,响应头有 `GMSSL` 或证书签名算法含 `SM2`
- 致远 / 泛微 / 用友密码字段格式异常(双层 MD5 / 用户相关盐)
- 网关签名格式:`appKey=xxx&timestamp=xxx&nonce=xxx&body=xxx&sign=xxx`
- 微信小程序 `session_key` / 银联 `SM2` 证书 / 政务"签名验签服务器"

## Coverage points (查什么)

- **国密算法识别**:SM2 签名(64 字节)/ SM2 加密(C1C3C2 vs C1C2C3)/ SM3(32 字节,OID 区分)/ SM4(ECB/CBC,16 字节块)
- **国密证书**:`SignatureAlgorithm: SM2WITHSM3` / OID `1.2.156.10197.1.501` / 双证书体系(签名证书 + 加密证书)
- **双证书体系**:金融/政务常见 — 签名证书(私钥用户独占)+ 加密证书(私钥托管在 CA),解密时需调"密码机"
- **OA 密码套娃**:致远 `md5(md5(password) + salt)` / 泛微 `md5(password + "1" + userid)` / 用友 NC 密码哈希
- **微信小程序登录态**:`code → openid + session_key` → 自定义登录态生成(注意 `session_key` 不能下发前端)
- **国密 SSL/TLS 改造坑**:GMTLS / 双证书握手 / 国密证书链常断 / 客户端需国密浏览器
- **政务网关签名验签**:`appKey + timestamp + nonce + body + sign`,常见 HMAC-SM3;无 nonce / nonce 可复用 = 重放
- **银联 / 支付宝签名**:RSA2(SHA256WithRSA)vs SM2 国密改造,签名编码 DER vs 原始 R||S
- **签名可重放**:服务端不校 timestamp 偏移 / 不存 nonce / 不校验签名的"防重放 nonce"
- **加密完整性校验缺失**:SM4-CBC 无 MAC → 密文可篡改(比特翻转攻击)

## Common misses (AI 常忘)

- 看到 32 字节哈希就当 SHA256 → 国密 SM3 长度同 32 字节,只能靠 OID / 接口名 / 库名区分
- SM2 签名当 RSA 签名解 → SM2 签名是 64 字节裸 R||S(R、S 各 32 字节),不是 DER 编码;Base64 长度约 88
- SM2 加密 C1C2C3 vs C1C3C3 搞混 → 老标准 GM/T 0003-2005 是 C1C2C3,新标准 GM/T 0009-2012 改为 C1C3C2,库默认不同(BouncyCastle 老版 C1C2C3,新版可配置)
- 致远密码只看一层 MD5 → 实际是 `md5(md5(password) + salt)` 双层套娃,改盐就能爆破
- 泛微密码盐是 userid → 同密码不同用户哈希不同,**离线爆破时盐必须带 userid**
- 微信 `code` 当 `session_key` 用 → code 是一次性换 session_key 的凭证,5 分钟过期,不能复用
- 国密 SSL 抓包失败就放弃 → 需国密浏览器(奇安信/红莲花)或导出双证书私钥才能解
- 政务网关签名能逆出来就报漏洞 → 签名本身不是漏洞,**签名后能重放/越权/篡改才是**
- 双证书体系只测签名证书 → 加密证书私钥常托管在密码机,客户端无可导出私钥,但服务端解密接口可能可滥调

## Verification (verified 标准)

- 国密算法识别:接口/库/OID 三者之一确认 = 真;仅长度猜测 = 待证实
- OA 密码套娃:用已知密码 + 盐本地复算哈希,与库中值一致 = 真
- 微信 session_key 滥用:能拿 session_key 解出手机号 / 越权换 openid = 真;只在官方流程内 = 误报
- 政务网关重放:同签名请求 N 秒后仍成功(>时效窗口)= 真;服务端拒绝 = 已防重放
- SM4-CBC 篡改:改密文 1 字节,解密后对应块乱码但请求被接受 = 真(无完整性校验)
- 国密证书登录签名重放:同签名值多次登录成功 = 真;服务端要求 nonce = 已防

## Related playbooks

- 通用 AES/RSA/HMAC 逆向 → `skills/js-reverse/crypto-sign.md`
- 前端密钥/盐提取 → `skills/js-reverse/js-deep-analysis.md`
- OA/ERP 密码字段定位 → `skills/cn-specific/cn-oa-erp.md`
- 微信小程序完整流程 → `skills/mobile/miniprogram.md`
- CN 认证流程(扫码/SSO/短信)→ `skills/cn-specific/cn-auth.md`
- 自研加密层指纹 → `skills/fingerprint/recon-product-fingerprint.md`

## Reference (深度参考 — AI 可能不会的细节)

### 国密算法识别速查表

| 算法 | 长度/特征 | 区分点(避免与通用算法混) |
|---|---|---|
| SM2 签名 | 64 字节裸 R‖S(R、S 各 32),Base64 ≈ 88 字符 | 不是 DER 编码( RSA 签名是 DER);验签需用户 ID(默认 `1234567812345678`) |
| SM2 加密 | C1(64字节点)+ C3(32字节)+ C2(明文等长) | C1C3C2(新标准 GM/T 0009-2012)vs C1C2C3(老 GM/T 0003-2005);BouncyCastle `SM2Engine` 可配 Mode |
| SM3 | 32 字节,hex 64 字符 | 长度同 SHA256;OID `1.2.156.10197.1.401`;常配 SM2 出现 |
| SM4 | 16 字节块,密钥 16 字节 | 块大小同 AES;ECB/CBC 模式;无内置 GCM 模式(国密规范是 GB/T 32907) |
| SM9 | 标识密码(IBE) | 公钥是用户标识(邮箱/手机号);金融少见,政务偶现 |

### SM2 加密 C1C3C2 vs C1C2C3 实战坑

```
老标准(GM/T 0003-2005):  C1 || C2 || C3    ← C2 是密文,C3 是 SM3 哈希
新标准(GM/T 0009-2012):  C1 || C3 || C2    ← 顺序换了

BouncyCastle:
  SM2Engine.Mode.C1C2C3   ← 老模式
  SMEngine.Mode.C1C3C2   ← 新模式(默认)

坑点:服务端用老库,客户端用新库 → 解密失败,但报错信息往往不提示顺序问题
排查:抓到密文后,手动切出 C1(前 64 字节,可能带 04 前缀表示未压缩点),C3(32 字节),C2(剩余),互换 C2/C3 顺序再解
```

### 国密证书 OID 速查

```
SM2 签名算法:        1.2.156.10197.1.501   (SM2WITHSM3)
SM3 哈希:            1.2.156.10197.1.401
SM4 对称:            1.2.156.10197.1.104
SM4 ECB:             1.2.156.10197.1.104.1
SM4 CBC:             1.2.156.10197.1.104.2
国密 CA 体系:        CFCA / BJCA / GDCA / SZCA(签名证书 + 加密证书双发)
```

### 双证书体系(金融/政务必踩)

- **签名证书**:用户私钥自己持有(USB Key/软证书),用于签名;公钥在证书里
- **加密证书**:私钥托管在 CA 或密码机,用于解密;用户拿不到加密私钥,需调"密码机 API"解密
- **攻击点**:
  1. 服务端"代理解密"接口未鉴权 → 任意提交密文让密码机解密返回明文
  2. 签名验签服务器(`signServer`)接口可滥调 → 任意人提交数据让服务器代签名
  3. 证书绑定 IP/会话不严 → 中间人重放签名

### 致远 / 泛微 / 用友 密码哈希套娃

```python
# 致远 Seeyon:双层 MD5 + 盐
hash = md5( md5(password) + salt ).hexdigest()
# 盐在 user 表 cpassword 字段旁的 csalt;部分版本盐是 userid

# 泛微 e-cology:MD5 + 用户相关盐
hash = md5( password + "1" + userid ).hexdigest()
# 老版本无盐:hash = md5(password)

# 用友 NC:历史多版本
# NC65 之前:md5(password) 直接存
# NC65 之后:加盐 PBKDF2 或自研
# 字段:sm_user.password / pwd
```

爆破策略:`hashcat -m 0` (MD5)先试单层,失败则 `-m 20`(md5(md5($pass).$salt))配 salt 文件。

### 微信小程序登录态与 session_key

```
1. wx.login() → code(5 分钟一次性)
2. code → 后端 → 调 jscode2session → openid + session_key
3. 后端用 session_key 生成自定义登录态(token)下发给前端
4. 后续请求带 token,后端用 session_key 校验

漏洞点:
  - session_key 下发到前端(错误实现)→ 前端可自己算 signature 解 wx.getUserInfo 等接口
  - openid 当鉴权唯一标识 → 可枚举/替换 openid 越权
  - code 5 分钟内可重放 → 同 code 多次换 session_key(部分实现不查重)
  - 自定义登录态用 session_key 当密钥 → session_key 泄露后可伪造任意用户 token
```

### 政务网关签名格式与重放坑

```
常见格式:
  appKey=xxx&timestamp=xxx&nonce=xxx&body=xxx&sign=xxx
  sign = HMAC-SM3(secret, sorted_params) 或 SM2 签名

重放检测点:
  1. timestamp 偏移校验? — 服务端常只判 > 0,不判 < N 秒 → 老签名永久有效
  2. nonce 是否存? — 不存 = 可重放;存但无 TTL = 内存爆;存但用 appKey 维度不用 nonce 维度 = 同 nonce 不同 appKey 可重用
  3. sign 是否绑定 body 哈希? — 不绑 = 改 body 不影响签名
  4. appKey 默认值? — 政务网关常有 `appKey=test` / `appKey=default` 弱默认
```

### 银联 / 支付宝签名国密改造坑

```
银联:
  老规范:RSA-SHA1 / RSA-SHA256
  国密改造:SM2WITHSM3,证书走 CFCA 双证书
  坑:签名编码 DER vs 裸 R||S — 银联老接口要 DER,新国密接口要裸 R‖S,客户端搞混就验签失败

支付宝:
  RSA2 (SHA256WithRSA) 主流
  国密改造:部分政务场景支持 SM2,但支付宝官方 SDK 默认不开启
  坑:签名串组装顺序 — 支付宝按 ASCII 排序,银联按字段定义顺序,搞混就验签失败
```

### SM4-CBC 比特翻转攻击(无完整性校验时)

```
SM4-CBC 加密:  C_i = Enc(P_i XOR C_{i-1})
解密:          P_i = Dec(C_i) XOR C_{i-1}

改 C_{i-1} 第 j 字节 → P_i 第 j 字节对应变化(但 P_{i-1} 整块乱码)
利用:若请求体 { "userId":"A","role":"user" } 加密后传,改前一密文块对应字节可把 "user" 翻成 "admin"(但前一字段会乱码,需 Padding 兼容)
前提:服务端不做 MAC/签名校验密文完整性
```

### JDKeySn 工具与国密密钥定位

- JDKeySn:聚龙/捷德等厂商的密钥管理工具,常用于国密 USB Key
- 定位密钥:`certutil -store -user My` 列证书;`certutil -dump <cert.cer>` 看 OID
- Java 端:`KeyStore.getInstance("PKCS12")` 读国密证书需 BouncyCastle provider
- 客户端国密库常见:`gm-js` `sm-crypto`(JS)/ `bcprov-jdk18on`(Java)/ `tongsuossl`(C)

### 国密 SSL/TLS 抓包坑

- GMTLS 握手双证书:ECDHE-SM2 + SM4-GCM-SM3
- 抓包:Wireshark 需配置国密 cipher suite;或导出双证书私钥(签名私钥 + 加密私钥)配 SSLKEYLOGFILE
- 国密浏览器:奇安信浏览器 / 红莲花 / 密信;普通 Chrome 不能解 GMTLS
- 兜底:在客户端 hook 国密库(BouncyCastle / GmSSL)导出明文
