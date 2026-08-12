---
name: crypto-sign
domain: js-reverse|crypto|sign
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 加密 / 签名算法逆向

## Domain

- 请求含 sign/signature/token/nonce;改 1 字节 401
- Body 密文;国密 SM2/SM3/SM4 见 cn-crypto
- 工具: mcp js-reverse(CDP),禁止硬猜算法

## Boundaries

- 铁律:先断点再识别算法,不拍脑袋 MD5
- 不外泄目标私钥/生产密钥到公网
- evaluate_script 当签名机仅本地会话
- 逆向仅服务授权测试

## Pivot Hints

- search_in_sources → break_on_xhr → get_paused_info
- 同输入异输出 → 找 timestamp/nonce
- 混淆逆不出 → evaluate_script 魔改运行时
- 签名通了仍 401 → 换鉴权 skill,非算法问题

## Exit Evidence

### src
- E2: 独立 Python/脚本可复现签名 + 改参成功请求
- E3: 用签名链打到越权/未授权业务接口
- 仅「找到 sign 函数」无利用 → phenomenon

### redteam
- E2: 能重放业务请求即可推进
- 签名机稳定后转 auth-bypass/idor

## Tactics

> 原 Triggers / Coverage / Common misses / Verification 压缩如下;深度细节见文末 Reference(若有)。

> **决策手册** — 工具调用见 `mcp__js-reverse-mcp__*`。本文讲"何时该做什么 + 为什么不要硬猜"。

## Triggers (何时用)

- 请求带 `sign` / `signature` / `_sign` / `token` / `_t` / `nonce`
- 重放原 curl OK,但**改 1 个字节**就 401(完整性校验)
- 响应 Body 是密文(`{"data":"U2FsdGVkX1+..."}`)

## Coverage points (查什么)

**铁律 — 不要硬猜算法**:看到 `sign=abc123` 拍脑袋猜 MD5/HMAC 是大坑。**先下断点,运行时告诉你算法**(新 MCP 是 CDP 调试器范式,无 hook;用 XHR 断点抓现场)。

按症状直挑动作:

| 症状 | 直接做 |
|---|---|
| 看到 `sign` / `signature` 但不知道在哪算 | `search_in_sources('sign' / 'signature' / 'computeSign' / 'CryptoJS')` |
| 知道带 sign 的接口,想抓是哪段 JS 算的 | `break_on_xhr(url=<接口片段>)` → 触发后 `get_paused_info` 看调用栈 + scope,或 `get_request_initiator` 看发起栈 |
| 找到算签函数,想看入参→输出对 | `set_breakpoint_on_text(text=<funcName>)` → 触发后 `get_paused_info` 读 scope 变量,`step` 单步看返回,抓 5-10 组 |
| 同输入是否同输出? | 5-10 组对照,同 → 纯函数(下面长度表识别)/ 异 → 含时间戳/nonce/随机数 |
| 算法识别后能复刻 | Python 自算,改参数重发 |
| 算法识别后逆不出(混淆 / 反调试) | "魔改运行时" — `evaluate_script` 当签名机用 |

## Common misses (AI 常忘)

- 看到 sign 就猜 MD5 → 大坑,先断点看运行时算法
- 抓 5-10 组对照没做就下结论 → 漏了时间戳/nonce/随机数导致"同输入异输出"
- 复刻对不上 → 大概率有 salt / 拼参顺序 / 加密钥,没排查就放弃
- 签名是防爬虫 / 防重放时,自动化高频请求会触防护 → RPS ≤ 1-5(逆向只读放行,但高频触风控)

## Verification (verified 标准)

逆向出 sign 本身不算漏洞,要配 IDOR / 越权 / 注入才值钱。典型驳回(SRC 不收):

1. **逆出来了但没找到漏洞** — 签名是工程问题
2. **签名 key 在客户端 JS 暴露** — 客户端代码不可信,密钥泄露**本身**几乎不算高危。除非这 key 是后端共享密钥(如服务端验签也用它)
3. **响应解密后是公开数据** — 加密无意义,SRC 不收
4. **重放检测靠 sign 但接口本身就鉴权前** — 直接打鉴权前接口,不需要逆 sign

## Related playbooks

- 逆出 API → `skills/api-logic/`
- 二开框架自研加密层(国密 SM2/SM4 + base64+gzip+base64) → `skills/fingerprint/recon-product-fingerprint.md`
- 移动端加密 → 优先 `frida-mcp` / `jadx-mcp`,JS 反汇编是最后一招

## Reference (深度参考 — AI 可能不会的细节)

### 长度→算法识别表(纯函数前提下)

| 长度 | 候选 |
|---|---|
| 32 hex | MD5 / HMAC-MD5 |
| 40 hex | SHA1 / HMAC-SHA1 |
| 64 hex | SHA256 / HMAC-SHA256 |
| 24 base64 (==) | DES |
| 44 base64 (=) | AES-128/256-CBC/GCM 输出 |
| 含 `==` 多行 / >300 字符 | RSA / 国密 SM2 签名 |

复刻验证:用 hook 看到的 input 自己跑算法,对不上 → 大概率有 salt / 拼参顺序 / 加密钥。

### 4 大常见签名模式

### A. `sign = MD5(参数排序 + secret)`
```js
const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&')
const sign = MD5(sorted + secretKey)
```
→ Python 复刻,改参数能算新 sign。

### B. `sign = HMAC-SHA256(secret, body + timestamp + nonce)`
secret 来源:硬编码(找到就赢)/ 登录后下发(看登录响应)/ 设备指纹(走 fingerprintjs)。

### C. AES 加密 Body(对称)
key/iv 通常硬编码 → search_in_sources('CryptoJS.AES.encrypt' / 'createCipheriv')提出 → Python `Crypto.Cipher.AES` 解。

### D. RSA 公钥加密(单向)
公钥在 JS / 登录页 / `GetLoginPageInfo` 类元数据接口暴露。**不能解响应**,但能加密自己的 payload 重发。

### 魔改运行时(逆向死磕的兜底)

签名算法被 obfuscator 极端混淆 / 反调试 → **不再尝试逆向**,直接把页面当签名机:

```
# 1. 确认签名函数挂在哪(全局 / 模块闭包)
search_in_sources('computeSign')          # 定位
set_breakpoint_on_text('computeSign')      # 断点确认调用时机与 this

# 2. 直接调用(mainWorld 才能访问 window 全局)
evaluate_script(
  function="() => window.computeSign({orderId:'B', userId:'B'})",
  mainWorld=true
)
→ 拿签名拼 curl 重发
```

闭包内拿不到全局时:在算签函数处 `set_breakpoint_on_text` 断住,`get_paused_info` 读出当前 scope 的 input/output;或在断点暂停态下 `evaluate_script(frameIndex=N)` 就地求值。慢但永远能用。

