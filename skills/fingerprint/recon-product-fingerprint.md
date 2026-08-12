# 产品 / 二开框架识别(找到产品 → 跨实例同款打)

> **目标**:从指纹反推**产品名 + 客户化代号 + 二开层**,然后:
> 1. 同产品其他客户实例 = 同款漏洞复现池
> 2. 厂商默认配置 / 默认凭据 / 历史 CVE 直接套
> 3. 二开层(客户化目录 / 自研字段 / 自研加密)= 比标准框架更脆弱(代码更少人审)

## Triggers (何时用)

- 看到响应有非标字段(`SERVICEPROVIDER` / `LSAuthHeader` / 自定义 errorCode)
- 路径有客户化代号(`/CustStyle/<x>/` / `/Theme/<x>/` / `/skin/<x>/`)
- `X-Powered-By` 是非主流值(不是 PHP/Express/ASP.NET 这种通用)
- 系统主页文案/Footer 含厂商名,但不是大众已知开源项目
- 标准框架特征(.NET MVC / Spring) **+** 业务领域强(EHR / OA / ERP / SCADA)

## Coverage points (查什么)

5 类信号(零额外发包,从已抓的 probe 里 grep):
1. 厂商指纹:响应头 `X-Powered-By` / `Server` + 主页 `copyright`/`©`/版权
2. 客户化代号:URL 路径里非通用目录(`/CustStyle/` `/Theme/` `/Skin/` `/Custom/` `/Template/` `/Tenant/`)
3. 自研字段:JSON 响应非通用 key(全大写下划线 / 帕斯卡 + 厂商前缀如 `LsXxxYyy`)
4. 自研路径前缀:API URL 非通用前缀(帕斯卡 / 厂商缩写)
5. 错误格式:全局异常 handler 标志(`errorCode`/`ExceptionMessage`/`errno`/`resCode`/`resultCode`/`retCode`)

拿到厂商指纹后:WebSearch 反查产品名 + 历史 CVE + 默认凭据;fofa 反查同产品其他客户实例。

## Common misses (AI 常忘)

- 把"二开特征"当"信息泄露"看 — 应当当"产品级反查入口"看:一个特征命中 → 全产品客户横扫
- **二开层比标准层更脆弱**:客户化目录 / 自研鉴权 / 自研加密 / 统一异常包装 — 更少人审、更少 SAST 覆盖,优先深探
- 客户化覆盖目录(`/CustStyle/<x>/`)只试了 `admin/test/default`,漏了把 **fofa 反查到的其他客户代号**当 `<x>` 试遍历
- 自研鉴权层(包在标准 cookie/JWT 外面)只看头是否存在,没试**不带自研头能否调接口**(原生 cookie 仍在)
- 自研加密层只看密文格式,没试**加密前后是否做完整性校验**(若否,密文可重放任意篡改)
- 统一异常包装只看格式,没投不同畸形输入(SQL/路径/JSON/XML)看异常分支是否回显内部细节(表名/路径/类名)
- scope 外的同产品其他客户:**只反查不发包**,记录到 `intel.md` 写"同产品 N 个其他客户(fofa 引用),漏洞潜在影响面"

## Verification (verified 标准)

二开层漏洞 SRC 评级 **比标准层同等漏洞高半级**(影响面 = 同产品所有客户):

| 漏洞 | 标准框架(单实例) | 二开层(产品级) |
|---|---|---|
| 鉴权前接口数据返回 | 低 | **中**(同产品全部客户) |
| 自研加密层重放 | 低 | **高**(产品级密码学缺陷) |
| 客户化目录穿越 | 中 | **高**(可读其他客户配置) |
| 统一异常 SQL 表名外泄 | 中 | **中-高**(同产品全部客户漏 SQL) |

**报告写法**:在"业务危害"一段标注 `产品级 → 影响面 = <fofa N 个客户>`。

## Related playbooks

- `waf-evasion.md` — WAF 指纹识别与对抗
- `skills/js-reverse/crypto-sign.md` — 自研加密层抓明文
- `skills/api-logic/auth-bypass.md` — 自研鉴权头绕过
- [[playbook-frontend-config-js-attack-surface]] — 配套 JS 抢全攻击面
- [[playbook-twinflex-ipes-auth-stack]] — 示例厂商 iPES 三件套(同产品横扫案例)

## Reference (深度参考 — AI 可能不会的细节)

### 二开层 5 大特征检测信号 + 攻击思路

二开框架 = **标准框架内核 + 厂商在外层加的私货**。私货层比标准层更脆弱(更少人审、更少 PR、更少 SAST 覆盖):

| 二开特征 | 检测信号 | 攻击思路 |
|---|---|---|
| **客户化覆盖目录** | `/CustStyle/<x>/` `/Theme/<x>/` `/Skin/<x>/` | 试遍历:`<x>=admin/test/demo/default`;试 `..` 路径穿越;试同产品其他客户代号(从 fofa 反查得到) |
| **自研鉴权层**(包在标准 cookie/JWT 外面) | `LSAuthHeader` / `LsCookies` / 服务端动态指定 header 名 | 试不带自研头能否调到接口(原生 cookie 仍在);试自研头注入(`X-Forwarded-User` 同款) |
| **自研加密层**(包在标准 HTTPS 外面) | base64+gzip+base64 / RSA 公钥前端写死 / SM2/SM4 国密 | hook crypto 拿明文;试加密前后是否做完整性校验(若否,密文可重放任意篡改) |
| **统一异常包装** | 全接口返 `{errorCode, ExceptionMessage, force}` | 投不同畸形输入(SQL/路径/JSON/XML),看异常分支是否回显内部细节(表名/路径/类名) |
| **自研字段命名** | 全大写下划线(`SERVICEPROVIDER`)/ 帕斯卡 + 厂商前缀(`LsXxxYyy`)| 字段名反查 → 找产品 → 找产品级公开漏洞 |

### 5 大主流国产二开 EHR/OA/ERP 速查表

看到任何一条特征命中 → 直接走对应厂商的"历史漏洞品类"打,**不要从 0 开始探**。

| 厂商 | 产品标识 | 客户化路径 | 自研字段 | 历史漏洞品类 |
|---|---|---|---|---|
| **长盛(Longshine)** | `X-Powered-By: longshine` `LsCookies` `STALENT_VC` | `/CustStyle/<x>/` | `SERVICEPROVIDER` `LsAuthHeaderName` | RSA 弱填充 / 客户化目录穿越 |
| **致远(Seeyon)** | `Server: Coyote` + `/seeyon/` 路径 | `/seeyon/customize/<x>/` | `M3` 移动接口前缀 | A8 反序列化(CNVD-2022-77692) |
| **泛微(Weaver e-cology)** | `/wui/` `/api/ec/` 前缀 + ` ecology` cookie | `/wui/theme/<x>/` | `WeaverNcLogin` | E-Office 文件上传 / SQLi(CNVD-2023-00257) |
| **金蝶(Kingdee K3 Cloud)** | `/k3cloud/` + `cookie: kdservice-` | `/k3cloud/Kingdee.BOS.App/` | `currentculture` `dbid` | 反序列化 / SSRF |
| **用友(YonYou NC)** | `/nc/` `/uapws/` + JNDI | `/nccloud/<modulename>/` | `cookie nccode` | NC Cloud 任意文件上传 / 反序列化 |

### fofa 反查语法(同款攻击池)

```
"X-Powered-By: longshine"                    ← 长盛全网部署
body="SERVICEPROVIDER" && body="bjcx"        ← 搜 bjcx 客户化代号其他实例
title="sTalent" || title="长盛"                  ← 产品名 fallback
```

scope 内允许 → 跨实例验证漏洞通用性(F-001 在其他客户上一样可调?)
scope 外仅记录 → `intel.md` 写"同产品 N 个其他客户(fofa 引用),漏洞潜在影响面"

### bluegate 实战回放(典型正确打法)

```
30 秒内识别(回放):
  X-Powered-By: longshine          → 长盛
  /CustStyle/bjcx/                  → bjcx 客户化代号
  SERVICEPROVIDER: sTalent系统      → 产品 = 长盛 sTalent
  LsCookies / LsAuthHeaderName     → 自研鉴权层(本应试不带头能否调接口)
  base64+gzip+base64 密码          → 自研加密层(本应 hook 看完整性校验)
  统一 errorCode/ExceptionMessage   → 自研异常包装(本应深探异常回显)

→ fofa 反查同产品其他客户:每个客户独立 SRC,但漏洞是产品级
→ 长盛历史 CVE / 默认配置 / 默认凭据 列出来逐项试
→ /CustStyle/admin/ /CustStyle/test/ /CustStyle/default/ 试遍历
```

bluegate 错过的 = 把"二开特征"当"信息泄露"看,而不是当"产品级反查入口"看。
