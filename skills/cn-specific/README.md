# skills/cn-specific/ — CN 特有攻击面

> 收录 AI 模型可能**不可靠掌握**的中国大陆场景特有知识:国产 OA/ERP 业务模块、国密算法、二开框架残留、CN 认证流程。通用 OAuth2/JWT/AES 不在此,见各自领域目录。

## 文件清单

| 文件 | 一句话 |
|---|---|
| `cn-oa-erp.md` | 致远/泛微/用友/浪潮/通达等 OA 的工作流越权、Excel 公式注入、模板 SSTI、印章/档案 IDOR |
| `cn-crypto.md` | 国密 SM2/SM3/SM4 识别、C1C3C2 vs C1C2C3、双证书体系、OA 密码套娃、政务网关签名重放 |
| `second-dev.md` | 基于若依/Jeecg/ThinkPHP/Spring Cloud Gateway 二开的残留接口与幽灵接口攻击面 |
| `cn-auth.md` | 短信码/微信扫码/企业微信/钉钉/政务 SSO/数字证书/生物认证/MFA 的 CN 特有绕过 |

## 使用原则

- 厂商指纹识别 → `skills/fingerprint/recon-product-fingerprint.md` 先行,本目录是其下游深度打法
- 通用鉴权绕过 → `skills/api-logic/auth-bypass.md`,本目录只补 CN-specific 部分
- 通用加密逆向 → `skills/js-reverse/crypto-sign.md`,本目录只补国密与 CN 框架特有坑
