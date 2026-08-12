# 攻击面清单（surface.md）— 脱敏演示案例（虚构）

> recon 产出摘要。全部资产为虚构（RFC 5737 / example.com）。

## 资产清单

| 资产 | 地址 | 技术栈（指纹） | 入口 |
|---|---|---|---|
| 主站 Web | demo-acme.example.com (198.51.100.7) | Nginx + Vue SPA | https://demo-acme.example.com |
| API 网关 | api.demo-acme.example.com (198.51.100.8) | Nginx + Spring Boot | /api/v1/* |
| 管理后台 | admin.demo-acme.example.com (198.51.100.8) | 网关鉴权 + React | /admin/*（401 起步） |

## JS / API 面（js-recon 摘要）

- `main.js` 暴露端点：`/api/v1/asset-preview`（url 参数）、`/api/v1/orders/<id>`、`/api/v1/user/me`
- 硬编码线索：管理后台路径前缀 `/admin/dashboard`（源码注释残留）
- 无 SourceMap / swagger 暴露

## 指纹与 N-day

- Spring Boot 版本头部泄露（演示用版本无已知 CVE 命中）
- N-day 匹配：0 命中（nday-matcher）

## 高 ROI 候选（Top 3）

1. **api.demo-acme.example.com** — url= 参数（SSRF 候选）→ ACME-F-001
2. **admin.demo-acme.example.com** — 网关后管理口（认证绕过候选）→ ACME-F-002
3. **api.demo-acme.example.com /orders/<id>** — id 参数（IDOR 候选）→ ACME-F-003
