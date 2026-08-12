# demo-acme — Findings 索引（自动生成）

> 真相源 = `lifecycle.yaml`；由 `python tools/findings-lint.py demo-acme --lifecycle --gen` 生成，勿手改本文件。

共 3 条 · verified/money_ready=3 · candidate=0

| ID | 摘要 | 级别 | 状态 | 目标 | money_ready |
|---|---|---|---|---|---|
| ACME-F-001 | SSRF：/api/v1/asset-preview?url= 可读取内网管理配置（组合验证证明可做内网探测） | high | verified | api.demo-acme.example.com | yes |
| ACME-F-002 | 认证绕过：`..;/` 路径归一化绕过网关鉴权，未认证访问管理接口 | high | verified | admin.demo-acme.example.com | no（缺甲方对管理接口数据敏感度的确认（订单聚合是否属机密）） |
| ACME-F-003 | IDOR：/api/orders/<id> 未校验归属，GET 越权读取他人订单 | medium | verified | api.demo-acme.example.com | no（缺影响面评估（可遍历订单规模）+ 甲方确认） |
