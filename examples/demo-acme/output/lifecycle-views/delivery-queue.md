# 投递队列（自动生成）

> 由 lifecycle.yaml 生成。**投递动作由用户人为执行**，本清单只排顺序（delivery_order 字段=用户拍板顺序）。
> **最近复检列**：lifecycle 每条 verified 的 `last_rechecked`（YYYY-MM-DD）。缺 ⚠️ = 未复检，投递前必须补测 liveness（v4 P0-5 复盘固化：PH-F-003 死洞就是此环节抓到的）。

| # | ID | 摘要 | 级别 | 最近复检 |
|---|---|---|---|---|
| 1 | ACME-F-001 | SSRF：/api/v1/asset-preview?url= 可读取内网管理配置（组合验证证明可做内网探测） | high | 2026-08-12 |
