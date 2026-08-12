# materials.md — 业务物料门(仅盲 ID enum)

> **何时需要本文件:** 参数是业务主键/分享链/会话 ID,且**没有**真实样本时,禁止大字典盲扫。  
> **不需要:** path fuzz、API 路径发现、资产 recon、已知锚点的 2 包定性。

## 规则

| 场景 | 动作 |
|---|---|
| 有真实 `shareId` / 订单号 / 会话 cookie | 登记下方表 → 允许定点重放 |
| 无真实 ID,接口返回「不存在/NPE」 | **Dead End**,写 timeline,停止 enum |
| 用户提供测试号/卖家号 | 登记 + 权限范围 |
| 自建可删资源(AppXite path 等) | 不标 materials;走 ROE 自建清理 |

## 物料登记

| id | 类型 | 值/获取方式 | 权限 | 过期 | 备注 |
|---|---|---|---|---|---|
| _(例)_ MAT-001 | shareId | 用户提供 `abc...` | 只读 | 2026-08-01 | downloadZip 链 |
| | | | | | |

## 当前阻塞(无物料不测)

- [ ] shareId / sessionId / recordId 四参链
- [ ] 卖家/CRM 测试账号
- [ ] FOFA keys(资产扩,非 ID enum)

## 变更

- YYYY-MM-DD 创建
