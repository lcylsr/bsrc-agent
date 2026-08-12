---
name: business-logic
domain: business-logic|payment|privilege-escalation|state-machine
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 业务逻辑漏洞深挖（高 ROI，WAF 不拦）

> **定位**：竞态已合并进本 skill（见下方"竞态深挖思路"段）。本 skill 补支付逻辑/权限提升/状态机绕过。业务逻辑漏洞**不触发 WAF**，是 WAF 目标的最佳攻击面。

## Domain

- 支付/交易：下单/退款/转账/优惠券/积分
- 权限：角色分配/权限修改/资源归属
- 状态机：多步流程（下单→支付→发货→确认）/审批流
- 数量/金额：购物车/库存/限购
- modes: src 高价值（逻辑漏洞常评高危）；pentest 必测；redteam 逻辑绕过入口

## Boundaries

- **资金类操作提交前必拦截**（law.md 铁律）——测到"可改金额"即停，不实际提交
- 测试用自己注册的小号 + 最小金额（0.01）+ 立即退款
- 写操作用无害 payload（`test_vuln`）+ 测完清理
- 不修改他人订单/不批量操作他人资源

## Pivot Hints

- 金额改不了 → 试数量（负数/0/超大值）
- 前端校验 → 绕过前端直接改 API 请求
- 正向流程堵 → 试逆向流程（退款→改金额→再退）
- 单次没问题 → 试并发（竞态）
- API 有鉴权 → 试 mass assignment（加 `role:admin` `isAdmin:true`）

## Exit Evidence

### src
- E2: 可重放 curl（篡改后的请求） + 响应证明业务逻辑被绕过
- E3: 金额/权限/状态被实际改变（自己小号 + 立即回退 + 清理记录）

## Tactics

### 1. 支付逻辑（3-5 包，提交前必拦）

#### 金额篡改
```bash
# 下单请求改 price/amount 字段
curl -X POST https://target.com/api/order/create -d '{"productId":1,"price":0.01,"quantity":1}'
# price=0.01 或 price=-1 或 price=0
# 注意：检测到可改即停，不实际支付
```

#### 数量/库存绕过
```bash
# 负数数量（负数购买 = 退款？）
curl -X POST https://target.com/api/order/create -d '{"productId":1,"quantity":-1}'
# 超大数量（整数溢出？）
curl -X POST https://target.com/api/order/create -d '{"productId":1,"quantity":999999999}'
# 限购绕过（改 userId 或不传 userId）
```

#### 优惠券竞态
```bash
# 同一优惠券并发使用 20 次
for i in $(seq 1 20); do
  curl -X POST https://target.com/api/coupon/use -d '{"couponId":"ABC","orderId":'$i'}' &
done
```

#### 竞态深挖思路（原 race-condition 合并）

**触发条件**：有限资源扣减（积分/余额/优惠券/库存/邀请码/OTP/投票/礼品）+ 状态流转不可逆（确认收货/取消订单/阅后即焚）

**并发技术思路**：
- HTTP/2 多路复用：N 个请求塞同一 TCP 包（Turbo Intruder + Single-Packet Attack）
- HTTP/1.1 Last-Byte Sync：保留最后字节，N 连接全建立后同时发
- curl 并发：`for i in $(seq 1 20); do curl ... & done`（不够精确但够定性）

**判定标准**：
- ✅ B 收到 >100 元 / 余额变负 / 数据库重复记录 = 漏洞
- ❌ B 收到 ≤100 元 = 后端有锁，无漏洞
- ⚠️ 应用层有竞争但 DB 唯一约束兜底 = 无实际损失，不算

**Pivot**：
- 本地复现不稳定（一次成功九次失败）→ 加并发数 / 报告承认不稳定但贴数据库证据
- 触发风控（多次并发账号封禁）→ 先低并发探，逐步加
- 数据库有唯一约束 → 应用层竞争但 DB 拦了，不算

### 2. 权限提升（3-5 包）

#### Mass Assignment
```bash
# 注册/更新接口加额外字段
curl -X POST https://target.com/api/user/update -d '{"name":"test","role":"admin"}'
curl -X POST https://target.com/api/user/update -d '{"name":"test","isAdmin":true}'
curl -X POST https://target.com/api/user/update -d '{"name":"test","balance":99999}'
```

#### 水平越权（改 ID）
```bash
# 替换 userId/orderId 为他人 ID
curl https://target.com/api/order/detail?userId=<other_user_id>&orderId=1
```

### 3. 状态机绕过（3-5 包）

#### 跳步
```bash
# 正常流程: 下单(1) → 支付(2) → 发货(3) → 确认(4)
# 跳过支付直接发货
curl -X POST https://target.com/api/order/ship -d '{"orderId":1}'  # 不带支付凭证
```

#### 回退
```bash
# 已发货的订单回退到未支付状态
curl -X POST https://target.com/api/order/cancel -d '{"orderId":"已发货的订单ID"}'
```

#### 重放
```bash
# 同一个支付凭证重复使用
curl -X POST https://target.com/api/order/pay -d '{"paymentToken":"已用的token","orderId":2}'
```

### 4. 数量/限制绕过

- 限购 N 件 → 改请求不传 `userId` / 换设备 ID / 并发下单
- 限频 → 改 IP / 换 token / 并发
- 库存为 0 → 试负数库存 / 超卖竞态

## Common misses

- **只测金额** → 数量/优惠券/积分常被忽略
- **前端能改就不测 API** → 前端校验不代表后端校验，必须直接打 API
- **不测并发** → 很多逻辑漏洞只在并发时暴露
- **测完不清理** → 修改了订单/权限状态不回退 = 影响业务
- **不区分"可改"和"可利用"** → 能改 price 但提交时被后端二次校验 = phenomenon 不是 verified

## Verification

- **verified**：篡改请求 + 响应证明逻辑被绕过（金额/权限/状态实际改变）
- **phenomenon**：能改参数但后端二次校验拦截 / 改了但无实际影响
- **rejected**：后端严格校验，无法绕过

## ⚠️ 红线

- **资金类提交前必拦截**——检测到可改金额即停，不实际支付
- 测试用小号 + 0.01 元 + 立即退款
- 写操作无害 payload + 测完清理 + 报告写 `[清理动作]`
- 不修改他人订单/不批量操作他人资源

## Related

- `idor-bola.md` — 水平越权（本 skill 的权限场景）
- `auth-bypass.md` — 垂直越权
- `doctrine/law.md` §2 — 资金类操作铁律
- `memory/insights/playbook-trash-finding-checklist-before-report.md` — 防逻辑洞误报
