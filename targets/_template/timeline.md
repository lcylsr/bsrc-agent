# 时间线(Timeline)+ 猎杀日志

> 每次会话追加。简短,记关键决策和发现。
> 挖洞过程**主动**输出 `[专家直觉]` / `[攻击推演]`,verified 后输出 `[实战复盘]`。

---

## 结构化记录(2026-07-10 新增标准格式)

用于人工维护时间线（v6 无自动统计）。每次产生 finding / Dead End / auth 状态变化时追加一行:

| 时间 | 子域 | 状态 | ID | 标题/动作 | 包数/备注 |
|---|---|---|---|---|---|
| 2026-06-15 15:30 | api.target.com | verified | F-003 | 订单水平越权 | 12 packets |
| 2026-06-15 16:45 | api.target.com | dead_end | — | /api/v1/x 404 永久死 | 2 包 |

记录类型列只能是: `verified` / `candidate` / `phenomenon` / `dead_end` / `auth_expired`。
（timeline 是动作日志，不是 finding 状态机；finding 状态见 lifecycle.yaml）

---

## 2026-06-15(范例 — 资深赏金猎人怎么记日志)

- 14:00 接单。范围:`*.target.com`,排除 `internal.target.com`。task_weight=standard。
- 14:05 关口 1 跑完:`grep memory` 命中"同框架 .NET [Authorize] 类级漏配"经验;CVE 2024-XXXX 已知影响该版本。
- 14:10 进场探针:阿里云 WAF,登录口 5 次错误密码出验证码。
- 14:15 **[专家直觉]** 发现 `/api/v1/bind-device`,直觉:这种"绑定"接口开发常常只校验登录态,不校验 device_id 归属,IDOR 概率高。
- 14:20 抓 JS,发现 SourceMap 暴露 → shuji 还原源码,提取 23 个 API 接口。
- 14:30 surface.md 攻击树画完,优先级:🔥 支付 / 🟧 设备绑定 / 🟧 订单越权 / 🟨 用户信息。
- 15:00 **[攻击推演]** 测 device_id IDOR,WAF 拦截了 `id=` 参数。推演 WAF 是基于参数名的,改成 `deviceId`(驼峰)绕过成功。
- 15:30 测 `/api/v1/orders/<id>` 水平越权 → 验证成功(F-003)。
- 15:45 **[实战复盘 — F-003]**
  - 开发为何犯错:ORM 用 `findById(id)` 单参数查询,没把 `user_id` 作为联合 Where 条件
  - 通用挖掘模型:任何 `_id/_no/_order` 类参数,先抓自己的→改邻居 ID→看回包是否换数据
  - 同 target 下一步:同一开发可能写了"取消订单/删收藏"也有同样问题 → F-004/F-005 候选
- 16:00 报告写完,业务灾难填:"订单越权可拉取全平台用户家庭住址+电话,可触发个保法 1000 万级罚款"。落 `output/target_idor_订单越权_20260615.md`。

---

## 2026-06-16

- (下次会话开始追加)
