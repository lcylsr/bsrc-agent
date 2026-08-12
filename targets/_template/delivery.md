# delivery.md — 交单闭环清单(src mode)

> money_ready 后 **默认动作是投递**,不是继续扩面。扩面是可选并行,不阻塞交单。

## 交单循环

```
money_ready ≥ 1
  → 写/更新 output/delivery-pack-<date>.md(可复制 URL + 影响 + PoC)
  → AI 现场重放:python output/poc-<id>.py 或重跑 poc_curl,确认 last_replay=passed
  → 平台提交
  → lifecycle status → delivered(追加 history 一条 + submitted_at)
  → 继续扩面或结案
```

## 本目标投递队列

| # | finding | host | 标题摘要 | pack | 状态 |
|---|---|---|---|---|---|
| 1 | | | | output/delivery-pack-….md | pending/submitted |
| 2 | | | | | |

## 检查项(每洞)

- [ ] `business_evidence` 非 HTTP 200 空话
- [ ] `poc_curl` / replay.py 可复制
- [ ] `last_replay: passed` 或 `.replay-status.json` verdict=passed
- [ ] 无 trash 清单项(CORS/安全头/Self-XSS alone…)
- [ ] ROE: 无真实数据破坏;自建 blob 已清理

## 组合拳(可选加分)

- verified ≥ 2 → 评估 chain(F-001→…→写面)
- 写入 delivery-pack ⭐ 节,不单独虚报

## 变更

- YYYY-MM-DD 创建
