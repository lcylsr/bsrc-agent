# investigations/ — AI 思维链留底(BitWarden 风格双轨)

> **2026-06-19 加 · v4.3.2 · 教训源**:struts-198.51.100.1 F-005 推翻路径只在 _RESUME.md 一行字,新会话 resume 看不到当时怎么想的、为什么推翻。
>
> **设计源**:看雪 BitWarden《打破传统AI逆向的新思路:多Agent、自主管理上下文》 — 产物 vs 思维链显式双轨(.artifacts/ vs .investigations/)。

---

## 三铁律

1. **不强制每个 finding 都写 investigation** — 避免形式主义。**只在以下情景写**:
   - 推翻假设(任意 finding 从 verified/candidate 降级到 rejected)
   - 多假设并行验证(2 个或更多互斥假设需要打)
   - 多 agent fan-out(每个 agent 一份 investigation = 自然分支)

2. **产物 vs 思维链严格分离**
   - **产物** → `findings.md` F-XXX(verified 套报告模板)
   - **思维链** → `investigations/<task-id>/`(分析路径,不投递)
   - 结案后 investigations/<task>/结论.md 必须**回链** findings.md F-XXX

3. **fan-out 互斥假设用 "假设X-<topic>.md" 命名**
   - 每个假设独立文件 — 推翻一个不丢另一个
   - 升为活跃方案的假设 → 复制其内容到 结论.md

---

## 文件结构

```
investigations/
└── <task-id>-<slug>/                 例:001-decision-filter-bypass-attempt
    ├── 任务.md                        简报(谁/为什么/预期产出/起始 frontmatter)
    ├── 假设A-<topic>.md               并行假设 A(独立留底)
    ├── 假设B-<topic>.md               并行假设 B
    ├── 假设C-<topic>.md               (任意多)
    └── 结论.md                        结案后写,链回 findings.md
```

---

## 任务.md 模板

```markdown
---
task_id: 001
slug: decision-filter-bypass-attempt
status: 进行中           # 进行中 / 已结案 / 已放弃
type: 攻击面探测          # 攻击面探测 / 协议分析 / 算法还原 / 链式攻击 / 反思 / ...
created: 2026-06-19T20:00+08:00
updated: 2026-06-19T21:00+08:00
agent: Commander         # Commander / pentest-agent / recon-agent
---

# 任务 — <一句话>

## 起因
- 触发指纹 / 入口现象 / 用户提示

## 预期产出
- 验证 / 推翻 / 链式攻击候选 / playbook 升级建议

## 假设清单(各对应一个 假设X-*.md)
- A: <假设短描述>(状态:验证中/已推翻/已升活)
- B: <假设短描述>
- C: <假设短描述>

## 决策点
- 进入此任务 = 主上下文剩余预算 / 包数预算 / 时间预算
- 退出条件 = 命中 verified / 全部假设推翻 / 包数耗尽 / 用户打断
```

---

## 假设X-*.md 模板

```markdown
---
hypothesis: A             # A / B / C / ...
topic: <一句话主题>
status: 验证中            # 验证中 / 已推翻 / 已升活 / 已合并
verdict_reason:           # 推翻 / 升活 时填写"为什么"
created: 2026-06-19T20:30+08:00
---

# 假设 A — <主题>

## 假设内容
- 我想验证什么(具体到某个行为 / 某个返回值 / 某个 bug 模式)

## 验证步骤
1. <step 1 + 包数 + 预期>
2. <step 2 + 包数 + 预期>

## 实测证据
\`\`\`bash
# 实际跑的 curl + 输出片段(非占位)
\`\`\`

## 推论
- 命中:<提供升活 / 合入主分支的理由>
- 推翻:<具体反证,**不是 hand-wave**>
- 待定:<差什么证据可结论>

## 链接
- 相关 finding: findings.md#F-XXX
- 相关 playbook: memory/playbooks/playbook-X.md#件Y
```

---

## 结论.md 模板

```markdown
---
final_verdict: A          # 哪个假设升活 / 全部推翻
linked_findings:          # 回链 findings.md
  - F-005
linked_playbook_upgrade:  # 是否提示升级 playbook(可空)
  - playbook-X#件Z
closed: 2026-06-19T22:00+08:00
---

# 结论

## 结论一句话
<升活假设 / 全部推翻 / 推翻后转向新方向>

## 决策路径回顾
1. 假设 A 验证 → 结果 X
2. 假设 B 验证 → 结果 Y
3. ...

## 教训(可选,若值得写到 memory/rejected/ 或 memory/insights/)
- ...

## 投递产物
- findings.md F-XXX(若升活到 verified)
- 或 phenomenon 标注(若全部推翻)
- 或 playbook 升级 patch
```

---

## 与 playbook 子系统的关系

结论.md 的 `linked_playbook_upgrade` 字段记录升级建议 → AI 复核后手动升级 `memory/playbooks/` 对应文件。

**形成闭环**:findings → investigation → playbook upgrade → 下次复用更准。

---

## 反模式(违反 = 重演 struts-139 70 包教训)

| 反模式 | 后果 |
|---|---|
| ❌ 推翻假设只在 _STATE.md 一行字 | 新会话 resume 看不到推理路径 |
| ❌ 每个 finding 都强制写 investigation | 形式主义,投资回报极低 |
| ❌ 假设互斥但写在同一文件 | 推翻一个污染另一个 |
| ❌ 结论.md 不回链 findings | 后续审计不知道 investigation 影响哪个 finding |
