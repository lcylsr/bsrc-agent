# 自由探索时段

> **B 类嗅觉保护沙箱**(v3)。详见 `memory/insights/weapon-stack-three-checkpoints.md` → 自由探索时段
>
> **时间盒**:light=10 分钟 / standard=30 分钟 / heavy=60 分钟
>
> **规则**:任意发包(scope+L1 内)/ 违反三道关口顺序 / 不查 memory / 主观感受必填。
>
> **禁止**:直接进 findings.md / 触发重武器 / 违反 L1。

---

## 时段元信息

```yaml
task_weight: standard               # light | standard | heavy
started_at: 2026-MM-DDTHH:MM:00+08:00
deadline:   2026-MM-DDTHH:MM:00+08:00
```

---

## 探索记录

### 探索 #1
- **做了什么**:<具体动作 1 句>
- **回包概况**:<状态码 + 关键字段>
- **主观感受**:<必填,无感受不允许提交>

### 探索 #2
- **做了什么**:
- **回包概况**:
- **主观感受**:

---

## 收敛阶段(Commander 人工收敛)

```
[converge at <time>]
- 探索 #1 → F-XXX [phenomenon]  (planned: ...)
- 探索 #2 → F-YYY [candidate]   (intuition: ...)
- 探索 #N → freelance-archived.md
```

收敛后,本文件归档为 `E:/claude-artifacts/<target>/freelance-<timestamp>.md`(仓库不留 raw/),新一轮自由时段开新文件。

---

## 校验

Commander 收敛校验:
- ≥ 50% 必须有归宿(进 lifecycle.yaml 或归档),否则提示"探索质量不足"
- 探索条目必须包含"主观感受"(无即视为不达标)
- 时段超时(超过 deadline)未收敛 → 阻断进入 findings.md
