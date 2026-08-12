# tools/playbook/ — playbook 复用子系统

> **v6.0-slim 定位**: 轻量召回层。`match.py` 读 scope.md 命中 playbook 指纹,`quickcheck.py` 对命中项做最小验证,输出候选状态供 LLM 决定是否继承。不替代 AI 判断,不自带审计/升级闭环。

---

## 解决的问题

2026-06-19 反思:struts-198.51.100.1 任务 70 包重复挖掘已 verified 过的示例厂商 iPES playbook,框架 recall 了文件但 LLM 默认从头自取证。

v6.0-slim 解法:保留 `match.py + quickcheck.py` 最小机器层,把“是否继承”交还 LLM;删除 audit/upgrade/lint/test 等维护脚本,避免“用工具维护工具”。

---

## 一句话用法

```bash
# 一键(推荐)
bash tools/playbook/run.sh <target_dir>

# 分步
python tools/playbook/match.py      <target_dir>      # 1. 命中检测
python tools/playbook/quickcheck.py <target_dir>      # 2. 三档验证
```

---

## 输入契约 — playbook 文件结构

`memory/playbooks/playbook-*.md` 文件必须含以下结构:

### 1. frontmatter

```yaml
---
name: <slug>
description: <一行描述>
playbook_type: executable    # 或 reference
---
```

- **executable**(默认):quickcheck.py 可执行此 playbook,必须带 `## 触发指纹`/`## 验证命令`/`## 报告模板` 三段
- **reference**:仅作经验沉淀(清单/技巧),跳过段落校验

### 2. 必须段落(executable 类)

```markdown
## 触发指纹
- 多行,每行一个特征(支持 `backtick 包裹` 强指纹 / 整行模糊指纹)
- match.py 在 scope.md 中 grep ≥ 2 个指纹命中即视为该 playbook 适用

## 验证命令(quickcheck.py 执行)

### 件 1: xxx
- METHOD: GET | POST | HEAD | PUT | DELETE  (默认 GET)
- PATH: /relative/path?with=query
- HIT_GREP: 命中模式(grep -E ERE 正则匹配响应体,支持 `a|b|c` 交替)
- FIXED_GREP: 已修模式(可空;非空时若命中标 🔴 已修)
- COMMENT: 备注

### 件 2: yyy
...

## 报告模板(LLM 写 findings.md 时套用)

### 件 1 命中模板

\`\`\`markdown
## F-XXX — xxx (verified · P3-P4 · inherited_from playbook 件 1)
**inherited_from**: <playbook-name>#件1
**poc_packets**: 1
\`\`\`
```

---

## 输出契约

### scope.md frontmatter

```yaml
---
playbooks_match: ["playbook-name-1", "playbook-name-2"]    # match.py 自动填
---
```

### scope.md 章节

```markdown
## playbook 件状态(quickcheck.py @ <timestamp> 自动填,LLM 复核)

- playbook: playbook-name-1
    - 件 1 xxx: 🟢 命中 (grep '...' 命中)
    - 件 2 yyy: 🔴 已修 (grep '...' 命中)
    - 件 3 zzz: 🟡 不确定 (HIT_GREP 未中,FIXED_GREP 未配置或未中)
```

三档语义:
- 🟢 命中:HIT_GREP 在响应中匹配 → LLM 套报告模板写 verified F-XXX
- 🔴 已修:FIXED_GREP 在响应中匹配 → LLM 标 rejected F-XXX
- 🟡 不确定:都不中 / curl 失败 → LLM 必须自取证

### findings.md F-XXX 标记

LLM 写 findings.md 时,从 playbook 套用模板,加:

```markdown
## F-XXX — xxx (verified · inherited_from)

**inherited_from**: playbook-name-1#件1
**poc_packets**: 1
```

---

## 三档判定 — 核心反假阳性机制

工具**只输出"候选状态"**,**verified 标定永远由 LLM 基于完整证据决定**:

| 工具输出 | LLM 该做什么 |
|---|---|
| 🟢 命中 | 看 quickcheck 实际响应 → 套 playbook 报告模板 → 写 verified F-XXX 标 inherited_from |
| 🔴 已修 | 标 rejected F-XXX 标 inherited_from(rejected) |
| 🟡 不确定 | 自取证(走原工作流),无 inheritance 标记 |

**工具不替 LLM 做 verified 决定** — 这是不假阳性的关键。

---

## 多场景行为

| 场景 | 行为 |
|---|---|
| 全新目标无 playbook 命中 | match.py 退出码 0,不写任何字段;run.sh 优雅退出 |
| 多 playbook 同时命中 | playbooks_match: 列表多个,quickcheck 依次跑 |
| 部分 🟡 不确定 | LLM 须自取证 |
| run.sh 不可用 | 直接调 `python tools/playbook/match.py` + `python tools/playbook/quickcheck.py` |

---

## 升级 / 维护

### 加新 executable playbook

1. 按上方契约写 `memory/playbooks/playbook-<name>.md`
2. 跑 `bash tools/playbook/run.sh targets/_template` 或具体 target 验证 match/quickcheck 不报错
3. 命中后由 LLM 按报告模板写 findings.md

### 加新 reference playbook

只需 frontmatter 加 `playbook_type: reference` 即可。

---

## 历史

- **2026-06-19**:子系统初版,含 match/quickcheck/audit/upgrade/lint/test。
- **2026-08-07**:v6.0-slim 瘦身,仅保留 `match.py`/`quickcheck.py`/`run.sh`,删除 audit/upgrade/lint/test wrapper。
