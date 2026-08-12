# subagent 路由 — 决策与执行解耦(L5)

> 命中本质:**决策慢、要少、要外部强化;执行要快、要多、可并行**。
> 你单兵 + 工程兜底已在最佳实践带,这里只解决"主上下文挤压"问题。

---

## 何时分叉(主上下文 → subagent)

主上下文(决策 / 私有经验 / 投递判断)负责:

- memory 反查 / 续接 `_STATE.md`
- 看 `lifecycle.yaml` 状态机 / `current_attack_surface`
- 决定下一步打什么、什么时候停、什么时候投递
- 写 / 改 报告
- 与用户交互、请示重武器

分叉到 subagent(纯执行,Agent 工具的 Explore / general-purpose / 自定义)的任务:

| 任务 | subagent_type | 为什么解耦 |
|---|---|---|
| **读 > 50 KB 单文件 JS / 抽 URL 表 / 抽密钥** | `Explore` | 读完 200 KB 不能进主上下文 — 抽出的几个 URL 才进 |
| **跨多文件 grep "参数名出现位置"** | `Explore` | 50 文件搜索结果不必都进主上下文 |
| **业务路径定向扫描的产物 dedupe / 排序** | `general-purpose` | 200 个 URL 状态码不进主上下文,只进"发现 N 个 200 / M 个 401" |
| **WAF tamper 候选生成(纯模板批量)** | `general-purpose` | 模板生成是机械活,不需要主上下文判断 |
| **从一堆 raw/ 响应里挑出"看起来是注入点"的接口** | `Explore` | 50 个响应过一遍,只回 5 个候选 |
| **memory/ 反查多关键词整合** | `Explore` | grep 多个 keyword 后总结 |
| **candidate 对抗证伪(独立视角)** | `verifier-agent` | 验证与挖掘分离,防沉没成本自欺 |
| **挖掘日末复盘(盲区 / 规则修订)** | `review-agent` | 只读档案不发包,输入 rounds 卷 + lifecycle 变更 |

**共同特征**(必须满足才分叉):
1. 输入是"一堆原料"(多文件 / 多接口 / 多响应)
2. 输出是"少量结论"(一个 URL 表 / 一组关键字段 / 一个判断)
3. 不需要在执行过程中**回头改主决策**

---

## 何时**不**分叉(主上下文亲自做)

- 任何涉及"判断要不要投递" → 自检不能交出去
- 任何涉及"要不要请示重武器" → 红线判断必须主上下文
- 短链推理(< 5 步)/ 单一参数测试 → 分叉成本 > 收益
- 与用户对话 / 请示 / 确认 → 必须主上下文
- 写 `output/*.md` 报告 → 报告判断不能委派

---

## 分叉调用骨架(Agent 工具)

```
# 长 JS 审计样例
Agent(
  subagent_type="Explore",
  description="抽 app.xxx.js 的 API 路径",
  prompt="""
  读 targets/<X>/raw/app.xxx.js(若 > 50 KB,只读关键 chunk),
  抽出全部 (1) /api/* 路径 (2) 内部域名 (3) 硬编码密钥候选。
  只返回这 3 个表,不要返回 JS 原文。
  """
)
```

```
# memory 反查样例
Agent(
  subagent_type="Explore",
  description="memory 多关键词反查",
  prompt="""
  在 memory/playbooks/ memory/rejected/ 两个目录搜:
  关键词 = [longshine, sTalent, .NET, Authorize, EHR]
  返回:命中文件列表 + 每个文件 1 行核心结论。
  """
)
```

---

## 反模式(不要这样用 subagent)

- ❌ "让 subagent 决定打不打 sqlmap" — 重武器请示是主上下文红线
- ❌ "让 subagent 判断洞值不值得投" — 自检 ≠ 终验,主上下文必须看
- ❌ "让 subagent 跑半天再告诉我什么也没找到" — subagent 必须有明确的 stop condition / 时间预算
- ❌ "什么都丢 subagent" — 短任务分叉成本(打开新 context)> 直接做

---

## 与 orchestrator 的关系

`skills/orchestrator.md` 描述的是**主流程**(进场 → 探针 → 测试 → 投递 → 复盘)与轮次状态机(广度批 spawn ≤4 pentest-agent 正交分面 → 深度批 → verifier 并行证伪 → review 复盘)。
本文 subagent 路由是**主流程内部的横向并行**:某些重活儿丢出去,主流程继续推进。

不冲突 —— orchestrator 描述"做什么 + 谁做",subagent 路由描述"哪些动作哪个上下文做"。

---

## Custom Agent vs 通用 Explore(velox SRC 教训)

| 维度 | 通用 Explore / general-purpose | Custom Agent(`.claude/agents/<name>.md`)|
|---|---|---|
| **场景** | 单次纯执行任务(读大文件 / 跨文件 grep) | 反复出现的领域工作流(信息收集 / 漏洞挖掘 / 验证 / 复盘) |
| **system prompt** | 默认通用 | 专属定制(必读列表 / 反模式 / stop conditions) |
| **触发** | 主线临时 spawn | 主线根据"何时调用"判断 spawn |
| **典型** | 抽 1MB JS bundle 的 API | recon 全流程 / pentest 单子域全流程 / verifier 证伪 |
| **生命周期** | 几分钟内完成 | 几分钟到几十分钟,有明确阶段 |

### Custom Agent 使用方式

用 `tools/agent-launch.py` 统一渲染 prompt，再交给 `Agent` 工具:

```bash
python tools/agent-launch.py recon-agent <target_dir> --roots xxx.com yyy.com
python tools/agent-launch.py pentest-agent <target_dir> --subdomain api.xxx.com
python tools/agent-launch.py verifier-agent <target_dir> --finding <id>
```

渲染出的 prompt 会在开头注入角色定义文件路径，subagent 启动后先 Read 角色定义，再按规则执行。  
**不要再在 prompt 里重复写工作流细节** — 全部以 `.claude/agents/*.md` 为 single source of truth，以 `skills/orchestrator.md` 为编排 SOP。

### 当前定义的 Custom Agent 清单（6 个）

| 文件 | 触发条件 | 输入 | 输出 | 禁止 |
|---|---|---|---|---|
| `.claude/agents/recon-agent.md` | scope > 10 子域 / 大厂 SRC | target_dir + 根域列表 | 子域清单 + Top 10 ROI | 不挖洞,不写 findings.md |
| `.claude/agents/pentest-agent.md` | recon 完成后对每个子域并行 spawn | target_dir + 单个子域 | finding 候选 | 不横向,不写 findings.md |
| `.claude/agents/app-agent.md` | scope 含 APK/IPA/小程序 | target_dir + 包路径 + 设备 | 静态攻击面 + API 回归 | 不横向打其他资产 |
| `.claude/agents/client-agent.md` | scope 含桌面客户端 | target_dir + 客户端路径 | 动静结合审计候选 | 不横向 |
| `.claude/agents/verifier-agent.md` | pentest-agent 产出 candidate 后 | target_dir + 证据包 | VERDICT + 反例测试记录 | ≤5 包,不写 lifecycle 真相源 |
| `.claude/agents/review-agent.md` | 挖掘日末 / 周期深复盘 | rounds 卷 + lifecycle 变更 | 盲区清单 + 规则修订提案 | 只读档案不发包 |

**调用方式**:先用 `agent-launch.py` 渲染 prompt，再直接使用 `Agent` 工具传入该 prompt。

**prompt 模板化**:对有标准输出的任务,用 `tools/agent-launch.py` 统一渲染 agent 定义 prompt(支持 `--output-prompt` / `--format=json` / `--inline`)。比自由文本 prompt 更可解析、可回归测试。

### 各 agent 职责边界（v6 实际模型）

- **`recon-agent`** — 信息收集 / OSINT 流水线(scope > 10 子域时调用)
  - 必读:`doctrine/reflexes.md` 第二层 + `skills/orchestrator.md` 阶段 1
  - 写入仅 `recon/` + `_PENDING.md` recon 块
- **`pentest-agent`** — 单子域漏洞挖掘(recon Top N 后并发 spawn)
  - 必读:`doctrine/reflexes.md` 完整 + `memory/rejected/*` + 垃圾洞 playbook
  - 写入仅 `probes/<子域>/` + `_PENDING.md` pentest 块
  - **不直接写 lifecycle.yaml**(防并发竞争,Commander 独占真相源)
- **`verifier-agent`** — candidate 对抗证伪(独立视角,不阻塞下一轮挖掘)
  - 只验证不挖掘;≤5 包;结论只通过一次 Write 到 `<target>/output/delivery-reports/<ID>-verify-<日期>.md`
  - **不写 lifecycle.yaml / findings.md**(Commander 独占真相源)
- **`review-agent`** — 日末 / 周期复盘(只读档案,不发包)
  - 输入:本轮 rounds 卷 + lifecycle 变更 + DE 记录 + 验证 verdicts
  - 输出:盲区清单 + 规则修订提案 + playbook 增量,每条必须有档案证据引用

### 选择经验法则

- 任务**只跑这一次** → 用通用 Explore + 普通 prompt
- 任务**会反复出现 + 有专属规则要遵守** → 写 `.claude/agents/<name>.md` + prompt 注入

### Custom Agent 与本文路由的关系

Custom Agent 本质是"带专属角色定义的 Explore",**遵守本文所有原则**:
- ✅ 输入原料,输出结论
- ✅ 必有 stop condition
- ✅ 不嵌套 spawn(Custom Agent 不能 spawn 子 Custom Agent)
- ✅ 决策 / 投递 / 请示留主线(Commander)

---

## 关联

- L5 决策 vs 执行解耦 —— `CLAUDE.md` 心法
- 长 JS / 多文件读 —— `skills/js-reverse/js-deep-analysis.md`
- 业务路径定向扫描 —— `doctrine/law.md §4.2`
- 多 Agent 编排与轮次状态机 —— `skills/orchestrator.md` + `.claude/agents/`
