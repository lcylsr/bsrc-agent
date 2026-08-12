# 框架架构说明（提取自 v6.0-slim 源码）

> 本文档是对 `framework.yaml` + `CLAUDE.md` + `skills/orchestrator.md` + `.claude/agents/` + `tools/` 的架构提取。
> 一句话：**AI 主驾驶 + 脚本副驾 + 多 Agent 协同 + 纪律文档约束** 的分层协作框架。

---

## 1. 总体架构图

```
┌────────────────────────────────────────────────────────────────────┐
│                        指挥层（LLM 主循环 / Commander）                │
│   CLAUDE.md（铁律/流程） + framework.yaml（单真相源） + QUICK.md（决策树）│
└───────────────┬────────────────────────────┬────────────────────────┘
                │ 决策 / 状态 / 写回           │ 按需 Read（不开场全加载）
┌───────────────▼────────────┐  ┌─────────────▼──────────────────────┐
│        行动准则层 doctrine/ │  │         技能库层 skills/             │
│  law.md（法律红线）          │  │  api-logic / injection / fingerprint│
│  reflexes.md（双层反射）     │  │  js-reverse / cn-specific / mobile   │
│  coverage-audit.md（覆盖审计）│  │  orchestrator / chain / cloud       │
└───────────────┬────────────┘  └─────────────┬──────────────────────┘
                │ 驱动（bash tools/run.sh）    │ 唤醒（Agent spawn / MCP）
┌───────────────▼─────────────────────────────▼──────────────────────┐
│                       执行层（多 Agent 协同）                        │
│  recon-agent → pentest-agent×≤4（广度批）→ 深度批 Top N              │
│  → verifier-agent（并行证伪）→ review-agent（日末复盘）              │
│  app-agent / client-agent（移动端 / 桌面客户端专项）                 │
└───────────────┬─────────────────────────────┬──────────────────────┘
                │                              │
┌───────────────▼─────────────┐  ┌─────────────▼──────────────────────┐
│  工具层 tools/（脚本副驾）     │  │  数据层（目标工作区 targets/<t>/）    │
│  run.sh 统一入口              │  │  _STATE.md（7 段工作状态，防失忆）    │
│  recon-pipeline / js-recon   │  │  lifecycle.yaml（finding 唯一真相源）│
│  nday-matcher / findings-lint│  │  scope.md（授权边界）                │
│  scanner-dispatch（重武器闸门）│  │  findings.md / timeline.md / rounds/ │
│  playbook（知识召回）          │  │  output/（PoC / 报告 / 投递队列）     │
│  danger-guard.sh（法律硬拦hook）│  │  + 自动生成 lifecycle-views/        │
└──────────────────────────────┘  └───────────────────────────────────┘
```

## 2. 分层职责

| 层 | 载体 | 职责 | 关键约束 |
|---|---|---|---|
| 指挥层 | `CLAUDE.md` / `framework.yaml` / `QUICK.md` | 顶层决策、流程推进、状态写回 | 铁律不可妥协；framework.yaml 是结构唯一真相源 |
| 模型适配层 | `driver/copilot.py` | 接入国内大模型（DeepSeek/GLM/Comate），function calling + ReAct 双协议、黑名单硬拦 | 零依赖（stdlib）；参赛运行时模型不限海外模型 |
| 行动准则层 | `doctrine/*.md` | 法律红线、反射准则、收尾审计 | 按需 Read；law.md 不确定即停问用户 |
| 技能库层 | `skills/**` | 漏洞类 × 技术栈 × 场景的实操方法 | 命中指纹/参数才 Read，不开场全加载 |
| 执行层 | `.claude/agents/*.md` | 多 Agent 并行挖掘 / 证伪 / 复盘 | 每 agent ≤20 包 / ≤20 分钟；同 host 并发 ≤1；叶子节点不嵌套 |
| 工具层 | `tools/**` | 批量 IO、外部二进制调度、法律硬拦 | AI 驱动，不做决策；重武器经 scanner-dispatch + 请示 |
| 数据层 | `targets/<t>/**` | 工作状态 / finding 真相源 / 证据 | _STATE 只存 7 段；lifecycle.yaml 只改不手写视图 |

## 3. 多 Agent 协同模型（轮次状态机）

```
广度批：Commander spawn ≤4 pentest-agent 并行（正交分面 + 共享基线注入）
  → 批末强制写回产物（Top N 深挖清单 / 待重试记录）
  → 深度批：Top N 各 1 个 pentest-agent 深挖（≤20 包 / ≤20 分钟，到点返回 partial）
  → 候选产出：立即 spawn verifier-agent 并行证伪（不阻塞后续轮次）
  → 组合步：候选池 ≥2 时 Commander 做跨面组合分析 → 组合 PoC
  → 微反思：日末 spawn review-agent 复盘（只读档案不发包）→ 规则/playbook 增量注入下一轮
```

角色契约（决策与执行解耦）：

| Agent | 输入 | 输出 | 纪律 |
|---|---|---|---|
| recon-agent | 根域列表 | 子域清单 + Top N 高 ROI 候选 | 不挖洞，只摸面 |
| pentest-agent | 单子域 + banner 上下文 | finding 候选（verified/candidate/phenomenon） | 只攻一个子域，绝不横向 |
| app-agent | APK/IPA/wxapkg | 静态攻击面 + API 回归 | 移动三栈专项 |
| client-agent | 桌面客户端安装包 | 动静结合审计候选 | 深审模式需用户授权 |
| verifier-agent | candidate 证据包 + PoC | VERDICT（verified/降级/rejected + 判据） | 只验证不挖掘，≤5 包 |
| review-agent | rounds 卷 + lifecycle 变更 | 盲区清单 + 规则修订提案 | 只读档案，不发包 |

## 4. 生命周期与状态机（数据流）

```
新探针 phenomenon ──有业务影响证据──▶ candidate ──反事实校验+证伪4问──▶ verified
      │                                   │                              │
      └─无信号：Dead End（A硬墙/B物料门/C灰区）◀──驳回：rejected（留档防复发）

变更路径：只改 lifecycle.yaml（追加 history 一条）
  → python tools/findings-lint.py <t> --lifecycle --gen
  → 自动生成：findings-index / delivery-queue / evidence-queue / approval-queue / expiry-alerts
```

- **单真相源**：`lifecycle.yaml` 记录 finding 全部状态变迁；`output/lifecycle-views/` 为生成视图，禁止手改
- **lint 报错即违规**：candidate 无解锁计划 / verified 缺 PoC / money_ready 缺 missing → 立即修
- **防失忆写回**：每次进展实时追加 `output/rounds/<日期>.md` + `_STATE.md` 摘要行（compaction 后的唯一续接依据）

## 5. 4 阶段攻击流程

| 阶段 | 目标 | 必产出 | 工具 |
|---|---|---|---|
| 1 接单&开图 | 授权边界 + 资产清单 | scope.md / recon 清单 | recon-pipeline / space-recon |
| 2 攻击面识别 | 技术栈 + API 面 | surface.md / N-day 候选 | js-recon / nday-matcher / 11 项信息泄露探针 |
| 3 主动测试&验证 | candidate → verified | PoC 脚本 + 证据 | reflexes / skills / poc-<id>.py |
| 4 链式利用&报告 | 可投递交付 | report / delivery-queue | coverage-audit / findings-lint |

## 6. 关键设计决策（v6.0-slim）

1. **砍掉元维护自动化**：v5.x 的 board/status/graph/session-memory 等状态机全部移除 → 状态归 `_STATE.md` 文本，AI 自记（多目标 ≤3 active）
2. **findings 单真相源收敛**：findings.md 人工摘要 vs lifecycle.yaml 机器校验 → 状态以 lifecycle 为准
3. **playbook 子系统轻量化**：保留 `match.py`（指纹召回）+ `quickcheck.py`（最小验证），删除 audit/upgrade/lint 维护脚本，"是否继承"交还 LLM 判断
4. **法律硬拦前置**：PreToolUse hook 跑 `danger-guard.sh`（重武器黑名单），PostToolUse hook 提醒防失忆写回
5. **2 包定性 / 5 包定死**：接口级探测预算纪律，低产面标"待重试"轮次化换角度重试，不一次判死
6. **MCP 工具生态**：js-reverse（JS 逆向）/ jadx（APK 反编译）/ frida（动态注入）/ scrcpy+adb（设备控制）/ idapro（二进制）/ everything（全盘搜索），替代 curl/Burp/ffuf 的机械化操作

## 7. 覆盖审计闭环

`doctrine/coverage-audit.md` 提供 core-10（src 模式）与 88 项（pentest 模式）checklist：
收尾按 mode 逐条标注 ✓ / ✓★ / — / ✗ → ✗ 按优先级补测
（RCE/反序列化 > SSRF/文件读 > SSTI/命令注入 > SQLi > 认证绕过 > 逻辑类 > 前端类）→ 全部闭环才写报告。
