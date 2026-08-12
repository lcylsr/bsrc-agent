# 渗透副驾 Copilot Framework — 技术方案文档

> 版本：v6.0-slim（作品演示版）
> 日期：2026-08-12
> 说明：本方案描述框架的整体设计、模块划分、核心机制与工程实现。本包为脱敏演示版，真实目标/凭据/报告已全部移除。

---

## 1. 背景与目标

### 1.1 问题背景

传统渗透测试工具链（Burp / sqlmap / nuclei 等）存在三个结构性矛盾：

1. **工具多、编排难**：扫描器、抓包器、漏洞库、字典分散，攻击思路与工具操作割裂；
2. **思路依赖人**：经验型打法（认证状态机、反射准则、N-day 指纹）无法沉淀复用，每单从零开始；
3. **验证靠自觉**：现象（HTTP 200）与漏洞（已证明的影响）混淆，误报率高，交付质量参差。

### 1.2 方案定位

以 **LLM（国内大模型 DeepSeek / GLM / 文心 Comate，或 Claude Code 等 Agentic 宿主）为主驾驶** 的协作框架，解决"思路"与"工具"之间的编排鸿沟：

- AI 负责**决策**（下一步打什么、怎么打、何时停、什么能投递）；
- 脚本只做 AI 干不好的事：**法律硬拦、外部二进制调度、批量 IO**；
- 文档体系承载**纪律与经验**：铁律、反射准则、技能库、playbook 知识库。

### 1.3 设计目标

| 目标 | 手段 |
|---|---|
| 最小化框架复杂度 | 砍掉元维护自动化（board/status/graph 状态机），状态归文本，AI 自记 |
| 防自欺验证 | 无 PoC = 不报；现象≠漏洞；verified 须反事实校验 + 证伪 4 问 |
| 防失忆续接 | `_STATE.md` 7 段 + 当日 rounds 卷实时写回，compaction 后仍可续接 |
| 防越权失控 | scope.md 授权边界 + danger-guard 法律硬拦 + 重武器请示闸门 |
| 经验沉淀 | doctrine 反射准则 + skills 技能库 + playbook 指纹召回 + 复盘注入 |

---

## 2. 总体设计

### 2.1 分层架构

```
指挥层（LLM 主循环）←── framework.yaml（单真相源）
   │ 按需 Read
行动准则层 doctrine/    技能库层 skills/（命中才读，不开场全加载）
   │ 驱动                    │ 唤醒
执行层 多 Agent 协同（recon / pentest / app / client / verifier / review）
   │
工具层 tools/（run.sh 统一入口）＋ MCP 工具生态（js-reverse/jadx/frida/scrcpy/adb/idapro/everything）
   │
数据层 targets/<t>/（_STATE / lifecycle.yaml / scope / rounds / output）
```

### 2.2 模块清单

| 模块 | 构成 | 职责 |
|---|---|---|
| 指挥内核 | CLAUDE.md（铁律+流程）、QUICK.md（决策树）、framework.yaml（清单） | 会话启动加载、流程推进、状态写回 |
| 准则库 | doctrine/law.md、reflexes.md、coverage-audit.md | 法律红线、双层反射、收尾审计 |
| 技能库 | skills/ 约 30 个技能文件 | 按漏洞类/技术栈/场景组织的实操方法 |
| Agent 层 | .claude/agents/ ×7 自定义 agent | 并行挖掘、对抗证伪、日末复盘 |
| 工具层 | tools/ 约 20 个脚本 + lib | 测绘/JS/指纹/状态机/闸门/hook |
| 知识层 | tools/playbook（match.py + quickcheck.py） | 产品指纹 → playbook 召回 → 最小验证 |
| 工作区 | targets/_template/（scope/_STATE/lifecycle/timeline/...） | 单目标全生命周期文件 |

---

## 3. 核心机制设计

### 3.1 假设-验证-报告闭环（AI 主动推理）

```
观察（响应/JS/指纹/参数中的信号）
  → 假设（可证伪语句："若 id 参数未做鉴权，则替换 id 应返回他人订单"）
  → 最小测试（≤5 包，记录预期 vs 实际）
  → 生成 PoC（output/poc-<finding_id>.py，可重放）
  → 反事实校验 + 证伪（3 反事实 + 1 证伪）
  → 升级/降级（evidence 唯一 → verified；不足 → candidate；误报 → rejected）
```

### 3.2 验证纪律（防自欺三件套）

1. **无 PoC = 不报**：candidate 必须有可执行 PoC 脚本重放仍成立；
2. **现象 ≠ 漏洞**：`HTTP 200`/`success:true` 只是 phenomenon；verified 必须有真实业务影响证据（business_evidence）；
3. **反事实校验 4 问**：
   - 改 ID/参数会怎样？（IDOR/BOLA 反证）
   - 无认证会怎样？（未授权反证）
   - 假响应会怎样？（误报反证）
   - **证伪**：假设 finding 是假的，写出能推翻它的反例测试——反例推翻成立则保留 candidate，无法推翻才升 verified。

### 3.3 finding 生命周期状态机

```
phenomenon ──有业务影响证据──▶ candidate ──反事实+证伪通过──▶ verified
      │                            │                          │
      └─ 无信号 ──▶ Dead End       └──驳回──▶ rejected         └─ money_ready（可投递）
```

- 唯一真相源：`targets/<t>/lifecycle.yaml`（每次状态变更追加 history 一条）；
- 视图生成：`python tools/findings-lint.py <t> --lifecycle --gen` → lifecycle-views/（索引/投递队列/证据队列/审批队列/到期提醒），**禁止手改**；
- lint 违规项（candidate 无解锁计划 / verified 缺 PoC / money_ready 缺 missing）即报错，立即修。

### 3.4 多 Agent 协同与轮次状态机

```
广度批 ≤4 pentest-agent（正交分面）→ 强制写回产物
  → 深度批 Top N 各 1 agent（≤20 包/≤20 分钟）
  → verifier-agent 并行证伪（不阻塞）
  → 跨面组合分析（候选≥2 时）
  → review-agent 日末复盘（只读档案）→ 规则/playbook 增量注入下一轮
```

- 切换信号：同一面连续 3 轮无 ≥medium 新洞 → 切出（投递准备/补证据/框架改进）；
- 低产面不判死：标"待重试"（记录已试角度），每 3-5 轮循环一轮，每轮必换角度（参数/方法/域名/签名/越权维度）；
- 时间分配：广度 ≤30% / 深度 ≥70%。

### 3.5 防失忆写回机制

- 每次进展（新探针/新 finding/新死路/阶段切换）**实时追加** `output/rounds/<日期>.md` + 更新 `_STATE.md` 摘要行；
- `_STATE.md` 只存 7 段（元信息/时间线摘要/当前阶段·下一步/已verified/深挖焦点&假设链/死路/待决），禁止长叙事（>30KB 违规）；
- PostToolUse hook 检测漏写并提醒；compaction 后重读 `_STATE.md` 续接，永久死路勿重测。

### 3.6 法律红线机制

1. **不破坏**：无 `rm -rf` / DROP TABLE / 不可逆写入；
2. **不影响业务**：不修改真实业务数据，写操作只用无害 payload 且测完清理；
3. **不下载敏感数据**：不 dump 库 / 不批量拉 PII，越权仅 GET 读取；
4. **重武器先请示**：sqlmap / nuclei / 通用大字典 / RCE / 反序列化 / 上传 PoC → 记录 `_PENDING.md` 由用户拍板；
   - 定向扫描免请示：单 host + ≤200 entries + 仅 GET + 已知锚点；
5. **PreToolUse 硬拦**：`tools/danger-guard.sh` 在 Bash 调用前拦截黑名单命令。
6. **不确定算不算违法 → 算。先停，问用户。**

### 3.7 playbook 知识召回（工具/知识分层）

- `memory/playbooks/`（操作者私有，本包不含）：按攻击面分类的产品级漏洞 playbook（N-day 指纹 + 验证流程）；
- `tools/playbook/match.py`：读 scope.md 命中 playbook 指纹 → 输出候选；
- `tools/playbook/quickcheck.py`：对命中项最小验证（HIT_GREP / FIXED_GREP），三档判定；
- 命中 ≠ verified：N-day 类 playbook 是"入口识别 + 验证流程"，仍须 PoC 重放。

---

## 4. 工具层设计

### 4.1 统一入口 `tools/run.sh`

- 自动发现 `tools/*.py` 并提取首行注释作为描述（`--list` 列出）；
- 拒绝 Windows Store python stub；`PYTHONIOENCODING=utf-8`；
- v6.0-slim 定位：只做发现+转发，不做决策。

### 4.2 核心工具

| 工具 | 输入 | 输出 | 设计要点 |
|---|---|---|---|
| recon-pipeline.py | target_dir + 根域 | 子域/存活资产清单 | 外部二进制 + API 分页（AI 逐个慢） |
| js-recon.py | URL/文件 | JS URL 表 / API 面 / 硬编码密钥 | 批量 JS 提取 |
| nday-matcher.py | target_dir | N-day 指纹命中列表 | 命中≠verified，须验证 |
| findings-lint.py | target_dir | 校验报告 + 视图生成 | lifecycle 状态机唯一校验器 |
| agent-launch.py | agent 名 + target | agent prompt 注入 | 6 种自定义 agent 渲染 |
| scanner-dispatch.py | tool + url + tags | 受控扫描结果 | scope/rate-limit/GET-only 校验，--confirm 才放行 |
| danger-guard.sh | Bash 命令 | 拦截/放行 | PreToolUse hook，黑名单硬拦 |
| state-checkpoint-hook.sh | 写文件事件 | 防失忆提醒 | PostToolUse hook |
| mcp-health.sh | - | MCP 健康度报告 | 功能性自检 |

### 4.3 MCP 工具生态（可选增强）

js-reverse（JS 断点/堆栈/源码）、jadx（APK 反编译）、frida（动态 hook）、scrcpy/adb（设备控制）、idapro（二进制）、everything（全盘搜索）——覆盖 Web / 移动 / 桌面客户端 / 二进制全攻击面。

---

## 5. 数据设计

| 文件 | 职责 | 写入方 | 规则 |
|---|---|---|---|
| `scope.md` | 授权边界 + mode + 任务权重 | 人工（接单门禁） | 7 项必填齐全才动手 |
| `_STATE.md` | 工作状态续接 | AI | 7 段 ≤30KB，实时写回 |
| `lifecycle.yaml` | finding 状态真相源 | AI | 状态变更仅追加 history |
| `findings.md` | 人工可读摘要 | AI | 以 lifecycle 为准 |
| `timeline.md` | 时间线 | AI | 一行一条 |
| `output/rounds/<日>.md` | 轮次详情（叙事） | AI | 防失忆主载体 |
| `output/poc-<id>.py` | 可重放 PoC | AI | verified 必备 |
| `output/lifecycle-views/*.md` | 自动生成视图 | lint 脚本 | 禁止手改 |
| `_PENDING.md` | 重武器请示单 | AI | 法律闸门 |

---

## 6. 工程化与质量保障

1. **回归测试**：`tests/` 含 findings 解析 / lifecycle 校验的 fixture 回归（已脱敏）；
2. **框架结构校验**：`framework.yaml` 为结构唯一真相源，结构变更先改 yaml 再改 CLAUDE.md；
3. **覆盖审计**：收尾按 mode 跑 core-10（src）/ 88 项（pentest）checklist，✗ 按优先级补测闭环；
4. **复盘闭环**：误测/漏测 → reflections，中标打法 → playbook，证伪 → rejected（双层反思循环）；
5. **可移植性**：纯 Markdown + Python3 + Bash，零第三方运行时依赖（可选 MCP 增强）。

---

## 7. 部署与使用

### 7.1 环境要求

| 项 | 要求 |
|---|---|
| 宿主 | 国内大模型经 `driver/` 接入（DeepSeek / GLM / Comate），或 Claude Code 等 Agentic 宿主 |
| Python | 3.8+（工具层） |
| Bash | Git Bash / WSL / Linux / macOS |
| 可选 | FOFA/Hunter/Quake API Key、MCP 工具链、ADB/模拟器 |

### 7.2 接入步骤

1. 国内模型接入：复制 `driver/config.example.json` 为 `driver/config.json` 并填入 api_base/api_key/model（或环境变量），`python driver/copilot.py self-check` 自检；以 Claude Code 等 Agentic 宿主运行则直接放入项目根；
2. 按 `targets/_template/` 建目标工作区，填 `scope.md` 七项；
3. 会话开场由驱动层/宿主读取 `CLAUDE.md` 自动进入指挥模式；
4. 按 4 阶段流程推进，收尾过覆盖审计 + lint 后交付。

### 7.3 边界与限制（诚实声明）

- 框架不替代人工授权与合规评审：任何测试须以正式授权为前提，L1 红线不可配置化绕过；
- 工具层不内置扫描器本身，重武器需操作者自备并走请示闸门；
- 知识库（memory/playbooks）属操作者私有沉淀，本演示包不含；
- 真实效果取决于宿主 LLM 的推理与纪律执行，框架的作用是把纪律与经验固化为可复用的操作协议。

---

## 8. 交付物清单

| 交付物 | 路径 |
|---|---|
| 框架源码（脱敏版） | 本包根目录 |
| 架构说明 | docs/ARCHITECTURE.md |
| 技术方案文档 | docs/TECHNICAL-SOLUTION.md（本文档） |
| 使用说明 | README.md |
| 压缩包 | src-copilot-framework-v6.0-slim-demo.zip |
