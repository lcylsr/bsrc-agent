# 渗透副驾 Copilot Framework v6.0-slim — BSRC "Agent+" 挑战赛作品

> AI 主驾驶渗透测试协作框架：**AI 在驾驶座**，以国内大模型为推理引擎，以"假设-验证-报告"闭环驱动
> SRC 定向漏洞挖掘全流程（接单开图 → 攻击面 → 主动测试 → 验证 → 报告）。
> 本包为作品演示版，已全面脱敏：真实目标、凭据、报告、个人记忆全部剔除，品牌名/内网 IP 替换为占位符。
> **参赛文档**：[docs/competition-submission.md](docs/competition-submission.md)（≤5000 字技术方案）
> **演示案例**：[examples/demo-acme/](examples/demo-acme/)（脱敏虚构漏洞实践案例，含 3 条可重放 PoC）

---

## 一、一句话介绍

一个以 LLM（DeepSeek / GLM / 文心 Comate 等**国内大模型**，或 Claude Code 等 Agentic 宿主）为主驾驶、
脚本与多 Agent 为副驾的**半自动化渗透测试协作框架**。全程按"假设-验证-报告"闭环驱动，
配套防自欺的验证纪律：**无 PoC 不报、现象≠漏洞、verified 须反事实校验+证伪**。
Claude Code 仅是开发与演示宿主之一，参赛运行时由自研 `driver/` 层驱动国内模型，不依赖海外模型。

## 二、比赛材料清单

| 材料 | 位置 | 说明 |
|---|---|---|
| ① 团队介绍 | `docs/submission-materials/team.md`（模板） | ≤3 人 + 分工 |
| ② 作品 Demo | 本仓库 + `examples/demo-acme/` | 含脱敏漏洞实践案例（3 verified + 可重放 PoC） |
| ③ 技术方案文档 | `docs/competition-submission.md` | 技术架构 / 核心方法 / 实验结果 / 创新点（≤5000 字） |
| ④ 演示视频 | `docs/submission-materials/video-script.md`（脚本模板） | MP4 ≤5min，加分项 |
| ⑤ 源码仓库 | 本仓库（README + 运行环境与部署方式见下） | 加分项 |

## 三、目录结构

```
├── README.md               # 本文件（作品介绍 + 部署方式）
├── CLAUDE.md               # 框架顶层入口：铁律 / 4 阶段流程 / 工具速查
├── QUICK.md                # 决策树速查：看到什么 → 立刻做什么
├── framework.yaml          # 框架唯一真实来源：docs / skills / tools 清单
├── driver/                 # ★ 国内大模型适配层（OpenAI 兼容 API，零依赖）
│   ├── copilot.py          #   主驱动：双协议（function calling + ReAct）、黑名单、写白名单、编排
│   ├── config.example.json #   模型接入配置（DeepSeek / GLM / Comate）
│   └── README.md           #   模型矩阵 + 安全边界
├── examples/demo-acme/     # ★ 脱敏漏洞实践案例（虚构目标，3 条 verified 全闭环）
├── doctrine/               # 行动准则层（law / reflexes / coverage-audit / benchmark-mode）
├── skills/                 # 技能库层（漏洞类 × 技术栈 × 场景，按需读取）
│   ├── binary/             #   f1/f2 内存安全 & 逆向 playbook（pwntools/gdb/z3）
│   └── cloud/              #   云攻击速查（IMDS/Azure SAS/对象存储，跑分 d 系）
├── tools/                  # 工具层（AI 驱动，run.sh 统一入口）
│   ├── run.sh              #   CLI 入口：工具发现 + 参数转发
│   ├── findings-lint.py    #   lifecycle 状态机校验 + 视图生成
│   ├── agent-launch.py     #   子代理 prompt 渲染器（6 种 agent，可渲染为纯文本喂给国内模型）
│   ├── scanner-dispatch.py #   外部重武器受控调度
│   ├── benchmark-api.py    #   TSecBench 跑分平台 API 客户端（list/start/hint/submit/close）
│   ├── benchmark-watch.py  #   跑分实时监控终端（轮询 API + tail 日志）
│   ├── channel-template.py #   RCE 通道模块生成器（webshell/ssh/cmd-inject 等 5 型）
│   └── danger-guard.sh     #   PreToolUse 法律硬拦 hook
├── targets/benchmark/      # ★ 跑分实战配置（TSecBench：NOTES/STATE/scripts 四件套 + 托管镜像 agent/）
├── .claude/agents/         # 多 Agent 协同层（6 种 agent 定义，模型无关）
├── mcp/                    # MCP 工具生态文档
├── targets/_template/      # 目标工作区模板
├── tests/                  # 回归测试 + fixtures（已脱敏）
└── wordlists/              # 字典（路径 / 参数 / SSRF payload / WAF 签名）
```

## 四、运行环境与部署方式

**硬件**：8 核 16G（比赛托管环境达标）；无 GPU 需求；磁盘 <200MB。
**依赖**：Python 3.10+ 与 Bash（Windows 用 Git Bash），**零第三方库**（driver 层仅标准库）。

```bash
# 1. 克隆与自检
git clone <本仓库> && cd claude-demo
python driver/copilot.py self-check          # 自检：协议解析 / 黑名单 / 写白名单 / 命令执行

# 2. 接入国内大模型（三选一）
cp driver/config.example.json driver/config.json   # 填入 api_base / api_key / model
#   DeepSeek:  https://api.deepseek.com/v1        （deepseek-chat）
#   GLM:       https://open.bigmodel.cn/api/paas/v4 （glm-4-flash 等）
#   文心 Comate: 以赛事说明为准
#   也支持环境变量 COPILOT_API_BASE / COPILOT_API_KEY / COPILOT_MODEL

# 3. 离线演示（不发真实包）
python driver/copilot.py demo                # 回放演示对话
python examples/demo-acme/output/poc-acme-001.py --demo   # 重放 SSRF 验证（exit 0 = VERIFIED）

# 4. 接入真实目标（需授权）
mkdir -p targets/<甲方>/<目标>
cp targets/_template/_STATE.md targets/_template/scope.md targets/<甲方>/<目标>/
python driver/copilot.py commander targets/<甲方>/<目标>   # 或由 Claude Code 等宿主直接驱动
```

**运行指标**：完整小型目标约 1~2 万 token（DeepSeek 约 ¥0.1）、内存 <500MB、PoC 全离线可重放。
**测试**：`pytest`（`pytest.ini` / `requirements-dev.txt`，仅回归测试需要）。

## 四·补充、跑分模式（TSecBench / BSRC Agent+）

同一框架的竞速形态（`mode: benchmark`，纪律见 `doctrine/benchmark-mode.md`）：

```bash
# 本地实时监控（跑分时开一个终端挂着）
bash tools/run.sh benchmark-watch                # 15s 刷新：每题 flag 数/得分/容器状态
bash tools/run.sh benchmark-watch --interval 5   # 5s 一刷（--once 单次快照 / --no-clear 增量）

# 托管镜像（上传平台后容器内自动解题）
cd targets/benchmark/agent && bash build.sh      # 构建 agent.tar.gz 上传
#   镜像内自动：ROI 队列 → 快路径端点 → 跨题 KB → 并发 3 靶场 → 多 flag 循环 → PARTIAL sweep
#   日志双写 /app/workspace/run.log（可下载查看）

# 本地直接驱动平台 API
bash tools/run.sh benchmark-api list             # 题目清单 + 作答进度
bash tools/run.sh benchmark-api start <code>     # 启动靶场（并发 ≤3）
```

跑分模式三大机制（首轮 2250 分 → 对标榜单第一 22340 分机制拆解后的 v3.1 改进）：
1. **得分率优先**：换类不换题（无进展触发换攻击面重试）、部分得分题第二轮 sweep 拿全剩余 flag
2. **跨题经验库**：KB.md（中标打法）/ DEAD.md（死路）注入 LLM，兄弟题复用
3. **快路径 + 实时可见**：16 个低开销端点命中即交；watch 终端实时监控每题进度

## 五、脱敏声明（重要）

作品打包已执行以下处理，**包内不包含任何真实敏感信息**：

| 内容 | 处理 |
|---|---|
| `targets/`（真实客户目标数据 27MB+） | ✂ 仅保留 `_template/` 模板 |
| `memory/`（个人记忆 / 反思 / 复盘） | ✂ 整体剔除（操作者私有，演示不含） |
| `output/`（真实交付报告） | ✂ 剔除，仅留演示案例 |
| `.env` / `tools/keys.env`（真实 API Key / Cookie） | ✂ 剔除，仅留 `keys.env.example` |
| `.mcp.json` / `.claude/settings*.json`（本机路径） | ✂ 剔除 |
| 真实品牌名 | ✂ 替换为占位符（acme / demo-acme） |
| 真实 IP | ✂ 替换为 RFC 5737 文档网段（10.0.0.x / 198.51.100.x） |
| 探测响应体、临时文件、git 历史 | ✂ 剔除 |

## 六、核心设计理念

1. **AI 在驾驶座**：模型做推理主驾驶，框架用状态机/预算/纪律约束它不乱来
2. **无 PoC = 不报**：HTTP 200 / success:true 只是现象；verified 必须有可重放 PoC + 真实业务影响证据
3. **证伪优先**：candidate 升 verified 前必须过反事实校验（3 反事实 + 1 证伪）
4. **广度 ≤30% / 深度 ≥70%**：批量探测只用于选目标，选完立即切深度模式
5. **法律红线不可妥协**：重武器先请示、不破坏、不影响业务、不下载敏感数据
6. **模型无关**：Claude Code 只是宿主之一；参赛运行走 `driver/` 驱动国内模型，双协议降级保证行为一致

详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[docs/TECHNICAL-SOLUTION.md](docs/TECHNICAL-SOLUTION.md)、
[docs/competition-submission.md](docs/competition-submission.md)。
