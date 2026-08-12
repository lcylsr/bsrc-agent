# driver/ — 国内大模型 Agent 驱动层

> 解决一个硬约束：**"Agent+" 攻防挑战赛仅限使用国内大模型（GLM / DeepSeek 等），暂不支持 Claude、GPT 等海外模型**。
> 本层让框架脱离特定 Agentic 宿主，改由**任意 OpenAI 兼容 chat/completions API**（DeepSeek / GLM / 文心 Comate 等）驱动，保持框架的纪律文档体系与工具层完全复用。

## 一、为什么需要它

框架的指挥层（CLAUDE.md 铁律 / QUICK.md 决策树 / skills 技能库）本来就是**模型无关的 Markdown**，但之前只演示了 Claude Code 这一种宿主。比赛环境要求国内模型，因此补上本层：

- **零第三方依赖**：仅 Python3 标准库（urllib / subprocess / concurrent.futures），适配 8 核 16G 托管平台
- **双协议动作解析**：OpenAI function calling（原生优先）+ ReAct 代码块 fallback（兼容无 tools 参数的模型端点）
- **安全硬拦自动生效**：危险命令黑名单 + 写入白名单（镜像 `tools/danger-guard.sh` 语义）——靶场无人值守时法律红线不靠自觉
- **预算纪律**：max_steps / 单命令超时 / 并行 ≤4（8 核 16G 资源适配）
- **防失忆写回**：每轮自动追加 `output/rounds/<日期>.md` + 更新 `_STATE.md` 时间戳

## 二、快速开始

```bash
# 0. 配置（三选一）
cp driver/config.example.json driver/config.json   # 填入 api_base / api_key / model
# 或环境变量：COPILOT_API_BASE / COPILOT_API_KEY / COPILOT_MODEL

# 1. 离线自检（无 API 也可跑，验证协议/黑名单/白名单）
python driver/copilot.py self-check

# 2. 离线演示回合（不调 API，展示循环机制）
python driver/copilot.py demo examples/demo-acme

# 3. Commander 主循环（接入 API 后实跑）
python driver/copilot.py commander targets/<甲方>/<目标> --config driver/config.json

# 4. 单 agent 循环（prompt 由 tools/agent-launch.py 渲染，角色定义在 .claude/agents/）
python driver/copilot.py agent pentest-agent targets/xxx --subdomain api.xxx.com --config driver/config.json

# 5. 多 agent 并行编排（广度批，默认 ≤4 并发）
python driver/copilot.py orchestrate targets/xxx --subdomains api1.xxx.com api2.xxx.com --config driver/config.json
```

## 三、模型矩阵（比赛环境内）

| 模型 | api_base | model 建议 | 备注 |
|---|---|---|---|
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` / `deepseek-reasoner` | 官方直连，OpenAI 兼容 |
| GLM（智谱） | `https://open.bigmodel.cn/api/paas/v4` | `glm-4.5` / `glm-4-flash` | OpenAI 兼容 |
| 文心 Comate | 以赛事发放的 Comate API 说明为准 | 以 Comate 文档为准 | 比赛 Token 福利指定渠道 |

> 未配置 api_base 时按 key 前缀自动猜测端点（`sk-` → DeepSeek；`glm`/`zh` → 智谱）。

## 四、安全边界（与 doctrine/law.md 对齐）

- **黑名单硬拦**：`rm -rf` / `mkfs` / `DROP TABLE` / `sqlmap` / `nuclei` / `hydra` / 大字典暴力等——模型无法通过本层执行，即使它想
- **写入白名单**：仅 `targets/` / `examples/` / `driver/` / `output/` / `tests/`，系统文件不可写
- **授权边界**：`scope.md` 是唯一授权来源，模型越界意图被明确要求 stop 并 finish 请示
- **重武器**：比赛环境无人值守 → 一律拦截；确需使用由操作者离线跑完后把结果喂回

## 五、为什么这算"原创代码"

框架的文档纪律体系（假设-验证闭环 / 证伪 4 问 / 2 包定性 / 轮次状态机）是多年实战沉淀，而本层把「纪律文档 + 工具层 + 多角色 Agent」在**零依赖、国内模型、受限资源**条件下粘合成可自主运行的 Agent——安全硬拦、双协议容错、预算与写回机制均为本项目自研实现。
