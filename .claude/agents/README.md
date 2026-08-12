# Agent 定义

`.claude/agents/` 下的 `.md` 文件为模型无关的 Custom Agent 定义（需有 YAML frontmatter 声明 `name` / `description` / `tools`）：可由 Claude Code 等 Agentic 宿主直接识别，也可由本项目 `driver/` 通过 `tools/agent-launch.py` 渲染成纯文本 prompt 喂给国内大模型（DeepSeek / GLM / 文心等）。

## Agent 列表

| Agent | 用途 | 触发条件 | tools |
|---|---|---|---|
| `recon-agent` | 信息收集 / OSINT 流水线 | scope > 10 子域 / > 1 业务线 / 大厂 SRC | Bash, Read, Write, Edit, Glob, Grep, WebFetch + js-reverse-mcp |
| `pentest-agent` | 单子域漏洞挖掘 | recon-agent 输出 Top N 高 ROI 子域后，Commander 对每个子域 spawn 一个（并行 ≤4） | Bash, Read, Write, Edit, Glob, Grep, WebFetch + js-reverse-mcp / scrcpy-mcp / jadx-mcp |
| `app-agent` | 移动应用渗透（APK/IPA/小程序）：静态全自动 + 动态按需 + API 回归 | scope 含客户端资产（APP 测试），见 `skills/mobile/app-auto-test.md` | Bash, Read, Write, Edit, Glob, Grep, WebFetch, jadx/frida/scrcpy MCP |
| `client-agent` | 桌面客户端安全研究（Electron/CEF/Win32/.NET）；支持标准模式与深审模式 | 目标提供桌面客户端安装包；深审模式需用户授权运行/修改/Frida | Bash, Read, Write, Edit, Glob, Grep, WebFetch + jadx/frida/scrcpy MCP |
| `verifier-agent` | candidate 对抗证伪（独立视角）+ 投递报告复核 | ① pentest-agent 产出 candidate 后并行证伪；② 投递报告产出后必复核。只验证不挖掘，≤5 包，结论写 `<target>/output/delivery-reports/<ID>-verify-<日期>.md` | full-tools（纪律约束见契约） |
| `review-agent` | 反思复盘（盲区 + 规则修订提案） | 挖掘日末 / 周期深复盘；只读 rounds 卷 + lifecycle 变更 + DE 记录 + verdicts，不发包 | full-tools（纪律约束见契约） |

## 调用方式

```
Agent(
  subagent_type="pentest-agent",
  description="pentest: api.example.com",
  prompt="""
  任务上下文: target_dir=targets/example/recon / 子域=api.example.com
  start。
  """
)
```

- `subagent_type` 直接用 agent 的 frontmatter `name`，不需要 `"Explore"` 或 `"general-purpose"` 包装
- Commander 在 prompt 中注入任务上下文（target_dir / 子域 / banner 等），agent 启动后按自身工作流执行

## 约束

- 所有 agent 均为**叶子节点**，不嵌套 spawn 子 agent
- 写入权限由各 agent 文件中"写入权限"段强约束，违反 = 失控
- stop conditions 由各 agent 文件硬编码（包数 / 时间 / 命中 / 死局）
