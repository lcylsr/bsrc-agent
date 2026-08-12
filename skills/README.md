# skills/ — 战术手册(领域分)

> 主流程见 `skills/orchestrator.md`。
> AI 在分析阶段按攻击面查阅本目录,获取具体打法 + payload + 工具链。

## 子目录(按攻击面)

| 文件/目录 | 触发场景 | 何时查 |
|---|---|---|
| `orchestrator.md` | 主编排器 + 主流程 | 每次新会话开始 |
| `js-reverse/` | 前端逆向(路由提取 / 加密签名) | 看到 Vue/React/Webpack,有混淆 / 加密参数 |
| `api-logic/` | 接口逻辑(IDOR / 认证绕过 / SSRF / 任意文件 / 枚举) | 看到 401/403/ID 参数/url 参数/路径遍历 |
| `injection/` | 注入类(SQL / NoSQL / GraphQL) | 看到查询参数/JSON 查询/GraphQL 端点 |
| `fingerprint/` | 产品/框架/WAF 识别 | 看到非通用 banner/自研加密/WAF 拦截 |
| `mobile/` | 小程序 / Android / iOS / 桌面客户端 | scope 含移动端或拿到 APK/wxapkg |
| `cn-specific/` | 国产 OA/ERP/国密/二开框架/政务 SSO | 看到若依/Jeecg/ThinkPHP/蓝凌/致远/用友/金蝶/政务网关 |

> 经 v6.0-slim 技能蒸馏后,未再被 active docs 引用的通识 skill 已移至 `attic/`,被引用的核心 skill 仍保留在 active skills。

## 维护原则

1. **领域优先,不按生命周期分** —— AI 实战时问的是"现在打什么",不是"现在做哪步"
2. **收什么进 skills**:
   - ✅ 具体工具链 + 工具名(`turbo intruder` / `shuji` / `findsrc`)
   - ✅ 非教科书的实战 trick(JS 列表页明文返回所有 UUID 只是 UI 隐藏)
   - ✅ 触发场景 → 3 个最常用 payload → 典型驳回原因
   - ❌ 漏洞分类大全 / HTTP 状态码 / OWASP Top 10 这种 AI 自己能背的
3. **每个文件前 30 行**必须能让 AI 决定"这场景适不适合这文件"
4. **关联 memory**:打法成功后回链 `memory/playbooks/`,踩坑回链 `memory/rejected/`
5. **新增触发**:同一打法 ≥3 次出现 → 抽到对应领域目录新文件

## 武器组合原则(CLAUDE.md 重申)

`curl` + `MCP` + `skills` 三件套并用。看到混淆 / 加密 / APK 必须先开 MCP,**禁止幻觉硬猜**。
