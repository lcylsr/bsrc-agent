# QUICK 速查卡 v6.0-slim

> 决策树 / 反射准则 fallback。被 [`CLAUDE.md`](CLAUDE.md) 速查卡指向，挖洞拐点主动 Read。
> 中间层不靠记忆，关键规则反复出现。
>
> **顺序设计**：头部硬约束 → **反射准则(双层 → 详见 `doctrine/reflexes.md`)** → 主奖品 → 决策树(fallback)→ 拐点 skills → 工程触发 → 法律红线。

---

## 心法

**SRC挖洞思维链路（7环）**：
资产展开 → 目标筛选 → 切入点发现 → 深挖扩展 → 验证确证 → 链式放大 → 复盘沉淀
详见 `skills/src-hunting-methodology.md`（给思路不局限方法）

**状态实时写回**(防失忆)：
- 产出的 verified/Dead End → 立即写回 `lifecycle.yaml`（追加 history）/ `_STATE.md`（摘要行），不等汇总
- **compaction 恢复后禁止**：重新验证 Dead Ends 中标"永久死"的路径 / 重新确认 auth_status=EXPIRED 的凭据
- **探测落盘**：响应体进 `E:/claude-artifacts/tmp/<key>/`，禁止 `targets/<t>/probes` 堆 body；证据手动 `cp` 到 `E:/claude-artifacts/<target>/`

(写回事件通用规则详见 `CLAUDE.md` 全局铁律：TEMP/写回/并行/无PoC/现象≠漏洞/money_ready 须重放)

**语义对齐**：
- "继续分析 / 深挖" = 当前焦点深度优先，不是广扫全部端口
- "修框架 / 优化" = 见 `memory/insights/` 最新框架优化记录

---

## 启动细节补充

1. WebSearch 3 次封顶：`<产品名> CVE` / `默认密码` / `site:github.com`
2. **资产测绘优先(≥5 根域 / 大厂 SRC)**：先跑 `bash tools/run.sh space-recon <target_dir> <domain>` / `bash tools/run.sh recon-pipeline <target_dir> <domain>`
3. 0 verified 目标：按 4 阶段流程（`skills/orchestrator.md`）从 recon 推进
4. **多目标并行**：同时 active ≤3，AI 自记（每个 target 独立 `_STATE.md`）；子域 >10 时 spawn recon-agent。
5. **mode 决定 TODO 语言**：`src` → soft_fail 补 poc/impact/交单；`redteam` → 入口最小重放/下一跳/Kill Chain(不逼 core-10)。
6. **V=0 确定性优先**：recon → nday-matcher → playbook 命中后验证；有强信号再 spawn。命中后验证 playbook，**不**重跑 matcher。

(会话启动 SOP 详见 `CLAUDE.md` §0 会话启动)

## Light 任务细节

触发条件：`scope.md` 顶部 `task_weight: light`(复测/单点 PoC/≤30 包/无需 kill-chain)。

- **不 spawn agent**（CLAUDE.md §5）——AI 现场 write PoC 脚本验证已知漏洞；如需新发现由 Commander 自行深挖。
- Light 只缩短流程，不降 verified 标准。

## 不报清单(一句版，无例外)

**无 PoC = 不报。** 没有任何"除非...则可以"。

形式合规 ≠ 实质有洞。沉没成本是赌徒逻辑。

**详细垃圾洞清单**(报告前必过)→ [`memory/insights/playbook-trash-finding-checklist-before-report.md`](memory/insights/playbook-trash-finding-checklist-before-report.md)；`findings-lint` 会按 trash 关键词硬拦 verified。

具体绝不报：

- CORS 配置 **除非** 同域存在返回敏感数据的 API 且 Origin+Credentials 可被跨源利用（否则 2 包内标 phenomenon 不报）
- HTTP 安全头缺失 / 版本号暴露
- Self-XSS / Sourcemap 泄露(仅路径未拿数据)
- SSL/TLS 常规警告 / Rate limiting 缺失
- 无法链式利用的开放重定向
- 任何没有可执行 PoC 的"发现"

---

## 反射准则(★ 优先于决策树查这个)

详见 [`doctrine/reflexes.md`](doctrine/reflexes.md) — 参数级 + 系统指纹级双层覆盖；看到 `url/path/file/redirect/callback/proxy` 等参数先怼 SSRF/任意文件读，看到系统指纹(\.NET Kestrel/Spring Boot/Consul 等)走完对应必做清单。

---

## SRC 主奖品分布(高 → 低)

```
RCE / 任意文件读 / SSRF / 上传 ≫ SQLi / IDOR ≫ 撞库降级 / 弱随机数 ≫ 信息泄露 / 配置类
```

**单包成本对照**：翻 skills 30 秒；5 个 SSRF payload 怼一个参数 5 秒。比研究密码学算法 30 分钟便宜 360 倍。

---

## 高 ROI 通用打法(参数级反射不命中时)

- 替换 ID 至少测 3-5 个
- A 接口响应字段 → 喂 B 接口(跨接口参数移植)
- 排序参数(`sort` / `orderBy` / `desc`)是被低估的注入点
- 任何带 `_id` / `_no` / `_order` 的参数，先抓自己 → 改邻居 → 看回包是否换数据
- 拿到 1 个鉴权前接口 → 同前缀 API 枚举(`skills/api-logic/api-guessing.md`)
- 同主机有"鉴权完整"的兄弟服务 → 当架构对照，找漏配的弟弟服务

---

## 决策树(目标特征 → 主攻击面，fallback)

> **何时看**：反射准则(参数级 + 系统指纹级)都没命中 / 还在踩点阶段 / 不知道往哪打。
> **不要顺着读这棵树** — 反射准则比它颗粒度更细、ROI 更高。

```
有登录功能    → IDOR 越权
API 服务      → 未授权访问
文件上传      → 上传绕过
搜索 / 输入框 → 注入类
GraphQL       → 内省 + 未授权 mutation
Java 中间件   → 反序列化 / JNDI
PHP           → 文件包含 / SQL 注入
支付功能      → 竞态 / 金额篡改
什么都没有    → 翻 JS 找隐藏接口
```

## skill 速查（决策树命中后看对应 skill 的方法）

| 目标特征 | skill |
|---|---|
| 接口薄/隐藏面/参数不明/信号判读 | `skills/api-logic/fuzz.md` |
| 有测试账号/认证后深挖 | `skills/api-logic/authed-deep-dive.md`（IDOR/越权/Mass Assignment/签名绕过） |
| JS深度分析(隐藏API/密钥/签名/源码) | `skills/js-reverse/js-deep-analysis.md`（6维度:文件发现/API/baseURL/密钥/签名/sourcemap） |
| SSTI/命令注入/XXE | `skills/injection/ssti-cmdi-xxe.md`（三类注入合一个skill） |
| 云安全(S3/IAM/K8s/容器) | `skills/cloud-security.md`（云存储+签名URL/类型混淆/桶接管/元数据/K8s） |
| 文件上传 | `skills/api-logic/file-upload.md` |
| 支付/权限/状态机 | `skills/api-logic/business-logic.md` |
| Java 反序列化/RCE | `skills/injection/deserialization-rce.md` |
| 缓存投毒 | `skills/injection/cache-poisoning.md` |
| 子域 CNAME 可疑 | `skills/api-logic/subdomain-takeover.md` |
| HTTP 请求走私 | `skills/api-logic/request-smuggling.md` |
| WAF 拦截 | `skills/fingerprint/waf-evasion.md` |
| APP 测试(APK/IPA/小程序) | `skills/mobile/app-auto-test.md`（静态全自动+动态半自动+API回归） |
| 拿到 ≥1 verified 想扩战果 | `skills/chain-playbook.md` |

---

## 拐点必查(死磕前先翻，反"无脑 curl"懒惯性)

死磕 30 分钟无果时，**先查这 5 张牌再问用户**：

- **参数名带 `url/path/file/redirect/callback/target/image/proxy`** → `doctrine/reflexes.md` 第一层参数级反射 ★★★
- **业务功能路径**(`/addon/* /service/* /tool/* /file/* /upload/*`)→ **定向扫描**(law.md §4.2 已放行，字典 ≤ 200 entries 免请示)
- **401/403/404** → [`doctrine/reflexes.md`](doctrine/reflexes.md) 认证绕过 8 大头
- **加密/签名阻断** → [`skills/js-reverse/crypto-sign.md`](skills/js-reverse/crypto-sign.md)(MCP 工具断点逆向)
- **是否在重蹈覆辙** → `grep -ri "<指纹/产品>" memory/reflections/`（误测/漏测学费反查，防同类认知错误再现）

---

## 业务逻辑 / Auth 状态机(深挖，反轮次堆包)

- **有登录/注册/重置/邀请/MFA/IdP** → 必跑 [`memory/playbooks/playbook-auth-state-machine-resolve-style.md`](memory/playbooks/playbook-auth-state-machine-resolve-style.md)(≤30 包 checklist；Feature 关仍打 POST)
- **Dead End** → [`memory/insights/dead-end-taxonomy.md`](memory/insights/dead-end-taxonomy.md)：class **A 硬墙 / B 物料门 / C 灰区** + `auth_context` + `reopen_if`；A 勿重测，B 等物料只打该面

---

## 工具速查(AI 自主调用，不等人提醒)

> 完整命令表见 `CLAUDE.md` §7 工具速查。此处只留 QUICK 独有 / 非 CLI 工具：

| 场景 | 命令/工具 | 成本 |
|---|---|---|
| **会话启动** | 读 `targets/<t>/_STATE.md` 续接 | 0s |
| **进场前** | `bash tools/mcp-health.sh <target>` | 3s |
| **playbook 命中** | `bash tools/playbook/run.sh <target>` | 1s |
| **文件搜索**(本地) | everything-mcp search(healthy) / `rg -n` / `grep -Rln`(degraded) | <1s / 5-30s |
| **浏览器操作**(网页/微信) | js-reverse-mcp (new_page / screenshot) | 秒级 |
| **Android 操作** | scrcpy-mcp (tap / screenshot / ui_dump) | 秒级 |

**铁律**：读 `_STATE.md` 的"下一步"是直接指令 — **照做，不问用户**。

---

## 何时停手

- 同一攻击面 30 分钟死磕 → `_STATE.md` "待决问题" 留档，问用户继续还是切
- 拿不到 PoC 实证 → 标 `phenomenon` 留档，**不删**(凑链时回头用)
- 整单跑完无可投 → `_STATE.md` 标"未中标"，**不**硬出垃圾报告

---

## 工程触发(自动，不靠你)

- **20min 无进展换方向 / 长会话及时总结** = 认知纪律自己守
- 写 `findings.md` → 用 `tools/findings-lint.py` 校验格式（verified 字段完整）
- 写 `output/*.md` → AI 自审 9 项（PoC / 业务结果 / 可付费视角 / 客户文档同步）
- 命中 `rm -rf` 危险根 / `DROP TABLE` / fork bomb / `mkfs` / `dd` 裸盘 → PreToolUse L1 `tools/danger-guard.sh` exit 2 拦
- 命中改密/HTTP DELETE/资金提交/SQL 写/PUT·PATCH → PreToolUse L2 `business_impact.py` 按 **method×path×body 语义** 拦。授权：`SRCOOP_DANGER_ALLOW=1` + timeline。见 `doctrine/law.md` §2.1

---

## 法律红线

→ 详见 `CLAUDE.md` 法律红线 4 条 + `doctrine/law.md` 全文。
