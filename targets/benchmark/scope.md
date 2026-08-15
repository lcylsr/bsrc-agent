---
mode: pentest
task_weight: standard
---
# 授权范围(Scope)

> **L1 红线边界。范围外资产严禁动手。**
>
> ⚠️ **接单门禁**:本文件 7 项必填全填齐之前(下面 ✅ 标记),**不动手**。任一 `_TBD_` / 空白 → stop-the-line,先问用户。

---

## 任务分级

```yaml
mode: pentest                  # pentest | src | redteam
# pentest: 完整渗透测试,报告前必须过 coverage-audit 88 项
# src:     赏金/众测,重视可投递性与影响面,过 findings-lint + core-10
# redteam: 攻防演练/打点,优先 RCE / 凭据 / 隧道入口

task_weight: standard          # light | standard | heavy
# light: 单点 PoC / 已知洞复测 / ≤ 30 包预算 / 见 CLAUDE.md §Light 任务 SOP
# standard: 默认,投递闸门全跑
# heavy: 多攻击面 / 工期 ≥ 1 天 / 主动 OSINT
# 包数预算(AI 自律,无脚本强制):light=30 / standard=100 / heavy=不限,超预算时主动升级 task_weight 并说明
# token 预算由 AI 自律(长会话及时总结,无脚本计数)
```

```yaml
# 客户文档同步路径(可选,2026-06-18 internal-10.0.0.1 教训新增)
# 如客户提供了模板 docx 或要求最终交付到指定 docx,在此声明绝对路径。
# AI 自审:报告交付前确认 docx 时间戳 ≥ output/report-*.md,否则客户拿到过期版本。
# 示例: customer_docx: "D:\\桌面\\工作\\...\\智能水电10.0.0.1-v2.docx"
customer_docx:            # 留空则跳过同步检查
```

```yaml
# playbook 召回(2026-06-19 加,struts-139 教训:召回 ≠ 复用)
# nday-matcher 命中后,AI 对照 memory/playbooks/ 对应文件验证。
# 命中≠verified — 必须按 playbook 步骤验证后才能升级 finding。
# 详见 memory/insights/reflection-loop-design.md + memory/reflections/playbook-reverification-trap.md
playbooks_match: []       # 留空 = 未命中;AI 填入命中的 playbook 文件名列表
```

| 维度 | light | standard | heavy |
|---|---|---|---|
| 7 项必填 | 简化为 4 项(1/3/5/6,保法律命根子) | 全 7 项 | 全 7 项 + intel.md 完整 |
| 反查 memory + CVE | ✅ 必跑(零成本下限) | ✅ | ✅ |
| 攻击面覆盖 | 单点(仅目标接口) | 全流程 4 阶段 | 全流程 + 主动 OSINT |
| 自由探索 | 10 分钟 | 30 分钟 | 60 分钟 |
| 投递闸门(lifecycle 校验) | 跳 | 跑 | 跑 + 灰度扩展 |
| 复盘(见 orchestrator.md 核心复盘问题) | 简版(每问 1 行) | 标准 | 标准 + lesson 文件 |
| 包数预算 | 30 (超 → 自动升档) | 100 | 不限 |

---

## 接单门禁清单(任一 ❌ → 不开测)

> light 任务压成 4 项必填(保法律命根子);standard/heavy 全 7 项。
> **无论 weight,第 5/6/7 三项法律红线绝不省**。

### light 任务 4 项必填

- [ ] 1. SRC 平台名 + URL 齐全
- [ ] 3. 范围白名单具体到字符串(域名 / 端口 / 子域)
- [ ] 5. 漏洞接受清单(Struts2 RCE / 反序列化 / 文件上传必须明确)— **法律红线,不能省**
- [ ] 6. 测试钳制(RPS 上限 / 禁用工具 / 写操作)+ 7. 撞账号红线 — **法律红线,不能省**

### standard / heavy 全 7 项

- [ ] 1. SRC 平台名 + URL 齐全
- [ ] 2. 厂商 / 资产关系核实(目标域名归属公司至少 1 条 OSINT 命中)
- [ ] 3. 范围白名单具体到字符串(域名 / 端口 / 子域)
- [ ] 4. 范围黑名单显式列出(邻居资产 / 同 IP 其他端口 / 其他客户实例)
- [ ] 5. 漏洞接受清单(Struts2 RCE / 反序列化 / 文件上传必须明确)
- [ ] 6. 测试钳制(RPS 上限 / 禁用工具 / 写操作豁免)
- [ ] 7. 撞账号 / 字典 红线明示

---

## SRC 平台

- 平台名称:_TBD_
- 平台 URL:_TBD_
- 项目 / 厂商页面:_TBD_

## 范围内资产

### 入口 URL(playbook quickcheck 解析用,不填则 quickcheck 报错)
- 入口 URL: `_TBD_`

### 域名 / IP 白名单
- _TBD_

### 范围外(明确禁止)
- _TBD_(必须显式列出邻居资产 / 同 IP 其他端口 / 其他客户实例)

## 漏洞接受清单

| 类型 | 是否接受 | 备注 |
|---|---|---|
| SQL 注入 | _TBD_ | 仅时差 / 报错 / Boolean blind 验证,不 dump |
| XSS(反射 / 存储) | _TBD_ | 自存储 / Self-XSS 不收 |
| CSRF | _TBD_ | 视具体接口危害 |
| 信息泄露(SourceMap / Swagger) | _TBD_ | 单纯路径暴露不报 |
| 越权 / IDOR | _TBD_ | GET-only,不动他人数据 |
| RCE / 文件上传 | _TBD_ | 仅 `echo` / `id` / `whoami` 无害 payload,**先请示** |
| Struts2 系列 RCE | _TBD_ | **逐 payload 请示** |
| Spring/Shiro/Fastjson 反序列化 | _TBD_ | **先请示** |
| 拒绝服务 | ❌ | 一般不收且违规 |
| 物理 / 社工 | ❌ | |

## 测试限制

- **请求频率**:_TBD_(政企保守 ≤ 2 RPS)
- **测试时间窗口**:_TBD_(避开业务高峰)
- **禁用工具**:_TBD_(`sqlmap` / `nuclei` / `dirbuster` / `nmap -sS 全端口` / `msfconsole` 默认禁,使用前请示)
- **写操作**:_TBD_(默认严禁 / 自小号 + 无害 payload + 测完清理)

## 物料依赖评估（开图第 1 天必填 — 申请与挖掘并行）

> v2 根因方案 解法 B：账号/代码/批复是长 lead-time 外部依赖，开图第 1 天必须识别并发出申请，
> **与未授权面挖掘并行**，不等挖完才补（示例甲方教训：21 天认证后攻击面零产出 = 账号申请滞后）。
> 挖掘中"撞见"新物料门 → 当天补登记本表。

| 目标/面 | 需要什么 | 渠道 | lead time | 解锁面 | 申请状态 |
|---|---|---|---|---|---|
| _TBD_ | _TBD_（测试账号/供应商代码/设备/批复） | _TBD_（SRC 官方申请/平台注册/对话请示） | _TBD_（天级/周级） | _TBD_（认证后 IDOR/越权/支付链…） | [ ] 未发 |

规则：
- 开图第 1 天把本表可申请的项**全部发出**（如 SRC 测试账号），与阶段 1-3 并行推进
- 挖掘中撞见新物料门 → 当天补一行
- 审批分级（L0 只读默认授权 / L1 1包级预授权批量 / L2 注册类单次批准 / L3 重武器单次批准）：L1 项进 `_STATE.md` 可批清单，L2/L3 项逐条请示

## 积分规则

- 严重:_TBD_
- 高危:_TBD_
- 中危:_TBD_
- 低危:_TBD_
- 重复 / 已知:_TBD_

## ROE(Rules of Engagement)

- **L0 证据链** —— 所有结论粘 cURL + 字节回包,默认占位回包不算业务结果
- **L1 真实数据** —— 严禁 GET 之外操作触及他人数据
- **L1 测完清理** —— 写操作产生的修改 / 上传必须清理,报告写 `[清理动作]`
- **L2 重武器逐项请示** —— payload 类型、影响、退路 → 用户确认 → 发包
- **L2 战略请示** —— 30 分钟无新进展 → 主动问继续硬磕还是切面
- **撞账号红线** —— _TBD_(默认严禁字典暴破真账号;`admin/123456` 等极弱口令 1-2 次探测,触发防护立即停;**默认凭据**(产品弱配置,如 `admin/axis2`)单次尝试合规)

---

## 接单 checklist 完成状态

填齐后把上方 7 项的 `[ ]` 改成 `[x]`,timeline.md 第一条记录接单时间。**全 ✅ 之前不进入阶段 1**。
