# 主编排器 (Orchestrator)

> 输入目标 → 4 阶段推进 → 出洞/报告/归档。
> 不是流水线，跳步可以，但要说明理由（写在 `_STATE.md`）。
> 红线 / 契约 / 投递闸门 → 全在 `CLAUDE.md`。本文件只讲流程总图 + 命令骨架。

---

## 流程总图

```
输入目标 X
   ↓
[阶段 1: 接单 & 开图]  续接/新建 target → scope → recon → 资产清单
   ↓
[阶段 2: 攻击面识别]  指纹 + JS + N-day + 信息泄露 → surface.md
   ↓
[阶段 3: 主动测试 & 验证]  反射 + 认证 + 逻辑 → candidate → verified → PoC
   ↓
[阶段 4: 链式利用 & 报告]  kill chain → 报告 → lint → 结案归档
```

**核心原则**：
- 阶段 1 不直接打；没有资产清单就开图。
- 阶段 2 必须明确技术栈 + API 面。
- 阶段 3 candidate 必须经 PoC 验证才能进 verified。
- 阶段 4 只对 verified 做链式；phenomenon 不进链式。
- 20 分钟无进展换攻击面，30 分钟死磕留档问用户。
- 跳步可以，但必须在 `_STATE.md` 中说明理由。

---

## 阶段 1 — 接单 & 开图

```bash
# 新建 target
mkdir -p targets/<甲方>/<目标>
# 复制 targets/_template/ 的 _STATE.md 和 scope.md

# 已存在 target：读 _STATE.md 的"下一步"
cat targets/<t>/_STATE.md

# recon（至少 1 路成功）
bash tools/run.sh recon-pipeline <target_dir> <root>     # 子域 + 存活
bash tools/run.sh space-recon <target_dir> <domain>      # 空间测绘（FOFA/Hunter/Quake，需 keys）
```

**必产出**：
- `scope.md`（mode / 资产白名单 / 任务权重 / 时间窗）
- `recon/all-subdomains.txt` 或 `recon/surface-assets.md`

**完成条件**：至少识别到 1 个可打入口（子域 / IP / 客户端 / API）

**子域 >10 或大厂 SRC** 时 spawn recon-agent：
```bash
python tools/agent-launch.py recon-agent <target_dir> --roots <root1> [root2...]
```

---

## 阶段 2 — 攻击面识别

```bash
# 指纹 + JS 提取 + 硬编码密钥 + API 面
bash tools/run.sh js-recon <target_dir> <url_or_file>

# N-day 匹配（命中后必须逐个验证）
bash tools/run.sh nday-matcher <target_dir>

# 信息泄露面：.git / .env / actuator / swagger / sourcemap 等
# 直接按下方清单发 1-2 包探针
```

**信息泄露面（11 项各 1 包）**：
`.git` / `.env` / `config.js` / `swagger-ui.html` / `actuator` / GraphQL introspection / sourcemap / `.bak` / 目录列表 / 错误页堆栈 / 默认凭据

**必产出**：
- `surface.md`（fingerprint + API surface + secrets + crypto map）
- `findings.md` 中 N-day / 信息泄露 candidate 或 verified

**完成条件**：技术栈大类明确 + API 路径列表 ≥1 或确认无 JS

---

## 阶段 3 — 主动测试 & 验证

**必做**：
- [ ] 参数级反射：看到 url/path/file/id/redirect/callback 参数，直接投标准 payload（`reflexes.md` 第一层）。
- [ ] 认证面状态机：Read `memory/playbooks/playbook-auth-state-machine-resolve-style.md`，按 Auth-SM checklist ≤30 包。
- [ ] 生成 candidate 后 AI 现场 write PoC 脚本验证：
  ```bash
  # AI 写 output/poc-<finding_id>.py，然后直接跑
  python output/poc-<finding_id>.py
  ```
- [ ] 反事实校验：AI 自问 4 问（3 反事实：改 ID/无认证/假响应 + 1 证伪反例测试），见 CLAUDE.md §1 铁律。
- [ ] 覆盖跟踪：收尾读 `doctrine/coverage-audit.md` checklist 逐条标注。

**产出**：lifecycle.yaml verified/candidate 条目 + 收尾按 `doctrine/coverage-audit.md` checklist 标注

**完成条件**：所有反射点有明确结论（verified / phenomenon / rejected） + 认证面 checklist 闭合或死路分类

**卡死策略**：>20min 换攻击面，>30min 写 `_STATE.md` "待决问题" 问用户。

---

## 阶段 4 — 链式利用 & 报告

**必做**：
- [ ] 对 ≥2 verified finding 做链式分析（AI 自审）：
  常见链：SSRF + 云元数据 / 内网 actuator；任意文件读 + 配置文件；信息泄露 + sourcemap → 代码审计；IDOR + 批量接口；认证绕过 + admin 面板。
- [ ] 生成报告：AI 写 `targets/<t>/output/report-<日期>.md`
- [ ] **投递报告产出 SOP（v4 P0-5 复盘固化，批量产出必走）**：
  1. **状态注入块**：spawn 报告 agent 前，Commander 先注入该 finding 族的最新状态清单——`fixed/活` 每条 + 上次 revalidation 日期 + 计数演化史（如：`PH-F-006/007/003 已 fixed（File API v1 404/v2 401）；F-001/F-002/F-005 仍活；F-005 计数 124→132→134`）。报告 agent 禁止凭记忆写状态，所有编号/状态以注入块 + lifecycle.yaml 为准
  2. **报告模板强制字段**：撰写当日 liveness 快照（复检日期 + 实测结果 + 包数）；证据原件位置必须披露存档状态（TEMP 已清理 → 写"以重放复取为准"，禁止列已失效路径）
  3. **双口径规则**：旧证据报告一律"历史实证 + 现状披露"双口径（如 `07-21 实测 200 / 08-11 复检 v1 404`），复现状态列不得写现在时
  4. **verifier 对抗复核**：每份投递报告 spawn 独立 verifier（文件交付原生模式，见 verifier-agent 契约）→ VERDICT FAIL 的按修订点闭环后再交付
- [ ] 投递前 lint：
  ```bash
  python tools/findings-lint.py <target_dir>/findings.md
  ```
  AI 自审 9 项交付评分（PoC / 业务结果 / 可付费视角 / 客户文档同步）
- [ ] 投递对象强制带 `last_rechecked`（lifecycle 字段，delivery-queue 视图显示；缺 ⚠️ 未复检 = 投递前必须补测 liveness）
- [ ] 结案/归档：
  ```bash
  mv targets/<t> targets/_archived/
  ```

**产出**：`targets/<t>/output/report-*.md` + kill-chain 草稿 + `_archived/<target>`

**完成条件**：所有 verified 洞至少考虑 1 个延伸方向；报告通过 lint。

---

## 状态维护（轻量）

每个 target 目录只留一个 `_STATE.md`，固定 7 段（定义见 CLAUDE.md §1 铁律）：
```
## 元信息 / 时间线摘要 / 当前阶段·下一步 / 已 verified / 深挖焦点&假设链 / 死路 / 待决
```

会话开场 AI 读这一个文件续接。多目标并行靠 AI 自记 ≤3。

不要花大量时间维护状态；记录的目的是为了续接，不是为了形式正确。

---

## 多代理编排

**触发条件**：子域 >10 / 多根域大厂 SRC / scope 含客户端资产。

**角色**：
- `recon-agent`：多源被动 recon + 分类 + Top ROI（子域 >10 时 spawn）
- `app-agent`：APP 渗透测试（scope 含 APK/IPA/小程序时 spawn，静态全自动+动态半自动+API回归）
- `pentest-agent`：单子域漏洞挖掘（Commander 指派）
- `client-agent`：桌面客户端深审（Electron/CEF/.NET/Win32）

**spawn 要求**：
- `verifier-agent`：**双触发**（① candidate 产出后并行证伪——CLAUDE.md §3.0；② 投递报告产出后必须 spawn 复核——独立对抗复核 + 现场 liveness 重放，证伪"自挖自证"沉没成本；2026-08-11 实践：12/12 复核抓出 PH-F-003 死洞 + 36 处修订）。结论**只走文件交付**（Write 到 `output/delivery-reports/<ID>-verify-<日期>.md`），不依赖消息回传；idle 通知后检查文件是否落盘即可，勿催促
- 主 agent 自己做更好的：链式分析（自审）——不 spawn 链式分析 agent（组合 PoC 由 Commander 直接验证）

**timeline 参考**：
```
T+0     mkdir target + scope
T+5min  recon-pipeline + space-recon（+ 可选 recon-agent）
T+30min 攻击面识别（js-recon + nday-matcher + 信息泄露 + fuzz）
T+30min APP 测试（如有客户端资产：spawn app-agent，静态线并行）
T+1h    主动测试（反射 + Auth-SM + PoC + 链式假设链）
T+1.5h  链式 + 报告 + lint + 归档
```

---

## 收尾 & 复盘

**review-agent 复盘（D7）**：挖掘日末 / 周期深复盘时 spawn `review-agent`（每批次 2-3 个不同 lens 并行）：
- 输入：本轮 `output/rounds/` 卷 + `lifecycle.yaml` 变更 + 死路记录 + verifier 的 VERDICT
- 输出：盲区清单 + 规则修订提案 + playbook 增量（每条必须有档案证据引用）
- **只读档案不发包**；复盘产物由 Commander 判定采纳后写回 `memory/reflections|insights|playbooks`

结案时按 [`doctrine/reflexes.md`](../doctrine/reflexes.md) 复盘：

```bash
# 中标经验 → memory/playbooks/<甲方>-<漏洞>.md
# 未中标/证伪指纹 → memory/rejected/<日期>-<指纹>.md
# 误测/漏测/盲区复盘 → memory/reflections/<主题>.md
# 通用模式 → memory/insights/<主题>.md
# 手动更新 memory/INDEX.md 追加新条目
```

核心复盘问题：
1. 这个洞为什么现在才出现？哪个阶段如果早点做就能更早发现？
2. 哪些反射/指纹被误判了？
3. 下一个同类目标可以复用的最小步骤是什么？
4. 有没有本可以自动化但没自动化的重复劳动？
5. **本轮有没有误测（把现象当漏洞）或漏测（该测没测）？** → 有则写 `memory/reflections/`，防跨任务重蹈覆辙（详见 `memory/insights/reflection-loop-design.md`）

---

## 与相关文件关系

| 文件 | 关系 |
|---|---|
| [`../doctrine/reflexes.md`](../doctrine/reflexes.md) | reactive 反射，阶段 3 高频查 |
| [`../doctrine/coverage-audit.md`](../doctrine/coverage-audit.md) | 阶段 3 补测优先级；收尾 checklist |
| [`../doctrine/law.md`](../doctrine/law.md) | 法律红线 |
| [`../CLAUDE.md`](../CLAUDE.md) | 总铁律与落盘约定 |
| [`../QUICK.md`](../QUICK.md) | 决策树 fallback |
