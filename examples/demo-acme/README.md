# examples/demo-acme — 脱敏漏洞实践案例

> ⚠️ **虚构声明**：本目录所有目标域名（`demo-acme.example.com` 及其子域）、IP（RFC 5737 文档网段 `198.51.100.0/24`）、
> 数据、会话均为**虚构占位**，不指向任何真实系统。三个 PoC 默认 `--demo` 离线回放（内嵌虚构证据、验证重放逻辑），
> 不发任何真实网络请求——符合框架法律红线，可直接用于比赛 Demo 演示。

## 这是什么

展示框架 v6.0-slim 一次完整渗透会话的**端到端闭环**：接单门禁 → recon → 2 包定性探测 → 反事实 4 问 → verified → 组合验证 → money_ready → 报告。三条 finding 各演示一种典型漏洞验证纪律：

| Finding | 漏洞 | 演示的纪律 |
|---|---|---|
| ACME-F-001 | SSRF | **组合验证**：单现象（读 /etc/hosts）不能升 verified，组合"SSRF→内网配置泄露"才成立 |
| ACME-F-002 | `..;/` 认证绕过 | **判别三连**（P1 直连 401 / P2 绕过 200 / P3 假资源 404）排除误报 |
| ACME-F-003 | IDOR | **反事实 4 问** + GET-only 合规（2 包即止） |

## 快速重放（演示用）

```bash
python examples/demo-acme/output/poc-acme-001.py --demo   # SSRF 组合验证 → VERIFIED
python examples/demo-acme/output/poc-acme-002.py --demo   # ..;/ 判别三连 → VERIFIED
python examples/demo-acme/output/poc-acme-003.py --demo   # IDOR 反证 → VERIFIED
python tools/findings-lint.py examples/demo-acme --lifecycle --gen   # 生命周期状态机校验 + 视图生成
```

三个脚本均输出 `exit code 0 = VERIFIED`，且包含 `replay_signature` 命中校验——与 `lifecycle.yaml` 中登记的签名一致，证明"重放仍成立"。

## 目录结构与框架对应

```
examples/demo-acme/
├── scope.md          # 接单门禁 7 项 ✅（虚构授权/白名单/黑名单/速率纪律）
├── _STATE.md         # 会话状态（7 段，实时写回防失忆）
├── surface.md        # 攻击面清单（3 资产 + js-recon 摘要 + Top 3 候选）
├── timeline.md       # 时间线（14:00-18:10）
├── lifecycle.yaml    # ★ finding 唯一真相源（3 verified + history）
├── findings.md       # finding 详情（business_evidence / 反事实记录 / postmortem）
└── output/
    ├── poc-acme-00{1,2,3}.py   # 可执行 PoC（--demo 离线回放）
    ├── report-2026-08-12.md    # 渗透测试报告（含链式分析）
    ├── rounds/2026-08-12.md    # 轮次卷（P-001~P-005，实时写回样例）
    └── lifecycle-views/        # findings-lint --gen 自动生成（勿手改）
```

## 换成真实目标的步骤（框架使用方式）

1. `mkdir -p targets/<甲方>/<目标>` + 从 `targets/_template/` 复制 `_STATE.md`/`scope.md`
2. scope.md 填真实授权范围 → 阶段 1 recon → 阶段 2 攻击面 → 阶段 3 探测（PoC 去掉 `--demo`）
3. 每新 finding 只改 `lifecycle.yaml` + 跑 `findings-lint --lifecycle --gen`
4. 收尾过 `doctrine/coverage-audit.md` 自审 → 写报告 → `mv targets/<t> targets/_archived/`
