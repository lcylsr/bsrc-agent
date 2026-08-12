# 发现与漏洞(Findings)v3.1

> 状态机见 `lifecycle.yaml`：`phenomenon → candidate → verified → money_ready → delivered`（枚举：phenomenon | candidate | verified | money_ready | delivered | rejected | fixed）。**本文件章节分组仅为人工组织习惯，非状态机**；状态以 lifecycle.yaml 为唯一真相源。
>
> 每条 finding 必须有 frontmatter,升级到 `candidate` 必须填三选一升级路径(planned / linked / intuition)。
>
> **与 lifecycle.yaml 同步**:finding 状态唯一真相源为 `targets/<t>/lifecycle.yaml`，投递队列/证据/审批视图由 `python tools/findings-lint.py targets/<t> --lifecycle --gen` 生成。
>
> 详释:[doctrine/law.md](../../doctrine/law.md)

---

## 当前攻击面(改 5 — 方向偏移检测)

> 每次切攻击面时更新此块。攻击面切换 ≥3 次 / 20 分钟无进展 → 主动重读 QUICK.md 反射准则或问用户是否切面。

```yaml
current_attack_surface: recon       # recon | IDOR | SSRF | Auth | Upload | Inject | Crypto | RaceCond | Other
surface_set_at: 2026-MM-DDTHH:MM:00+08:00
surface_history:                     # 切换历史(append-only,最新在末尾)
  - {surface: recon, at: 2026-MM-DDTHH:MM:00+08:00, reason: "进场"}
  # - {surface: IDOR, at: ..., reason: "看到 /users/<id>"}
  # - {surface: SSRF, at: ..., reason: "发现 url= 参数"}
```

**铁律**:切攻击面前先**追加** `surface_history` 一条,再改 `current_attack_surface`。20 分钟无新进展 → 换攻击面,不要死磕。

---

## 模板:新增 finding 时复制此块

```yaml
---
id: F-XXX
status: phenomenon          # 枚举见 lifecycle.yaml：phenomenon | candidate | verified | money_ready | delivered | rejected | fixed
status_changed_at: 2026-MM-DDTHH:MM:00+08:00

# === 升级到 candidate 必须填三选一 ===
upgrade_path:
  type: planned             # planned | linked | intuition

  # type=planned (客观,严谨工程师视角)
  next_action: "<下一步具体动作>"
  estimated_packets: 0      # ≤ 5 包

  # type=linked (联合,多现象组合)
  linked_with: []           # [F-002, F-005]
  joint_hypothesis: ""

  # type=intuition (直觉,B 类嗅觉保护)
  intuition_text: |
    <≥ 50 字的主观描述>
  intuition_followup_deadline: 2026-MM-DDTHH:MM:00+08:00  # 60 分钟自检

# === 投递闸门字段(verified 后填)===
scope_authorized: 0         # 0 | 1 (硬否决)
reproduced: 0               # 0 | 1 (硬否决)
business_result: 0          # 0 | 1 (硬否决)
not_speculation: 0          # 0 | 1 (硬否决)
pay_view: 0                 # 0 | 0.5 | 1 (软评分)
readable: 0                 # 0 | 0.5 | 1 (软评分)
honest_value: 0             # 0 | 0.5 | 1 (软评分)

# === 第三层重放(现场重放用,verified 后必填,无 fallback)===
poc_type: curl             # curl | script | websocket | mobile | multi-step
                           #   curl:单条 curl 可重放(默认)
                           #   script:复杂/多步 PoC,需同时提供 replay_script 或 replay_artifacts/<fid>/replay.{sh,py}
                           #   websocket/mobile/multi-step:当前不支持自动重放,需手动验证
replay_signature: ""        # 必填:响应里必有的 ≥ 8 字节**具体业务证据串**,隔离重放后必须仍含此字符串,否则降级 phenomenon
                            #   必须是业务数据,禁止状态码或 success:true/code:200 等泛化字符串
                            #   示例:泄露的 phone="138...." / "USER=root" / 表名 / 凭据片段 / "cque/cque@1234"
auth_dependency: none       # none | unauth | pre-auth | bearer-required | session-required
                            #   none/unauth/pre-auth → 重放时强制清 cookie/Authorization 头
                            #   bearer-required → 重放时保留 token(声明该洞依赖鉴权);需在 replay_script 或 poc_curl 中提供 token 获取方式

# === 真实影响证据(2026-07-03 新增,verified 必填)===
business_evidence: |
  用大白话说明这个 PoC 导致了什么业务状态变化。例如:
  - "返回 138 条订单记录,含手机号、地址、金额"
  - "未登录即可调用 AI 机器人任务接口,day 参数任意值均被接受"
  - "上传接口处理危险脚本扩展名并返回服务器内部路径"
  禁止只写 "HTTP 200" / "success:true" / "code:200"。

# === 自主置信度通道(可选,谨慎使用)===
ai_confidence: 0            # 0-1 浮点,≥0.6 + reasoning ≥200 字 才能进 tentative
                            #   注意:ai_confidence 与 reasoning 由同一模型生成,相当于"自己担保",高影响漏洞必须追加人工 review

# === 业务灾难放大器(v3.5 强制,verified → deliverable 时必填)===
worst_case_business_disaster: |
  <用大白话翻译成"老板赔多少钱 / 公司倒闭场景 / 监管罚款级别"。
   不要写技术语言;假设审核员是商业总监,不是工程师。>
kill_chain_followups: []    # 这个洞还能怎么组合升级?[F-002 越权 + 本洞 SSRF → 内网]

# === 实战复盘三件套(v3.5 强制,verified 后必填,沉淀到 memory/playbooks/playbook-*.md)===
postmortem:
  dev_mistake: |
    <开发为什么犯错?ORM 没把 user_id 做联合主键?后端只校验登录态没校验归属?>
  general_pattern: |
    <这个洞的通用挖掘模型 — 下次怎么 5 秒识别同类系统的同类洞?>
  next_hunt: |
    <顺着这个开发的认知盲区,同 target 还该测哪几个接口?>
---

### F-XXX 标题
... 内容 ...
```

---

## 🟢 现象 (phenomenon)

(挖洞期看到、未深探的留档,**不删除**,凑链时回头用)

---

## 🟡 候选 (candidate)

---

## ✅ 已验证 (verified) — 双信号齐 + 字节证据

---

## 🚀 可投递 (money_ready)

---

## ❌ 已驳回 / 已证伪 (rejected)

(防再撞,撤档前对照 `lifecycle.yaml` 的 history + 死路记录复核)

---

## 📌 已投递 (delivered)
