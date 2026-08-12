# 发现与漏洞(Findings)v3.1 — 脱敏演示案例（虚构目标）

> 本案例为**虚构** acme 示例甲方，全部资产使用 RFC 5737 文档网段（198.51.100.x / 10.0.0.x）与
> example.com 占位域名。仅用于演示框架状态机与验证纪律，**不指向任何真实目标**。
> 状态唯一真相源：`lifecycle.yaml`；视图由 `python tools/findings-lint.py examples/demo-acme --lifecycle --gen` 生成。

---

## 当前攻击面(改 5 — 方向偏移检测)

```yaml
current_attack_surface: Auth       # recon | IDOR | SSRF | Auth | Upload | Inject | Crypto | RaceCond | Other
surface_set_at: 2026-08-12T17:40:00+08:00
surface_history:
  - {surface: recon, at: 2026-08-12T14:00:00+08:00, reason: "进场"}
  - {surface: SSRF, at: 2026-08-12T15:20:00+08:00, reason: "api 面抓到 url= 参数"}
  - {surface: Auth, at: 2026-08-12T15:50:00+08:00, reason: "管理口 401，测路径归一化"}
  - {surface: IDOR, at: 2026-08-12T17:00:00+08:00, reason: "订单接口 id 参数"}
```

---

## ✅ 已验证 (verified)

---
id: ACME-F-001
status: verified
status_changed_at: 2026-08-12T18:05:00+08:00
upgrade_path:
  type: planned
  next_action: "SSRF 读取内网配置 → 组合验证可做内网探测"
  estimated_packets: 5
scope_authorized: 1
reproduced: 1
business_result: 1
not_speculation: 1
pay_view: 1
readable: 1
honest_value: 1
poc_type: script
replay_signature: '"内网管理网段": "10.0.0.0/8"'
auth_dependency: unauth
business_evidence: |
  - 未认证即可让服务端代为请求内网地址，读取到内网管理系统配置
    （conf.json 含管理网段 10.0.0.0/8 与管理口地址）→ 内网拓扑泄露
  - 组合验证：SSRF 现象 + 配置内容 = 可被利用为内网探测入口
worst_case_business_disaster: |
  攻击者以公网身份访问内网管理网段，配合内网服务漏洞可横向移动到核心业务系统；
  若内网系统存在弱口令/未授权接口，可从"外网打不进来"升级为"内网全通"。
kill_chain_followups: ["ACME-F-002 认证绕过 + 本洞 → 内网管理口可直接登入"]
postmortem:
  dev_mistake: |
    资产预览功能需要拉取外部图片，开发直接拼接 url 参数发起服务端请求，
    未做协议白名单（仅允许 http/https 且目标必须公网）。
  general_pattern: |
    任何"服务端代为访问"类功能（预览/截图/代理/回调）都是 SSRF 温床；
    看到 url=/path=/file=/redirect=/callback= 立刻上 5 payload。
  next_hunt: |
    同类目标还该测：图片代理接口的 gopher/dict 协议、302 跳转跟随、
    DNS rebinding、以及 SSRF 读云元数据（169.254.169.254）。

### ACME-F-001 SSRF：/api/v1/asset-preview?url= 可读取内网管理配置

- **现象**：`/api/v1/asset-preview?url=` 服务端代为请求，file:// 与内网地址均可回显
- **组合验证**：SSRF 读取 `http://10.0.0.10/conf.json` → 内网管理网段 10.0.0.0/8 + 管理口地址
- **反事实 4 问**：换地址返回不同内容 / 无认证可触发 / 不可达地址 502 vs 可达 200 / 直连脚本重放成立 → 全部通过
- **PoC**：`python output/poc-acme-001.py --demo`（离线回放验证逻辑）

---
id: ACME-F-002
status: verified
status_changed_at: 2026-08-12T16:40:00+08:00
upgrade_path:
  type: planned
  next_action: "..;/ 判别三连：P2 绕过 → 无 Cookie 直连管理接口验证"
  estimated_packets: 4
scope_authorized: 1
reproduced: 1
business_result: 1
not_speculation: 1
pay_view: 1
readable: 1
honest_value: 1
poc_type: script
replay_signature: '"total_orders": 128'
auth_dependency: unauth
business_evidence: |
  - 未携带任何 Cookie/Authorization 访问 /assets/..;/admin/dashboard
    返回管理面板订单聚合数据（订单数 128、金额汇总）→ 网关鉴权被绕过
worst_case_business_disaster: |
  管理后台完全脱闸：订单聚合、客户统计等经营数据向公网裸奔；
  若管理接口存在写操作（配置/导出），可被直接利用而不留鉴权痕迹。
kill_chain_followups: ["ACME-F-003 IDOR + 本洞 → 管理视角批量导客户订单"]
postmortem:
  dev_mistake: |
    网关按前缀匹配放行静态资源（/assets/），后端框架对 ..;/ 做路径归一化时
    把分段合并——两端对同一 URL 的解释不一致，形成鉴权绕过。
  general_pattern: |
    403/401 不停：先在路径里试 ..;/ 判别三连（P1 直连 / P2 绕过 / P3 反证），
    网关-后端归一化差异是通用绕过模式（同族：QES-F-001 家族）。
  next_hunt: |
    同 target 还该测：URL 编码变体（%2e%2e%3b/）、大小写、双写斜杠、
    以及网关放行前缀（/static/ /public/ /vendor/）下的同款绕过。

### ACME-F-002 认证绕过：`..;/` 路径归一化绕过网关鉴权

- **现象**：/admin/dashboard 直连 401；/assets/..;/admin/dashboard 无 Cookie 返回 200
- **判别三连**：P1 直连 401 → P2 加 ..;/ 绕过 200 → P3 去掉前缀资源不存在 404（确认非网关统一放行）
- **反事实 4 问**：去 ..;/ 即 401（确认是归一化差异）/ 清 Cookie 仍成立 / 假资源 404 vs 管理路径 200 / 改 query 重放仍实时 → 全部通过
- **PoC**：`python output/poc-acme-002.py --demo`（离线回放验证逻辑）

---
id: ACME-F-003
status: verified
status_changed_at: 2026-08-12T17:30:00+08:00
upgrade_path:
  type: planned
  next_action: "替换订单 id 反证归属未校验（GET-only，2 次即止）"
  estimated_packets: 2
scope_authorized: 1
reproduced: 1
business_result: 1
not_speculation: 1
pay_view: 1
readable: 1
honest_value: 1
poc_type: script
replay_signature: '"order_no": "ORD-2026-08123"'
auth_dependency: session-required
business_evidence: |
  - 使用 A 账号登录后，替换订单 id 可读取他人订单（脱敏：订单号、
    金额、收件地址哈希）→ 归属未校验，GET 只读，未批量拉取
worst_case_business_disaster: |
  订单号可枚举（连续号段），攻击者可批量遍历读取全量订单；
  订单含收件地址哈希与金额，构成个人隐私批量泄露（PIPL 处罚级别）。
kill_chain_followups: ["配合 ACME-F-002 管理视角 → 数据聚合分析"]
postmortem:
  dev_mistake: |
    查询时只校验了"是否登录"，没有把 user_id 作为查询条件的一部分——
    典型"有认证无授权"（BOLA）。
  general_pattern: |
    看到 id/uid/orderId 参数 + 需登录 → 先想归属校验：换成别人的 id，
    返回 200 即 IDOR；GET-only 验证，不批量。
  next_hunt: |
    同 target 还该测：导出接口、发票接口、优惠券领取接口的同类归属缺失。

### ACME-F-003 IDOR：/api/orders/<id> 未校验归属，GET 越权读取他人订单

- **现象**：A 账号订单接口返回 id 字段 → 替换相邻订单号返回他人订单
- **反事实 4 问**：替换 id 返回不同订单（非自己下单记录）/ 无 Cookie 401（确需登录）/ 不存在订单 404 / 与下单记录比对无此单 → 全部通过
- **PoC**：`python output/poc-acme-003.py --demo`（离线回放验证逻辑）

---

## 🟢 现象 (phenomenon)

（无 — 演示案例全部闭环）

## 🚀 可投递 (money_ready)

- **ACME-F-001**（delivery_order=1）— 采样证据四件套齐，可投递示例
