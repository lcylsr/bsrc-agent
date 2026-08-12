---
mode: src
task_weight: standard
---
# 授权范围(Scope) — 脱敏演示案例（虚构）

> ⚠️ 本案例为**虚构** acme 示例甲方，资产全部使用 RFC 5737 文档网段与 example.com 占位域名，
> 不存在真实目标。本文件展示框架"接单门禁 7 项"如何填写。
> 真实项目中 7 项未填齐前不动手。

---

## 任务分级

```yaml
mode: src            # 赏金/众测模式，重视可投递性与影响面
task_weight: standard
包数预算: 100（演示案例实际用 12 包）
```

## 接单门禁清单（standard 全 7 项）

- [x] 1. SRC 平台名 + URL 齐全：AcmeBugBounty（虚构）— https://bounty.example.com
- [x] 2. 厂商 / 资产关系核实：acme 示例甲方官网声明域名归属（虚构 OSINT 命中）
- [x] 3. 范围白名单：`demo-acme.example.com` 及其子域 `api.` / `admin.`
- [x] 4. 范围黑名单：同网段 198.51.100.6（邻居资产）、198.51.100.9（甲方办公网，不在范围内）
- [x] 5. 漏洞接受清单：SQLi 仅时差/报错验证；XSS 不收 Self-XSS；越权仅 GET-only；RCE/上传逐 payload 请示
- [x] 6. 测试钳制：≤2 RPS；禁用 sqlmap/nuclei/dirbuster；写操作严禁（本案例全 GET）
- [x] 7. 撞账号红线：严禁字典暴破；默认凭据单次探测即止

## 范围内资产

### 入口 URL
- 入口 URL: `https://demo-acme.example.com`

### 域名 / IP 白名单
- `demo-acme.example.com` → 198.51.100.7（Web 主站）
- `api.demo-acme.example.com` → 198.51.100.8（API 网关）
- `admin.demo-acme.example.com` → 198.51.100.8（管理后台，网关后）

### 范围外(明确禁止)
- 198.51.100.6（同网段邻居资产）
- 198.51.100.9（甲方办公网段）
- 10.0.0.0/8（内网——仅作为 SSRF 验证目标，不做主动扫描）

## 漏洞接受清单

| 类型 | 是否接受 | 备注 |
|---|---|---|
| SQL 注入 | ✅ | 仅时差/报错/Bool 验证，不 dump |
| XSS | ⚠️ | Self-XSS 不收 |
| 越权 / IDOR | ✅ | GET-only，不动他人数据 |
| SSRF | ✅ | 只读验证，不触碰内网业务 |
| RCE / 文件上传 | 请示 | 仅无害 payload |
| 拒绝服务 | ❌ | |

## 测试限制

- **请求频率**: ≤ 2 RPS
- **禁用工具**: sqlmap / nuclei / dirbuster / nmap 全端口
- **写操作**: 严禁（演示案例全部为 GET 只读）

## 物料依赖评估

（演示案例无外部物料依赖；真实项目开图第 1 天即发账号申请）

## ROE(Rules of Engagement)

- **L0 证据链** —— 所有结论粘 cURL + 字节回包
- **L1 真实数据** —— 演示案例全部使用虚构数据
- **撞账号红线** —— 禁止字典；默认凭据单次即止

## 接单 checklist 完成状态

全 7 项 ✅ 于 2026-08-12T14:00 完成，进入阶段 1。
