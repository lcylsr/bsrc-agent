---
name: idor-bola
domain: idor|bola|authz
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# IDOR / BOLA(越权)战术手册

## Domain

- 路径含 `/users/<id>` `/orders/<id>` `/files/<uuid>`
- 列表疑前端过滤;请求含 tenant_id/org_id/company_id
- modes: src 必须能定位到人;redteam 跨租户商业秘密也算入口

## Boundaries

- 铁律:必须能定位到人(姓名/手机/邮箱/工号),否则 SRC 降档
- 公共目录/商品列表不算
- 只 GET 读越权;不批量 dump PII;不改真实业务数据
- 跨租户读到他公司业务数据 = 可报(商业秘密例外)

## Pivot Hints

- 数字 ID 无果 → batch/ids= / GraphQL 过多字段 / JS 明文 UUID
- 200 空对象 → 换接口或历史已删资源
- Snowflake → 时序推一批
- 垂直:路径 admin / mass assignment is_admin
- 无受害者字段 → phenomenon,不升 verified

## Exit Evidence

### src
- E2: A token + B id 可重放,Body 含 B 真实 PII
- E3: 业务影响句(谁的数据、量级)
- 无姓名/手机等 → 不报 verified

### redteam
- E2: 一个可重放越权读即可支撑横向/信息收集 hop
- 定位到人优先但仍可写路径级影响

## Tactics

> 原 Triggers / Coverage / Common misses / Verification 压缩如下;深度细节见文末 Reference(若有)。

## Triggers (何时用)

- 接口路径含 `/users/<id>` `/orders/<id>` `/files/<uuid>` 等资源标识
- 列表接口返回多用户数据(怀疑过滤在前端做)
- `tenant_id` / `org_id` / `company_id` 出现在请求中

## Coverage points (查什么)

- 水平越权:A 的 Token + B 的资源 ID,看响应是否返回 B 的真实数据
- 垂直越权:普通用户改路径/参数提权,主动加 mass assignment 字段(is_admin/role)
- UUID/复杂 ID:批量查询接口、JS 明文返回 UUID、GraphQL 过多字段、已删除资源、Snowflake 时序 ID
- **铁律:必须能定位到人**(姓名/手机/邮箱/工号),否则降档

## 核心思路

不要只盯着数字 ID。现代系统多用 UUID / Snowflake,重点在于**寻找 ID 泄露点**和**批量替换**。

## 铁律 — IDOR 必须能定位到人

返回数据里**没有用户标识字段**(姓名 / 手机 / 邮箱 / 工号 / 身份证 / 地址 / 订单号关联人)→ **立刻降档**。
- ✅ 200 + `{"name":"张三","phone":"138..."}` → 真 IDOR
- ❌ 200 + `{"data":{"value":"xxx","timestamp":...}}` → 仅业务数据,无受害者 → SRC 拒
- ❌ 200 + 公共目录(如商品列表)→ 设计上公开,不算

**例外**:跨租户读到他公司的**任何**业务数据(订单金额 / 内部价格 / 配置参数)= 商业秘密,即使无个人标识也算。

## 三类越权路径

### 1. 水平越权(同级用户)

抓 A 的请求,把 `user_id` / `order_id` / `phone` 替换为 B 的值。

**关键 trick**:
- 即使返回 200 也不算,**必须看响应 Body 里有没有 B 的真实数据**(姓名、手机、地址)
- 有些后端"返回空对象 + 200",看起来无漏洞,但其实是过滤后空数据 → 试更多接口
- 注意 Cookie / Token 是 A 的,**资源 ID 才是 B 的**(很多人弄反)

```bash
# A 的 Token,但请求 B(10086)的订单
curl -X GET "https://api.target.com/v1/orders/10086" \
  -H "Authorization: Bearer <User_A_Token>"
```

### 2. 垂直越权(低权打高权)

抓普通用户请求,改路径 / 参数:

- 路径替换:`/api/user/list` → `/api/admin/user/list`
- 参数提权:请求 Body 里 `role_id=2` → `role_id=1`(or `0`)
- 参数注入(mass assignment):请求 Body 不传 `is_admin`,**主动加** `"is_admin":true`
- Header 注入伪权限:`X-User-Role: admin` / `X-Forwarded-For: 127.0.0.1`

### 3. UUID / 复杂 ID 猜测

UUID 不可猜,但 ID 经常**不是真的不可枚举**:

- **批量查询接口**:试 `/api/users?ids=1,2,3` 或 `/api/users/batch` POST `{"ids":[...]}` —— 很多 batch 接口忘了校验
- **JS 列表页明文返回所有 UUID**,UI 仅 CSS 隐藏:F12 看 Network 响应原文
- **GraphQL 同接口返回过多字段**:列表接口里返回了详情字段,前端只显示标题
- **历史 ID 泄露**:删除的资源 UUID 仍在数据库,接口未校验"已删除"
- **Snowflake / 时序 ID** 看起来无序,但**包含时间戳**,知一个能推一批

## Verification (verified 标准)

```bash
# 步骤 1: 用 A 注册号拿一个 B 的资源 ID(从 leak / batch 来)
# 步骤 2: 用 A 的 Token 查 B 的资源
curl -X GET "https://api.target.com/v1/orders/<B_order_id>" \
  -H "Authorization: Bearer <A_Token>" \
  -H "Cookie: <A_Cookie>" \
  -i

# 双信号判定:
# ✅ 200 + Body 含 B 的姓名/手机/地址 → 水平越权确认
# ❌ 200 + 空对象 / 200 + A 的数据 → 后端有过滤,不算
# ❌ 403/401 → 鉴权正常
```

## Common misses (AI 常忘)

1. **响应 200 但 Body 是空对象** —— 后端有 filter,只是没返 403。不算漏洞。
2. **替换的 ID 是同租户内** —— SaaS 多租户,同租户内查询设计如此。需跨租户才算。
3. **能读但读到的不是敏感数据** —— `name="测试用户"`,业务危害降级,SRC 可能拒。
4. **接口本来就是公开列表** —— 如商家公开商品页,不算越权。

## Related playbooks

成功 → `memory/playbooks/<甲方>-idor-<接口>.md`
失败 → `memory/rejected/<日期>-idor-<指纹>.md`

