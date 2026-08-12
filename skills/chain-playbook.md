---
name: chain-playbook
domain: kill-chain|exploit-chain
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact, killchain]
---

# 链式利用操作手册（从单点到 Kill Chain）

> **何时用**：拿到 ≥1 个 verified/candidate 后，问"能接上哪条链？"。这不是模板（reflexes 里有 8 条启发），是**分步操作手册**——从信号到危害证明的具体步骤。
>
> **实战来源**：odoo killchain（公网入口→root RCE→容器逃逸）、acme PH-F-007（上传→CDN）、internal-10.0.0.3 F-15/F-16（未授权API→权限树→批量数据）。

## 何时启动链式分析

- 拿到 SSRF / 任意文件读 / 信息泄露 / 上传 / 未授权 API 任一 candidate
- **不等 verified 才想链**——candidate 阶段就登记假设链到 `_STATE.md` 深挖焦点&假设链段
- phenomenon 之间组合可能升 verified（见 `CLAUDE.md` 铁律·组合验证）

---

## 链 1：SSRF → 云凭据 → 内网横向

**前置**：SSRF 确认可打内网（`url=http://127.0.0.1/` 有响应）

### 步骤

1. **确认 SSRF 方向**（2 包）：打 `127.0.0.1` + 打 `169.254.169.254`，看哪个通
2. **提取云凭据**（2-3 包）：
   - AWS：`169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`
   - 阿里云：`100.100.100.200/latest/meta-data/ram/security-credentials/`
   - 腾讯云：`metadata.tencentyun.com/latest/meta-data/`
3. **用凭据探测内网**（3-5 包）：
   - 拿到 IAM 凭据 → **不调云 API**（法律红线），只在报告写"凭据已暴露"
   - SSRF 打内网 actuator：`http://127.0.0.1:8080/actuator/env`
   - SSRF 打内网 Consul/Nacos：`http://127.0.0.1:8500/v1/health/state/any`
4. **证明危害**：actuator/env 含 DB 密码 / Consul 返回内部服务拓扑 / metadata 含 IAM 凭据

### 失败 Pivot
- `169.254` 被拦 → 试 `fd00:ec2::254`（IPv6）/ 绕过 IP 黑名单（`0` / `0.0.0.0` / 整数）
- SSRF 只支持 http 不支持 file → 试 `http://a/../../../etc/passwd` 穿越读文件
- 云 metadata 要 IMDSv2 token → IMDSv1 老配置一打一个准，IMDSv2 暂跳过标 B（物料门）

### 危害证明标准
- verified：SSRF 请求 + 响应含凭据/内部数据截图
- phenomenon：SSRF 能打内网但拿不到敏感数据
- 法律边界：**不连 DB、不调云 API**，只截图证明

---

## 链 2：任意文件读 → 源码 → 代码审计 → 注入

**前置**：任意文件读确认（`file:///etc/passwd` 或 `../../../etc/passwd` 成功）

### 步骤

1. **读应用配置**（2-3 包）：
   - Spring Boot：`file:///proc/self/cwd/application.properties` / `application.yml`
   - Python：`file:///proc/self/cwd/settings.py` / `config.py`
   - Node：`file:///proc/self/cwd/.env` / `config.json`
   - PHP：`file:///var/www/html/config.php` / `.env`
2. **读源码**（3-5 包）：
   - 确认 webroot 路径（从配置/Nginx 配置读 `file:///etc/nginx/nginx.conf`）
   - 读关键文件：路由文件 / 数据库查询层 / 认证逻辑
3. **本地审计**（离线）：
   - grep SQL 拼接：`grep -rn "execute\|query\|cursor" <source>/`
   - grep 硬编码密钥：`grep -rn "password\|secret\|key\|token" <source>/`
   - grep 危险函数：`grep -rn "eval\|exec\|system\|popen\|Runtime" <source>/`
4. **回打**（2-3 包）：找到注入点 → 构造 payload → 验证

### 失败 Pivot
- 读不到源码路径 → 读 `/proc/self/cmdline` 看启动命令推 webroot
- 源码是编译后的 jar/war → 读 `.class` 文件 hex，用 javap 反编译
- 代码审计无注入点 → 转读配置文件找凭据（链 1 变体）

### 危害证明标准
- verified：源码审计发现注入点 + 回打 PoC 验证成功
- phenomenon：读到源码但审计无发现
- 法律边界：**不下载全部源码**，只读关键文件截图证明

### 实战案例
odoo killchain：`/web/database/manager` 暴露 → JSON-RPC 读数据库列表 → admin/admin 登录 → `ir.actions.server(state=code)` Python 执行 → `env.cr.execute` SQL → `base_import_module` 系统级 RCE → root → 容器逃逸

---

## 链 3：信息泄露 → sourcemap → 隐藏接口 → 越权

**前置**：sourcemap 可访问（JS 文件尾 `sourceMappingURL=app.js.map`）

### 步骤

1. **拉 sourcemap**（1-2 包）：
   ```bash
   curl -s https://target.com/static/js/app.js | grep -oE 'sourceMappingURL=.*'
   curl -s https://target.com/static/js/app.js.map -o /tmp/app.js.map
   ```
2. **还原源码**（离线）：
   ```bash
   # shuji 或手动还原
   npx shuji -i app.js.map -o app-src/
   grep -rn "api/\|/v1/\|/v2/\|baseURL\|axios" app-src/ | grep -v node_modules
   ```
3. **找隐藏接口**（离线）：
   - grep API 路径：`grep -roE '"/[a-z]+/[a-z]+[^"]*"' app-src/`
   - 找鉴权逻辑：`grep -rn "Authorization\|token\|permission\|role" app-src/`
4. **测未鉴权接口**（每接口 1-2 包）：
   - 无 token 访问隐藏 API → 200 + 业务数据 = 未授权
   - 低权限 token 访问管理 API = 越权

### 失败 Pivot
- sourcemap 已关闭 → 转 JS bundle grep（`grep -oE '"/api/[^"]+"' app.js`）
- 接口需鉴权 → 试 auth-bypass 8 大头（`X-Original-URL` / 路径变形）
- 接口 404 → baseURL 可能不同，从 JS 找真实 baseURL

### 危害证明标准
- verified：隐藏接口 + 未鉴权访问返回业务数据
- phenomenon：找到隐藏接口但都需要鉴权
- 法律边界：GET 只读，不批量拉数据

---

## 链 4：上传 → CDN 托管 → 钓鱼/XSS

**前置**：文件上传成功（任意文件可上传到服务器/CDN）

### 步骤

1. **确认上传后路径**（1-2 包）：
   - 响应含 URL → 直接用
   - 响应不含 URL → 猜测路径：`/uploads/` / `/files/` / `/static/uploads/` / CDN 域名
2. **测可执行内容**（2-3 包）：
   - 上传 HTML → 访问看 `Content-Type: text/html`（可触发 XSS）
   - 上传 SVG → 访问看是否执行内嵌 JS
   - 上传 PDF → 访问看是否可托管钓鱼页
3. **证明危害**（1-2 包）：
   - HTML 可执行 + 同域 = 存储型 XSS（可窃取 cookie）
   - CDN 可托管 + 可控域名 = 钓鱼页面（可信域名提高点击率）

### 失败 Pivot
- HTML 被 `Content-Type: application/octet-stream` → 试 SVG（`image/svg+xml` 常不拦）
- 上传后被 WAF 检测内容 → 试 demo-bank 式绕过（`var a=alert;a(1)` 变量别名）
- 路径不可猜测 → 试上传时指定 `filename` 参数控制路径

### 危害证明标准
- verified：上传 + 访问返回可执行内容 + 同域/可信域
- phenomenon：可上传但 Content-Type 强制 octet-stream（不可执行）
- 法律边界：上传 HTML/SVG/PDF 合规（不是 webshell），上传后验证完可删除

### 实战案例
acme PH-F-007：AppXite 未授权 multipart 上传 → 上传到 prod CDN → public 可访问 → 组合拳优先投递

---

## 链 5：未授权 API → 权限树 → 批量数据

**前置**：发现未授权 API（无 token 返回业务数据）

### 步骤

1. **枚举同前缀 API**（5-10 包）：
   - 已知 `/api/v1/users/list` → 试 `/api/v1/users/create` `/api/v1/users/delete` `/api/v1/roles/list`
   - 用 `api-guessing.md` 的 Get*/List*/Search* 模式枚举
2. **找权限/配置接口**（3-5 包）：
   - `/api/permissions/list` / `/api/roles/list` / `/api/config/get`
   - 权限树暴露 = 可枚举所有功能点
3. **找数据接口**（3-5 包）：
   - 权限树里的功能 → 对应数据接口
   - `/api/<module>/list` `/api/<module>/export` `/api/<module>/search`
4. **证明批量危害**（2-3 包）：
   - `pageSize=2` 翻页验证数据量（不 bulk 拉取）
   - Count 接口或 `total` 字段证明影响范围

### 失败 Pivot
- API 需鉴权 → 试 auth-bypass 8 大头
- 数据接口返回空 → 试不同参数（`status=all` / `pageSize=100`）
- 有鉴权但权限树泄露 → 权限树本身是信息泄露（降级 phenomenon 但仍可报）

### 危害证明标准
- verified：未授权 API + 返回业务数据 + 数据量证明（count/pageSize）
- phenomenon：API 可访问但返回空/测试数据
- 法律边界：`pageSize=2` 验证，**禁 bulk**（批量拉取 = 越界违法）

### 实战案例
internal-10.0.0.3 F-15/F-16：24020 Permission/GetAllPermissions 返回 518 项权限树 → DataSync/GetProducts 返回 138 条产品数据 → 证明未授权数据泄露

---

## 通用链式原则

1. **每条链登记到 `_STATE.md`** 深挖焦点&假设链段，不等 verified 才想链
2. **失败不放弃**——单 phenomenon 升不了 verified，但 A+B 组合可能升（组合验证）
3. **法律红线贯穿**——每条链的"证明危害"步骤都是 GET 只读/截图证明，不连 DB/不调云 API/不 bulk
4. **扩战果须请示**——链式利用到 RCE/横向/逃逸等后渗透，写 `_PENDING.md` 请示（law.md §4.1）
5. **链式报告**——kill chain 写 `targets/<t>/output/report-killchain-<日期>.md`，按 odoo 格式（摘要→环境→Kill Chain 总览→分步复现）

## Related

- `doctrine/reflexes.md` 常见链式模板 — 8 条启发式参考
- `CLAUDE.md` 铁律·组合验证 — phenomenon 组合升 verified
- `ssrf-arbitrary-file.md` — 链 1/2 的前置 skill
- `api-guessing.md` — 链 3/5 的接口枚举
- `file-upload.md` — 链 4 的前置 skill
- odoo killchain 报告 — `targets/odoo-198.51.100.2-9912/output/report-killchain-rce-to-escape-2026-07-16.md`
