---
name: fuzz
domain: fuzz|discovery|enumeration
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 系统化 Fuzz 方法论（5 维度）

> **定位**：v6 删了 fuzz-engine/param-fuzz/tech-fuzz/dict-harvest/signal-verify 5 个脚本（AI 能现场写），但方法论丢了。本 skill 补**判断框架**——何时 fuzz / 怎么投 / 怎么判读信号 / 怎么学习反哺。payload 在 `wordlists/` 里有，这里不重复。
>
> **与 api-guessing.md 的分工**：api-guessing 是"接口盲猜"视角（CRUD 矩阵 / 同前缀枚举），本 skill 是"系统化 fuzz"视角（5 种 fuzz 类型 + 信号判断 + 字典学习）。

## Domain

- 路径不明：surface.md 接口列表薄，怀疑有隐藏接口
- 参数不明：已知接口但不知道接受哪些参数
- 漏洞类型不明：已知参数但不知道注入类型
- 值不明：已知参数+类型但不知道有效值（ID/枚举）
- 信号不明：fuzz 出一堆响应，不知道哪些是真信号
- modes: 全模式——fuzz 是攻击面扩展的核心手段

## Boundaries

- 路径/参数/目录 fuzz = GET 只读，免请示（law.md §4.2 定向扫描）
- payload fuzz 含 POST/PUT → 重武器，须 _PENDING 请示
- 值枚举（ID 遍历）= GET 只读合规，但**盲 ID 枚举走 materials gate**（无真实样本 ID → 停 enum，不烧字典）
- 限速 `-t 5`，不 `-t 100` 拖垮目标
- WAF 目标降频（见 `waf-evasion.md` 速率自适应）

## 5 个维度

### 维度 1：路径 fuzz（技术栈感知）

**何时用**：进场后接口列表薄 / 怀疑有隐藏 admin/debug 面。

**怎么投**：
```bash
# L0/L1 先加载已沉淀强信号（开 fuzz 前必做——跨目标实测洞路径，比字典高效）
#   本目标: cat targets/<t>/recon/dict/* 2>/dev/null
#   跨目标: cat wordlists/learned/api-paths.txt 2>/dev/null
#   例: /strategy/validate-expression（ACM-F-001 实证 SpEL 注入 38 资产）直接投

# L1 定性（50 个高频路径，先判断有没有东西）
ffuf -u "https://target.com/FUZZ" -w wordlists/dir-common.txt -t 5 -mc 200,401,403,405

# L2 技术栈感知（按指纹追加对应字典）
# 先看 Server header / 技术栈 → 追加对应路径
# Spring Boot: /actuator/* /druid/ /h2/console /swagger-ui.html
# .NET: /Account/* /swagger/v1/swagger.json /_framework/blazor.boot.json
# PHP: /wp-admin/ /phpmyadmin/ /phpinfo.php /.env
# Node: /graphql /socket.io/ /.npmrc /metrics
# Java: /manager/html /jmxConsole/ /nacos/ /jenkins/
# 字典见 wordlists/api-paths.txt（含 #spring #dotnet 等技术栈标记）

# L3 深度扫（大字典，仅在 L2 有信号时）
# 走 external.yaml 指向的本机字典（SecLists/Assetnote），不入库
```

**递进策略**：L1(50) → 有信号 → L2(400) → 有信号 → L3(5000+)。不要上来就 L3。

**技术栈路径表**：见 `api-guessing.md` Reference 段（已有完整表，不重复）。

### 维度 2：参数 fuzz（隐藏参数发现）

**何时用**：已知接口但 Body/Query 参数少 / 怀疑 mass assignment。

**怎么投**：
```bash
# 方法 1: ffuf 参数发现（Query 参数）
ffuf -u "https://target.com/api/user?FUZZ=test" -w wordlists/param-names.txt -t 5 -mc 200,500

# 方法 2: 手工高价值参数（5-10 个，比字典快）
# debug / admin / role / isadmin / fields / limit / _method / format / callback / test

# 方法 3: mass assignment（POST Body 加字段）
curl -X POST https://target.com/api/user/update -d '{"name":"test","role":"admin","isAdmin":true}'

# 方法 4: HPP（参数污染）
curl "https://target.com/api/user?id=1&id=2"
curl "https://target.com/api/user?id[]=1"
```

**命名变异**：每个参数试 3 种风格（camelCase / snake_case / PascalCase）。后端 ORM 常只认一种。见 `api-guessing.md` 参数名变异规则表。

### 维度 3：payload fuzz（多漏洞混合投）

**何时用**：已知参数但不知道注入类型 / 一个参数可能同时是 SQLi+XSS+SSRF+命令注入。

**怎么投**：对同一参数投多种 payload，看哪种有信号：
```bash
# 手工混合投（5-10 个 payload，比单一类型字典快）
# 假设参数是 q=
curl "https://target.com/api/search?q='"              # SQLi 字符串截断
curl "https://target.com/api/search?q=1 AND 1=2"     # SQLi 数字盲注
curl "https://target.com/api/search?q=<script>1</script>"  # XSS
curl "https://target.com/api/search?q={{7*7}}"        # SSTI
curl "https://target.com/api/search?q=;id"            # 命令注入
curl "https://target.com/api/search?q=file:///etc/passwd"  # 任意文件读
curl "https://target.com/api/search?q=http://127.0.0.1/"   # SSRF
```

**优先级**：按 QUICK.md SRC 主奖品分布——RCE/文件读/SSRF ≫ SQLi/IDOR ≫ 其他。先投高奖 payload。

**POST payload fuzz 是重武器** → _PENDING 请示。

### 维度 4：字典学习（从响应反哺）

**何时用**：fuzz 过程中发现新路径/参数/错误信息泄露。

**怎么学**：
```bash
# 1. 从 JS bundle 提取路径
grep -oE '"/[a-z]+/[a-z]+[^"]*"' targets/<t>/recon/*.js | sort -u >> wordlists/learned/api-paths.txt

# 2. 从错误信息提取参数名
# "Required parameter 'userId' is not present" → userId 加入 param-names.txt
grep -oE "parameter '([^']+)' is not present" targets/<t>/recon/*.txt >> wordlists/learned/param-names.txt

# 3. 从响应字段名提取参数
# 响应 JSON {"userName":"x","roleId":"y"} → userName/roleId 可能是 mass assignment 字段

# 4. 沉淀规则：只写强信号（业务JSON/未授权敏感面/真实stack leak）
#    不写 SPA soft-404 / 纯HTML壳 / 静态资源
```

**目标专属字典**（L0）放 `targets/<t>/recon/dict/`，跨目标沉淀（L1）放 `wordlists/learned/`。不 commit 大字典。

### 维度 5：信号判断（最关键）

**何时用**：fuzz 出一堆响应，不知道哪些是真信号。这是 v5 signal-verify.py 做的事，删了后没有方法论。

**5 类响应的判读**：

| 响应特征 | 判定 | 动作 |
|---|---|---|
| 200 + 业务 JSON（含真实数据） | **真信号** | 深挖 |
| 200 + 与 baseline 完全相同（SPA fallback / 全返同一页） | **soft-404** | 忽略，不是真接口 |
| 401/403 + 统一拦截页 | **鉴权墙** | 试 auth-bypass 8 大头，不行标 Dead End |
| 403/503 + WAF 拦截页（CF-Ray/阿里云拦截特征） | **WAF 拦截** | 降频或绕过（见 skills/fingerprint/waf-evasion.md） |
| 500 + stack trace | **真信号**（信息泄露） | 看堆栈找框架/版本/内部路径 |
| 200 + 空 body / `{"code":0,"data":null}` | **默认占位** | 改参数值再看差异 |

**去噪关键步骤**：
```bash
# 1. 先记录 baseline（GET / 的响应大小/hash）
curl -s https://target.com/ | wc -c  # 例: 41189 字节 = SPA shell
curl -s https://target.com/ | md5sum # 例: abc123 = shell hash

# 2. fuzz 时过滤 baseline 响应
ffuf -u "https://target.com/FUZZ" -w wordlists/api-paths.txt -t 5 \
  -mc 200,401,403,405 -fs 41189  # -fs 过滤掉 41189 字节的 SPA fallback

# 3. 对 200 响应做差分（与 baseline 对比内容）
# 同 size ≠ 同内容 → 用 -fr 过滤响应文本
```

**SPA fallback 检测**（bazaar 教训）：
```
developers.bazaar.com 的 SPA shell = 41189 字节
任何返 41189 字节的请求都是 SPA fallback，根本没有命中 API
→ 探针前先记录该域 shell size，然后过滤
```

**soft-404 检测**：
```
GET /totally-nonexistent-path-12345 → 看返回
如果 200 + 和首页一样 = soft-404（所有路径都返首页）
如果 404 = 正常 404（只有真实路径才 200）
```

**默认占位检测**（acme/8038 教训）：
```
任意 ID 全返一致 default → L0 第 3 条铁律咬人
改 ID → 响应不变 = 占位回包，不是业务结果
改 ID → 响应变化 = 真业务数据
```

## 批量探测后选目标深挖（扫完不是结束，是开始）

> **教训**：示例甲方 SRC 2180 目标批量扫描 → 0 verified。之前 9 个 verified 全是选 3-5 个目标深度 API 测试挖出来的。广度扫描只是选目标，深度挖掘才出洞。

### 思维框架：广度选目标，深度出洞

批量探测的目的是**快速分类、选出值得深挖的目标**，不是穷尽扫描。扫完后问自己：

- 哪些目标有后端 API（不是 SPA fallback）？
- 哪些目标能登录（有测试账号 / 能注册 / 有默认凭据）？
- 哪些目标有已知产品指纹（能匹配 CVE / playbook）？
- **选完 Top 5 后立即停止扫描，切到深度模式。**

### 结果分类思路

扫完后的目标按信号强度分类——但不要机械化分类，要思考"这个目标为什么值得深挖"：

- **有 API 路径**：JS/HTML 里提取到 /api/ /v1/ → 最值得深挖，逐个 API 测
- **有登录页**：能登录 = 认证后攻击面打开 → 登录后测 IDOR/越权
- **有管理面板**：/admin /console → 试凭据 / 未授权 / 默认配置
- **有产品指纹**：Struts2/Spring/Tomcat/Keycloak/Nacos → 匹配 CVE + playbook
- **特殊端口**：非 80/443 → 识别服务 → 可能暴露管理接口
- **大 body SPA**：可能藏 API → 从 JS 深入提取（但不深挖 SPA 本身）

### baseline 去噪思路

**核心：区分"真信号"和"SPA fallback"。** 每个目标先记录首页 baseline——后续探测结果与 baseline 对比，一致的就是 fallback，不一致的才值得深挖。

已知 fallback 特征：所有路径返回同一 size / title 含 404/Not Found / Next.js(`/_next/`) / Nuxt / OSS 静态托管(`NoSuchKey`) / 返回的 HTML 和首页完全一样。

### 深挖切换思路

什么信号出现时该停止扫描切深度模式——不要等"扫完所有目标"，有信号就切：

- 发现真 API 路径（非 SPA fallback）→ 切 authed-deep-dive.md
- 能登录（有账号 / 注册成功 / 默认凭据）→ 切 authed-deep-dive.md
- 发现产品指纹 → 查 playbook / CVE
- 发现 actuator/swagger 真暴露 → 切 reflexes.md

**铁律：时间分配广度 ≤30%，深度 ≥70%。** 扫完选目标不超 30% 时间，70% 花在深挖选中的目标。

## Common misses

- **上来就 L3 大字典** → 先 L1(50) 定性，有信号再 L2/L3
- **不记录 baseline** → 200 响应全是 SPA fallback 却以为发现了接口
- **不区分真信号和 soft-404** → fuzz 出 200 个"发现"全是同一个 fallback 页
- **只 fuzz 路径不 fuzz 参数** → 路径找到但参数不明 = 无法利用
- **不学习反哺** → 同一目标多次 fuzz 用同一字典，不从响应学新路径
- **POST payload fuzz 不请示** → payload fuzz 含 POST = 重武器（law.md §4.1）
- **扫完不切深度** → 广度扫描扫了 2000 个目标 0 verified，不如深挖 5 个目标
- **`-t 100` 拖垮目标** → 限速 `-t 5`，政企 ≤ 2 RPS

## Verification

- **fuzz 发现新接口 verified**：200 + 非 baseline 内容 + 返回业务数据
- **fuzz 发现新参数 verified**：参数触发响应差异（状态码/长度/内容变化）
- **phenomenon**：200 但是 soft-404 / 401 但是无绕过 / 有差异但无业务影响
- **rejected**：全部 baseline 响应 / 全部 404

## ⚠️ 红线

- 路径/参数/目录 fuzz = GET 只读，免请示
- payload fuzz 含 POST/PUT → _PENDING 请示（重武器）
- 盲 ID 枚举走 materials gate（无真实样本 → 停 enum）
- 限速 `-t 5`，不拖垮目标
- WAF 目标降频（5 包后暂停 30 秒）

## Related

- `api-guessing.md` — 接口盲猜视角（CRUD 矩阵 / 同前缀枚举 / 技术栈路径表）
- `ssrf-arbitrary-file.md` — SSRF payload 投递（维度 3 的特化）
- `waf-evasion.md` — WAF 目标的速率自适应
- `wordlists/README.md` — L0/L1/L2/L3 四层字典架构
- `doctrine/law.md` §4.2 — 定向扫描免请示（单 host + ≤200 entries + 仅 GET + 已知锚点）
