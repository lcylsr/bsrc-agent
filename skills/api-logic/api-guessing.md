# 接口盲猜与参数 Fuzz

## Triggers (何时用)

- `surface.md` 已有的接口列表很薄,怀疑还有未公开接口
- 看到"半 RESTful"路径(`/api/user/get`),怀疑配套有 `update`/`delete`/`list`
- POST 请求 Body 字段少,怀疑后端接受未声明参数(mass assignment)
- 接口返回字段多于 UI 显示(怀疑前端过滤)
- **已知 1 个鉴权前接口必跑**(bluegate 实测:`/Account/GetLoginPageInfo` → 同前缀 13 包枚举捞到 `/account/islogged`)

## Coverage points (查什么)

- 隐藏接口:同义词补全(get→list/search/detail)、版本枚举(v1→v2/v0/internal/admin/dev)、文档泄露(swagger/openapi/actuator/debug 路由 — 进场扫一遍)
- 参数 Fuzz:Param Miner 自动挖 Header/Body/Query 隐藏参数;高价值参数手工试(`debug / admin / role / fields / limit / _method / format`)
- Mass Assignment:主动加 `role / is_admin / isAdmin / verified / balance / permissions / groups`,多种命名都试(后端常用其一)
- HPP:`?id=1&id=2` 看后端取首/末/数组/报错;`?id[]=1` 数组语法;`?id[$ne]=null` 配 NoSQL
- CRUD 矩阵:看到任一资源路径,展开全部 CRUD × 命名风格变体(见 Reference)
- 技术栈感知:看指纹追加对应路径字典(见 Reference)

## Common misses (AI 常忘)

- **参数命名风格只试一种**:后端 ORM 映射常常只认一种(camelCase / snake_case / PascalCase),同一参数 3 种风格都要试
- **CRUD 只补动词不补命名风格**:`getUserList` 命中但 `get_user_list` 漏掉,后端不一致命名极常见
- **隐藏接口存在但需鉴权,自己没权访问** —— 不算漏洞,只是未公开
- **Mass assignment 改了字段但回显原值** —— 后端忽略了未声明字段,无效
- **参数 fuzz 出 `debug=1` 但只多了一行 stack** —— 信息量低,SRC 给低危或拒

## Verification (verified 标准)

- 隐藏接口:200 / 401 / 403 都算"存在"(404 不算);**只有拿到 200 且返回非公开数据才算可用漏洞**
- Mass Assignment:改字段后**响应回显新值**(如 role 变成 admin),且后续接口确认权限变化 = 真
- 参数 fuzz:响应长度 / 状态码 / 报错信息与 baseline 有显著差异
- 限速 `-t 5`,别 `-t 100` 拖垮目标

## L1 提醒

- 接口枚举属**只读**,放行
- Mass assignment 测试**必须用测试小号**,改自己资料无害,改他人触红线

## Related playbooks

- 发现新接口 → 写 `targets/<X>/surface.md`
- 看到 GraphQL → `skills/injection/nosql-graphql.md`
- 看到 WAF 拦 fuzz → `skills/fingerprint/waf-evasion.md`

## Reference (深度参考 — AI 可能不会的细节)

### CRUD 矩阵(资源 × 动词 × 命名风格)

看到任意资源路径(如 `/api/user`),自动展开全部 CRUD 变体:

| 动作 | camelCase | snake_case | PascalCase | RESTful | 常见别名 |
|---|---|---|---|---|---|
| 列表 | getUserList | get_user_list | GetUserList | GET /users | list/query/search/find/fetch |
| 详情 | getUserInfo | get_user_info | GetUserInfo | GET /users/:id | detail/item/show/view |
| 创建 | createUser | create_user | CreateUser | POST /users | add/new/save/submit/register |
| 更新 | updateUser | update_user | UpdateUser | PUT/PATCH /users/:id | edit/modify/patch/change/set |
| 删除 | deleteUser | delete_user | DeleteUser | DELETE /users/:id | remove/del/drop/cancel |
| 计数 | getUserCount | get_user_count | GetUserCount | GET /users/count | total/size/stat |

**扩展规则**:
- 看到任何一种命名,其余 5 种**全部试一遍**(后端不一致命名极常见)
- 资源名复数化:user→users, person→people, child→children
- 嵌套资源:`/api/user/:id/orders` → 同样展开 CRUD

### 技术栈感知路径扩展

看到技术栈指纹后,**自动追加**对应路径字典（AI 用 curl 逐个探，或喂给 scanner-dispatch nuclei）:

| 技术栈 | 必追路径 | 信号来源 |
|---|---|---|
| **Spring Boot** | `/actuator/**`(health→env→heapdump→jolokia), `/druid/`, `/h2/console`, `/swagger-ui.html`, `/v2/api-docs` | `X-Application-Context`, /actuator 响应 |
| **.NET** | `/Account/Login`, `/Account/GetLoginPageInfo`, `/Account/islogged`, `/Identity/Account/*`, `/api/WeatherForecast`, `/_framework/blazor.boot.json`, `/swagger/v1/swagger.json` | `X-AspNetMvc-Version`, `X-Powered-By: ASP.NET` |
| **PHP/WordPress** | `/wp-login.php`, `/wp-admin/`, `/wp-json/wp/v2/`, `/phpmyadmin/`, `/phpinfo.php`, `/.env`, `/debugbar` | `X-Powered-By: PHP`, `wp-content` 路径 |
| **Node.js** | `/api/health`, `/graphql`, `/graphiql`, `/.npmrc`, `/socket.io/`, `/_status/`, `/metrics` | `X-Powered-By: Express`, `__NEXT_DATA__` |
| **Python/Django** | `/admin/`, `/docs/`, `/redoc/`, `/swagger/`, `/__debug__/`, `/silk/`, `/flower/`, `/django-debug-toolbar/` | `csrfmiddlewaretoken`, `X-Frame-Options` Django 特征 |
| **Java 通用** | `/manager/html`, `/jmx-console/`, `/jolokia/`, `/nacos/`, `/xxl-job-admin/`, `/solr/`, `/druid/`, `/jenkins/` | `Server: Coyote`, JSESSIONID cookie |

用法:AI 按上表路径用 curl 逐个探活(每路径 1 包),或 `bash tools/run.sh scanner-dispatch nuclei <target_dir> <url> --tags <tech>`。

### 参数名变异规则

已知一个参数名,自动推断其余风格:

| 已知风格 | → camelCase | → snake_case | → PascalCase |
|---|---|---|---|
| `user_id` | `userId` | `user_id` | `UserId` |
| `userId` | `userId` | `user_id` | `UserId` |
| `UserId` | `userId` | `user_id` | `UserId` |
| `is_admin` | `isAdmin` | `is_admin` | `IsAdmin` |
| `order_by` | `orderBy` | `order_by` | `OrderBy` |
| `page_size` | `pageSize` | `page_size` | `PageSize` |

**铁律**:参数 fuzz 时,每种命名风格都要试 — 后端 ORM 映射常常只认一种。(`wordlists/param-names.txt` 已含多风格变体,ffuf 直接引用)

### Fuzz 字典优先级

```
wordlists/api-paths.txt          # 按技术栈标记的 API 路径字典
wordlists/param-names.txt        # 参数名 + mass assignment 字段
wordlists/ssrf-payloads.txt      # SSRF/任意文件读 payload
wordlists/dir-common.txt         # 分层目录字典 L1/L2/L3 递进
```

工具:`ffuf -w wordlists/api-paths.txt -t 5`(推荐)、`Arjun`。**不要 `-t 100` 拖垮目标**。
