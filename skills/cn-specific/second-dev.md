# 二开框架识别与二开层漏洞位置

> **定位**:已知是"基于 X 框架二开"(RuoYi/Jeecg-Boot/ThinkPHP 等)之后,**二开改了什么、没改什么、改完留下哪些洞**。本文不重复厂商指纹(见 `skills/fingerprint/recon-product-fingerprint.md`),只讲"二开层"特有的攻击面定位。

## Triggers (何时用)

- 看到 `/system/` `/jeecg-boot/` `/index.php?s=` `/actuator` `/admin/` `/debug/` 等框架特征路径
- 响应里有若依/Jeecg/ThinkPHP 默认文案、Logo、版权、错误格式
- 抓到 `/jmreport/` `/online/` `/dev/` `/gen/` 等代码生成器/在线表单/低代码路径
- 目标明显是基于开源框架做的行业系统(如基于若依的 OA、基于 Jeecg 的 ERP)
- 配置中心(nacos/apollo)暴露或可被未授权访问

## Coverage points (查什么)

- **二开层改的地方**:登录页/权限/路由前缀/错误页/CSP/Logo/数据库表前缀
- **二开层不改的地方**:原始框架高危接口(代码生成器/在线表单/调试端点/actuator)
- **幽灵接口**:原框架接口二开后路由仍可达,但鉴权被改(原要 admin,二开后默认 token 即可)
- **二开添加的 API**:通常无鉴权或鉴权不严(开发者漏配 `@PreAuthorize` / shiro 注解)
- **配置即漏洞**:二开把凭据/密钥/连接串写进配置文件且配置可读
- **二开调试/日志接口**:开发遗留的 `/test/` `/debug/` `/api/dev/` `/log/view`
- **二开后门(供应链风险)**:二开模板被植入后门(近年若依/Jeecg 镜像供应链事件)
- **代码生成器滥用**:若依/Jeecg 的代码生成器可生成任意表 CRUD → 信息泄露 + 可写表注入

## Common misses (AI 常忘)

- 只测二开业务功能,漏了 **原框架默认接口没被二开删除**(jmreport/online/gen/actuator 是重灾区)
- 二开改了路由前缀(`/api/`)就以为原路径(`/system/`)不可达 → 老路径常仍残留可达
- 二开添加 API 只测业务接口,漏了 **二开者常忘加权限注解的"工具类"接口**(导出/字典/上传)
- 配置中心(nacos/apollo)只看是否暴露,漏了 **默认凭据 nacos/nacos + 配置内含数据库密码**
- 二开框架的 Excel 导入只测上传,漏了 **若依/Jeecg 的 Excel 导入解析器有历史 CVE**
- 把 actuator 暴露当低危信息泄露 → `env` 端点常含数据库密码 / `heapdump` 可提取密钥(高危)
- 二开后门只测常见 webshell,漏了 **供应链级后门(伪装成正常功能的隐藏接口)**
- 幽灵接口鉴权被改但**只测原路径**,漏了二开新前缀下的同名接口

## Verification (verified 标准)

- 二开层未授权访问:能调到原框架高危接口且返回非登录页 = 真;重定向到登录 = 误报
- 配置泄露:`env` / `/actuator/env` / `.env` 返回含 `password`/`secret`/`apikey` 字段 = 真;只有非敏感配置 = 低危
- 幽灵接口:原路径 + 二开新前缀路径都测,任一返回数据 = 真
- 二开后门:接口行为明显异常(任意命令执行/任意文件读)且非框架原生功能 = 真;功能正常 = 误报
- heapdump 提取:下载后用 `jhat` / `MemoryAnalyzer` 能搜到 `password=`/`secret=` 字符串 = 真
- nacos 默认凭据:`nacos/nacos` 登录成功且能读配置 = 真;改密码后 = 误报

## Related playbooks

- 厂商指纹识别(国产 OA/ERP 厂商) → `skills/fingerprint/recon-product-fingerprint.md`
- CN N-day 匹配 → `skills/fingerprint/nday-fingerprints.yaml`
- 鉴权绕过通用 → `skills/api-logic/auth-bypass.md`
- IDOR/BOLA 通用 → `skills/api-logic/idor-bola.md`
- OA/ERP 业务模块越权 → `skills/cn-specific/cn-oa-erp.md`
- 自研加密/签名逆向 → `skills/js-reverse/crypto-sign.md`
- 路由提取(前端 JS) → `skills/js-reverse/js-deep-analysis.md`

## Reference (深度参考 — AI 可能不会的细节)

### 基于若依(RuoYi)二开 — 残留路径与高危点

```
/system/user/list              ← 用户列表(原 admin 接口,二开常忘改权限)
/system/role/list              ← 角色列表
/system/menu/list              ← 菜单列表(含所有路由,信息泄露)
/system/config/list            ← 参数配置(常含默认密码/密钥)
/system/dept/list              ← 部门树
/monitor/server                ← 服务器监控(CPU/内存/磁盘,信息泄露)
/monitor/cache                 ← Redis 监控
/tool/gen/list                 ← 代码生成器(可生成任意表 CRUD → 表结构泄露)
/tool/swagger/index.html       ← Swagger 文档(若开启)
/common/download?fileName=xxx  ← 任意文件下载(老版本路径穿越)
```

- **数据权限绕过**:`params[dataScope]` 参数控制数据范围,二开常忘校验 → 传 `params[dataScope]=` 空值绕过租户隔离
- **Excel 导入解析**:若依 ExcelUtil 用 POI,老版本有公式注入 + XXE
- **默认凭据**:admin/admin123(若依官方默认,二开常忘改)
- **二开新前缀**:若二开把 `/system/` 改成 `/api/system/`,**两个前缀都测**

### 基于 Jeecg-Boot 二开 — 残留路径与高危点

```
/jmreport/list                  ← 在线报表(历史未授权 + SSTI + RCE,CVE-2023-49442)
/jmreport/loadTableData         ← 任意 SQL 执行(jmreport 经典)
/jmreport/show                  ← 报表查看(未授权)
/online/cgform/api/             ← 在线表单 API(自动生成 CRUD,SQLi)
/online/cgreport/api/getColumnsAndData  ← 在线报表数据接口(SQLi)
/jeecg-boot/sys/                ← 系统接口
/jeecg-boot/sys/login           ← 登录(测默认 admin/123456)
/jeecg-boot/sys/user/queryUserByDepId  ← 用户查询
/jeecg-boot/dev/                ← 开发调试接口(常忘删)
/jeecg-boot/sys/common/download  ← 文件下载
```

- **jmreport `loadTableData`**:可执行任意 SQL,部分版本无鉴权 → 直出数据 / 写 webshell
- **在线表单 `cgform`**:自动生成 CRUD,二开常忘给生成的接口加权限
- **默认凭据**:admin/123456(Jeecg 官方默认)
- **`/dev/` 接口**:开发期接口,生产常忘删,含 SQL 执行 / 类加载 / 字典导出

### 基于 ThinkPHP 二开 — 路由模式与残留

```
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1   ← TP5 RCE 经典
/index.php?s=/index/\think\Request/input&filter=phpinfo&data=1
/?s=index/think\app/invokefunction
```

- **路由模式识别**:`?s=` 是 TP 路由参数;`/module/controller/action` 是 pathinfo
- **二开常改**:路由前缀 `/index.php/` → `/api/`,但 `?s=` 入口常残留
- **TP6+**:默认不开启 `app_debug`,但二开常开 → 报错页泄露路径
- **TP 默认异常**:异常页含完整 SQL + 文件路径 + 表名(信息泄露)

### 基于 Spring Cloud Gateway 二开 — actuator 与路由注入

```
/actuator                       ← 端点列表
/actuator/env                   ← 环境变量(含数据库密码/密钥)
/actuator/heapdump              ← 堆转储(可提取内存中密钥)
/actuator/gateway/routes        ← 网关路由配置
/actuator/gateway/refresh       ← 刷新路由(可注入恶意路由 → SSRF/RCE,CVE-2022-22947)
/actuator/loggers               ← 日志级别(可改 DEBUG → 日志泄露)
```

- **CVE-2022-22947**:可注入恶意 filter 路由,执行 SpEL → RCE
- **heapdump 提取**:`jhat -port 7000 heapdump`,搜 `password`/`secret`/`apikey`/`jdbc`
- **二开常忘**:actuator 端点未限制 IP / 未关 `env` `heapdump`

### 基于 Django / Flask / Laravel / YII 二开 — 残留与默认

| 框架 | 二开残留路径 | 默认凭据/坑 |
|---|---|---|
| Django | `/admin/`(默认后台) `/media/` `/static/` | `DEBUG=True` 信息泄露;admin 默认 superuser;`/admin/auth/user/` 用户列表 |
| Flask | `/api/v1/` werkzeug `/console`(PIN) | werkzeug debugger PIN 可爆破;`app.config['SECRET_KEY']` 弱 → session 伪造 |
| Laravel | `/.env`(泄露) `/storage/logs/laravel.log` | `APP_DEBUG=true` → ignition RCE(CVE-2021-3129);`/.git/config` 残留 |
| YII | `/debug/`(debug module) `/gii/`(代码生成器) | debug module 残留 → SQL/请求历史泄露;gii 可生成代码 → 写 shell |

### 基于 nacos / apollo 二开 — 配置中心默认凭据

```
nacos:
  /nacos/v1/auth/users/login         ← 登录(默认 nacos/nacos)
  /nacos/v1/cs/configs?dataId=xxx&group=xxx  ← 拉配置(老版本未授权,CVE-2021-29441)
  /nacos/v1/auth/users?pageNo=1&pageSize=10  ← 用户列表(未授权)

apollo:
  /apollo                            ← 配置中心
  /configfiles/{appId}/{env}/{cluster}/{namespace}  ← 拉配置(常未授权)
```

- **nacos 默认凭据**:`nacos/nacos`(官方默认,二开常忘改)
- **CVE-2021-29441**:老版本 `User-Agent: Nacos-Server` 即可绕过鉴权
- **配置内含**:数据库连接串 / Redis 密码 / 第三方 API 密钥 / 短信网关密钥

### "幽灵接口"模式详解

二开常做的事:把原框架接口的鉴权从"必须 admin"改成"必须登录",或改成"放行"。结果:

```
原框架:    /system/user/list  →  需要 ROLE_ADMIN
二开后:    /system/user/list  →  需要登录(任意用户可调)
          /api/system/user/list  →  同接口新前缀,可能完全无鉴权(开发漏配)
```

- **必测**:同一接口的两个前缀(原 + 二开新)都测
- **必测**:二开新加的 `/api/` 前缀下,原框架所有接口路径都试一遍(常发现漏配权限注解)
- **二开 API 无鉴权模式**:二开者加接口时常忘加 `@PreAuthorize` / shiro 注解 / 中间件

### 二开后门与供应链风险

- **近年事件**:若依官方镜像曾被植入后门;Jeecg 镜像源被替换
- **后门特征**:
  1. 接口名伪装成正常功能(`/api/common/utils` `/api/system/init`)
  2. 接受 base64/加密参数 → 内部执行命令
  3. 异常的过滤逻辑(特定 User-Agent / 特定 header 触发)
- **排查**:对比官方开源代码,找二开新增的"工具类"接口;查 `@RequestMapping` 中异常路径

### 二开层漏洞优先级

```
1. 原框架高危接口未删/未鉴权(jmreport/online/gen/actuator)← 最高,直接 RCE 或数据全出
2. 配置泄露(env/.env/nacos/heapdump)                    ← 高,含密钥可横向
3. 二开新增 API 无鉴权                                  ← 中-高,业务数据泄露
4. 幽灵接口(原路径残留 + 新前缀)                       ← 中,信息泄露 + 越权
5. 二开后门/供应链                                      ← 罕见但致命
```
