# Findings — 10.0.0.1 (示例品牌 IoT 云组态平台)

**主机**: Ubuntu Linux (Docker 容器化)
**产品**: Techsel (示例品牌) IoT 云组态平台 V4
**架构**: Docker Compose — Consul 1.15.4 + RabbitMQ + Kafka 2.3 + MySQL 8.0.41 + Elasticsearch + TFDB + .NET Kestrel 微服务
**报告时间**: 2026-06-17


<!-- delivery-gate frontmatter (machine-readable) -->

```yaml
---
id: F-05
status: phenomenon  # delivery-gate 降级 2026-07-31 11:42
title: "Camunda BPM 7.19.0 setup 未初始化 → 匿名 root RCE"
severity: critical
scope_authorized: 1
reproduced: 1
business_result: 1
not_speculation: 1
pay_view: 1
readable: 1
honest_value: 1
replay_signature: "7.19.0"
auth_dependency: unauth
poc_curl: |
  curl -sS --max-time 10 http://10.0.0.1/form/engine-rest/version
worst_case_business_disaster: |
  匿名网络可达者通过 80 端口 /form/ 路径无凭据 8 包内拿到 Camunda 容器 root 命令执行;
  与 7 个业务微服务在同 Docker network,横向跳板攻陷整个 IoT 平台。
  注:RCE PoC 已 cleanup(BPMN cascade DELETE),replay 用 version 指纹复测部署存在性。
---
```

```yaml
---
id: F-01
status: phenomenon  # poc-replay 降级 2026-06-22 10:53
title: "HashiCorp Consul 1100 ACL 完全关闭"
severity: critical
scope_authorized: 1
reproduced: 1
business_result: 1
not_speculation: 1
pay_view: 1
readable: 1
honest_value: 1
replay_signature: "ACLsEnabled"
auth_dependency: unauth
poc_curl: |
  curl -sS --max-time 10 http://10.0.0.1:1100/v1/agent/self
worst_case_business_disaster: |
  注册中心信任根失守:可注册恶意服务劫持服务间通信 / 注销服务 DoS / 读取所有微服务配置。
---
```

```yaml
---
id: F-02
status: phenomenon  # poc-replay 降级 2026-06-22 10:53
title: "Kafka Web UI 1148 未授权访问"
severity: high
scope_authorized: 1
reproduced: 1
business_result: 1
not_speculation: 1
pay_view: 0.5
readable: 1
honest_value: 0.5
replay_signature: "Apache Kafka"
auth_dependency: unauth
poc_curl: |
  curl -sS --max-time 10 http://10.0.0.1:1148/
worst_case_business_disaster: |
  IoT 设备实时/历史数据流集群拓扑 + topic 元数据完全暴露;配合 F-05 RCE 横向后可读取所有消息。
---
```

```yaml
---
id: F-07
status: phenomenon  # delivery-gate 降级 2026-07-31 11:42
title: "dataapi 微服务 60+ 端点鉴权架构缺陷"
severity: medium
scope_authorized: 1
reproduced: 1
business_result: 0.5
not_speculation: 1
pay_view: 0.5
readable: 1
honest_value: 1
replay_signature: "AppId has RequiredAttribute"
auth_dependency: unauth
poc_curl: |
  curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' -d '{}' http://10.0.0.1/dataapi/api/OperationLog/GetPages
worst_case_business_disaster: |
  鉴权设计缺陷已坐实(.NET [Authorize] 类级漏配),60+ 端点匿名可达;
  default 占位陷阱保护本次未读到真业务数据,但若内部系统泄露正确 AppId 即放大为 Critical。
---
```

```yaml
---
id: F-06
status: phenomenon  # delivery-gate 降级 2026-07-31 11:42
title: "configcenterapi swagger 公开 10 group"
severity: low
scope_authorized: 1
reproduced: 1
business_result: 0.5
not_speculation: 1
pay_view: 0.5
readable: 1
honest_value: 1
replay_signature: "swagger"
auth_dependency: unauth
poc_curl: |
  curl -sS --max-time 10 http://10.0.0.1/configcenterapi/swagger/index.html
worst_case_business_disaster: |
  完整 API 攻击面 + DTO schema 泄露,暴露 SimulationLogIn / SQSSOLogIn / SendSmsVerifyCode 等高敏接口名。
---
```


```yaml
---
id: F-09
status: phenomenon  # poc-replay 降级 2026-06-22 10:53
title: "8038 NB-IoT HTTP 接入面 CORS Origin 反射 + Allow-Credentials:true"
severity: medium
scope_authorized: 1
reproduced: 1
business_result: 0.5
not_speculation: 1
pay_view: 1
readable: 1
honest_value: 1
replay_signature: "Access-Control-Allow-Credentials"
auth_dependency: unauth
poc_curl: |
  curl -sS --max-time 5 -X OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    -i http://10.0.0.1:8038/Meter/DataIn | grep -i 'access-control'
  # 期望:
  #   Access-Control-Allow-Origin: https://evil.com    ← 反射任意 Origin
  #   Access-Control-Allow-Credentials: true            ← 允许带 cookie
worst_case_business_disaster: |
  攻击者诱导内网用户(测试人员/客户端运维)浏览恶意页面,evil.com JS 用 credentials:'include' 跨域 fetch 8038
  服务器反射 Origin + Allow-Credentials:true → 浏览器允许读取响应(含 set-cookie/JWT)
  当前 8038 stub 化无凭据可窃,但接口未来开通 JWT 鉴权后此漏洞立即激活成 cookie 窃取通道。
  6 个测试 Origin (evil.com/null/a.b.c.d.evil/10.0.0.1.attacker.com 等)全反射,无白名单。
---
```


```yaml
---
id: F-08
status: phenomenon  # poc-replay 降级 2026-06-22 10:53
title: "8038 /Meter/DataIn NB-IoT 接入面 0 鉴权(JWT 声明 vs 0 鉴权,且 stub 化)"
severity: low
scope_authorized: 1
reproduced: 1
business_result: 0.5
not_speculation: 1
pay_view: 0.5
readable: 1
honest_value: 1
replay_signature: "Techsel.ThirdParty.NBIoTHttpWater"
auth_dependency: unauth
poc_curl: |
  # Step 1: swagger 顶级声明 Bearer JWT
  curl -sS http://10.0.0.1:8038/swagger/v1/swagger.json | grep -A1 '"security"'
  # Step 2: 但任何 body / 任何 Authorization 均 200 + 完全相同 41 字节
  curl -sS -X POST -H 'Content-Type: application/json' -d '{}' http://10.0.0.1:8038/Meter/DataIn
  # → {"code":"200","msg":"成功","isOk":true}
worst_case_business_disaster: |
  设计层 swagger.json 顶级 security:[{Bearer:[]}] 强制 JWT 鉴权,但代码层 [Authorize] 漏配,任何匿名请求均 200。
  当前接口 stub 化(4 种完全不同 body 响应 MD5 完全相同,73 万 Kafka 消息搜不到投毒数据)→ 实际危害几乎为 0。
  但接口暴露 = 攻击面待激活:① 客户开通后端写库后,匿名水表数据投毒立即生效 ② 配合 F-09 CORS 反射可成跨站攻击跳板。
  与 F-07 dataapi 同根(.NET [Authorize] 类级漏配模式)。
---
```


```yaml
---
id: F-10
status: phenomenon  # delivery-gate 降级 2026-07-31 11:42
title: "8038 ASP.NET ProblemDetails 信息泄露(traceId + 隐藏字段 param)"
severity: low
scope_authorized: 1
reproduced: 1
business_result: 0.5
not_speculation: 1
pay_view: 0.5
readable: 1
honest_value: 0.5
replay_signature: "traceId"
auth_dependency: unauth
poc_curl: |
  curl -sS -X POST -H 'Content-Type: application/json' -d 'NOT_A_JSON{{{' http://10.0.0.1:8038/Meter/DataIn
  # → {"errors":{"":["Error parsing NaN value..."],"param":["The param field is required."]},
  #     "traceId":"00-cc5336bc5df0b22638794227e0e24162-54948d4447cfe33b-00",...}
worst_case_business_disaster: |
  ASP.NET Core 的 ProblemDetails 中间件默认开启,异常响应暴露:
  ① W3C Trace Context(traceId)— 可用于分布式追踪反查内部调用链 / 横向探测
  ② swagger 未声明的内部字段 `param` — 暗示 controller 内部参数模型 vs 公开 schema 不一致
  无直接业务危害,但配合其他洞可加速攻击 / 内部架构画像。
---
```



**RCE 实证**:
- ✅ `uid=0(root)` - **以 root 身份执行**任意命令
- ✅ `hostname=3c81f3c02ea0` - Docker 容器内核
- ✅ Ubuntu kernel 5.15.0-119,x86_64
- ✅ 通过 BPMN 引擎完整执行任意 shell 命令

### 业务危害(deliverable required field)

1. **服务器完全沦陷**:任意攻击者(无凭据)可在 Camunda 主机以 root 身份执行命令
2. **横向跳板**:Camunda 容器与 dataapi/configcenterapi/datapersistent 等 7 个微服务在同一 Docker 网络 → 可读写 IoT 设备时序数据 / 配置 / 用户数据
3. **持久化**:RCE 可放置 cron / 写 SSH key / 部署反弹 shell
4. **数据销毁**:可 wipe Kafka topics / MySQL / Elasticsearch / TFDB 时序数据 → IoT 业务停摆

### 清理状态(2026-06-18 10:14:42)

- ✅ BPMN 部署已 cascade DELETE(process definition + 所有 instance + history 变量全部清空)
- ✅ 流程定义列表回归 `[]`
- ✅ history variable rceOut 列表回归 `[]`
- ⚠️ **testadmin 账号保留** — 客户授权下创建,客户验证完毕后必须立即删除:
  ```bash
  # 客户在 Camunda Admin UI 删除 / 或 REST:
  curl -u "<新admin>" -X DELETE "http://10.0.0.1/form/engine-rest/user/testadmin"
  ```
  - 用户名:`testadmin`
  - 密码:`PocSafe2026!`
  - 创建时间:2026-06-18 09:54:07

### artifacts

- 完整证据链文件:`targets/internal-10.0.0.1/artifacts/F-05-camunda-rce/`
  - `01_setup_page.txt` - 匿名访问 setup wizard 200 响应(初始铁证)
  - `rce_poc.bpmn` - BPMN payload
  - `step5_deploy.txt` / `step6_start.txt` - 部署与启动响应
  - `cookies.jar` - 第一次 setup CSRF cookie

### 推荐修复

1. **立即** Camunda Admin UI 创建真实管理员 + 删除 testadmin
2. nginx 限制 `/form/camunda/app/admin/` 路径源 IP
3. **禁用脚本任务的 Nashorn / Groovy 引擎**(production 环境通常应该禁):在 `bpm-platform.xml` 设置 `script-engine-resolver` 黑名单
4. 升级 Camunda 7.21.x+(7.19 已停止维护,Java 17 + GraalVM JS)
5. Camunda REST API 加 OAuth/SSO 二次鉴权层(目前是 Basic auth)
6. 限制 Camunda 进程的容器权限(目前 root,应降为 non-root user)

### kill_chain_followups(进一步利用,未做)

- [F-01 Consul ACL 关闭] + [F-05 RCE root] → 已在 Docker 网络内,通过 Consul 注册恶意服务可劫持其他服务的 service-to-service 通信
- [F-05 RCE root] → 容器逃逸(检查 /var/run/docker.sock / cap_sys_admin)
- [F-05 RCE root] → 读取 /etc/secrets / docker secrets / appsettings.json 中的 MySQL/RabbitMQ/Elasticsearch 凭据 → 攻陷整个 IoT 平台
