---
name: cloud-security
domain: cloud|aws|azure|aliyun|k8s|container|s3|oss|cos|minio|ceph|iam|presigned-url|bucket-takeover
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 云安全测试方法论（云存储 / 签名 URL / IAM / K8s / 容器）

> **定位**：SSRF/任意文件读 skill 提到云元数据但不是专门打法。本 skill 补云安全系统化测试思路。给方向不局限方法。
> **2026-08-10 强化**：新增维度 1.5「签名 URL / 类型混淆 / 桶接管」——曾因缺此模块漏掉 response-content-type 类主动攻击面（ICH-F-001 实证：示例甲方 sci.acme.com S3 签名 URL 泄露 + 内网 XSS 载体）。

## Domain

- 目标部署在云上（AWS/阿里云/腾讯云/Azure/GCP）
- 有云存储（S3/OSS/COS/Blob）
- 有容器编排（K8s/Docker Swarm/Rancher）
- 有云服务暴露（IAM/Lambda/CloudFunctions/元数据服务）
- modes: src 高价值（云凭据 = 租户接管），redteam 入口价值

## Boundaries

- 云元数据只读不调用（拿凭据后不调云 API，只截图证明）
- 云存储只读不写（不上传/删除/修改桶内容）
- K8s/容器只读配置不执行命令
- 命中云凭据 = 严重漏洞，但只用 DNSLOG/截图证明存在，不实际利用
- 不实际连接 DB / 不调用云 API / 不横向

---

## 4 个维度

### 维度 1：对象存储未授权（桶 / 公开读写 / CORS）

**思路：云存储（S3/OSS/COS/Blob）经常配置错误——公开读/公开写/CORS 错误。**

识别思路：
- 从 JS/HTML 提取存储域名：`*.s3.amazonaws.com` / `*.oss-cn-*.aliyuncs.com` / `*.cos.*.myqcloud.com` / `*.blob.core.windows.net`
- 从 JS 提取 bucket 名：`bucket` / `oss_bucket` / `cdn_domain` / `storage_bucket`
- **从响应头指纹化存储实现**（关键——决定签名规则与已知缺陷适用性）：

| 响应头 | 存储实现 |
|---|---|
| `x-oss-request-id` / `Server: AliyunOSS` / `x-oss-server-time` | 阿里云 OSS |
| `x-amz-request-id` / `x-amz-requestid` / `Server: AmazonS3` | AWS S3 |
| `x-cos-request-id` / `Server: tencent-cos` | 腾讯 COS |
| `x-minio-*` / `Server: MinIO` | **MinIO（S3 兼容,自建）** |
| `x-rgw-*` / `ETag` 非标准格式 / `Server: Ceph` | **Ceph RGW（S3 兼容,自建）** |
| 域名 NXDOMAIN 但应用引用它 | 内网桶（外部不可直达,见维度 1.5 接管判定） |

测试思路：
- 桶列表：`https://bucket.s3.amazonaws.com/` → XML 列出对象
- 对象读：`https://bucket.s3.amazonaws.com/secret.txt` → 200 = 公开读
- 对象写：PUT 请求 → 200 = 公开写（高危）
- CORS：`Origin: https://evil.com` → 反射 + Credentials = 可窃取
- 枚举：遍历对象 key（`?list-type=2&prefix=` / `?marker=`）

分析思路：区分公开设计（CDN 静态资源桶 = 正常）和敏感数据桶（用户上传/备份/日志 = 泄露）。

### 维度 1.5：签名 URL / 类型混淆 / 桶接管（2026-08-10 强化）

**思路：拿到签名 URL（presigned URL）≠ 只有"直接访问"一种用法。存储类型混淆 = 「类型标识的解析不一致」攻击矩阵，三个注入点：**

| 注入点 | 攻击形态 | 位置 |
|---|---|---|
| 请求头 | 上传时 Content-Type 元数据可控（`image/svg+xml` 伪装） | 上传接口 multipart |
| URL 路径 | 扩展名伪装 `/shell.jsp;.png`（魔数不校验时） | 对象 key |
| **URL 参数** | **`?response-content-type=text/html` 强制覆盖响应头** | 签名 URL query |

三者本质同一缺陷（类型治理缺失），若同时存在 = 系统性文件处理链路问题，报告按系统性提。

**签名 URL 参数注入（response-content-type 类）规则**：
- 主流厂商（AWS S3 / 阿里 OSS / 腾讯 COS）都支持 response-* 参数**覆盖返回的 Content-Type**（ResponseHeaderOverrides，正常用于预览/格式转换）
- AWS S3 v2/v4：response-* 属 subresource **必须参与签名** → 附加到已有签名 URL = `SignatureDoesNotMatch`（官方实现不可注入）
- **S3 兼容实现（MinIO / Ceph RGW / 旧 SDK / 自建网关）：presigned URL 参数注入是真实漏洞类别**——签名验证只覆盖部分参数的历史缺陷多起 → 附加 response-content-type 后签名仍有效
- **验证方法论（差分三包，审核员友好）**：
  1. 基线：`GET /file?<原始签名>` → 原始 CT
  2. 攻击：`GET /file?<原始签名>&response-content-type=text/html` → CT=text/html ✅
  3. 证伪：`...&response-content-type=image/png` → CT=image/png（证明参数生效且可控）
  - 同一文件仅因参数不同 CT 变化 = 注入成立；文件内容为 `<script>` 载体 + nosniff 缺失 → XSS
- **内网桶（域名 NXDOMAIN）**:公网不可实测 → 按「无法证明=无漏洞」原则不报（规则:无法实证的攻击面不构成投递），但要在 _STATE.md 记录已试角度 + reopen_if

**桶接管判定流程（bucket takeover / 悬空 DNS）**：
1. **六类 DNS 记录检查**（A/CNAME/ANY/NS/TXT/SOA，Google DoH `dns.google/resolve?name=X&type=T`）——NXDOMAIN 全无 = 无悬空 CNAME = 桶接管不可行；**有 CNAME 且指向云存储 endpoint** → 下一步
2. CNAME 目标桶名 → `GET https://<bucket>.s3.amazonaws.com`（或对应 endpoint）→ **NoSuchBucket = 可注册** → 注册 = 完全接管（高危）
3. NS 委派检查：NS 归云厂商/第三方可注册域 → 子域接管候选
4. 注意：**NXDOMAIN（连 A 都没有）≠ 悬空**——悬空是"有 CNAME 指向已删资源"；纯 NXDOMAIN 无接管面，直接 DE

**上传-存储-渲染链路类型治理检查点**（每环都要问：攻击者能否控制类型标识？）：
1. 上传校验：只查扩展名？只查魔数？Content-Type 元数据谁定？
2. 存储：对象元数据（Content-Type）攻击者可控？（上传 multipart 的 Content-Type 常直接落为对象元数据 → 直链渲染面）
3. 渲染：前端怎么加载文件？`<a href=filePath target=_blank>` 直链 / `<img src>` / 后端代理强制 octet-stream+nosniff？
4. 代理：downLoadFile 类后端代理若强制改写 CT+nosniff → 公网不渲染；内网直链仍按对象元数据 → 内网 XSS latent（执行路径明确但公网不可证 → 只作主链危害附注，不独立成洞）

**危害升级路径**：存储型 XSS（同域 Cookie 窃取）→ Electron/Desktop 加载 URL = 客户端 RCE → 后端 include/render = SSTI/SSRF → CDN 缓存投毒（带参 URL 独立缓存键）→ CSP 绕过（self 域内 OSS 直链）。

**修复建议（投递用）**：Bucket Policy 拒绝含 response-* 参数的请求 / 全部签名参数纳入 V4 签名 / WAF 拦截 response-content-type|disposition / 用户文件统一 nosniff+安全 CT / 业务层不信任存储返回的 CT 决定渲染。

### 维度 2：云元数据 + IAM 凭据

**思路：SSRF 打云元数据服务能拿到 IAM 凭据 = 租户接管。这是云安全最高价值。**

识别思路（先判断目标在哪个云）：
- AWS：响应头 `X-Amz-Cf-Pop` / IP 段 52.x / 54.x
- 阿里云：响应头 `x-oss-server-time` / IP 段 47.x / 116.x
- 腾讯云：IP 段 119.x / 49.x
- Azure：响应头 `x-azure-ref` / IP 段 20.x / 52.x
- GCP：响应头 `x-google-backend`

测试思路（通过 SSRF 打元数据）：
- AWS IMDSv1：`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
- AWS IMDSv2：需 PUT token（老配置一打一个准，新配置需先拿 token）
- 阿里云：`http://100.100.100.200/latest/meta-data/ram/security-credentials/`
- 腾讯云：`http://metadata.tencentyun.com/latest/meta-data/`
- GCP：`http://metadata.google.internal/computeMetadata/v1/`（需 Metadata-Flavor header）
- Azure：`http://169.254.169.254/metadata/instance?api-version=2021-02-01`（需 Metadata header）

分析思路：拿到 IAM 凭据后**不调云 API**——只在报告写"凭据已暴露，可被用于访问云资源"。截图元数据响应即可。

**Pivot**：
- `169.254` 被拦 → 试 `fd00:ec2::254`（IPv6）/ `0` / `0.0.0.0` / 整数 IP
- IMDSv2 要 token → IMDSv1 老配置，跳过标 B
- 无 SSRF 入口 → 从 env vars / 配置文件 / JS 硬编码找 AKID/Secret

### 维度 3：K8s / 容器管理

**思路：K8s API/Rancher/Docker 管理面板暴露 = 集群接管/容器逃逸。**

识别思路：
- K8s API：`/api/v1/` / `/version` / 响应头 `Server: kubelet`
- Rancher：`/dashboard/` + title "Rancher Dashboard"
- Docker：`/containers/json` / `/version` / `Server: Docker`
- 容器特征：`/.dockerenv` 文件 / `/proc/1/cgroup` 含 docker/containerd

测试思路：
- K8s API 未授权：`/api/v1/namespaces` / `/api/v1/pods` / `/api/v1/secrets`
- K8s Dashboard：`/api/v1/dashboard/` 未授权访问
- Rancher：`/v3/` / `/v3/projects` / 默认凭据 admin/admin
- Docker API：`/containers/json` / `/images/json` / `/exec` 创建容器
- 容器逃逸：发现 `/.dockerenv` + 挂载 `/host` → 可读写宿主文件系统

分析思路：K8s/Rancher/Docker 管理面板暴露本身就高危——即使不能未授权访问，API 端点存在 + 版本信息泄露 = 可匹配 CVE。

**Pivot**：
- K8s API 401 → 试 ServiceAccount token（从 `/var/run/secrets/kubernetes.io/serviceaccount/token` 读）
- Rancher 401 → 试 admin/admin → 试 `/v3/settings` 公开端点
- Docker API 不暴露 → 从容器内部探（如果有命令执行）

### 维度 4：云服务特有攻击面

**思路：不同云有不同特有服务，暴露 = 特有攻击面。**

按云厂商：
- **AWS**：Lambda 函数 URL / API Gateway / Cognito / SNS/SQS / Secrets Manager / CloudFront
- **阿里云**：Function Compute / API Gateway / RAM / OSS / KMS
- **Azure**：Function Apps / App Service / Key Vault / Storage Accounts / Entra ID
- **GCP**：Cloud Functions / Cloud Run / IAM / Secret Manager / Cloud Storage

测试思路：
- Cloud Functions URL 未授权 → 可能泄露函数代码/环境变量
- API Gateway 端点枚举 → 找未授权 API
- Key Vault / Secrets Manager → 从 SSRF/文件读拿凭据后访问
- Cognito / Entra ID → 用户池配置错误（注册策略/客户端配置）

## Pivot Hints

- SSRF 打不了 169.254 → 试 IPv6 / 整数 IP / 0.0.0.0 / DNS rebinding
- 云存储桶名猜不到 → 从 JS/HTML/响应头提取
- K8s API 401 → 从容器内 ServiceAccount token 读
- 无法判断哪个云 → 看响应头/IP 段/DNS 解析
- 有云凭据但不能用 → 截图元数据响应即可证明泄露，不实际调用

## Common misses

- **只测 S3 不测 OSS/COS/Blob** → 不同云存储配置不同，阿里云 OSS 也常配错
- **元数据只试 AWS** → 阿里云/腾讯云/Azure 各有不同元数据 IP 和格式
- **拿到 IAM 凭据就调云 API** → 违法（只截图证明泄露）
- **K8s 只看 Dashboard** → K8s API Server `/api/v1/` 也是入口
- **云存储只读不写** → PUT 测试公开写才是高危（但须授权 + 测完删除）
- **从容器内不探 K8s** → 容器内 `/var/run/secrets/` 有 ServiceAccount token
- **Docker API 不试** → `GET /containers/json` 是 Docker Remote API 入口
- **拿到签名 URL 只测"能否访问"** → 必须试 response-* 参数注入（类型混淆第 3 注入点）
- **NXDOMAIN 直接放弃** → 先走六类 DNS 记录检查排除悬空 CNAME/桶接管，再判内网桶 DE
- **忽略存储指纹** → 不指纹化就不知道适用官方规则还是 S3 兼容缺陷（MinIO/Ceph 才是注入高危区）
- **上传成功就当任务结束** → 上传-存储-渲染三环每环都要查类型标识可控性（Content-Type 元数据/扩展名/渲染路径）
- **公网不可测的"潜在漏洞"写进投递** → 按「无法证明=无漏洞」降级 DE（规则:公网无法实证的攻击面按无漏洞处理，不入投递材料）

## Verification

- **云存储未授权 verified**：桶列表 + 对象读 + 敏感数据截图
- **签名 URL 参数注入 verified**：差分三包（基线原始 CT / 附加 response-content-type=text/html → CT 变 / 换 image/png → CT 变）= 同一文件仅参数差异 → 可报
- **桶接管 verified**：CNAME 指向云 endpoint + GET 桶响应 NoSuchBucket + 注册成功 = 完全接管（注册属写操作须请示，通常只证明 NoSuchBucket 即可报候选）
- **云元数据 verified**：SSRF 请求 + 元数据响应截图（含 IAM 凭据/实例信息）
- **K8s/容器 verified**：API 未授权访问 + 返回集群信息/凭据
- **phenomenon**：桶公开但只有 CDN 静态资源 / 元数据 401 / K8s API 401 / 签名 URL 泄露但桶 NXDOMAIN（内网）

## ⚠️ 红线

- 云元数据只读不调用（拿凭据后不调云 API）
- 云存储只读不写（不上传/删除/修改）
- 不实际利用 IAM 凭据（只证明泄露）
- 不执行容器逃逸（只发现可逃逸条件）
- 重武器（SSRF 打云元数据）须 _PENDING 请示

## Related

- `skills/api-logic/ssrf-arbitrary-file.md` — SSRF 是打云元数据的手段
- `chain-playbook.md` 链1 — SSRF → 云元数据 → 凭据 → 内网
- `skills/js-reverse/js-deep-analysis.md` 维度4 — 从 JS 提取云存储桶名/CDN域名
- `doctrine/coverage-audit.md` #33-35 — SSRF 云元数据
- 实战案例：`targets/acme/ichain.acme.com/findings.md` ICH-F-001（2026-08-10 六面扩展验证全流程：S3 签名 URL 泄露 → 指纹/接管/解析/响应头覆盖全测 → 前端渲染路径确认 → 内网 latent 处置）
