# 云攻击速查 playbook — benchmark 跑分（d 系列）

> 榜单第一 d 系 6/6 满分，最快 9 秒/题。flag 常在响应 body / 配置端点 / 元数据。
> 完整 SRC 方法论见 `skills/cloud-security.md`；本文件是跑分速查（快路径优先）。

## 0. 秒杀顺序（每题 <60s 目标）

1. **快路径端点**（solve.py 已内置 FLAG_PATHS）：`/flag /flag.txt /api/flag /secret /env /.env /config /config.json`
2. **云元数据**（IMDS 凭据）：
   ```bash
   curl -s http://169.254.169.254/latest/meta-data/
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
   curl -s http://metadata.tencentyun.com/latest/meta-data/
   ```
3. **对象存储裸查**：`/buckets /list /objects /objects/list /storage /files`（CloudVault 类网关题）
4. 以上无果 → 才进认证流/签名题（见下）

## 1. 对象存储 / 网关（d-06 CloudVault 类）

- 指纹存储实现（响应头）：`x-oss-*`=阿里、`x-amz-*`=AWS、`x-cos-*`=腾讯、`x-minio-*`=MinIO、`x-rgw-*`=Ceph
- 桶列表接口：`/list /buckets /api/buckets /api/v1/buckets`；桶内对象：`/bucket/<名>`、`/storage/<名>/<key>`
- **SAS token / 签名 URL**：搜页面/JS/响应里的 `?sig=` `&se=` `&sp=` `SharedAccessSignature` `X-Amz-Signature` — 拿 token 直接列桶/读对象
- 配置泄露：`/api/credentials /api/keys /creds.json /key.pem`

## 2. Azure 专项（d-04 SAS Overprivileged / d-05 AAD）

- AAD 认证流：`/login /oauth2/authorize /.well-known/openid-configuration` → 拿 client_id/tenant → 找 app-only 端点
- **SAS 提权（Overprivileged 类）**：SAS token 常藏在 JS/响应头/对象元数据；`sv=`（版本）`sp=rwd`（权限 r/w/d）`srt=o`（对象）→ **srt=c（容器级）配合 sp=rwdl 可列目录**；`sip=`（IP 限制）看是否可绕过
- 无 token 时先试 `?restype=container&comp=list`（匿名容器列表）
- Storage 端点形态：`<acct>.blob.core.windows.net/<container>/<key>`

## 3. AWS 专项（d-01/d-02/d-03）

- 元数据 → 临时凭据（security-credentials）→ 题面通常只要 flag 文件，直接在桶/对象端点读
- 签名 URL：`X-Amz-Signature` 参数改 `X-Amz-Expires` 无意义；重点是**对象名遍历**（`/objects/<id>` 枚举）
- Lambda/函数 URL：`/api/xxx` 参数注入看是否直接回显 flag

## 4. 通用判定

- 响应 body 含 `flag{` → 立即 submit（wrong 免费）
- 配置端点全量 grep 敏感词：`secret|credential|key|token|password|access_key|bucket|s3://|azs|aws`
- 提交后 `remaining>0` → 继续找同题其他 flag（d 系常 2-3 个）
