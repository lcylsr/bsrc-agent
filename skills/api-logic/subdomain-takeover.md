---
name: subdomain-takeover
domain: subdomain-takeover
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 子域接管（中高 ROI，SRC 常收）

## Domain

- 子域 CNAME 指向已释放/可注册的第三方服务
- 常见可接管服务：S3 bucket / Azure traffic manager / Heroku / GitHub Pages / Shopify / Tumblr / Fastly / Pantheon / Wordpress.com / Surfer
- DNS 记录存在但对应服务已删除/改名/过期
- modes: src 高价值（可托管钓鱼/窃取 cookie）；pentest 中价值；redteam 低（不直接入口）

## Boundaries

- 只做 DNS 查询 + HTTP 访问验证，不注册/不接管（注册 = 实际接管 = 修改内容可能违法）
- 验证方式：访问子域看是否返回服务商的"未找到/配置错误"页面 = 可接管信号
- 证明可接管即可，不实际注册接管
- 如果已注册接管（授权 pentest 场景），接管后只放无害标记页

## Pivot Hints

- CNAME 指向正常但 404 → 检查 CNAME 目标是否可重新注册
- HTTP 200 但内容是服务商默认页 → 仍可能可接管（默认页 ≠ 已配置）
- HTTPS 证书错误 → 可能是接管信号（证书过期/域名不匹配）
- NXDOMAIN 但有 CNAME 记录 → 目标服务已完全删除 = 高概率可接管
- 多级 CNAME 链 → 逐级检查每一跳

## Exit Evidence

### src
- E2: dig CNAME 输出 + 访问子域截图（显示服务商"未配置/404"页面）
- E3: 证明该服务名可注册（截图注册页可用，不实际注册）
- missing_artifacts: [reproduction]

## Tactics

### 1. 从 recon 结果提取所有 CNAME（0 包，离线）

```bash
# 从 recon 子域列表批量查 CNAME
for sub in $(cat targets/<t>/recon/all-subdomains.txt); do
  dig +short CNAME "$sub" | grep -v '^$' && echo "  ← $sub"
done > targets/<t>/recon/cname-records.txt
```

### 2. 筛选可疑 CNAME（0 包，离线）

匹配已知可接管服务的 CNAME 模式：

```
.cloudfront.net        → AWS CloudFront（bucket 可注册）
.s3.amazonaws.com      → S3 bucket
.s3-*.amazonaws.com    → S3 bucket
.herokuapps.com        → Heroku（app 已删除）
.github.io             → GitHub Pages（repo 已删除）
.azureedge.net         → Azure CDN
.azurewebsites.net     → Azure App Service
.trafficmanager.net    → Azure Traffic Manager
.fastly.net            → Fastly
.shopify.com           → Shopify
.tumblr.com            → Tumblr
.pantheonsite.io       → Pantheon
.wordpress.com         → Wordpress.com
.surfer.sh             → Surfer
.cargocollective.com   → Cargo
```

### 3. 逐个验证（每子域 1-2 包）

```bash
# HTTP 访问看返回内容
curl -sI "https://<subdomain>" | head -20
curl -s "https://<subdomain>" | head -50

# 判断信号：
# - 404 + "NoSuchBucket" = S3 可接管
# - 404 + "No such app" = Heroku 可接管
# - 404 + "There isn't a GitHub Pages site here" = GitHub Pages 可接管
# - NXDOMAIN 但 CNAME 存在 = 服务已删除
```

### 4. 确认可注册性（0 包，离线验证）

对 AWS S3：尝试 `curl https://<bucket-name>.s3.amazonaws.com/` → 404 NoSuchBucket = 可注册
对 Heroku：访问 `https://<app-name>.herokuapp.com/` → "No such app" = 可注册
对 GitHub Pages：访问 `https://<user>.github.io/` → 404 = repo 不存在 = 可创建

## Common misses

- **只查 A 记录不查 CNAME** → 接管是 CNAME 层的问题
- **CNAME 指向正常就跳过** → 服务可能已删除但 DNS 还在（NXDOMAIN + CNAME = 可接管）
- **忽略多级 CNAME 链** → `sub → alias → real-target`，real-target 释放也能接管
- **只查 web 子域** → 非 web 服务（FTP/Mail/VPN）的 CNAME 也能接管
- **不验证可注册性** → 404 不代表可注册（可能服务存在但未配置），必须确认

## Verification（verified 标准）

- **verified**：dig CNAME 输出 + 子域访问截图显示服务商"未配置/404" + 服务名可注册证明
- **phenomenon**：CNAME 存在但服务正常配置（无法接管）
- **rejected**：CNAME 指向的服务不可注册（如 S3 bucket 名已被占）

## ⚠️ 红线

- **不实际注册接管**（注册=修改内容=可能违法，除非授权 pentest）
- 验证方式：访问子域看"未配置"页面 + 截图注册页"可用"状态
- 报告写"子域可被接管，未实际注册"即可

## Related

- `recon-pipeline.py` — 子域枚举（recon 阶段产出 CNAME 数据）
- `doctrine/coverage-audit.md` #41 子域接管
