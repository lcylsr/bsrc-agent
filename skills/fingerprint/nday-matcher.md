# N-day / 历史漏洞指纹识别

> **目标**:在 recon/status 阶段就把「产品/组件指纹」与「公开 N-day / 历史漏洞」对齐,**把随机探测变成按图索骥**。
> **原则**:命中 ≠ verified;匹配器只输出候选和安全的 GET 检查,具体利用必须按对应 playbook/skill 深入,并遵守「重武器先请示」。

## 何时会命中

框架在以下位置自动读取信号:

- `targets/<X>/scope.md` 的 frontmatter 与正文
- `targets/<X>/raw/` 下已抓取的 probe 响应
- `targets/<X>/recon/probe-results.txt` (httpx / curl fallback 输出)
- `targets/<X>/surface.md`

当上述文本中出现产品特征(路径、响应头、`Server:`、`Set-Cookie:`、标题、正文关键字)时,`tools/nday-matcher.py` 会在 `status` / `recon-pipeline` 阶段提示命中。

## 触发后必做的 3 步

1. **看报告**:读 `targets/<X>/recon/nday-matches.md`,确认哪些检查是 🟢 confirmed / 🟡 suspected / 🔴 fixed。
2. **读打法**:命中 playbook → 按 playbook 验证命令复测;无 playbook 时读 skill 文档(`skills/fingerprint/nday-matcher.md` 或 `skills/fingerprint/recon-product-fingerprint.md`)。
3. **才出洞**:只有拿到真实业务影响证据(文件内容、非预期响应、凭据、反序列化触发等)才能写 `findings.md` 标 `verified`。

## 命令

```bash
# 手动跑完整检查(自动发现 base_url)
bash tools/run.sh nday-matcher targets/<X>

# 只匹配本地信号,不联网(快速筛查)
bash tools/run.sh nday-matcher targets/<X> --dry-run

# 强制指定 base URL
bash tools/run.sh nday-matcher targets/<X> --base-url https://target.com

# recon-pipeline 会自动在阶段 3.5 跑 N-day 快查
bash tools/run.sh recon-pipeline targets/<X> example.com
```

## YAML 指纹库格式

文件位置:`skills/fingerprint/nday-fingerprints.yaml`

```yaml
fingerprints:
  - id: seeyon-a8                      # 唯一 slug
    name: 致远互联 OA A8 反序列化 / 文件上传
    product: 致远互联 Seeyon OA A8 / M3
    severity: critical                 # critical | high | medium | low
    tags: [seeyon, a8, oa]
    triggers:                          # 列表内为 OR,可用 all_of / any_of 嵌套
      - type: path
        value: "/seeyon/"
      - type: header
        value: "Server: Coyote"
      - type: body
        value: "M3"
    playbook: memory/playbooks/playbook-seeyon-a8-deserialization.md
    skill: skills/fingerprint/nday-matcher.md
    checks:                            # 安全 GET 探测
      - name: htmlofficeservlet 是否存在
        path: /seeyon/htmlofficeservlet
        status: ["200", "405", "500"]
        hit_grep: htmlofficeservlet
        fixed_grep: ""                 # 可选;命中即认为已修
        note: A8 历史反序列化/任意文件上传入口
        command: "curl -sk -m 10 -o /dev/null -w '%{http_code}' {base}/seeyon/htmlofficeservlet"
        scanner_tags: cve,seeyon       # 传给 scanner-dispatch 的 --tags
```

### trigger 类型

| type | 信号来源 | 示例 |
|---|---|---|
| `path` | 从文本提取的 URL/路径 | `/seeyon/` |
| `header` | 响应头文本(含 `Server:` / `Set-Cookie:` 等) | `Server: Coyote` |
| `body` | 响应体文本 | `FineReport` |
| `title` | HTML `<title>` | `Jenkins` |
| `server` | 单独提取的 `Server:` 头 | `Coyote` |
| `cookie` | 单独提取的 cookie | `ecology_` |

### 嵌套条件

```yaml
triggers:
  - all_of:
      - type: path
        value: "/api/"
      - type: body
        value: "swagger"
  - any_of:
      - type: title
        value: "Confluence"
      - type: path
        value: "/confluence/"
```

## 如何新增一个指纹

1. 确认产品有**公开 N-day / 历史漏洞 / CVE / CNVD**,不是纯技术栈。
2. 在 `skills/fingerprint/nday-fingerprints.yaml` 追加条目,`checks` 必须只含安全 GET 请求。
3. 若无现成 playbook,新建 `memory/playbooks/playbook-<id>.md`(至少 frontmatter + 触发指纹 + 验证命令 + 报告模板)。
4. 跑 `bash tools/run.sh nday-matcher <mock_target>` 验证能命中且不报错。
5. 改完手动更新 `memory/INDEX.md` 追加新条目。

## 与 scanner-dispatch 的关系

`nday-matcher` 只做**轻量指纹识别**;一旦确认目标存在某产品,需要跑定向扫描时:

```bash
bash tools/run.sh scanner-dispatch nuclei targets/<X> https://target.com --tags cve,seeyon --confirm
```

`--confirm` 是法律红线要求的重武器授权,必须先请示客户/SRC。

## 常见误区

- ❌ 把 `HTTP 200` 当漏洞 — 只是命中产品,必须进一步拿到业务影响证据。
- ❌ 在 matcher 里直接投 RCE payload — matcher 只发 GET,Exploit 走 scanner-dispatch + 授权。
- ❌ 不加 `fixed_grep` — 已修目标会反复报 suspected;加 fixed 特征可减少噪音。
- ❌ 指纹库无限膨胀 — 只放有明显历史漏洞的产品,纯框架(Java/PHP/Spring)不要放。

## 关联

- `skills/fingerprint/recon-product-fingerprint.md` — 更广义的产品/二开识别
- `tools/nday-matcher.py` — 匹配器实现
- `skills/fingerprint/nday-fingerprints.yaml` — 指纹库
- `tools/scanner-dispatch.py` — 命中后的重武器扫描入口
