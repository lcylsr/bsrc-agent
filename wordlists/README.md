# wordlists/ — 渗透副驾分层字典

> 设计原则: **L2 内置精简实用(每文件 ≤500 行)**;大字典走 **L3 外置**;目标学到的强信号写 **L0/L1**。
> Fuzz 是必要手段;0 新 money ≠ 失败。盲 ID enum 才走 materials gate,path/API fuzz 不强制。

## 分层架构

| 层 | 路径 | 内容 | 何时用 |
|---|---|---|---|
| **L0** | `targets/<t>/recon/dict/` | 本目标强信号路径/参数 | 同目标复测 / fuzz 续波优先 |
| **L1** | `wordlists/learned/` | 跨目标沉淀(强信号 only) | 自动 merge;不进大仓膨胀 |
| **L2** | `wordlists/*.txt` | 仓库内置精简 | 默认；AI 手工 ffuf / 见 `skills/api-logic/fuzz.md` |
| **L3** | `$SRCCOP_DICT_ROOT` + `external.yaml` | SecLists/Assetnote/本机 `E:\fuzz字典` | 深度扫;不入库 |

解析器: 分层字典架构（L0/L1/L2/L3），AI 手工管理，不依赖脚本
加载入口: AI 直接读 wordlists/*.txt，或 ffuf `-w` 指定（见 `skills/api-logic/fuzz.md` 维度 4 字典学习）

环境变量:
- `SRCCOP_DICT_ROOT` — 外置根(默认探测 `E:/fuzz字典`)
- `SRCCOP_DICT_LAYERS` — `0`=仅 L2 · `1`=L0+L1+L2 · `2`=全层(默认)

## 用法（AI 手工 / ffuf）

```bash
# 路径 fuzz（L2 字典）
ffuf -u "https://target.com/FUZZ" -w wordlists/api-paths.txt -t 5 -mc 200,401,403,405

# 参数 fuzz
ffuf -u "https://target.com/api/user?FUZZ=test" -w wordlists/param-names.txt -t 5 -mc 200,500

# SSRF payload（ssrf-probe.sh 内置，也可手动）
bash tools/run.sh ssrf-probe <target> "<url_with___PAYLOAD___>"

# 系统化 fuzz 方法论见 skills/api-logic/fuzz.md（5 维度+信号判断）
```

## L2 字典索引

| 字典 | 用途 | 行数 | 适用场景 |
|---|---|---|---|
| `api-paths.txt` | API/目录路径探测 | ~400 | 通用 + `#spring` `#dotnet` 等标记 |
| `param-names.txt` | 参数名 fuzz | ~200 | Arjun/ffuf 参数发现 + mass assignment |
| `ssrf-payloads.txt` | SSRF/任意文件读 | ~30 | ssrf-probe 内置;此处供手动 |
| `dir-common.txt` | 分层目录 | L1:50 / L2:200 / L3:500 | 先 L1 定性 |
| `fuzz-mutations.txt` | 变异后缀/绕过 | ~90 | 路径变形 |
| `waf-signatures.txt` | WAF 指纹 | ~50 | detect_waf |

## L3 推荐外置(不入库)

| 来源 | 用途 | 备注 |
|---|---|---|
| [Assetnote](https://wordlists.assetnote.io/) | 现代 API/httparchive 路径 | 优先于老 raft |
| [SecLists](https://github.com/danielmiessler/SecLists) | Discovery/Web-Content | 经典;按需裁剪 |
| [OneListForAll](https://github.com/six2dez/OneListForAll) | 合并精选 | micro 版日常 |
| 本机 `E:\fuzz字典` | PayloadsAllTheThings / fuzzDicts / 字典Mini | 已在 `external.yaml` 映射 |

**不要**把 10MB+ 字典 commit 进仓库。用 `external.yaml` alias 指向本机路径。

## 沉淀规则(harvest)

只写入 L0/L1 当命中:
- 业务 JSON / Blob 列表 / 未授权敏感面
- 真实 stack/path leak / 配置密钥
- **不写** SPA soft-404、纯 HTML 壳、静态资源

## materials gate(仅盲 ID)

`shareId` / `chatRecordId` / 订单号等 **未知真实 ID 的盲枚举**:
1. 先在 `targets/<t>/materials.md` 登记是否有真实样本
2. 无物料 → **停 enum**,记 DE,不烧字典
3. path/API/目录 fuzz **不**走此门
