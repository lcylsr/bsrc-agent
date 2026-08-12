# skills/js-reverse/ — 前端逆向决策手册

> **职责区分**(回答"是不是和 js-reverse-mcp 重复了"):
> - **MCP** = 执行工具(`break_on_xhr` / `set_breakpoint_on_text` / `search_in_sources` / `evaluate_script` 这些动作能力)
> - **本目录** = 决策手册(看到 X 该怎么打 / 不该犯什么错 / 典型驳回)
>
> 两者互补:MCP 给你手脚,skills 给你脑子。MCP 调用细节看 `mcp__js-reverse-mcp__*` 工具列表本身,本目录不重抄。

## 文件索引

| 文件 | 触发 |
|---|---|
| `js-deep-analysis.md` | JS 深度分析6维度:文件发现/API路径/baseURL/密钥/签名算法/sourcemap |
| `crypto-sign.md` | 请求带 sign/token/nonce / 改 1 字节就 401 / 响应是密文 |

## 何时不该开浏览器 MCP(省成本)

- 主页 HTML 已含全部 API 路径 → 直接 curl
- 接口无加密无签名 → 直接 curl
- 仅探 sourcemap → 4-6 包 curl 离线搞定,不必启浏览器

## 何时**必须**开浏览器 MCP

- 接口被 webpack 拼接成 `e.baseURL + "/" + e.path`(正则找不出)
- 加密 / 签名算法非显式 string match
- 看到 SignalR / WebSocket / SSE
- 二开自研鉴权头(服务端动态指定 header 名,如 longshine `LsAuthHeaderName`)
- 业务流跨多个 XHR(单 curl 跑不完整链路)

## 启动 MCP 的标准动作

新 MCP 自管浏览器(CDP 调试器范式,**无需手起 chrome --remote-debugging-port**):

```
mcp__js-reverse-mcp__new_page(url="https://target.com")   # 打开/复用页面
```

后续 `select_page` / `navigate_page` 切换。注:旧的 `mcp-bootstrap.sh` + `check_browser_health` 已废弃(脚本下架到 `tools/attic/`),不要再用。
