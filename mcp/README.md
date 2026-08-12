# mcp/ — MCP 文档

> MCP server 的实际配置在 `~/.claude.json`,不在这里。
> 本目录只放**用法文档**:7 个 MCP 在哪些场景顶替 curl / Burp / ffuf。

## 当前可用 MCP(7 个)

| MCP | 场景 | 关联 skills |
|---|---|---|
| `js-reverse-mcp` | JS 逆向调试,断点 / 堆栈 / 源码搜索 | `skills/js-reverse/` |
| `scrcpy-mcp` | Android 设备控制(快速版) | (移动渗透时) |
| `adb-mcp` | Android 测试报告流(带 step 归档) | (移动渗透时) |
| `frida-mcp` | iOS / Android Frida 注入 | (反 SSL pinning / 函数 hook) |
| `jadx-mcp` | APK 反编译 + 源码查询 | (Android APK 逆向) |
| `idapro-mcp` | IDA Pro 二进制逆向 | (PC 客户端 / Native lib) |
| `everything-mcp` | Windows 全盘秒搜 | (本机找泄露 / 字典 / 老 PoC) |

## 武器组合原则(CLAUDE.md 重申)

遇到混淆 / 加密 / APK,**必须**唤醒对应 MCP,**禁止幻觉硬猜**:

| 看到什么 | 立即开 |
|---|---|
| Vue / React 打包 + sign 参数 | `js-reverse-mcp` |
| `.apk` 文件 | `jadx-mcp` |
| Android APP 抓不到包(SSL pinning) | `frida-mcp` + `scrcpy-mcp` |
| `.exe` / `.dll` / `.so` | `idapro-mcp` |
| 在 Windows 找老 PoC / 字典 | `everything-mcp` |

## 维护

启用 / 禁用 MCP → 在这里追加变更日志,**不要只改 ~/.claude.json**。
