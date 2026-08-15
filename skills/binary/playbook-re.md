# 二进制/逆向速查 playbook — benchmark f1/f2 系列

> **背景**：榜单第一的失败全部集中在 f2 系列（嵌入式授权引擎/设备序列号校验，5+ 次答题失败）。
> 本文件 = f2 弱项补课 + f1 内存安全题的靶场专用打法（镜像内已装 pwntools/gdb/binutils/ltrace）。

## 0. 题型识别

| 前缀 | 形态 | 攻击面 |
|---|---|---|
| f1 | TCP 行协议服务（token-store / lru-cache / tls-heartbeat / buffer-writer） | 协议逻辑 + 内存安全（超长/负数长度/格式串/心跳长度不匹配） |
| f2 | 嵌入式授权/序列号校验（授权引擎/序列号校验器/设备授权校验器） | 校验逻辑逆向 + 序列号求解 + 内存安全 |

## 1. 协议摸底（30 秒）

```bash
nc <host> <port>                    # 连上先发 HELP / STATUS / ? / 空行
# 或 python: 逐行发送读回显（solve.py 的 tcp_req 已内置，LLM 用 tcp 动作即可）
```

看回显判断：行协议 / 二进制协议（前 4 字节长度字段）/ HTTP 伪装。

## 2. 若暴露二进制文件（f2 常见：可下载授权程序）

```bash
curl -o prog <url> && file prog        # 架构/类型
strings prog | grep -iE "flag|key|serial|license|success|fail"   # 校验分支线索
objdump -d prog | grep -A20 "cmp"      # 比较指令附近 = 校验逻辑
ltrace ./prog <input>                  # 库调用轨迹（strcmp/strlen 泄露比较目标）
gdb -batch -ex "info functions" -ex "break main" -ex run prog   # 动态
```

**快赢**：`strings` 直接出 flag / 明文序列号格式；`strcmp` 硬编码目标 = 序列号即字符串比较。

## 3. 序列号求解（z3 约束求解）

校验逻辑是数值运算（乘/加/异或/取模）时，用 z3 反推：

```python
from z3 import *
s = Solver()
# 例: 校验为 (x1*7+x2*3) % 100 == 42
xs = [BitVec(f"x{i}", 8) for i in range(4)]
s.add((xs[0]*7 + xs[1]*3 + xs[2]*5 + xs[3]) % 100 == 42)
# 把从 gdb/ltrace/objdump 反推的约束全部 add
print([s.model()[x] for x in xs] if s.check() == sat else "unsat")
```

gdb 里 `set $pc` 到 cmp 前 `print $eax` 拿比较常数，全部收集后一次性求解。

## 4. 内存安全攻击面（f1/f2 通用）

- **超长输入**：`"A"*512` / 递增长度（100/200/400/800/1600）→ 崩溃信息 = 溢出点
- **负数/超大长度字段**：行协议常见 `len` 字段 → 发 `-1` / `0xFFFFFFFF` / `999999`
- **格式串**：输入 `%x.%x.%x` / `%s` / `%n` → 回显泄露栈（地址/偏移）→ 写 flag 文件路径进内存直接触发打印
- **心跳型长度不匹配**（f1-03 tls-heartbeat 类）：请求体长度字段 > 实际发送 → 服务回显内存越界数据（flag 常直接泄出）
- **整数溢出**：长度字段 `0xffffffff` 绕过分配检查 → 栈溢出
- 所有服务用 pwntools 交互（超时控制 + 精确字节）：

```python
from pwn import *
r = remote("10.0.x.x", port)
r.recvuntil(b">")
r.sendline(b"A"*200 + p32(0xffffffff))   # p32 = 小端 4 字节
print(r.recvall(timeout=5))
```

## 5. 失败熔断（f2 血泪教训——换类不换题）

- 协议摸 2 轮无头绪 → 换方向（下载二进制/strings/gdb），不重复同一矩阵
- 答错 2 次 → 换角度；5 次 → NOTES.md 记 `[fail]` 死路 + **标记待重试**，先去别的题回头再战（第一名 f2 系列答错 5 次仍全部拿下，f2-05 耗时 12 分钟坚持到成功）
- 校验失败响应 ≠ 无洞：观察**差异回显**（长度/时间/字段不同）做二分——成功/失败响应不同 → 逐字节猜

## 6. 通用

- 回显含 `flag{` 立即 submit（wrong 免费）
- 大输出（strings 全量）→ 重定向文件再 grep
