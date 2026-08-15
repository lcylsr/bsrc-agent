#!/usr/bin/env python3
# benchmark-api — TSecBench 跑分平台 API 客户端（list/start/hint/submit/close，零依赖 stdlib only）
"""benchmark-api — TSecBench 跑分平台 API 客户端（挑战赛评测专用，零依赖 stdlib only）

用法:
  bash tools/run.sh benchmark-api list                          # 题目列表 + 作答进度
  bash tools/run.sh benchmark-api start <unique_code>           # 启动容器（并发上限 3 题，满时先 close 旧题）
  bash tools/run.sh benchmark-api hint  <unique_code>           # [会扣分] 获取提示
  bash tools/run.sh benchmark-api submit <unique_code> <flag>   # 提交 flag（1~4096 字符，特殊字符请加引号）
  bash tools/run.sh benchmark-api close <unique_code>           # 关闭容器，释放资源

环境:
  BENCHMARK_BASE_URL / BENCHMARK_TOKEN
    在 TSecBench 平台创建跑分任务后下发（token 按任务隔离，一任务一个）。
    从系统环境变量或 tools/keys.env 读取（勿提交 git，模板见 keys.env.example）。
  靶场 VPN: start 返回的 container_addr 需连接 SSLVPN 后才可访问。

退出码: 0=成功  1=配置/用法错误  2=业务错误（token 无效/任务结束/资源不可用等）
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS_PATH = ROOT / "tools" / "keys.env"
TIMEOUT = 30

# Windows 控制台/管道默认 GBK 会炸 Unicode 符号 → 统一 UTF-8 输出（run.sh 已设，直跑 python 也不崩）
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# 通用错误码 → 处置提示（对应 API 文档 §4.2）
ERR_HINTS = {
    "task_not_found": "BENCHMARK_TOKEN 无效/缺失或任务不存在 — 核对 keys.env 中 token，或确认任务未被删除",
    "challenge_not_found": "unique_code 不在当前任务用例集 — 先 list 核对题号",
    "invalid_state": "任务已结束（超时/手动停止）或容器并发达到上限（先 close 已完成的题）",
    "duplicate": "该 flag 已正确提交过（幂等保护，无需重提）",
    "resource_unavailable": "靶场资源暂不可用（实例未就绪/已耗尽）— 稍后重试",
    "internal_error": "平台内部错误 — 稍后重试",
}


def load_keys():
    """读取 tools/keys.env（KEY=VALUE，# 注释）。文件缺失返回空 dict。"""
    env = {}
    if not KEYS_PATH.is_file():
        return env
    for line in KEYS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def get_cfg():
    """环境变量 > keys.env。返回 (base_url, token)。"""
    keys = load_keys()
    base = os.environ.get("BENCHMARK_BASE_URL") or keys.get("BENCHMARK_BASE_URL", "")
    token = os.environ.get("BENCHMARK_TOKEN") or keys.get("BENCHMARK_TOKEN", "")
    return base.rstrip("/"), token


def die(msg, code=1):
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(code)


def call(base, token, method, path, body=None):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"BENCHMARK_TOKEN": token, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"code": str(e.code), "message": raw[:200]}
        return e.code, payload
    except urllib.error.URLError as e:
        die(f"网络错误: {e.reason}（确认 BENCHMARK_BASE_URL 正确且网络可达）")
    except OSError as e:
        die(f"网络错误: {e}")


def fail(code, payload):
    """打印业务错误 + 处置提示，返回退出码 2。"""
    if code == 422 and isinstance(payload.get("detail"), list):
        die("参数校验失败: " + json.dumps(payload["detail"], ensure_ascii=False), 2)
    ecode = payload.get("code", str(code))
    msg = payload.get("message", "")
    hint = ERR_HINTS.get(ecode)
    print(f"✗ HTTP {code} [{ecode}]: {msg}", file=sys.stderr)
    if hint:
        print(f"  处置: {hint}", file=sys.stderr)
    return 2


def cmd_list(base, token):
    code, payload = call(base, token, "GET", "/openapi/v1/challenges")
    if code != 200:
        return fail(code, payload)
    if not payload:
        print("（空列表 — 当前任务无题目）")
        return 0
    for ch in payload:
        mark = "✓" if ch.get("is_completed") else ("▶" if ch.get("container_status") == "available" else "·")
        addr = ", ".join(ch.get("container_addr") or []) or "-"
        print(f"{mark} {ch.get('unique_code')}  [{ch.get('difficulty')}/L{ch.get('level')}]  "
              f"{ch.get('correct_flag_count', 0)}/{ch.get('flag_count', 0)} flags  "
              f"{ch.get('total_score', 0)}分  {ch.get('container_status')}  {addr}")
        if ch.get("description"):
            print(f"    {ch['description']}")
    return 0


def cmd_start(base, token, unique_code):
    code, payload = call(base, token, "POST", f"/openapi/v1/challenges/start?unique_code={unique_code}")
    if code != 200:
        return fail(code, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    for addr in payload.get("container_addr", []):
        print(f"  → 容器: {addr}（需先连接靶场 VPN 再访问）")
    print("  ⚠ 完成答题后记得 close 释放容器；同开上限 3 题")
    return 0


def cmd_hint(base, token, unique_code):
    code, payload = call(base, token, "GET", f"/openapi/v1/challenges/hint?unique_code={unique_code}")
    if code != 200:
        return fail(code, payload)
    hint = payload.get("hint")
    print(f"提示: {hint if hint is not None else '（无提示）'}")
    print("⚠ 已扣分：本次查看提示后，该题后续 flag 得分按 hint_cost_radio 比例扣减")
    return 0


def cmd_submit(base, token, unique_code, flag):
    if not flag or len(flag) > 4096:
        die("flag 长度须在 1~4096 字符内")
    code, payload = call(base, token, "POST", "/openapi/v1/challenges/submit",
                         {"unique_code": unique_code, "flag": flag})
    if code != 200:
        return fail(code, payload)
    r = payload
    verdict = "✓ 正确" if r.get("correct") else "✗ 错误"
    print(f"{verdict}  本次得分={r.get('awarded', 0)}  本题累计={r.get('cumulative_score', 0)}  "
          f"({r.get('correct_flag_count', 0)}/{r.get('total_flag_count', 0)} flags)")
    if r.get("matched_flag_index") is not None:
        print(f"  命中 flag 索引: {r['matched_flag_index']}")
    return 0


def cmd_close(base, token, unique_code):
    code, payload = call(base, token, "POST", f"/openapi/v1/challenges/close?unique_code={unique_code}")
    if code != 200:
        return fail(code, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    base, token = get_cfg()
    if not base or not token:
        die("缺少配置: 请在 tools/keys.env（或系统环境变量）设置 BENCHMARK_BASE_URL 与 BENCHMARK_TOKEN"
            "（TSecBench 平台创建跑分任务后下发，模板见 tools/keys.env.example）")
    cmd, args = argv[0], argv[1:]
    if cmd == "list":
        if args:
            die(f"list 不接受参数: {args}")
        return cmd_list(base, token)
    if cmd in ("start", "hint", "close"):
        if len(args) != 1:
            die(f"{cmd} 需要 1 个参数: <unique_code>")
        return {"start": cmd_start, "hint": cmd_hint, "close": cmd_close}[cmd](base, token, args[0])
    if cmd == "submit":
        if len(args) != 2:
            die("submit 需要 2 个参数: <unique_code> <flag>（flag 含特殊字符时请加引号）")
        return cmd_submit(base, token, args[0], args[1])
    die(f"未知命令: {cmd}（可用: list / start / hint / submit / close）")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
