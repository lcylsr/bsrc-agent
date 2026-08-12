#!/usr/bin/env python3
# tools/scanner-dispatch.py — 受控重武器统一 wrapper
#
# 解决 AI "不知道让 AI 用啥工具" 中重武器被 deny 的问题:
#   - raw nuclei/sqlmap/nmap/nmap 保留在 settings.json deny
#   - 所有重武器必须走本 wrapper,由本脚本做 scope/rate-limit/GET-only/审计日志 强制检查
#
# 用法:
#   python tools/scanner-dispatch.py --dry-run nuclei  <target_dir> <url_or_host>
#   python tools/scanner-dispatch.py nuclei  <target_dir> <url_or_host> [--tags cve,spring]
#   python tools/scanner-dispatch.py sqlmap  <target_dir> <url> --confirm
#   python tools/scanner-dispatch.py nmap    <target_dir> <host> --confirm
#
# 退出码:
#   0 = 执行成功(或 dry-run 通过)
#   1 = 执行失败
#   2 = 用法/配置错
#   3 = scope 外 / 未授权 / 安全层拒绝

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.lib.tool_resolve import resolve as resolve_tool, cmdline as tool_cmdline

# Windows Git Bash 默认 GBK,强制 UTF-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ALLOWED_TOOLS = ["nuclei", "sqlmap", "nmap", "dirsearch", "afrog", "xray"]
DEFAULT_GET_TOOLS = ["nuclei", "dirsearch", "afrog"]
REQUIRES_CONFIRM = ["sqlmap", "nmap", "xray"]
MAX_THREADS = {
    "nuclei": 25,
    "sqlmap": 4,
    "nmap": 100,
    "dirsearch": 20,
    "afrog": 30,
    "xray": 10,
}
RATE_LIMITS = {
    "nuclei": "-rl 150",
    "sqlmap": "--delay=0.5",
    "nmap": "--max-rate 300",
    "dirsearch": "-t 20",
    "afrog": "-rate 100",
    "xray": "--max-rate 50",
}


def err(msg):
    print(f"❌ {msg}", file=sys.stderr, flush=True)


def log(msg):
    print(f"✅ {msg}", flush=True)


def read_scope(scope_path):
    """读取 scope.md,提取根域/IP 列表和 mode。"""
    text = scope_path.read_text(encoding="utf-8", errors="ignore")
    domains = []
    ips = []
    mode = ""
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("mode:"):
            mode = line.split(":", 1)[1].strip().lower()
        # 简单提取域名/IP
        for m in re.finditer(r"(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,})", line):
            domains.append(m.group(1).lower())
        for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?\b", line):
            ips.append(m.group(1))
    return {"domains": list(set(domains)), "ips": list(set(ips)), "mode": mode, "text": text}


def target_in_scope(target_str, scope):
    """检查目标字符串是否在 scope 内。"""
    target_str = target_str.lower()
    # IP 直接匹配
    for ip in scope["ips"]:
        if ip in target_str:
            return True
    # 域名:子域或根域匹配
    for domain in scope["domains"]:
        if domain in target_str:
            return True
        # 也允许 target 是根域本身
        root = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        if root and root in target_str:
            return True
    return False


def validate_scope(tool, target_dir, target_str, confirm=False):
    """返回 (ok:bool, reason:str)。"""
    scope_path = target_dir / "scope.md"
    if not scope_path.is_file():
        return False, "scope.md 不存在"
    if "_TBD_" in scope_path.read_text(encoding="utf-8", errors="ignore"):
        return False, "scope.md 未填齐(_TBD_)"

    scope = read_scope(scope_path)
    if not target_in_scope(target_str, scope):
        return False, f"目标 {target_str} 不在 scope.md 授权范围内"

    if tool in REQUIRES_CONFIRM and not confirm:
        return False, f"{tool} 属于写操作/重武器,必须加 --confirm"

    return True, ""


def ensure_output_dir(target_dir, tool):
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = target_dir / "recon" / f"scanner-{tool}-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def _tool_bin(tool: str) -> list[str]:
    """解析工具可执行前缀(python 脚本自动加解释器)。缺失则硬失败。"""
    p = resolve_tool(tool)
    if p is None:
        err(
            f"工具 `{tool}` 未找到。请检查 tools/external-tools.yaml / "
            f"env SRCOOP_TOOL_{tool.upper()} / PATH"
        )
        sys.exit(2)
    try:
        return tool_cmdline(tool, [])
    except FileNotFoundError as exc:
        err(str(exc))
        sys.exit(2)


def build_cmd(tool, target_str, out_dir, extra_args):
    """构造带安全限速的最终命令(绝对路径,不依赖 PATH 裸名)。"""
    safe_extra = []
    # 过滤危险参数(注意:sqlmap 内部会自行加 --batch,不在用户 extra 中拒绝)
    for arg in extra_args:
        if any(bad in arg.lower() for bad in ["-y", "--risk=3", "--level=5", "--os-shell", "--sql-shell"]):
            err(f"参数 {arg} 被安全策略拒绝")
            sys.exit(3)
        safe_extra.append(arg)

    bin_prefix = _tool_bin(tool)
    threads = MAX_THREADS.get(tool, 10)
    rate_arg = RATE_LIMITS.get(tool, "")

    if tool == "nuclei":
        cmd = bin_prefix + [
            "-u", target_str,
            "-c", str(threads),
            "-o", str(out_dir / "nuclei.txt"),
            "-json-export", str(out_dir / "nuclei.json"),
        ]
        if rate_arg:
            cmd.extend(rate_arg.split())
        return cmd + safe_extra
    elif tool == "sqlmap":
        cmd = bin_prefix + [
            "-u", target_str,
            "--batch", "--random-agent",
            "--output-dir", str(out_dir),
        ]
        if rate_arg:
            cmd.extend(rate_arg.split())
        return cmd + safe_extra
    elif tool == "nmap":
        cmd = bin_prefix + [
            "-T3",
            "-oA", str(out_dir / "nmap"),
            target_str,
        ]
        if rate_arg:
            cmd.extend(rate_arg.split())
        return cmd + safe_extra
    elif tool == "dirsearch":
        cmd = bin_prefix + [
            "-u", target_str,
            "-r", "1",
            "-o", str(out_dir / "dirsearch.txt"),
        ]
        if rate_arg:
            cmd.extend(rate_arg.split())
        return cmd + safe_extra
    elif tool == "afrog":
        cmd = bin_prefix + [
            "-t", target_str,
            "-o", str(out_dir / "afrog.html"),
        ]
        if rate_arg:
            cmd.extend(rate_arg.split())
        return cmd + safe_extra
    elif tool == "xray":
        cmd = bin_prefix + [
            "webscan", "--url", target_str,
            "--html-output", str(out_dir / "xray.html"),
        ]
        if rate_arg:
            cmd.extend(rate_arg.split())
        return cmd + safe_extra
    else:
        return []


def log_timeline(target_dir, tool, target_str, status):
    tl = target_dir / "timeline.md"
    if tl.is_file():
        with open(tl, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M')} [scanner-dispatch] {tool} {target_str} → {status}\n")


def main():
    parser = argparse.ArgumentParser(description="受控重武器统一 wrapper")
    parser.add_argument("tool", choices=ALLOWED_TOOLS, help="扫描器名")
    parser.add_argument("target_dir", help="target 目录,如 targets/example")
    parser.add_argument("target", help="目标 URL 或 host")
    parser.add_argument("--confirm", action="store_true", help="确认授权写操作/重武器")
    parser.add_argument("--dry-run", action="store_true", help="只检查 scope 并打印命令,不执行")
    parser.add_argument("--tags", help="nuclei tags,如 cve,spring")
    parser.add_argument("--extra", nargs="*", default=[], help="额外参数(需安全校验)")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.is_dir():
        err(f"target_dir 不存在: {target_dir}")
        return 2

    ok, reason = validate_scope(args.tool, target_dir, args.target, confirm=args.confirm)
    if not ok:
        err(f"scope 校验失败: {reason}")
        return 3

    extra = list(args.extra)
    if args.tags:
        extra.extend(["-tags", args.tags])

    out_dir = ensure_output_dir(target_dir, args.tool)
    cmd = build_cmd(args.tool, args.target, out_dir, extra)

    print(f"[scanner-dispatch] scope 校验通过")
    print(f"[scanner-dispatch] 输出目录: {out_dir}")
    print(f"[scanner-dispatch] 命令: {' '.join(cmd)}")

    if args.dry_run:
        log("dry-run 通过")
        return 0

    log_timeline(target_dir, args.tool, args.target, "started")
    result = subprocess.run(cmd, cwd=str(ROOT))
    status = "done" if result.returncode == 0 else f"exit-{result.returncode}"
    log_timeline(target_dir, args.tool, args.target, status)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
