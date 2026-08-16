#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""benchmark-watch — 跑分实时监控终端（轮询平台 API + tail 本地日志）

跑分时开一个终端跑它，实时看到每题状态 / 已提交 flag 数 / 得分 / 容器状态，
以及本地运行日志的最新事件（托管镜像内 solve.py 写 run.log，本地模式写 run-<日期>.log）。

用法:
  bash tools/run.sh benchmark-watch                 # 每 15s 轮询，清屏刷新表格
  bash tools/run.sh benchmark-watch --interval 5    # 自定义间隔（秒）
  bash tools/run.sh benchmark-watch --once          # 单次输出后退出（适合脚本/告警）
  bash tools/run.sh benchmark-watch --log <file>    # 额外 tail 本地日志文件
  bash tools/run.sh benchmark-watch --no-clear      # 增量输出（不刷屏，适合重定向）
  bash tools/run.sh benchmark-watch --demo          # 演示模式（无 token 验证渲染）

环境: BENCHMARK_BASE_URL / BENCHMARK_TOKEN（与 benchmark-api 同源，见 tools/keys.env）
退出码: 0=正常  2=任务已结束（invalid_state）
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent.parent
KEYS_PATH = ROOT / "tools" / "keys.env"
DEFAULT_LOG = ROOT / "targets" / "benchmark" / "output" / f"run-{time.strftime('%Y-%m-%d')}.log"

# 状态图标
ICON = {"done": "✅", "active": "▶️ ", "idle": "·", "ended": "⛔", "err": "❌"}


def load_keys():
    env = {}
    if KEYS_PATH.is_file():
        for line in KEYS_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def get_cfg():
    keys = load_keys()
    base = os.environ.get("BENCHMARK_BASE_URL") or keys.get("BENCHMARK_BASE_URL", "")
    token = os.environ.get("BENCHMARK_TOKEN") or keys.get("BENCHMARK_TOKEN", "")
    return base.rstrip("/"), token


def api_fetch(base, token, timeout=20):
    req = urllib.request.Request(
        base + "/openapi/v1/challenges",
        headers={"BENCHMARK_TOKEN": token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
            return 200, (json.loads(raw) if raw else [])
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {"message": raw[:200]}
    except Exception as e:
        return 0, {"message": str(e)}


# 题型关键词（与 solve.py TYPE_RULES 同步；watch 只用于显示排序，保持执行/显示顺序一致）
WATCH_TYPE_FACTOR = [
    ("cloud",    ["aws", "azure", "云", "cloud", "s3", "oss", "cos", "bucket", "对象存储",
                  "storage", "sas", "aad", "imds", "元数据", "ec2", "lambda", "minio", "ceph"], 0.5),
    ("android",  ["android", "apk", "dex", "安卓", "移动", "deep link", "社区 app", "app 附件"], 1.5),
    ("chain",    ["合约", "rpc", "ethereum", "以太坊", "solidity", "区块链", "web3", "issolved",
                  "抽奖", "私钥", "contract", "blockchain"], 1.5),
    ("ai",       ["大模型", "llm", "模型", "prompt", "提示注入", "教练", "生成平台", "文档解析",
                  "ai 面试", "ai 前端", "chat", "对话网站"], 1.2),
    ("reverse",  ["license", "授权", "serial", "序列号", "crack", "逆向", "reverse", "keygen",
                  "校验器", "验证器", "embedded", "嵌入式", "activation", "激活", "macos", "ios"], 2.0),
    ("memsafe",  ["tcp", "udp", "socket", "协议", "buffer", "overflow", "heartbeat", "心跳",
                  "lru", "cache", "缓存", "内存", "memory", "tls", "格式串", "字节"], 1.5),
    ("sandbox",  ["沙箱", "sandbox", "escape", "逃逸", "restricted", "受限", "jail", "isolat"], 0.7),
    ("evasion",  ["waf", "绕过", "bypass", "evasion", "对抗", "filter", "过滤", "拦截", "网关"], 0.7),
    ("product",  ["泛微", "weaver", "shiro", "log4j", "fastjson", "spring", "weblogic",
                  "thinkphp", "tomcat", "redis", "jenkins", "gitlab", "confluence", "cve", "spring boot"], 1.2),
    ("multi",    ["内网", "横向", "渗透测试", "全链路", "apt", "域", "smb", "多阶段", "企业",
                  "internal", "lateral", "fleet", "pivot", "enterprise"], 3.0),
    ("web",      ["login", "登录", "php", "jsp", "web", "blog", "博客", "cms", "admin",
                  "api", "idor", "upload", "上传", "越权", "注入", "portal", "forum", "论坛", "商城", "社区"], 1.0),
]
def roi_order(ch):
    """动态 ROI 显示排序（低投入高确定性先显示；与 solve.py build_queue 同思路）。"""
    code = ch.get("unique_code", "")
    desc_l = (ch.get("description") or "").lower()
    tf = 1.0
    hits = [(sum(1 for k in kws if k in desc_l), tf_) for _, kws, tf_ in WATCH_TYPE_FACTOR]
    hits = [h for h in hits if h[0] > 0]
    if hits:
        # 与 solve.py detect_type 同规则：命中数优先，打平时因子大的类型优先
        hits.sort(key=lambda h: (-h[0], -h[1]))
        tf = hits[0][1]
    else:
        # 无描述时前缀 fallback（与 solve.py 同表；前缀后必须跟 - 或数字——"b-01" 匹配，"bctf-01" 不匹配）
        PREFIX_TF = {"d": 0.5, "f1": 1.5, "f2": 2.0, "e1": 0.7, "e2": 0.7, "e3": 0.7,
                     "c": 1.2, "b": 3.0, "a": 1.0}
        for prefix, ftf in PREFIX_TF.items():
            if re.match(rf"^{re.escape(prefix)}[-_0-9]", code):
                tf = ftf
                break
    diff = {"easy": 3, "medium": 8, "hard": 20}.get(ch.get("difficulty"), 10)
    flags = max(ch.get("flag_count", 1), 1)
    est = max(diff * flags * tf, 1)
    spf = ch.get("total_score", 0) / flags
    return - (spf / est)  # 升序排序取负 = ROI 降序


def render(chs, log_tail=None, interval=None):
    """渲染实时表格。chs: API 题目列表；log_tail: 最近日志行列表。"""
    total_score = sum(c.get("total_score", 0) for c in chs)
    done = [c for c in chs if c.get("is_completed")]
    active = [c for c in chs if c.get("container_status") == "available"]
    score = sum(c.get("total_score", 0) * c.get("correct_flag_count", 0) / max(c.get("flag_count", 1), 1)
                for c in chs)
    print("=" * 72)
    print(f"TSecBench 跑分监控  {time.strftime('%Y-%m-%d %H:%M:%S')}"
          + (f"  （每 {interval}s 刷新，Ctrl+C 退出）" if interval else ""))
    print(f"  完成 {len(done)}/{len(chs)} 题 | 运行中 {len(active)} | "
          f"得分 ≈{score:,.0f} / {total_score:,.0f}（{score / total_score * 100:.1f}% 若满额）")
    print("-" * 72)
    print(f"{'状态':<3} {'题号':<8} {'难度':<6} {'flag':<9} {'得分':<7} {'容器':<18} 标题")
    print("-" * 72)
    for c in sorted(chs, key=lambda x: (x.get("is_completed"), roi_order(x))):
        mark = ICON["done"] if c.get("is_completed") else (
            ICON["active"] if c.get("container_status") == "available" else ICON["idle"])
        flags = f"{c.get('correct_flag_count', 0)}/{c.get('flag_count', 0)}"
        got = int(c.get("total_score", 0) * c.get("correct_flag_count", 0) / max(c.get("flag_count", 1), 1))
        addr = (c.get("container_addr") or [""])[0]
        title = (c.get("title") or c.get("description") or "")[:24]
        print(f"{mark}  {c.get('unique_code', ''):<8} {str(c.get('difficulty', '')):<6} "
              f"{flags:<9} {got:<7} {addr:<18} {title}")
    print("=" * 72)
    if log_tail:
        print("最近事件（本地日志）：")
        for line in log_tail[-6:]:
            print("  " + line.rstrip()[:100])
        print("=" * 72)


def tail_file(path, n=40):
    """读文件最后 n 行。文件不存在返回 []。"""
    if not path or not Path(path).is_file():
        return []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-n:]
    except OSError:
        return []


def demo_challenges():
    """演示数据（--demo 用，渲染 UI 验证）。"""
    names = ["云上档案库", "对象存储网关", "统一认证中心", "博客系统", "授权引擎", "多阶段渗透"]
    chs = []
    for i in range(6):
        code = ["d-03", "d-06", "a-11", "c-01", "f2-05", "b-02"][i]
        chs.append({
            "unique_code": code, "difficulty": "medium" if i < 4 else "hard",
            "is_completed": i < 3, "container_status": "available" if i == 3 else "closed",
            "correct_flag_count": 1 if i < 3 else 0, "flag_count": 1 if i < 3 else 6,
            "total_score": [400, 300, 500, 500, 500, 1200][i],
            "container_addr": [f"10.0.163.2{i}:8000"] if i < 4 else [],
            "title": names[i],
        })
    return chs


def main():
    ap = argparse.ArgumentParser(description="跑分实时监控终端")
    ap.add_argument("--interval", type=int, default=15, help="轮询间隔秒（默认 15）")
    ap.add_argument("--once", action="store_true", help="单次输出后退出")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help=f"tail 的本地日志文件（默认 {DEFAULT_LOG.name}）")
    ap.add_argument("--no-clear", action="store_true", help="不刷屏（增量输出）")
    ap.add_argument("--demo", action="store_true", help="演示模式（无 token）")
    args = ap.parse_args()

    if args.demo:
        render(demo_challenges(), tail_file(args.log), args.interval if not args.once else None)
        return 0

    base, token = get_cfg()
    if not base or not token:
        print("✗ 缺少 BENCHMARK_BASE_URL / BENCHMARK_TOKEN（tools/keys.env 或环境变量）— 或用 --demo 预览渲染")
        return 1

    last_lines = []
    while True:
        code, payload = api_fetch(base, token)
        if code == 200 and isinstance(payload, list):
            chs = payload
            if args.no_clear:
                # 增量：只打状态变化 + 新日志
                cur = {(c["unique_code"], c.get("correct_flag_count", 0)) for c in chs}
                prev = getattr(main, "_prev", None)
                if prev is not None:
                    for (code0, n) in sorted(cur - prev):
                        print(f"[{time.strftime('%H:%M:%S')}] {code0} flag {n} ✓", flush=True)
                main._prev = cur
                new_logs = tail_file(args.log)
                for line in new_logs[len(last_lines):] if last_lines else new_logs[-6:]:
                    print(f"  {line.rstrip()[:100]}", flush=True)
                last_lines = new_logs
            else:
                os.system("cls" if os.name == "nt" else "clear")
                render(chs, tail_file(args.log), None if args.once else args.interval)
        elif isinstance(payload, dict) and payload.get("code") == "invalid_state":
            print(f"⛔ 任务已结束（invalid_state）：{payload.get('message')} — 需在平台新建任务并更新 token")
            return 2
        else:
            print(f"❌ API 请求失败 [{code}] {payload.get('message', payload)} — 稍后重试", flush=True)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
