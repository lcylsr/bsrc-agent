#!/usr/bin/env python3
# tools/lib/lifecycle.py — lifecycle.yaml 解析/校验/视图生成
# v2 根因方案 解法 A：单一日志 → 生成视图，消灭人肉双写。
# 调用方: tools/findings-lint.py <target_dir> --lifecycle [--gen]
import os
from datetime import datetime
from pathlib import Path

ALLOWED_STATUS = {
    "phenomenon", "candidate", "verifying", "verified",
    "money_ready", "delivered", "rejected", "fixed",
}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "?": 9}
VIEW_DIR = "output/lifecycle-views"


def load_lifecycle(target_dir):
    """解析 targets/<t>/lifecycle.yaml → dict；文件缺失返回 None。"""
    p = Path(target_dir) / "lifecycle.yaml"
    if not p.is_file():
        return None
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"lifecycle.yaml 解析失败: {exc}")
    return data if isinstance(data, dict) else {}


def validate(data):
    """状态机前置条件校验 → (errors, warnings)。"""
    errors, warnings = [], []
    seen = set()
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            errors.append("findings 存在非 dict 条目")
            continue
        fid = str(f.get("id") or "?")
        if not fid.strip() or fid == "?":
            errors.append("finding 缺 id")
        if fid in seen:
            errors.append(f"{fid}: 重复 id")
        seen.add(fid)

        st = f.get("status")
        if st not in ALLOWED_STATUS:
            errors.append(f"{fid}: 非法 status={st}")
            continue

        # candidate 门：必须带触发物 + 解锁计划
        if st in ("candidate", "verifying"):
            if not f.get("trigger"):
                errors.append(f"{fid}: candidate 缺 trigger（等账号/等样本/等批复/技术闭）")
            if not isinstance(f.get("unlock_plan"), dict) or not f.get("unlock_plan", {}).get("trigger_what"):
                errors.append(f"{fid}: candidate 缺 unlock_plan.trigger_what（解锁计划必填，无计划不生成 candidate）")

        # verified 门：证据三件套
        if st in ("verified", "money_ready", "delivered"):
            if not str(f.get("summary") or "").strip():
                errors.append(f"{fid}: verified 缺 summary/business_evidence")
            if not str(f.get("poc") or "").strip():
                errors.append(f"{fid}: verified 缺 poc（replay_script/poc_curl 至少一）")
            if not str(f.get("replay_signature") or "").strip():
                errors.append(f"{fid}: verified 缺 replay_signature（≥8 字节具体业务证据串）")

        # 投递复检纪律（v4 P0-5 复盘固化）：verified+ 应有最近复检日
        lrc = f.get("last_rechecked")
        if st in ("verified", "money_ready", "delivered"):
            if not str(lrc or "").strip():
                warnings.append(f"{fid}: verified 缺 last_rechecked（投递对象必须带最近复检日 YYYY-MM-DD；未复检的投递前补测）")
            else:
                try:
                    datetime.strptime(str(lrc), "%Y-%m-%d")
                except (ValueError, TypeError):
                    errors.append(f"{fid}: last_rechecked 格式错（应为 YYYY-MM-DD，实际 {lrc}）")

            # TEMP 证据错位提醒（v4 P0-5 复盘固化）：verified 证据仍在 TEMP → 应 promote
            # 仅 verified+ 触发：candidate/phenomenon 的证据在 TEMP 属正常（工作态），verified 才必须留档
            for key in ("evidence", "evidence_files", "poc"):
                val = f.get(key) or ""
                if isinstance(val, str) and ("tmp/" in val or "artifacts/tmp" in val):
                    warnings.append(f"{fid}: {key} 仍指向 TEMP（{str(val)[:40]}…）→ verified 后立即 cp 到 E:/claude-artifacts/<target>/，防工作区清理错位")
                    break

        # money_ready 字段一致性
        if st == "money_ready" and f.get("money_ready") is not True:
            errors.append(f"{fid}: status=money_ready 但 money_ready!=true")
        if f.get("money_ready") is False and st not in ("candidate", "verifying", "phenomenon", "rejected", "fixed"):
            if not str(f.get("missing") or "").strip():
                warnings.append(f"{fid}: money_ready=false 缺 missing（缺 business_evidence/缺采样/缺拍板…）→ 无法自动进补证据队列")
        if st == "delivered" and f.get("money_ready") is not True:
            errors.append(f"{fid}: delivered 但 money_ready!=true")

        if st in ("rejected", "fixed") and not str(f.get("reason") or "").strip():
            warnings.append(f"{fid}: rejected/fixed 建议补 reason")

        # deadline 归档提醒（等样本 2 周规则）
        up = f.get("unlock_plan") or {}
        dl = up.get("deadline")
        if dl and st in ("candidate", "verifying"):
            try:
                if datetime.fromisoformat(str(dl).replace("Z", "+00:00")) < datetime.now():
                    warnings.append(f"{fid}: unlock_plan.deadline={dl} 已过期 → 按 2 周归档规则移 dead-ends（带 reopen_if）")
            except (ValueError, TypeError):
                pass

    # approval_queue 校验
    for i, a in enumerate(data.get("approval_queue") or []):
        if not isinstance(a, dict):
            continue
        if a.get("approved") is True and not a.get("approved_at"):
            warnings.append(f"approval_queue[{i}]: approved=true 缺 approved_at")
        if a.get("level") not in ("L1", "L2", "L3"):
            errors.append(f"approval_queue[{i}]: level 必须 L1/L2/L3（按包数不按工具名判定）")
        # L1 判别包指纹确认前置（law.md §4.0）：未批准条目必须带 fingerprint
        if a.get("level") == "L1" and not a.get("approved") and not str(a.get("fingerprint") or "").strip():
            warnings.append(f"approval_queue[{i}] (L1 {a.get('finding')}): 缺 fingerprint（目标指纹确认记录必填，见 law.md §4.0）")

    return errors, warnings


# ── 视图生成 ──────────────────────────────────────────

def _sort(items):
    return sorted(
        items,
        key=lambda f: (SEV_RANK.get(str(f.get("severity") or "?").lower(), 9), str(f.get("id") or "")),
    )


def _line(f, money_col=True):
    mr = f.get("money_ready")
    if mr is True:
        mrs = "yes"
    elif mr is False:
        mrs = f"no{f'（{f.get("missing")}）' if f.get("missing") else ''}"
    else:
        mrs = "-"
    return f"| {f.get('id')} | {str(f.get('title') or '')[:60]} | {f.get('severity') or '?'} | {f.get('status')} | {f.get('target') or ''} | {mrs} |"


def gen_index(data, target):
    """顶层 findings.md 索引（自动生成，勿手改）。"""
    rows = _sort(data.get("findings") or [])
    lines = [
        f"# {target} — Findings 索引（自动生成）",
        "",
        f"> 真相源 = `lifecycle.yaml`；由 `python tools/findings-lint.py {target} --lifecycle --gen` 生成，勿手改本文件。",
        "",
        f"共 {len(rows)} 条 · verified/money_ready={sum(1 for f in rows if f.get('status') in ('verified', 'money_ready', 'delivered'))} · candidate={sum(1 for f in rows if f.get('status') == 'candidate')}",
        "",
        "| ID | 摘要 | 级别 | 状态 | 目标 | money_ready |",
        "|---|---|---|---|---|---|",
    ]
    lines += [_line(f) for f in rows]
    return "\n".join(lines) + "\n"


def gen_delivery_queue(data):
    """投递队列：money_ready=true 且 verified+，按 delivery_order（缺省 severity）排序。"""
    rows = [
        f for f in data.get("findings") or []
        if f.get("status") in ("verified", "money_ready", "delivered") and f.get("money_ready") is True
    ]
    if not rows:
        return None

    def key(f):
        order = f.get("delivery_order")
        try:
            o = int(order) if order not in (None, "") else 999
        except (TypeError, ValueError):
            o = 999
        return (o, SEV_RANK.get(str(f.get("severity") or "?").lower(), 9), str(f.get("id") or ""))

    rows = sorted(rows, key=key)
    lines = [
        "# 投递队列（自动生成）",
        "",
        "> 由 lifecycle.yaml 生成。**投递动作由用户人为执行**，本清单只排顺序（delivery_order 字段=用户拍板顺序）。",
        "> **最近复检列**：lifecycle 每条 verified 的 `last_rechecked`（YYYY-MM-DD）。缺 ⚠️ = 未复检，投递前必须补测 liveness（v4 P0-5 复盘固化：PH-F-003 死洞就是此环节抓到的）。",
        "",
        "| # | ID | 摘要 | 级别 | 最近复检 |",
        "|---|---|---|---|---|",
    ]
    for i, f in enumerate(rows, 1):
        lrc = str(f.get("last_rechecked") or "")
        lrc_disp = lrc if lrc else "⚠️ 未复检"
        lines.append(f"| {i} | {f.get('id')} | {str(f.get('title') or '')[:60]} | {f.get('severity') or '?'} | {lrc_disp} |")
    return "\n".join(lines) + "\n"


def gen_evidence_queue(data):
    """补证据队列：verified/money_ready 但 money_ready=false（缺 missing 标注者也列出）。"""
    rows = [
        f for f in data.get("findings") or []
        if f.get("status") in ("verified", "money_ready") and f.get("money_ready") is not True
    ]
    if not rows:
        return None
    lines = [
        "# 补证据队列（自动生成）",
        "",
        "> money_ready=no 的 verified：按 missing 字段补证据（采样证据四件套：数据量/采样≤5/敏感度论证/反事实）。",
        "",
        "| ID | 摘要 | 级别 | 缺什么 |",
        "|---|---|---|---|",
    ]
    for f in _sort(rows):
        lines.append(f"| {f.get('id')} | {str(f.get('title') or '')[:50]} | {f.get('severity') or '?'} | {str(f.get('missing') or '')[:80]} |")
    return "\n".join(lines) + "\n"


def prefilter_judgement(f):
    """判定类条目预筛（v4 P0-1）：按垃圾洞清单自动分类。

    返回 (类别, 原因) 表示自动跳过/合并；返回 None 表示保留待判。
    原则：① 预筛只决定"是否值得占用用户注意力"，不决定"投不投"，原因可查可复议；
         ② low 级才自动筛，medium+ 一律保留待判；
         ③ lifecycle.yaml 可显式覆盖：prefilter: keep（保留）/ skip（跳过，须带 prefilter_reason）。
    """
    up = f.get("unlock_plan") or {}
    t = str(f.get("title") or "")
    tw = str(up.get("trigger_what") or "")
    hay = t + " " + tw  # 标题 + 解锁计划，双信号匹配

    # 人工覆盖优先
    pf = f.get("prefilter")
    if pf == "keep":
        return None
    if pf == "skip":
        return ("人工标跳过", str(f.get("prefilter_reason") or "无"))

    # 并入主投递包（不是跳过，是合并叙述）
    if "并入" in tw and "投递" in tw:
        return ("并入主投递包", tw[:44])

    # medium+ 一律保留待判（不自动消耗用户判定权）
    if str(f.get("severity") or "?").lower() not in ("low",):
        return None

    RULES = [
        ("枚举oracle无链", ["枚举", "oracle", "分叉"]),
        ("拓扑/配置泄露", ["dns 泄露", "内网地址", "配置泄露", "stats.do", "统计泄露", "env ", "/env", "错误回显", "配置错误"]),
        ("低危公开面", ["公开面", "商品列表", "公开数据"]),
        ("骚扰类无法实证", ["轰炸", "骚扰", "垃圾邮件"]),
        ("硬编码密钥无法利用", ["硬编码", "私钥"]),
        ("信息暴露无敏感数据", ["信息泄露", "信息暴露"]),
    ]
    for cat, kws in RULES:
        if any(k in hay.lower() for k in kws):
            return (cat, f"命中「{cat}」垃圾洞特征（标题/解锁计划双信号）")
    return None


def gen_approval_queue(data):
    """每日可批清单：approval_queue（发包授权 L1/L2/L3）+ trigger=等批复 的 candidate（投递判定类）。

    两类区分：L1/L2/L3 = 发包授权类（用户批后执行，逐条置 approved）；
    「判定」 = 投递判定类（不发包，只等用户拍板投不投/怎么投）。"""
    entries = []      # 需人拍板区（保留待判）
    skips = []        # auto-skip 区（预筛默认不投/并入主包，可复议）
    in_approval = set()
    for a in data.get("approval_queue") or []:
        if isinstance(a, dict) and not a.get("approved"):
            entries.append((a.get("level", "L1"), f"{a.get('finding')}: {a.get('action')}", a.get("packets", "-"), a.get("benefit", "")))
            in_approval.add(str(a.get("finding") or ""))
    for f in data.get("findings") or []:
        if f.get("status") in ("candidate", "verifying") and f.get("trigger") == "等批复":
            fid = str(f.get("id") or "")
            if fid in in_approval:
                continue  # 已入 approval_queue（如 SF-066），去重
            up = f.get("unlock_plan") or {}
            item = (f"{fid}: {str(f.get('title') or '')[:50]}", "-", up.get("trigger_what", ""))
            pre = prefilter_judgement(f)
            if pre:
                skips.append((fid, item, pre[0], pre[1]))
            else:
                entries.append(("判定", item[0], item[1], item[2]))
    if not entries and not skips:
        return None
    lines = [
        "# 每日可批清单（自动生成）",
        "",
        "> L0 只读 GET=默认授权；L1 1包级=批量预授权（用户回「批 1/3/5」或「全批 L1」）；L2 注册类=单次批准；L3 重武器=单次批准。",
        "> 「判定」= 投递判定类（不发包，只等用户拍板投不投/怎么投）。",
        "> **预筛（v4 P0-1）**：low 级按垃圾洞清单自动标跳过（下方 auto-skip 区，原因可查、可复议）；medium+ 与业务类一律保留待判。",
        "",
    ]
    if entries:
        lines += [
            "## 需人拍板区",
            "",
            "| # | 级 | 动作 | 包数 | 预期收益 |",
            "|---|---|---|---|---|",
        ]
        for i, (lv, act, pk, bn) in enumerate(entries, 1):
            lines.append(f"| {i} | {lv} | {act} | {pk} | {bn} |")
    if skips:
        lines += [
            "",
            f"## auto-skip 区（预筛 {len(skips)} 项默认不投/并入主包，复议请在 lifecycle.yaml 标 prefilter: keep 或找 Commander）",
            "",
            "| ID | 摘要 | 类别 | 原因 |",
            "|---|---|---|---|",
        ]
        for fid, item, cat, why in skips:
            lines.append(f"| {fid} | {item[0][:44]} | {cat} | {why} |")
    return "\n".join(lines) + "\n"


def gen_expiry_alerts(data):
    """到期提醒：deadline 已过 / 3 日内到期的 candidate + tasks（v4 §6.4/§10.1）。"""
    now = datetime.now()
    rows = []
    for f in data.get("findings") or []:
        if f.get("status") not in ("candidate", "verifying"):
            continue
        up = f.get("unlock_plan") or {}
        dl = up.get("deadline")
        if not dl:
            continue
        try:
            dt = datetime.fromisoformat(str(dl).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        days = (dt - now).days
        if days < 3:
            rows.append((f.get("id"), dl, str(f.get("trigger") or "?"), str(f.get("title") or "")[:50], days, "finding"))
    for t in data.get("tasks") or []:
        dl = t.get("deadline")
        if not dl:
            continue
        try:
            dt = datetime.fromisoformat(str(dl).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        days = (dt - now).days
        if days < 3:
            rows.append((t.get("id"), dl, str(t.get("trigger") or "?"), str(t.get("title") or "")[:50], days, "task"))
    if not rows:
        return None
    lines = [
        "# 到期提醒（自动生成）",
        "",
        "> findings = candidate/verifying 的 unlock_plan.deadline；tasks = 待账号/待验证任务（v4 §6.4）。deadline 已过或 3 日内到期才列出。",
        "",
        "| ID | 类型 | deadline | 触发物 | 摘要 | 剩余天数 |",
        "|---|---|---|---|---|---|",
    ]
    for fid, dl, tr, ti, days, kind in sorted(rows, key=lambda r: r[4]):
        lines.append(f"| {fid} | {kind} | {dl} | {tr} | {ti} | {days} |")
    return "\n".join(lines) + "\n"


def write_views(target_dir, data):
    """--gen 落盘视图 → targets/<t>/output/lifecycle-views/。返回 [写入路径]。"""
    views = {
        "findings-index.md": gen_index(data, Path(target_dir).name),
        "delivery-queue.md": gen_delivery_queue(data),
        "evidence-queue.md": gen_evidence_queue(data),
        "approval-queue.md": gen_approval_queue(data),
        "expiry-alerts.md": gen_expiry_alerts(data),
    }
    out_dir = Path(target_dir) / VIEW_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in views.items():
        if content is None:
            p = out_dir / name
            if p.is_file():
                p.unlink()
            continue
        p = out_dir / name
        p.write_text(content, encoding="utf-8")
        written.append(str(p))
    return written
