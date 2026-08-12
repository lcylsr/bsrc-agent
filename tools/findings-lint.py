#!/usr/bin/env python3
# tools/findings-lint.py — findings.md 状态机校验 + 倒计时。退出码:0=合规 / 2=警告 / 1=阻断错误 / 3=用法错
import sys, os
import argparse
from datetime import datetime
from pathlib import Path

# Windows Git Bash pipe 环境下 stdout 可能默认 gbk,强制 utf-8
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from findings_parser import (
    parse_findings,
    scan_orphan_headers,
    is_generic_signature,
    is_generic_business_evidence,
    trash_hit,
    compute_readiness,
    is_shell_verified,
)
from findings_paths import resolve_findings_inputs, FindingsPathError
from lifecycle import load_lifecycle, validate, write_views


def parse_iso(s):
    if isinstance(s, datetime):
        return s.timestamp()
    s = str(s).strip()
    try:
        return datetime.fromisoformat(s).timestamp()  # 3.11+ 支持 +08:00 时区
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try: return datetime.strptime(s, fmt).timestamp()
        except ValueError: pass
    return 0


def get_head_findings(path):
    """读取 git HEAD 版本的 findings 并返回 {id: status}。"""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{path}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if result.returncode != 0:
            return {}
    except Exception:
        return {}
    # 复用 parse_findings 解析
    try:
        items = parse_findings_from_text(result.stdout)
    except Exception:
        return {}
    return {item["id"]: item["yaml"].get("status", "") for item in items}


def parse_findings_from_text(text):
    """从文本解析 findings(避免 parse_findings 只接受文件路径)。"""
    # findings_parser.parse_findings 接受文件路径;这里我们手写最小解析
    import re
    import yaml
    items = []
    # 匹配 ```yaml 块或直接 --- frontmatter
    for block in re.split(r"```yaml\s*\n|---\s*\n", text):
        if not block.strip():
            continue
        yaml_part = block.split("```", 1)[0]
        try:
            fm = yaml.safe_load(yaml_part) or {}
        except Exception:
            continue
        if isinstance(fm, dict) and fm.get("id"):
            items.append({"id": fm["id"], "yaml": fm})
    return items


def check_verified_monotonic(path, current_items):
    """检查 verified finding id 是否单调不减。"""
    head_map = get_head_findings(path)
    if not head_map:
        return []
    current_ids = {item["id"] for item in current_items}
    missing = []
    for fid, status in head_map.items():
        if status in ("verified", "deliverable") and fid not in current_ids:
            missing.append(fid)
    return missing


def _lint_one_file(f, *, host="", now=None, fold_shell=True):
    """
    校验单个 findings.md。
    返回 (errors, warnings, intuition_count, items_n, shell_n)。
    fold_shell: 空壳 verified 只计 error,最多打印 2 条后摘要。
    """
    if now is None:
        now = datetime.now().timestamp()
    errors = warnings = intuition_count = shell_n = 0
    prefix = f"{host}/" if host else ""

    try:
        items = parse_findings(f)
    except Exception as exc:
        print(f"❌ 解析 {f} 失败: {exc}")
        print("   修复: 检查文件 YAML frontmatter 是否合法")
        return 1, 0, 0, 0, 0

    # orphan: 叙事 ### F- 标题无 frontmatter → 工具链失明,阻断
    try:
        orphans = scan_orphan_headers(f)
    except Exception:
        orphans = []
    if orphans:
        print(f"❌ [{prefix or 'root'}] 发现 {len(orphans)} 个 orphan 叙事洞:")
        for o in orphans[:12]:
            print(f"   - {prefix}{o['id']} L{o['line']}: {o.get('title','')[:60]}")
        if len(orphans) > 12:
            print(f"   … 另有 {len(orphans) - 12} 个")
        print("   修复: 按 targets/_template/findings.md 格式补 YAML frontmatter")
        errors += len(orphans)

    if not items:
        # tree 模式下根 findings 常为纯索引 → 不报错,由调用方决定
        return errors, warnings, intuition_count, 0, 0

    # 单调性校验:禁止 agent 覆盖导致 verified finding 丢失
    try:
        rel_path = os.path.relpath(f, os.getcwd())
    except ValueError:
        rel_path = f
    missing_verified = check_verified_monotonic(rel_path, items)
    if missing_verified:
        print(f"❌ [{prefix or 'root'}] 以下 verified/deliverable 在 HEAD 中存在,当前文件缺失:")
        for fid in missing_verified:
            print(f"   - {prefix}{fid}")
        print("   修复: 从 git 恢复该 finding,或显式说明已合并/关闭")
        return errors + len(missing_verified), warnings, intuition_count, len(items), 0

    shell_shown = 0
    for item in items:
        fid = item["id"]
        disp = f"{prefix}{fid}"
        d = item["yaml"]
        status = d.get("status", "")
        changed = d.get("status_changed_at", "")
        upath_type = d.get("upgrade_path", {}).get("type", "") if isinstance(d.get("upgrade_path"), dict) else ""
        poc_curl = d.get("poc_curl", "")
        replay_script = d.get("replay_script", "")
        replay_signature = d.get("replay_signature", "")
        business_evidence = d.get("business_evidence", "")

        # L-TITLE / L-SEV: 空壳 verified
        if status in ("verified", "deliverable") and is_shell_verified(item):
            shell_n += 1
            errors += 1
            if not fold_shell or shell_shown < 2:
                print(f"── {disp} [{status}]")
                print("  ❌ L-TITLE/L-SEV 空壳 verified(title 空或 severity 非法) → 降 phenomenon 或补 title")
                shell_shown += 1
            continue

        print(f"── {disp} [{status}]")

        if status in ("candidate", "verifying") and not upath_type:
            print("  ❌ candidate/verifying 状态缺 upgrade_path.type")
            errors += 1

        if status in ("candidate", "verifying") and isinstance(d.get("upgrade_path"), dict):
            ma = d.get("upgrade_path", {}).get("missing_artifacts")
            if ma is None or (isinstance(ma, str) and not str(ma).strip()):
                print("  ⚠️  upgrade_path 建议补 missing_artifacts: [reproduction] 和/或 [impact]")
                warnings += 1
            else:
                try:
                    rd_c = compute_readiness(item, findings_path=f)
                    stale = rd_c.get("missing_artifacts_stale") or []
                    if stale:
                        print(
                            f"  ⚠️  missing_artifacts 声明过期 stale={stale}；"
                            f"derived={rd_c.get('missing_artifacts')} "
                            f"plan={rd_c.get('missing_artifacts_plan')}"
                        )
                        warnings += 1
                except Exception:
                    pass

        if status in ("verified", "deliverable"):
            if not poc_curl.strip() and not replay_script.strip():
                print("  ❌ verified 必须提供 poc_curl 或 replay_script")
                errors += 1
            if is_generic_signature(replay_signature):
                print(f"  ❌ verified replay_signature 太泛化或为黑名词: {str(replay_signature)[:40]}")
                errors += 1
            if is_generic_business_evidence(business_evidence):
                print("  ❌ verified business_evidence 缺失或为泛化状态描述(需真实业务影响,非 HTTP 200)")
                errors += 1
            th = trash_hit(item.get("title_line") or "") or trash_hit(str(d.get("title") or ""))
            if th:
                print(f"  ❌ verified 命中垃圾洞关键词 '{th}' — 无链式利用禁止 verified")
                errors += 1
            try:
                rd = compute_readiness(item, findings_path=f)
                if rd.get("blockers") and not rd.get("money_ready"):
                    bl = rd["blockers"]
                    if set(bl) <= {"need_replay"}:
                        print("  ⚠️  verified 仅缺 replay → AI 现场写 output/poc-<finding_id>.py 并运行验证后才 money_ready(非缺 PoC)")
                    else:
                        print(f"  ⚠️  readiness blockers: {','.join(bl)}")
                    warnings += 1
            except Exception:
                pass
            for key in ("evidence_files", "evidence", "poc_path", "poc_file"):
                val = d.get(key)
                refs = []
                if isinstance(val, list):
                    refs = [str(x) for x in val]
                elif isinstance(val, str):
                    refs = [val]
                for ref in refs:
                    r = ref.replace("\\", "/")
                    if "targets/" in r and ("/probes/" in r or "/raw/" in r) and not r.startswith("artifact:"):
                        print(f"  ⚠️  workspace-path-legacy: {key} 仍写仓库路径 → 改 artifact: 或 promote")
                        warnings += 1
                        break

        if status in ("candidate", "verifying", "phenomenon"):
            th = trash_hit(item.get("title_line") or "") or trash_hit(str(d.get("title") or ""))
            if th:
                print(f"  ⚠️  标题像垃圾洞模式('{th}') — 无链保持 phenomenon/不升 verified")
                warnings += 1

        if upath_type == "intuition":
            intuition_count += 1
            it_len = 0
            if d.get("upgrade_path") and isinstance(d.get("upgrade_path"), dict):
                it_text = d.get("upgrade_path", {}).get("intuition_text", "")
                it_len = len(it_text)
            if it_len < 50:
                print(f"  ❌ intuition_text < 50 字 (实际 {it_len})")
                errors += 1
            deadline = d.get("upgrade_path", {}).get("intuition_followup_deadline", "") if isinstance(d.get("upgrade_path"), dict) else ""
            if deadline:
                dt = parse_iso(deadline)
                if dt > 0 and dt < now:
                    print(f"  ⚠️  intuition followup 已超时 ({deadline}) → 应降回 phenomenon")
                    warnings += 1

        if status in ("candidate", "verifying") and changed:
            c = parse_iso(changed)
            if c > 0:
                age = now - c
                if age > 1800:
                    print(f"  ⚠️  {status} 已挂 {int(age//60)} 分钟 (>30) → 必须证伪试探或降级")
                    warnings += 1

    if fold_shell and shell_n > 2:
        print(f"  … L-TITLE 空壳 verified×{shell_n - 2} 折叠({f})")

    return errors, warnings, intuition_count, len(items), shell_n


def main():
    parser = argparse.ArgumentParser(description="findings.md 状态机校验 + 倒计时(支持 program tree)；--lifecycle 单一日志模式")
    parser.add_argument("findings", nargs="?", default="", help="findings.md 或 target_dir")
    parser.add_argument("--lifecycle", action="store_true", help="lifecycle.yaml 状态机校验模式(v2 根因方案 解法 A)")
    parser.add_argument("--gen", action="store_true", help="--lifecycle 时生成视图(output/lifecycle-views/ + 覆盖顶层 findings.md 索引)")
    args = parser.parse_args()

    raw = args.findings
    if not raw:
        print("❌ findings-lint: 缺参数 findings.md 或 target_dir")
        print("   usage: python tools/findings-lint.py <findings.md|target_dir> [--lifecycle [--gen]]")
        return 3

    # ── lifecycle 单一日志模式(v2):target_dir + lifecycle.yaml 为真相源 ──
    if args.lifecycle:
        try:
            res0 = resolve_findings_inputs(raw)
        except FindingsPathError as e:
            print(f"❌ findings-lint: {e}")
            return 3
        tdir = str(res0["target_dir"])
        data = load_lifecycle(tdir)
        if data is None:
            print(f"❌ --lifecycle: {tdir}/lifecycle.yaml 不存在")
            print("   模板: targets/_template/lifecycle.yaml")
            return 3
        errors, warnings = validate(data)
        print("━━━ findings-lint --lifecycle (v2 解法 A) ━━━")
        print(f"target : {tdir}")
        print(f"findings: {len(data.get('findings') or [])} · approval_queue: {len(data.get('approval_queue') or [])}")
        print()
        if errors:
            for e in errors:
                print(f"  ❌ {e}")
        if warnings:
            for w in warnings:
                print(f"  ⚠️  {w}")
        if not errors and not warnings:
            print("  ✓ 状态机前置条件全部满足")
        if args.gen:
            written = write_views(tdir, data)
            print()
            print("── 视图已生成 ──")
            for p in written:
                print(f"  ✓ {os.path.relpath(p, tdir)}")
            print(f"  （顶层 {Path(tdir).name}/findings.md 索引请由生成器落盘或人工同步——生成内容见 output/lifecycle-views/findings-index.md）")
        print()
        print("━━━ 汇总 ━━━")
        print(f"  错误 : {len(errors)}")
        print(f"  警告 : {len(warnings)}")
        return 1 if errors else (2 if warnings else 0)

    try:
        res = resolve_findings_inputs(raw)
    except FindingsPathError as e:
        print(f"❌ findings-lint: {e}")
        return 3

    target_dir = str(res["target_dir"])
    files = [str(p) for p in res["files"]]

    if os.environ.get("BYPASS", "0") == "1":
        print("⚠️  findings-lint BYPASS=1")
        tl = os.path.join(target_dir, "timeline.md")
        if os.path.isfile(tl):
            with open(tl, "a", encoding="utf-8") as t:
                t.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} [bypass] findings-lint BYPASS=1\n")
        return 0

    now = datetime.now().timestamp()
    errors = warnings = intuition_count = total_items = shell_total = 0
    files_with_items = 0

    print("━━━ findings-lint v5 (tree-aware) ━━━")
    print(f"input : {raw}")
    print(f"mode  : {res['mode']} program={res['is_program']} files={len(files)}")
    print(f"target: {target_dir}")
    print()

    for fpath in files:
        host = ""
        try:
            parent = os.path.dirname(os.path.abspath(fpath))
            tdir = os.path.abspath(target_dir)
            if parent != tdir and parent.startswith(tdir):
                host = os.path.relpath(parent, tdir).replace("\\", "/")
        except ValueError:
            host = os.path.basename(os.path.dirname(fpath))

        e, w, ic, n, sh = _lint_one_file(fpath, host=host, now=now, fold_shell=True)
        errors += e
        warnings += w
        intuition_count += ic
        total_items += n
        shell_total += sh
        if n > 0:
            files_with_items += 1
        # tree 根空索引: 跳过「无 finding」报错
        if n == 0 and res["mode"] == "tree" and not host:
            continue
        if n == 0 and res["mode"] == "file":
            print("❌ 未找到任何带 id: F-XX 的 frontmatter 块")
            print("   修复: 按 targets/_template/findings.md 格式补 frontmatter")
            return 1

    if total_items == 0 and res["mode"] == "tree":
        print("❌ tree 模式未找到任何带 id: F-XX 的 frontmatter(含子域)")
        print("   修复: 检查子域 */findings.md 或先 migrate")
        return 1

    print()
    print("━━━ 汇总 ━━━")
    print(f"  finding 数 : {total_items} (files_with_yaml={files_with_items})")
    print(f"  错误     : {errors}")
    print(f"  警告     : {warnings}")
    print(f"  intuition: {intuition_count}")
    if shell_total:
        print(f"  空壳 L-TITLE: {shell_total}")
    if intuition_count > 5:
        print("  ⚠️  intuition 升级累计 > 5,建议先收敛验证(防滥用为逃逸口)")
        warnings += 1

    if errors > 0:
        return 1
    if warnings > 0:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FileNotFoundError as exc:
        print(f"❌ findings-lint: 文件未找到: {exc.filename}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"❌ findings-lint: 未预期错误: {exc}", file=sys.stderr)
        sys.exit(1)
