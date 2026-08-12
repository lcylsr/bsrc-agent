#!/usr/bin/env python3
# tools/playbook/match.py — match.sh 的 Python 实现(治本:~16s → <1s,消除双层 while + 每 token 一次 grep fork)
#
# v6.0-slim: 行为契约见 README.md。历史 bash 版回归测试(test.sh)已随瘦身删除。
#   1. 读 target/scope.md
#   2. 遍历 memory/playbooks/playbook-*.md(playbook_type: executable),做 ## 触发指纹 子串匹配
#   3. 命中 ≥2 个指纹 → 写入 scope.md frontmatter 的 playbooks_match: 列表
# 退出码: 0=完成 / 1=用法/目录错误
import sys, os, re
from datetime import datetime

def die(msg, code=1):
    try:
        sys.stderr.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors="replace"))
    sys.exit(code)

# Windows console (GBK) 无法打印 ✓⚠️📌 — 失败时替换为 ASCII 回退(照 quickcheck.py)
def _safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        for a, b in (("✓", "OK"), ("✗", "X"), ("⚠", "!"), ("📌", "->"), ("━", "-")):
            text = text.replace(a, b)
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.buffer.write((text + kwargs.get("end", "\n")).encode(enc, errors="replace"))

def extract_section(text, header_re):
    out, flag = [], False
    hre = re.compile(header_re)
    for line in text.splitlines():
        if hre.match(line):
            flag = True; continue
        if flag and line.startswith("## "):
            break
        if flag:
            out.append(line)
    return out

def main():
    args = sys.argv[1:]
    if not args:
        die("用法: match.py <target_dir>")
    target = args[0]
    if not os.path.isdir(target):
        die(f"✗ 目录不存在: {target}")
    scope = os.path.join(target, "scope.md")
    if not os.path.isfile(scope):
        die(f"✗ scope.md 不存在: {scope}")

    scope_text = open(scope, encoding="utf-8", errors="replace").read()

    matched, reasons = [], []
    import glob
    for pb in sorted(glob.glob("memory/playbooks/playbook-*.md")):
        pb_text = open(pb, encoding="utf-8", errors="replace").read()
        tm = re.search(r"^playbook_type:\s*(.+)$", pb_text, re.M)
        pb_type = (tm.group(1).strip().strip('",').strip() if tm else "executable") or "executable"
        if pb_type != "executable":
            continue

        trigger = extract_section(pb_text, r"^## 触发指纹")
        if not trigger:
            continue

        hit_count = 0
        evidence = []
        for line in trigger:
            clean = re.sub(r"^[ \t]*[-*][ \t]*", "", line).strip()
            if not clean or len(clean) < 5:
                continue
            if "`" in clean:
                for tok in re.findall(r"`([^`]+)`", clean):
                    if tok and tok in scope_text:
                        hit_count += 1
                        evidence.append(f"    📌 {tok}")
            else:
                tok = clean[:50]
                if tok in scope_text:
                    hit_count += 1
                    evidence.append(f"    📌 {tok}")

        if hit_count >= 2:
            pb_name = os.path.basename(pb)[:-3]  # 去 .md
            matched.append(pb_name)
            reasons.append(f"{pb} (命中 {hit_count} 个指纹):\n" + "\n".join(evidence))

    _safe_print(f"━━━ playbook match @ {datetime.now().strftime('%H:%M')} ━━━")
    _safe_print(f"target: {target}")
    _safe_print()

    if not matched:
        _safe_print("⚠️ 未命中任何 executable playbook")
        _safe_print("  (目标 scope.md 与所有 playbook 的触发指纹匹配 < 2 个)")
        if not re.search(r"^playbooks_match:", scope_text, re.M):
            _safe_print("  scope.md 无 playbooks_match 字段,跳过写入")
        return 0

    _safe_print(f"✓ 命中 {len(matched)} 个 playbook")
    for r in reasons:
        _safe_print(f"  {r}")

    list_yaml = "playbooks_match: [" + ", ".join(f'"{m}"' for m in matched) + "]"

    lines = scope_text.splitlines()
    # frontmatter 第二个 --- 的行号(1-based)
    fm_end = None
    c = 0
    for i, ln in enumerate(lines):
        if ln.strip() == "---":
            c += 1
            if c == 2:
                fm_end = i  # 0-based index of 2nd ---
                break
    if fm_end is None:
        _safe_print("⚠️ scope.md 无 frontmatter,跳过写入")
        return 0

    if any(re.match(r"^playbooks_match:", ln) for ln in lines):
        out = [list_yaml if re.match(r"^playbooks_match:", ln) else ln for ln in lines]
    else:
        out = lines[:fm_end] + [list_yaml] + lines[fm_end:]
    open(scope, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")

    _safe_print()
    _safe_print("✓ scope.md 已更新 frontmatter:")
    _safe_print(f"  {list_yaml}")
    _safe_print()
    _safe_print(f"下一步: python tools/playbook/quickcheck.py {target}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
