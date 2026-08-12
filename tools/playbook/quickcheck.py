#!/usr/bin/env python3
# tools/playbook/quickcheck.py — quickcheck.sh 的 Python 实现(治本:Windows 上从 ~57s 降到 <1s)
#
# v6.0-slim: 行为契约见 README.md。历史 bash 版回归测试(test.sh)已随瘦身删除。
#   1. 读 scope.md 的 playbooks_match 列表 + 入口 URL -> BASE
#   2. 对每个命中 playbook,解析 ## 验证命令 段(### 件 N: METHOD/PATH/HIT_GREP/FIXED_GREP)
#   3. 逐件构造请求(--mock 读 fixture),三档判定(HIT_GREP / FIXED_GREP 按 ERE 正则匹配)
#   4. 写回 scope.md 的 "## playbook 件状态" 章节(不写 findings.md)
#
# 退出码: 0=完成 / 1=用法/目录错误
import sys, os, re, subprocess
from datetime import datetime

# Windows console (GBK) cannot print 🟢🟡🔴 — replace for stdout only
def _safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        for a, b in (("🟢", "[HIT]"), ("🔴", "[FIXED]"), ("🟡", "[?]"), ("✓", "OK"), ("✗", "X"), ("⚠", "!")):
            text = text.replace(a, b)
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.buffer.write((text + kwargs.get("end", "\n")).encode(enc, errors="replace"))

def die(msg, code=1):
    try:
        sys.stderr.write(msg + "\n")
    except UnicodeEncodeError:
        sys.stderr.buffer.write((msg + "\n").encode("utf-8", errors="replace"))
    sys.exit(code)

def main():
    args = sys.argv[1:]
    if not args:
        die("用法: quickcheck.py <target_dir> [--mock <fixture_dir>]")
    target = args[0]
    mock_dir = ""
    if len(args) >= 2 and args[1] == "--mock":
        if len(args) < 3:
            die("用法: quickcheck.py <target_dir> [--mock <fixture_dir>]")
        mock_dir = args[2]
        if not os.path.isdir(mock_dir):
            die(f"✗ mock dir 不存在: {mock_dir}")
    if not os.path.isdir(target):
        die(f"✗ 目录不存在: {target}")
    scope = os.path.join(target, "scope.md")
    if not os.path.isfile(scope):
        die("✗ scope.md 不存在")

    scope_text = open(scope, encoding="utf-8", errors="replace").read()

    # ── playbooks_match ──
    m = re.search(r"^playbooks_match:\s*\[(.*?)\]\s*$", scope_text, re.M)
    pb_list = []
    if m:
        pb_list = [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]
    if not pb_list:
        _safe_print("⚠️ scope.md 无 playbooks_match 命中,跳过 quickcheck")
        _safe_print(f"  先跑: python tools/playbook/match.py {target}")
        return 0

    # ── BASE URL ──
    base = ""
    for line in scope_text.splitlines():
        if re.search(r"入口\s*URL", line):
            bm = re.search(r"`([^`]+)`", line)
            if bm:
                um = re.match(r"^([a-z]+://[^/]+)", bm.group(1))
                if um:
                    base = um.group(1)
                    break
    if not base:
        die('✗ scope.md 无入口 URL(grep "入口 URL" + backtick)')

    now_hm = datetime.now().strftime("%H:%M")
    now_full = datetime.now().strftime("%Y-%m-%d_%H:%M")
    _safe_print(f"━━━ playbook quickcheck @ {now_hm} ━━━")
    _safe_print(f"target: {target}")
    _safe_print(f"BASE:   {base}")
    if mock_dir:
        _safe_print(f"mode:   --mock {mock_dir}")
    _safe_print()

    status_lines = [f"## playbook 件状态(quickcheck.py @ {now_full} 自动填,LLM 复核)", ""]
    total_packets = 0

    for pb_name in pb_list:
        # playbooks live in memory/playbooks/
        candidates = []
        name = pb_name
        if name.endswith(".md"):
            name = name[:-3]
        candidates.append(os.path.join("memory", "playbooks", f"{name}.md"))
        if not name.startswith("playbook-"):
            candidates.append(os.path.join("memory", "playbooks", f"playbook-{name}.md"))
        # also accept bare basename without playbook- prefix if list already has full name
        pb_file = next((c for c in candidates if os.path.isfile(c)), None)
        if not pb_file:
            _safe_print(f"✗ playbook 文件不存在: {pb_name} (tried memory/playbooks/)")
            continue

        _safe_print(f"── playbook: {pb_name} ──")
        status_lines.append(f"- playbook: {pb_name}")

        pb_text = open(pb_file, encoding="utf-8", errors="replace").read()
        # 提取 ## 验证命令 段
        cmd_block = extract_section(pb_text, r"^## 验证命令")
        if not cmd_block.strip():
            _safe_print("  ✗ 无 ## 验证命令 段")
            status_lines.append(f"  - {pb_name}: 无 ## 验证命令 段(playbook 不可执行)")
            continue

        # 逐件
        for item_num, block in iter_items(cmd_block):
            title = block[0].lstrip("# ").strip()  # "件 N: ..."
            fields = parse_fields(block)
            method = (fields.get("METHOD") or "GET").strip()
            path = (fields.get("PATH") or "").strip()
            hit_grep = (fields.get("HIT_GREP") or "").strip()
            fixed_grep = (fields.get("FIXED_GREP") or "").strip()

            if not path or not hit_grep:
                _safe_print(f"  ✗ {title} — 缺 PATH 或 HIT_GREP")
                status_lines.append(f"    - 件 {item_num}: 🟡 不确定 (playbook 配置不全)")
                continue

            # ── 请求 ──
            if mock_dir:
                fname = path.replace("/", "_").replace("?", "_q_").replace("&", "_a_").replace("=", "_e_")
                fpath = os.path.join(mock_dir, fname + ".txt")
                response = open(fpath, encoding="utf-8", errors="replace").read() if os.path.isfile(fpath) \
                    else "__MOCK_MISSING__"
                miss_name = fname
            else:
                response = curl(method, base + path)
                miss_name = ""
            total_packets += 1

            # ── 三档判定(HIT_GREP/FIXED_GREP = ERE 正则)──
            state, reason = grade(response, hit_grep, fixed_grep, miss_name)
            _safe_print(f"  {state}  {title}  {reason}")
            stripped = re.sub(r"^件\s+[0-9]+:\s*", "", title)
            status_lines.append(f"    - 件 {item_num} {stripped}: {state} {reason}")

        status_lines.append("")

    _safe_print()
    _safe_print("━━━ 汇总 ━━━")
    _safe_print(f"总包数: {total_packets}")

    write_scope_section(scope, "\n".join(status_lines))
    _safe_print("✓ scope.md 已更新 \"## playbook 件状态\" 章节")
    _safe_print()
    _safe_print("下一步: 读 scope.md \"## playbook 件状态\" 章节,LLM 决定继承")
    _safe_print("       命中件套报告模板写 verified;已修件标 rejected;🟡 自取证")
    return 0


def extract_section(text, header_re):
    """提取从 header 到下一个 ## 标题(不含)之间的内容,等价 awk flag。"""
    out, flag = [], False
    hre = re.compile(header_re)
    for line in text.splitlines():
        if hre.match(line):
            flag = True
            continue
        if flag and line.startswith("## "):
            break
        if flag:
            out.append(line)
    return "\n".join(out)


def iter_items(cmd_block):
    """切出每个 '### 件 N:' 块,返回 (N, [lines...])。"""
    lines = cmd_block.splitlines()
    items, cur, cur_n = [], None, None
    hdr = re.compile(r"^### 件 ([0-9]+):")
    for line in lines:
        m = hdr.match(line)
        if m:
            if cur is not None:
                items.append((cur_n, cur))
            cur_n = m.group(1)
            cur = [re.sub(r"^### ", "", line)]
        elif cur is not None:
            cur.append(line)
    if cur is not None:
        items.append((cur_n, cur))
    return items


def parse_fields(block_lines):
    fields = {}
    for line in block_lines:
        m = re.match(r"^- ([A-Z_]+):[ \t]*(.*?)[ \t]*$", line)
        if m and m.group(1) not in fields:
            fields[m.group(1)] = m.group(2)
    return fields


def grade(response, hit_grep, fixed_grep, miss_name):
    if response == "__MOCK_MISSING__":
        return "🟡 不确定", f"(mock fixture 缺失: {miss_name}.txt)"
    if response == "__CURL_FAILED__":
        return "🟡 不确定", "(curl 失败 / 超时)"
    try:
        if re.search(hit_grep, response):
            return "🟢 命中", f"(grep '{hit_grep}' 命中)"
    except re.error:
        if hit_grep in response:  # 正则非法时退化为子串
            return "🟢 命中", f"(grep '{hit_grep}' 命中)"
    if fixed_grep:
        try:
            if re.search(fixed_grep, response):
                return "🔴 已修", f"(grep '{fixed_grep}' 命中)"
        except re.error:
            if fixed_grep in response:
                return "🔴 已修", f"(grep '{fixed_grep}' 命中)"
    return "🟡 不确定", "(HIT_GREP 未中,FIXED_GREP 未配置或未中)"


def curl(method, url):
    try:
        r = subprocess.run(["curl", "-sk", "--max-time", "8", "-X", method, url],
                           capture_output=True, text=True, timeout=15)
        return r.stdout if r.returncode == 0 else "__CURL_FAILED__"
    except Exception:
        return "__CURL_FAILED__"


def write_scope_section(scope_path, new_block):
    text = open(scope_path, encoding="utf-8", errors="replace").read()
    out, skip = [], False
    for line in text.splitlines():
        if line.startswith("## playbook 件状态"):
            skip = True
            continue
        if skip and line.startswith("## "):
            skip = False
        if not skip:
            out.append(line)
    out.append("")
    out.append(new_block)
    open(scope_path, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")


if __name__ == "__main__":
    sys.exit(main())
