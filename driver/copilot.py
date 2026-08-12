#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# driver/copilot.py — 国内大模型 Agent 驱动层（作品核心原创代码）
#
# 用途：让本框架脱离 Claude Code，改由国内大模型（DeepSeek / GLM / 文心 Comate 等
#       OpenAI 兼容 chat/completions API）驱动，满足"Agent+" 攻防挑战赛
#       「仅限国内大模型」硬性要求。
#
# 设计原则（与框架一致）：
#   - 零第三方依赖：仅标准库（urllib / json / subprocess / concurrent.futures）
#   - 双协议动作解析：OpenAI function calling（原生优先）+ ReAct 代码块 fallback
#   - 安全硬拦：命令黑名单 + 写入白名单（镜像 tools/danger-guard.sh 语义）
#   - 预算纪律：max_steps / 单命令超时 / 并行 ≤4（8 核 16G 托管平台适配）
#   - 防失忆：每轮写回 rounds 卷 + _STATE.md 摘要行
#
# 用法示例：
#   python driver/copilot.py --self-check                       # 离线自检（无 API）
#   python driver/copilot.py commander examples/demo-acme --demo   # 离线演示回合
#   python driver/copilot.py commander targets/xxx --config driver/config.json
#   python driver/copilot.py agent pentest-agent targets/xxx --subdomain api.xxx.com --config ...
#   python driver/copilot.py orchestrate targets/xxx --subdomains a.com b.com c.com d.com --config ...
#
# config.json 字段（亦可用环境变量）：
#   api_base: https://api.deepseek.com/v1            # DeepSeek 官方 / GLM / 文心兼容端点
#   api_key:  <sk-...>                                # 或 env DEEPSEEK_API_KEY / GLM_API_KEY / COMATE_API_KEY
#   model:    deepseek-chat                            # deepseek-reasoner / glm-4.5 / ernie-x1 等

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------------------
# 0. 常量：工具定义 / 黑名单 / 写白名单
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "在框架仓库根目录执行一条 bash 命令（优先用 bash tools/run.sh 调度工具）。受黑名单与超时约束。",
            "parameters": {
                "type": "object",
                "properties": {"cmd": {"type": "string", "description": "要执行的完整 shell 命令"}},
                "required": ["cmd"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "python",
            "description": "执行一段 python3 代码（框架内工具如 findings-lint 可直接调用）。",
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string", "description": "要执行的 python 代码"}},
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read",
            "description": "读取一个文件（UTF-8，截断到 8000 字符），优先用于 CLAUDE.md / skills / 工作区文件。",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "仓库内相对路径或绝对路径"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write",
            "description": "写入/追加一个文本文件。仅允许写入当前 target 工作区与输出目录（防越界写）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "相对仓库根路径"},
                    "content": {"type": "string", "description": "完整文件内容"},
                    "mode": {"type": "string", "enum": ["write", "append"], "description": "write=覆盖，append=追加"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "完成当前任务。summary 为任务结论（findings 摘要 / 死路 / 需要人工决策的请示），会写回 rounds 卷。",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    },
]

# 危险命令黑名单（镜像 tools/danger-guard.sh；比赛环境无人值守，硬拦必须自动生效）
BLACKLIST = [
    r"\brm\s+-rf\b", r"\brmdir\b", r"\bmkfs", r"\bdd\s+if=", r"\bshutdown\b", r"\breboot\b",
    r"\bDROP\s+TABLE\b", r"\bDELETE\s+FROM\b", r"\bTRUNCATE\b", r"\bformat\b",
    r"\bsqlmap\b", r"\bnuclei\b", r"\bhydra\b", r"\bmedusa\b", r"\bjohn\b",
    r"\bcurl\s+.*--upload", r"\bwget\s+.*\s+-\s*O\s+/", r"chmod\s+-R\s+777\b",
    r"\bsudo\b", r">\s*/dev/sd", r":\(\)\s*\{", r"\bpython.*\brmtree\b",
]
# 写入白名单前缀：target 工作区 + 输出目录 + driver/ 自身（防模型越界写系统文件）
WRITE_ALLOWED = ["targets/", "examples/", "driver/", "output/", "tests/"]

# ---------------------------------------------------------------------------
# 1. LLM 调用（OpenAI 兼容 / chat completions）
# ---------------------------------------------------------------------------


class Config:
    def __init__(self, path=None):
        self.api_base = os.environ.get("COPILOT_API_BASE", "")
        self.api_key = (
            os.environ.get("COPILOT_API_KEY")
            or os.environ.get("DEEPSEEK_API_KEY")
            or os.environ.get("GLM_API_KEY")
            or os.environ.get("COMATE_API_KEY")
            or ""
        )
        self.model = os.environ.get("COPILOT_MODEL", "")
        if path and Path(path).is_file():
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.api_base = data.get("api_base", self.api_base)
            self.api_key = data.get("api_key", self.api_key)
            self.model = data.get("model", self.model)
        if not self.api_base:
            # 兜底：按 key 形态猜测端点
            if self.api_key.startswith("sk-"):
                self.api_base = "https://api.deepseek.com/v1"
                self.model = self.model or "deepseek-chat"
            elif self.api_key.startswith(("glm", "zh")):
                self.api_base = "https://open.bigmodel.cn/api/paas/v4"
                self.model = self.model or "glm-4.5"
        if not self.model:
            self.model = "deepseek-chat"

    def ok(self):
        return bool(self.api_base and self.api_key)


def llm_chat(cfg: Config, messages, tools=None, max_tokens=4096, temperature=0.2):
    """调用 OpenAI 兼容 chat/completions，返回 (content, tool_calls)。"""
    url = cfg.api_base.rstrip("/") + "/chat/completions"
    body = {
        "model": cfg.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg.api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    msg = data["choices"][0]["message"]
    content = msg.get("content") or ""
    tool_calls = msg.get("tool_calls") or []
    return content, tool_calls


# ---------------------------------------------------------------------------
# 2. 动作解析：function calling 优先，ReAct 代码块 fallback
# ---------------------------------------------------------------------------

FENCE_RE = re.compile(r"```([a-zA-Z_+-]*)\s*\n(.*?)```", re.DOTALL)


def parse_tool_calls(tool_calls):
    """OpenAI 格式 tool_calls → [(name, args_dict)]，过滤掉 finish。"""
    out = []
    for tc in tool_calls or []:
        fn = tc.get("function", {})
        name = fn.get("name", "")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except Exception:
            args = {"cmd": fn.get("arguments", ""), "code": fn.get("arguments", "")}
        out.append((name, args))
    return out


def parse_react_blocks(content):
    """ReAct fallback：解析 ```bash / ```python / ```write {json} / ```finish {json} 块。"""
    actions = []
    for lang, body in FENCE_RE.findall(content):
        lang = lang.strip().lower()
        if lang in ("bash", "sh", "shell"):
            actions.append(("bash", {"cmd": body.strip()}))
        elif lang in ("python", "py"):
            actions.append(("python", {"code": body.strip()}))
        elif lang == "write":
            try:
                data = json.loads(body.strip())
                actions.append(("write", {"path": data.get("path", ""), "content": data.get("content", ""), "mode": data.get("mode", "write")}))
            except Exception:
                pass
        elif lang == "finish":
            try:
                data = json.loads(body.strip())
                actions.append(("finish", {"summary": data.get("summary", body.strip())}))
            except Exception:
                actions.append(("finish", {"summary": body.strip()}))
    return actions


# ---------------------------------------------------------------------------
# 3. 安全硬拦：黑名单 + 写白名单 + 超时
# ---------------------------------------------------------------------------

def guard_blocked(command):
    for pat in BLACKLIST:
        if re.search(pat, command, re.IGNORECASE):
            return pat
    return None


def guard_write(path):
    p = Path(path)
    try:
        p.resolve()
    except Exception:
        return True
    s = str(p).replace("\\", "/")
    return not any(s.startswith(x) or f"/{x}" in s.split("/")[:3] and s.startswith(x) for x in WRITE_ALLOWED)


def run_action(name, args, target_dir, timeout=90):
    """执行单个动作，返回文本结果。所有输出截断到 6000 字符。"""
    if name == "bash":
        cmd = (args.get("cmd") or "").strip()
        if not cmd:
            return "❌ 空命令"
        pat = guard_blocked(cmd)
        if pat:
            return f"⛔ 命令被黑名单拦截（命中: {pat}）。框架铁律：重武器/破坏性命令不可由 AI 自动执行。"
        try:
            r = subprocess.run(["bash", "-c", cmd], cwd=str(ROOT), capture_output=True,
                               text=True, timeout=timeout, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return f"⏱️ 命令超时（>{timeout}s）: {cmd[:120]}"
        out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
        out = out.strip()[:6000]
        return out or f"（无输出，exit={r.returncode}）"
    if name == "python":
        code = (args.get("code") or "").strip()
        if not code:
            return "❌ 空代码"
        try:
            r = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True,
                               text=True, timeout=timeout, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return f"⏱️ 代码执行超时（>{timeout}s）"
        out = ((r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")).strip()[:6000]
        return out or f"（无输出，exit={r.returncode}）"
    if name == "read":
        p = Path(args.get("path", ""))
        if not p.is_absolute():
            p = ROOT / p
        if not p.is_file():
            return f"❌ 文件不存在: {p}"
        text = p.read_text(encoding="utf-8", errors="ignore")
        return text[:8000] + ("\n…（截断）" if len(text) > 8000 else "")
    if name == "write":
        path = args.get("path", "")
        content = args.get("content", "")
        if not path:
            return "❌ write 缺少 path"
        if guard_write(path):
            return f"⛔ 写入被白名单拦截（仅允许: {' / '.join(WRITE_ALLOWED)}）: {path}"
        p = ROOT / path
        p.parent.mkdir(parents=True, exist_ok=True)
        mode = args.get("mode", "write")
        if mode == "append":
            with open(p, "a", encoding="utf-8") as f:
                f.write(content + "\n")
        else:
            p.write_text(content, encoding="utf-8")
        return f"✅ 已写入 {p}（{len(content)} 字符）"
    if name == "finish":
        return f"[FINISH] {args.get('summary', '')}"
    return f"❌ 未知动作: {name}"


# ---------------------------------------------------------------------------
# 4. 防失忆写回：rounds 卷 + _STATE 摘要行
# ---------------------------------------------------------------------------

def append_round(target_dir, phase, note):
    """向 targets/<t>/output/rounds/<日期>.md 追加一条轮次记录。"""
    d = Path(target_dir)
    if not d.is_dir():
        return False
    rounds_dir = d / "output" / "rounds"
    rounds_dir.mkdir(parents=True, exist_ok=True)
    date = time.strftime("%Y-%m-%d")
    vol = rounds_dir / f"{date}.md"
    if not vol.is_file():
        vol.write_text(f"# 轮次卷 {date}\n\n> 由 driver/copilot.py 自动记录。\n", encoding="utf-8")
    ts = time.strftime("%H:%M")
    with open(vol, "a", encoding="utf-8") as f:
        f.write(f"\n## P-driver {phase}（{ts}）\n{note}\n")
    # _STATE.md 摘要行更新时间戳
    state = d / "_STATE.md"
    if state.is_file():
        text = state.read_text(encoding="utf-8", errors="ignore")
        import re as _re
        new = _re.sub(r"(最后更新[:：].*)", f"最后更新: {date} {ts}", text, count=1)
        state.write_text(new, encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# 5. 系统提示组装（把框架纪律注入模型）
# ---------------------------------------------------------------------------

def build_system_prompt(target_dir):
    parts = []
    for name in ("CLAUDE.md", "QUICK.md"):
        p = ROOT / name
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="ignore")
            parts.append(f"# 框架文档 {name}（节选，最多 24000 字符）\n{text[:24000]}")
    parts.append(
        f"""# 运行协议（必须遵守）
- 你是安全测试 Agent。当前目标工作区: {target_dir}
- 所有探测请求遵守 scope.md 授权边界；不确定是否越界 → 停下来 finish 并说明，禁止擅自发包。
- 重武器（sqlmap/nuclei/大字典）已被黑名单硬拦，不要尝试。
- 首选工具: bash tools/run.sh <tool-name> …；查看可用工具: bash tools/run.sh --list。
- 每步一个动作，观察结果后再决定下一步；禁止一口气执行破坏性操作。
- 预算：每次任务 ≤{DEFAULT_MAX_STEPS} 步；单命令超时 90s；并行不超过 4。
- 收尾：写 rounds 卷（append_round 由 driver 自动完成），用 finish 返回任务结论。
- 语言：中文输出。"""
    )
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# 6. Agent 主循环
# ---------------------------------------------------------------------------

DEFAULT_MAX_STEPS = 40


def run_loop(cfg, system, task, target_dir, max_steps=DEFAULT_MAX_STEPS, offline_script=None, quiet=False):
    """单 agent 循环。offline_script: [(action_name, args)] 用于 --demo 离线演示。"""
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": task},
    ]
    step = 0
    if offline_script:
        # 离线演示：不调 API，按脚本回放协议机制
        for i, (name, args) in enumerate(offline_script):
            step = i + 1
            if name == "finish":
                print(f"\n[回合 {step}] FINISH: {args.get('summary', '')}")
                return args.get("summary", "")
            print(f"\n[回合 {step}] 动作: {name}({json.dumps(args, ensure_ascii=False)[:160]})")
            result = run_action(name, args, target_dir)
            print(f"[回合 {step}] 结果: {result[:600]}")
        return "[demo 离线脚本结束]"

    while step < max_steps:
        step += 1
        try:
            content, tool_calls = llm_chat(cfg, messages, tools=TOOLS)
        except urllib.error.HTTPError as e:
            return f"❌ API HTTP 错误 {e.code}: {e.read().decode('utf-8', 'ignore')[:500]}"
        except Exception as e:
            return f"❌ API 调用失败: {e}"

        if not quiet:
            print(f"\n[{step}/{max_steps}] 模型: {content[:300]}")

        actions = parse_tool_calls(tool_calls) or parse_react_blocks(content)
        if not actions:
            # 纯文本回复：继续对话
            messages.append({"role": "assistant", "content": content})
            if step >= max_steps:
                return content
            continue

        for name, args in actions:
            result = run_action(name, args, target_dir)
            if not quiet:
                print(f"[{step}] {name} → {result[:300]}")
            if name == "finish":
                append_round(target_dir, args.get("summary", "")[:60], args.get("summary", ""))
                return args.get("summary", "")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "tool", "tool_call_id": str(step), "content": result})
            if len(messages) > 60:  # 上下文裁剪
                messages = messages[:2] + messages[-50:]
    return "[达到 max_steps 上限，任务未 finish]"


# ---------------------------------------------------------------------------
# 7. 多 Agent 编排（8 核 16G 适配：并行 ≤4）
# ---------------------------------------------------------------------------

def orchestrate(cfg, target_dir, subdomains, concurrency=4, max_steps=25):
    system = build_system_prompt(target_dir)
    results = {}

    def one(sub):
        task = f"深度挖掘单个子域: {sub}（并行批次，≤{max_steps} 步，只攻这一个子域，绝不横向）。"
        return run_loop(cfg, system, task, target_dir, max_steps=max_steps, quiet=True)

    workers = max(1, min(concurrency, os.cpu_count() or 2, len(subdomains)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(one, s): s for s in subdomains}
        for f in futs:
            sub = futs[f]
            try:
                results[sub] = f.result()
            except Exception as e:
                results[sub] = f"❌ agent 异常: {e}"
    summary = "\n".join(f"- {s}: {str(v)[:300]}" for s, v in results.items())
    append_round(target_dir, "orchestrate 批次结束", summary)
    print(f"\n===== 批次结果 =====\n{summary}")
    return results


# ---------------------------------------------------------------------------
# 8. CLI 入口
# ---------------------------------------------------------------------------

def cmd_self_check():
    """离线自检：不调 API，验证协议解析 / 黑名单 / 白名单 / 预算逻辑。"""
    ok = True
    # 1) function calling 解析
    tc = [{"function": {"name": "bash", "arguments": json.dumps({"cmd": "echo hi"})}}]
    assert parse_tool_calls(tc) == [("bash", {"cmd": "echo hi"})], "function calling 解析失败"
    # 2) ReAct fallback 解析
    content = "先看下工具```bash\nbash tools/run.sh --list\n```再来```finish\n{\"summary\":\"完成\"}\n```"
    acts = parse_react_blocks(content)
    assert ("bash", {"cmd": "bash tools/run.sh --list"}) in acts, "ReAct bash 解析失败"
    assert any(a[0] == "finish" for a in acts), "ReAct finish 解析失败"
    # 3) 黑名单
    for bad in ["rm -rf /tmp/x", "sqlmap -u http://x", "echo 'DROP TABLE users;'", "dd if=/dev/zero of=/dev/sda"]:
        assert guard_blocked(bad), f"黑名单漏拦: {bad}"
    assert guard_blocked("curl -s http://x") is None, "正常 curl 不应被拦"
    # 4) 写白名单
    assert not guard_write("targets/demo/_STATE.md"), "targets/ 内写入应放行"
    assert guard_write("C:/Windows/system32/drivers/etc/hosts"), "系统文件写入应拦截"
    # 5) 真实命令执行
    res = run_action("bash", {"cmd": "echo driver-ok"}, "examples/demo-acme")
    assert "driver-ok" in res, "bash 动作执行失败"
    res = run_action("bash", {"cmd": "rm -rf /tmp/should-not-run"}, "examples/demo-acme")
    assert "黑名单" in res, "黑名单执行未拦截"
    # 6) 离线回放
    demo = [
        ("read", {"path": "examples/demo-acme/scope.md"}),
        ("bash", {"cmd": "bash tools/run.sh --list | head -5"}),
        ("finish", {"summary": "自检通过"}),
    ]
    out = run_loop(Config(), "system", "task", "examples/demo-acme", offline_script=demo, quiet=True)
    assert "自检通过" in out, "离线回放失败"
    print("✅ 自检全部通过：协议解析 / 黑名单 / 白名单 / 命令执行 / 离线回放")
    return ok


def cmd_demo(target_dir):
    """离线演示回合：展示循环机制如何工作（不调 API、不发真实探测包）。"""
    print("===== driver 离线演示（--demo）=====")
    print("目标: 展示 agentic 循环机制 — 文档加载 → 工具调用 → 观察 → 写回 → finish\n")
    script = [
        ("read", {"path": "examples/demo-acme/scope.md"}),
        ("read", {"path": "examples/demo-acme/_STATE.md"}),
        ("bash", {"cmd": "python tools/findings-lint.py examples/demo-acme --lifecycle --gen"}),
        ("read", {"path": "examples/demo-acme/output/lifecycle-views/findings-index.md"}),
        ("finish", {"summary": "demo 回合演示完成：框架纪律已注入，循环机制正常，接入国内模型 API 后即可实跑。"}),
    ]
    out = run_loop(Config(), build_system_prompt(target_dir), "演示回合", target_dir, offline_script=script)
    print(f"\n===== 演示结束 =====\n{out}")


def main():
    ap = argparse.ArgumentParser(description="Copilot Framework 国内大模型驱动层")
    sub = ap.add_subparsers(dest="mode", required=True)

    p_self = sub.add_parser("self-check", help="离线自检")
    p_self.set_defaults(fn=lambda a: cmd_self_check())

    p_demo = sub.add_parser("demo", help="离线演示回合")
    p_demo.add_argument("target_dir")
    p_demo.set_defaults(fn=lambda a: cmd_demo(a.target_dir))

    p_cmd = sub.add_parser("commander", help="Commander 主循环")
    p_cmd.add_argument("target_dir")
    p_cmd.add_argument("--task", default="按 CLAUDE.md 4 阶段推进当前目标，先读 _STATE.md 续接。")
    p_cmd.add_argument("--config", default="driver/config.json")
    p_cmd.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    p_cmd.set_defaults(fn=run_commander)

    p_agent = sub.add_parser("agent", help="单 agent 循环（prompt 由 agent-launch.py 渲染）")
    p_agent.add_argument("agent_name", choices=["recon-agent", "pentest-agent", "app-agent", "client-agent", "verifier-agent", "review-agent"])
    p_agent.add_argument("target_dir")
    p_agent.add_argument("--subdomain")
    p_agent.add_argument("--roots", nargs="+")
    p_agent.add_argument("--finding")
    p_agent.add_argument("--config", default="driver/config.json")
    p_agent.add_argument("--max-steps", type=int, default=25)
    p_agent.set_defaults(fn=run_agent)

    p_orb = sub.add_parser("orchestrate", help="多 agent 并行编排（默认 ≤4 并发）")
    p_orb.add_argument("target_dir")
    p_orb.add_argument("--subdomains", nargs="+", required=True)
    p_orb.add_argument("--config", default="driver/config.json")
    p_orb.add_argument("--concurrency", type=int, default=4)
    p_orb.add_argument("--max-steps", type=int, default=25)
    p_orb.set_defaults(fn=run_orch)

    args = ap.parse_args()
    args.fn(args)


def run_commander(a):
    cfg = Config(a.config)
    if not cfg.ok():
        print("❌ 未配置 API。写 driver/config.json 或设置 COPILOT_API_BASE / COPILOT_API_KEY / COPILOT_MODEL")
        print("   演示请用: python driver/copilot.py demo examples/demo-acme")
        return 1
    out = run_loop(cfg, build_system_prompt(a.target_dir), a.task, a.target_dir, max_steps=a.max_steps)
    print(f"\n===== Commander 结束 =====\n{out}")
    return 0


def run_agent(a):
    cfg = Config(a.config)
    if not cfg.ok():
        print("❌ 未配置 API。写 driver/config.json 或设置环境变量；演示请用 --demo 于 commander。")
        return 1
    import subprocess as sp
    cmd = [sys.executable, str(ROOT / "tools" / "agent-launch.py"), a.agent_name, a.target_dir]
    if a.subdomain:
        cmd += ["--subdomain", a.subdomain]
    if a.roots:
        cmd += ["--roots", *a.roots]
    if a.finding:
        cmd += ["--finding", a.finding]
    prompt = sp.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    out = run_loop(cfg, build_system_prompt(a.target_dir), prompt, a.target_dir, max_steps=a.max_steps)
    print(f"\n===== {a.agent_name} 结束 =====\n{out[:2000]}")
    return 0


def run_orch(a):
    cfg = Config(a.config)
    if not cfg.ok():
        print("❌ 未配置 API。写 driver/config.json 或设置环境变量。")
        return 1
    orchestrate(cfg, a.target_dir, a.subdomains, concurrency=a.concurrency, max_steps=a.max_steps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
