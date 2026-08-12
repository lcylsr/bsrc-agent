#!/usr/bin/env python3
# tools/agent-launch.py — 统一渲染 .claude/agents 角色定义 + 任务 prompt
#
# 用法:
#   python tools/agent-launch.py recon-agent <target_dir> --roots domain1.com domain2.com
#   python tools/agent-launch.py pentest-agent <target_dir> --subdomain api.xxx.com
#   python tools/agent-launch.py app-agent <target_dir> --client-type miniapp --install-path <wxapkg>
#   python tools/agent-launch.py client-agent <target_dir> --client-type android --install-path <apk>
#   python tools/agent-launch.py verifier-agent <target_dir> --finding <finding_id>
#   python tools/agent-launch.py review-agent <target_dir>
#   python tools/agent-launch.py recon-agent <target_dir> --roots xxx.com --output-prompt prompt.md
#
# 输出:
#   - 默认打印可直接喂给 Agent 工具的 prompt 文本
#   - --output-prompt 写入文件
#   - --format=json 输出 {name, description, prompt, inputs} JSON
#   - --inline 把 agent 定义全文嵌入 prompt，避免子 agent 再 Read 一次

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = ROOT / ".claude" / "agents"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


AGENT_CHOICES = [
    "recon-agent",
    "pentest-agent",
    "app-agent",
    "client-agent",
    "verifier-agent",
    "review-agent",
]


def parse_agent_frontmatter(path: Path) -> dict:
    """解析 agents/*.md 的 YAML frontmatter。"""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if not text.startswith("---\n"):
        return {"name": path.stem, "description": "", "tools": "", "body": text}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {"name": path.stem, "description": "", "tools": "", "body": text}
    fm_text = text[4:end]
    body = text[end + 5 :]
    try:
        import yaml
        fm = yaml.safe_load(fm_text) or {}
    except Exception:
        fm = {}
    return {
        "name": fm.get("name", path.stem),
        "description": fm.get("description", ""),
        "tools": fm.get("tools", ""),
        "body": body,
    }


def extract_finding(target_dir: Path, finding_id: str) -> dict:
    """从 findings.md 提取指定 finding 的 frontmatter + 正文。"""
    findings_path = target_dir / "findings.md"
    if not findings_path.is_file():
        return {}
    text = findings_path.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.MULTILINE | re.DOTALL)
    for m in pattern.finditer(text):
        try:
            import yaml
            fm = yaml.safe_load(m.group(1)) or {}
        except Exception:
            continue
        if not isinstance(fm, dict) or fm.get("id") != finding_id:
            continue
        body_start = m.end()
        next_match = pattern.search(text, body_start)
        body_end = next_match.start() if next_match else len(text)
        fm["_body"] = text[body_start:body_end].strip()
        return fm
    return {}


def render_prompt(agent_name: str, target_dir: str, extra: dict, inline: bool = False) -> str:
    agent_path = AGENTS_DIR / f"{agent_name}.md"
    if not agent_path.is_file():
        raise SystemExit(f"❌ agent 定义不存在: {agent_path}")
    agent = parse_agent_frontmatter(agent_path)

    role_section = f"## 角色\n{agent['name']}: {agent['description']}\n\n{agent['body']}" if inline else f"## 角色\n{agent['name']}: {agent['description']}\n\n第一步：完整读取 {agent_path}，你就是这个角色，严格按其规则执行。"

    lines = [
        f"# {agent['name']} 任务",
        "",
        role_section,
        "",
        "## 本次任务输入",
        f"target_dir: {target_dir}",
    ]
    for k, v in extra.items():
        if k == "finding" and isinstance(v, dict):
            # 把 finding 的 frontmatter 摘要注入
            lines.append(f"finding_id: {v.get('id', '')}")
            lines.append(f"finding_status: {v.get('status', '')}")
            lines.append(f"finding_poc_type: {v.get('poc_type', '')}")
            lines.append(f"finding_poc_curl: {v.get('poc_curl', '')}")
            lines.append(f"finding_replay_signature: {v.get('replay_signature', '')}")
            lines.append(f"finding_business_evidence: {v.get('business_evidence', '')}")
            body = v.get("_body", "")[:800]
            if body:
                lines.append(f"finding_body_preview:\n  {body.replace(chr(10), chr(10)+'  ')}")
        elif isinstance(v, list):
            lines.append(f"{k}: {', '.join(str(x) for x in v)}")
        else:
            lines.append(f"{k}: {v}")
    lines += [
        "",
        "## 输出要求",
        "- 按角色定义中的工作流执行，到 stop condition 立即 return。",
        "- 只返回结论，不要把原始 JS/响应体/大段 grep 结果塞进返回。",
        "- 禁止写 lifecycle.yaml / findings.md / scope.md / output/ 报告（除非角色定义明确允许）。",
        "",
        "开始执行。",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="统一渲染 agent 启动 prompt")
    ap.add_argument("agent", choices=AGENT_CHOICES, help="agent 角色名")
    ap.add_argument("target_dir", help="目标目录，如 targets/xxx")
    ap.add_argument("--roots", nargs="+", help="recon-agent 根域列表")
    ap.add_argument("--subdomain", help="pentest-agent 子域")
    ap.add_argument("--client-type", choices=["android", "ios", "miniapp", "desktop"], help="app-agent/client-agent 客户端类型")
    ap.add_argument("--install-path", help="app-agent/client-agent 安装包路径")
    ap.add_argument("--finding", help="verifier-agent 要验证的 finding id（自动从 findings.md 提取 frontmatter）")
    ap.add_argument("--output-prompt", help="输出 prompt 到文件")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="输出格式")
    ap.add_argument("--inline", action="store_true", help="把 agent 定义全文嵌入 prompt，避免子 agent 再 Read 一次")
    args = ap.parse_args()

    extra = {}
    if args.agent == "recon-agent":
        extra["roots"] = args.roots or []
    elif args.agent == "pentest-agent":
        extra["subdomain"] = args.subdomain or ""
    elif args.agent in ("app-agent", "client-agent"):
        extra["client_type"] = args.client_type or ""
        extra["install_path"] = args.install_path or ""
    elif args.agent == "verifier-agent":
        extra["finding"] = extract_finding(Path(args.target_dir), args.finding) if args.finding else {}
    elif args.agent == "review-agent":
        pass

    prompt = render_prompt(args.agent, args.target_dir, extra, inline=args.inline)

    if args.output_prompt:
        out = Path(args.output_prompt)
        out.write_text(prompt, encoding="utf-8")
        print(f"✅ prompt 已写入: {out}")
        return 0

    if args.format == "json":
        agent_path = AGENTS_DIR / f"{args.agent}.md"
        agent = parse_agent_frontmatter(agent_path)
        # finding 是 dict，JSON 序列化需要去掉 _body 或转字符串
        inputs = {"target_dir": args.target_dir, **extra}
        if "finding" in inputs and isinstance(inputs["finding"], dict):
            inputs["finding"] = {k: v for k, v in inputs["finding"].items() if not k.startswith("_")}
        print(json.dumps({
            "name": agent["name"],
            "description": agent["description"],
            "prompt": prompt,
            "inputs": inputs,
        }, ensure_ascii=False, indent=2))
    else:
        print(prompt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
