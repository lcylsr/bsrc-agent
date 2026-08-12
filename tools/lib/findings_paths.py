#!/usr/bin/env python3
# tools/lib/findings_paths.py — 统一 findings 入参解析(file | tree)
#
# 入参可以是:
#   - …/findings.md(单文件)
#   - targets/<t> 或 targets/<t>/(目录 → 自动 tree)
#   - program 根 findings.md(0 YAML + 子域有 findings)→ **强制 tree**,禁止静默 0
#
# 被 findings-lint 调用。

from __future__ import annotations

import os
from pathlib import Path

# 同目录导入
try:
    from findings_parser import (
        is_program_target,
        list_findings_files,
        parse_findings,
    )
except ImportError:
    from tools.lib.findings_parser import (  # type: ignore
        is_program_target,
        list_findings_files,
        parse_findings,
    )


class FindingsPathError(FileNotFoundError):
    """路径不存在或无法解析为 findings 输入。"""


def _norm(p: Path) -> Path:
    try:
        return p.resolve()
    except OSError:
        return p.absolute()


def resolve_findings_inputs(path_or_target, *, no_tree: bool | None = None) -> dict:
    """
    解析 findings 输入。

    返回:
      {
        mode: "file" | "tree",
        target_dir: Path,          # 目标根
        files: [Path, ...],        # 要处理的 findings.md 列表(绝对)
        primary: Path,             # 兼容旧逻辑的「主」文件(file 模式=唯一文件;tree=根 findings 或首个)
        is_program: bool,
        input: str,                # 原始入参
      }

    规则:
      1) 路径是文件且名 findings.md → 默认 file;若父目录 is_program_target 且根 0 YAML → 升级 tree
      2) 路径是目录 → target_dir=path; is_program_target 或 多 findings → tree, else files=[dir/findings.md]
      3) SRCCOP_FINDINGS_NO_TREE=1 或 no_tree=True → 永不升级 tree
      4) 不存在 → FindingsPathError
    """
    raw = str(path_or_target or "").strip()
    if not raw:
        raise FindingsPathError("缺参数: findings.md 或 targets/<name>")

    if no_tree is None:
        no_tree = os.environ.get("SRCCOP_FINDINGS_NO_TREE", "").strip() in ("1", "true", "yes")

    p = Path(raw)
    if not p.exists():
        raise FindingsPathError(
            f"{raw} 不存在\n"
            "  1) 路径错 → 读 targets/<t>/_STATE.md 确认当前 target\n"
            "  2) 还没接单 → 先建 targets/<甲方>/<目标>/scope.md\n"
            f"  3) 模板没拷 → cp targets/_template/findings.md <target>/"
        )

    p = _norm(p)

    # ── 目录 ──
    if p.is_dir():
        target_dir = p
        root_f = target_dir / "findings.md"
        try:
            prog = bool(is_program_target(str(target_dir)))
        except Exception:
            prog = False
        files = list_findings_files(str(target_dir))
        # 无任何 findings
        if not files:
            if root_f.is_file():
                files = [root_f]
            else:
                raise FindingsPathError(
                    f"{raw} 下无 findings.md\n"
                    f"  修复: cp targets/_template/findings.md {target_dir}/"
                )
        # program 或 >1 findings → tree; 单文件 → file
        child_n = sum(1 for f in files if _norm(f.parent) != target_dir)
        use_tree = (not no_tree) and (prog or child_n > 0 or len(files) > 1)
        if use_tree:
            primary = root_f if root_f.is_file() else files[0]
            return {
                "mode": "tree",
                "target_dir": target_dir,
                "files": [_norm(f) for f in files],
                "primary": _norm(primary),
                "is_program": prog or child_n > 0,
                "input": raw,
            }
        # 单 host 目录
        primary = root_f if root_f.is_file() else files[0]
        return {
            "mode": "file",
            "target_dir": target_dir,
            "files": [_norm(primary)],
            "primary": _norm(primary),
            "is_program": False,
            "input": raw,
        }

    # ── 文件 ──
    if not p.is_file():
        raise FindingsPathError(f"{raw} 既非文件也非目录")

    target_dir = _norm(p.parent)
    try:
        prog = bool(is_program_target(str(target_dir)))
    except Exception:
        prog = False

    # program 根 findings 自动升级 tree(关键: 避免 findings-lint 静默 0)
    root_n = 0
    try:
        root_n = len(parse_findings(str(p)))
    except Exception:
        root_n = 0

    child_files = []
    if not no_tree:
        try:
            all_f = list_findings_files(str(target_dir))
            child_files = [f for f in all_f if _norm(f.parent) != target_dir]
        except Exception:
            child_files = []

    upgrade = (not no_tree) and root_n == 0 and len(child_files) > 0
    # 也: 用户传了子域 findings.md → file 模式不升级
    is_root_findings = p.name.lower() == "findings.md" and _norm(p.parent) == target_dir
    # 若传入的是子域 findings,不 tree 整个 program
    if p.name.lower() == "findings.md" and not is_root_findings:
        # 子路径: parent 相对 target 有层级 — 实际上 p.parent 就是 target_dir 我们设的
        # 用户传 targets/acme/host/findings.md → target_dir=host 目录, is_program_target 通常 False
        pass

    if upgrade and is_root_findings:
        files = list_findings_files(str(target_dir))
        return {
            "mode": "tree",
            "target_dir": target_dir,
            "files": [_norm(f) for f in files],
            "primary": p,
            "is_program": True,
            "input": raw,
        }

    # 另: 传入 program 目录下的根 findings 但 is_program 因某种原因失败,
    # 而 child 存在且 root 0 — 上面 upgrade 已覆盖。
    return {
        "mode": "file",
        "target_dir": target_dir,
        "files": [p],
        "primary": p,
        "is_program": False,
        "input": raw,
    }


def describe_resolve(res: dict) -> str:
    """人类可读一行。"""
    n = len(res.get("files") or [])
    return (
        f"mode={res.get('mode')} program={res.get('is_program')} "
        f"files={n} target={res.get('target_dir')}"
    )


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("usage: python tools/lib/findings_paths.py <path> [--no-tree]", file=sys.stderr)
        sys.exit(2)
    no = "--no-tree" in sys.argv[2:]
    try:
        r = resolve_findings_inputs(sys.argv[1], no_tree=no)
    except FindingsPathError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(3)
    print(json.dumps({
        "mode": r["mode"],
        "target_dir": str(r["target_dir"]),
        "primary": str(r["primary"]),
        "is_program": r["is_program"],
        "files": [str(f) for f in r["files"]],
        "n_files": len(r["files"]),
    }, ensure_ascii=False, indent=2))
