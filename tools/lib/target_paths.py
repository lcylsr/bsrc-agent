#!/usr/bin/env python3
# tools/lib/target_paths.py — target / temp workspace 路径解析公共库
#
# 用法(脚本内):
#   from tools.lib.target_paths import workspace_path, temp_workspace, target_key
#   raw_dir = workspace_path(target_dir, "recon/ssrf-raw")
#
# 用法(shell):
#   eval "$(python tools/lib/target_paths.py --export targets/xxx)"

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))


def load_cfg():
    """读取 framework.yaml;失败返回空 dict。"""
    yaml_path = ROOT / "framework.yaml"
    if not yaml_path.is_file():
        return {}
    try:
        import yaml
        return yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def cfg_value(*keys, default=None):
    """按层级取配置,缺失返回 default。"""
    d = load_cfg()
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d


def target_key(target_dir):
    """返回 target 相对于 targets/ 的 key,支持嵌套目录。

    例:
      targets/democlient/democlient.com.cn -> democlient/democlient.com.cn
      targets/velox/recon                   -> velox/recon
    """
    p = Path(target_dir).resolve()
    try:
        rel = p.relative_to(ROOT / "targets")
    except ValueError:
        # 若不是标准 targets/ 下路径,返回目录名兜底
        return p.name
    return rel.as_posix()


def temp_root():
    """返回配置的临时工作区根目录（从 framework.yaml artifacts.temp_root 读取，缺失则用默认值）。"""
    v = cfg_value("artifacts", "temp_root", default=None)
    if v:
        return Path(v)
    return Path("E:/claude-artifacts/tmp")


def raw_subdirs():
    """返回应写入 temp workspace 的相对目录列表。"""
    return cfg_value("artifacts", "raw_subdirs", default=[
        "raw", "probes",
        "recon/sources", "recon/ssrf-raw", "recon/tech-fuzz-raw",
        "recon/fuzz-raw", "recon/js-recon/downloaded",
    ])


def _is_raw_subdir(rel, patterns):
    """判断 rel 是否命中某个 raw_subdir 前缀。"""
    rel_parts = Path(rel).as_posix().strip("/").split("/")
    for pat in patterns:
        pat_parts = Path(pat).as_posix().strip("/").split("/")
        if len(rel_parts) >= len(pat_parts) and rel_parts[:len(pat_parts)] == pat_parts:
            return True
    return False


def temp_workspace(target_dir):
    """返回该 target 在外部临时目录中的根路径。"""
    return temp_root() / target_key(target_dir)


def workspace_path(target_dir, rel):
    """根据 rel 决定写入 target 目录还是 temp workspace。

    若 rel 命中 raw_subdirs 前缀 -> 写入 temp workspace。
    否则 -> 写入 target 目录。
    """
    target_dir = Path(target_dir)
    rel = Path(rel).as_posix().strip("/")
    if _is_raw_subdir(rel, raw_subdirs()):
        return temp_workspace(target_dir) / rel
    return target_dir / rel


def ensure_parent(path):
    """确保父目录存在。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _export_shell(target_dir):
    target_dir = Path(target_dir).resolve()
    key = target_key(target_dir)
    tmp = temp_workspace(target_dir)
    print(f'export CLAUDE_TARGET_DIR="{target_dir}"')
    print(f'export CLAUDE_TARGET_KEY="{key}"')
    print(f'export CLAUDE_TARGET_TEMP="{tmp}"')


def main():
    parser = argparse.ArgumentParser(description="target / temp workspace 路径解析")
    parser.add_argument("target_dir", nargs="?", help="target 目录,如 targets/xxx 或 targets/xxx/yyy")
    parser.add_argument("--key", action="store_true", help="输出 target_key")
    parser.add_argument("--temp-dir", action="store_true", help="输出临时工作区根目录")
    parser.add_argument("--workspace-path", metavar="REL", help="输出 REL 对应的实际路径")
    parser.add_argument("--export", action="store_true", help="输出 shell export 语句")
    args = parser.parse_args()

    if not args.target_dir and not args.export:
        parser.error("必须提供 target_dir")

    target_dir = args.target_dir or "."

    if args.key:
        print(target_key(target_dir))
        return
    if args.temp_dir:
        print(temp_workspace(target_dir))
        return
    if args.workspace_path:
        print(workspace_path(target_dir, args.workspace_path))
        return
    if args.export:
        _export_shell(target_dir)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
