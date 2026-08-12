#!/usr/bin/env python3
# tools/lib/tool_resolve.py — 外部二进制路径解析 + API keys 加载
#
# 作用：给 recon-pipeline / space-recon / scanner-dispatch 提供统一的外部工具路径解析。
# SSOT：tools/external-tools.yaml（声明各工具的 path / cmdline / tags）
# keys：tools/keys.env（FOFA/Hunter/Quake API keys，gitignore，从 keys.env.example 复制）
#
# 设计原则：
# - 不硬编码任何机器特定路径（去天狐 E:/Tianhu 耦合）
# - yaml 缺失时退回 PATH 查找（shutil.which）
# - keys 缺失时返回空 dict，调用方自行判断

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
YAML_PATH = ROOT / "tools" / "external-tools.yaml"
KEYS_PATH = ROOT / "tools" / "keys.env"

try:
    import yaml
except ImportError:
    yaml = None


def load_yaml():
    """加载 external-tools.yaml。文件不存在或 yaml 不可用 → 返回空 dict。"""
    if not YAML_PATH.is_file() or yaml is None:
        return {}
    try:
        with open(YAML_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def resolve(name):
    """解析工具名 → 可执行文件绝对路径。
    优先级：external-tools.yaml 中该工具的 path → PATH 查找 → None。
    """
    cfg = load_yaml()
    tools = cfg.get("tools", {}) if cfg else {}
    entry = tools.get(name, {})
    # yaml 中可指定 path
    p = entry.get("path") if isinstance(entry, dict) else None
    if p and Path(p).is_file():
        return p
    # 退回 PATH
    return shutil.which(name)


def cmdline(name, extra_args):
    """构造工具的完整命令行列表 [exe, *args]。
    exe 解析失败时抛 FileNotFoundError。
    """
    exe = resolve(name)
    if not exe:
        raise FileNotFoundError(
            f"工具 `{name}` 未找到。请在 tools/external-tools.yaml 声明 path，或确保其在 PATH 中。"
        )
    return [exe] + list(extra_args)


def load_keys():
    """加载 tools/keys.env，返回 dict。
    文件不存在 → 返回空 dict（调用方自行判断哪些 key 缺失）。
    """
    if not KEYS_PATH.is_file():
        return {}
    keys = {}
    try:
        with open(KEYS_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    keys[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        return {}
    return keys


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        cfg = load_yaml()
        print(f"external-tools.yaml: {'OK' if cfg else 'EMPTY/MISSING'}")
        for tool in ["subfinder", "httpx", "nuclei", "sqlmap", "nmap", "oneforall"]:
            p = resolve(tool)
            print(f"  {tool}: {p or 'NOT FOUND'}")
        keys = load_keys()
        print(f"keys.env: {'OK' if keys else 'EMPTY/MISSING'}")
        for k in ["FOFA_EMAIL", "FOFA_KEY", "HUNTER_KEY", "QUAKE_KEY"]:
            print(f"  {k}: {'SET' if keys.get(k) else 'MISSING'}")
        sys.exit(0)
