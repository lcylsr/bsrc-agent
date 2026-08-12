#!/usr/bin/env python3
# tools/android-recon.py — 已合并到 client-recon.py，保留为兼容 wrapper
#
# 用法:
#   bash tools/run.sh android-recon <target_dir> <apk_path> [--out-dir <dir>]
#
# 该脚本直接调用 tools/client-recon.py --type android，输出统一在
# <target_dir>/recon/client-recon/ 目录下。

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    client_recon = ROOT / "tools" / "client-recon.py"
    argv = [str(client_recon), "--type", "android"]
    argv.extend(sys.argv[1:])
    return subprocess.run([sys.executable] + argv).returncode


if __name__ == "__main__":
    sys.exit(main())
