# 托管模式自动解题镜像 v3 — BSRC Agent+ 挑战赛（TSecBench 平台）
# 平台要求：容器启动后自行开始解题；无公网访问（大模型走平台网关）
# v3：bash 万能动作 + 完整工具链 + 方法论提示（对标 Kali 风格）
FROM python:3.10-slim

WORKDIR /app

# 工具链：recon + 漏洞利用 + 网络工具 + 逆向/OCR（构建时安装，运行期无法访问公网）
# v3 增补（对标榜单第一 agent-hehua 工具栈）：
#   tesseract/ddddocr — 验证码 OCR（前代教训：手撕验证码像素 = 送分）
#   binutils/file/ltrace — f2 逆向静态分析（strings/objdump）
#   socat — 内网转发/隧道
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget netcat-openbsd dnsutils iputils-ping procps \
        nmap ffuf hydra sqlmap gdb strace \
        openssl default-mysql-client redis-tools \
        tesseract-ocr binutils file ltrace socat \
    && rm -rf /var/lib/apt/lists/*

# Python 漏洞利用/分析库（与运行环境隔离）
# androguard：纯 python APK/DEX 解析（bctf 安卓题 25% 占比，无需 JRE 的 jadx）
RUN pip install --no-cache-dir -q \
        requests beautifulsoup4 lxml pyjwt pycryptodome z3-solver dnspython \
        ddddocr pwntools androguard

COPY solve.py /app/solve.py
RUN mkdir -p /app/workspace

# 运行时环境变量（平台自动分发 + 页面配置）：
#   BENCHMARK_BASE_URL / BENCHMARK_TOKEN   平台自动注入
#   MODEL_API_BASE                         平台官方大模型网关（默认已配置）
#   MODEL_API_KEY                          页面运行时环境变量添加（平台下发 Key）
#   MODEL_NAME                             平台网关模型名（默认已配置）
ENV MODEL_API_BASE=http://agent-awd.baidu.com.tsecbench.gw/v1
ENV MODEL_NAME=glm-5.2-agent-chanllenge

ENTRYPOINT ["python", "-u", "/app/solve.py"]
