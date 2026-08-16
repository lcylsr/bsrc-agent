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
#   nuclei + 模板 — c 系列产品题已知 CVE 扫描（构建期下载，运行期离线可用）
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget netcat-openbsd dnsutils iputils-ping procps \
        nmap ffuf hydra sqlmap gdb strace \
        openssl default-mysql-client redis-tools \
        tesseract-ocr binutils file ltrace socat unzip \
    && rm -rf /var/lib/apt/lists/*

# nuclei（Go 单二进制）+ 模板库（构建期下载；网络受限时失败跳过，不阻塞构建）
# 官方源失败 → 国内镜像源（ghfast.top）重试 → 仍失败则跳过（c 系列由 LLM 手写 exploit 兜底）
RUN (NUCLEI_VER=$(curl -s --max-time 20 https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name":\s*"v\K[0-9.]+' | head -1) \
    && { curl -sL --max-time 60 -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
         || curl -sL --max-time 60 -o /tmp/nuclei.zip "https://ghfast.top/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip"; } \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && rm -f /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && { curl -sL --max-time 120 https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz \
         || curl -sL --max-time 120 https://ghfast.top/https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz; } \
       | tar xz -C /opt/ && mv /opt/nuclei-templates-main /opt/nuclei-templates && rm -rf /opt/nuclei-templates/.git) \
    || echo "⚠ nuclei 下载失败（网络受限），跳过——c 系列题由 LLM 手写 exploit 兜底"

# Python 漏洞利用/分析库（与运行环境隔离）
# androguard：纯 python APK/DEX 解析（bctf 安卓题 25% 占比，无需 JRE 的 jadx）
# 显式官方源 + 重试（默认源曾返回哈希不符的包——疑似镜像污染）
RUN pip install --no-cache-dir -q --retries 5 --timeout 60 \
        -i https://pypi.org/simple \
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
