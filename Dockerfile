# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/4zrec。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out internal/platform/server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/4zrec ./cmd/4zrec
#   docker build -t 4zrec:local .
#
# massdns 不在 Debian 仓库，单独在构建阶段编译；其余 recon CLI 使用官方
# amd64/arm64 预编译包，避免在运行镜像里引入 Go/Rust 工具链。
FROM python:3.12-slim-bookworm AS massdns-build
ARG MASSDNS_VERSION=1.1.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libldns-dev ca-certificates git \
    && git clone --depth 1 --branch "v${MASSDNS_VERSION}" https://github.com/blechschmidt/massdns.git /src \
    && mkdir -p /src/bin \
    && make -C /src \
    && rm -rf /var/lib/apt/lists/*

FROM python:3.12-slim-bookworm

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

# 常用工具 + 项目运行时需要的 CLI 客户端/收集工具。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
      openssh-client postgresql-client default-mysql-client \
      sqlmap whatweb masscan gobuster ffuf libpcap0.8 libldns3 \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# 预编译 recon CLI（ProjectDiscovery / Amass / Feroxbuster / puredns / shuffledns）。
# 版本集中在这里，升级时只改这一处；安装逻辑在 scripts/install-recon-tools.sh。
ARG NUCLEI_VERSION=3.11.1
ARG SUBFINDER_VERSION=2.17.0
ARG HTTPX_VERSION=1.12.0
ARG DNSX_VERSION=1.3.1
ARG KATANA_VERSION=1.8.0
ARG NAABU_VERSION=2.6.1
ARG AMASS_VERSION=5.1.1
ARG FEROXBUSTER_VERSION=2.13.1
ARG PUREDNS_VERSION=2.1.1
ARG SHUFFLEDNS_VERSION=1.2.1
COPY scripts/install-recon-tools.sh /tmp/install-recon-tools.sh
RUN TARGETARCH="$TARGETARCH" \
    NUCLEI_VERSION="$NUCLEI_VERSION" \
    SUBFINDER_VERSION="$SUBFINDER_VERSION" \
    HTTPX_VERSION="$HTTPX_VERSION" \
    DNSX_VERSION="$DNSX_VERSION" \
    KATANA_VERSION="$KATANA_VERSION" \
    NAABU_VERSION="$NAABU_VERSION" \
    AMASS_VERSION="$AMASS_VERSION" \
    FEROXBUSTER_VERSION="$FEROXBUSTER_VERSION" \
    PUREDNS_VERSION="$PUREDNS_VERSION" \
    SHUFFLEDNS_VERSION="$SHUFFLEDNS_VERSION" \
    sh /tmp/install-recon-tools.sh \
    && rm -f /tmp/install-recon-tools.sh
COPY --from=massdns-build /src/bin/massdns /usr/local/bin/massdns

# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# 报告渲染：DOCX 用 python-docx；PDF 的 Playwright 兜底需要 Python playwright。
RUN pip install --no-cache-dir python-docx playwright \
    && python3 -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# 预编译好的对应架构二进制（dist/amd64/4zrec 或 dist/arm64/4zrec）
COPY dist/${TARGETARCH}/4zrec /app/4zrec
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 4zrec —— docker stop 只把信号发给 PID 1，
# 不转发的话 4zrec 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
# 运行期数据资产：SaaS/CDN/成功信号规则与指纹种子、1day 漏洞库。
COPY configs/ /app/configs/
COPY vulnkb/ /app/vulnkb/
RUN chmod +x /app/4zrec /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
