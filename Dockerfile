FROM python:3.12-slim

# ★ 构建期的镜像源，**默认留空 = 走官方源**（对海外构建者零影响）。
#   国内构建时传：
#     docker build --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn \
#                  --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple .
#   ⚠️ 不写死进镜像：这些只是**构建期**变量，运行时的镜像里一个字都不留。
ARG APT_MIRROR=""
ARG PIP_INDEX_URL=""

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    MG_DATA_DIR=/data \
    MG_FRPC_CONFIG=/frpc/frpc.toml

WORKDIR /app

# ⚠️ Debian 12+ 的源是 deb822 格式（/etc/apt/sources.list.d/debian.sources），
#    不再是老的 /etc/apt/sources.list。两个都处理，别只 sed 一个。
#    `deb.debian.org` 同时覆盖 debian 与 debian-security 两个 URIs。
RUN set -eux; \
    if [ -n "$APT_MIRROR" ]; then \
        for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do \
            [ -f "$f" ] && sed -i "s|deb.debian.org|$APT_MIRROR|g" "$f" || true; \
        done; \
        echo "--- 已切到 $APT_MIRROR ---"; \
        grep -rh "^URIs\|^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates tzdata curl; \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN if [ -n "$PIP_INDEX_URL" ]; then \
        pip install --no-cache-dir -i "$PIP_INDEX_URL" -r requirements.txt; \
    else \
        pip install --no-cache-dir -r requirements.txt; \
    fi

COPY app ./app

RUN mkdir -p /data /frpc

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
