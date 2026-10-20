# SentinelX image. Two targets from one base so the sensor and the API never share privileges:
#   docker build --target sensor -t sentinelx-sensor .   (python gets file capability NET_RAW only)
#   docker build --target api    -t sentinelx-api .      (no capabilities; works with cap_drop: ALL)
# Both run as a non-root user.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 sentinelx \
 && useradd --system --uid 10001 --gid sentinelx --home-dir /app --shell /usr/sbin/nologin sentinelx

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY main.py ./
COPY backend ./backend
COPY capture ./capture
COPY config ./config
COPY dashboard ./dashboard
COPY database ./database
COPY detection ./detection
COPY eval ./eval
COPY logs ./logs
COPY ml ./ml
COPY scripts ./scripts

# Data directories are created and owned here so named volumes inherit the ownership on first mount.
RUN mkdir -p /data/alerts /data/app && chown -R sentinelx:sentinelx /data

ENV SENTINELX_DB_PATH=/data/alerts/alerts.db \
    SENTINELX_ALERT_LOG=/data/alerts/alerts.jsonl \
    SENTINELX_APP_DB_PATH=/data/app/app.db

# ---------------------------------------------------------------- API (no capture privileges)
FROM base AS api
ENV SENTINELX_API_HOST=0.0.0.0
USER sentinelx
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "scripts/healthcheck.py", "api"]
CMD ["python", "main.py", "api"]

# ---------------------------------------------------------------- sensor (raw sockets via file capabilities)
FROM base AS sensor
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && setcap cap_net_raw+eip "$(readlink -f "$(command -v python)")"
USER sentinelx
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "scripts/healthcheck.py", "sensor"]
CMD ["python", "main.py", "sensor"]
