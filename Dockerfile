# syntax=docker/dockerfile:1
# All and One (antbb): Next.js landing + FastAPI backend in one image, one port.
# Multi-arch: node:22-bookworm-slim and python:3.12-slim are published for
# linux/amd64 and linux/arm64 (Oracle Ampere A1), so the same file builds both.
# No secrets are baked in. Keys and the admin hash come from antbb.env at runtime.

# ---- Stage 1: static export of the All-and-One landing (all-and-one/out) ----
FROM node:22-bookworm-slim AS web
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /src/all-and-one
COPY all-and-one/package.json all-and-one/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY antbb/locale /src/antbb/locale
COPY all-and-one/ ./
RUN npm run build

# ---- Stage 2: Python runtime ----
FROM python:3.12-slim AS app
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin antbb
WORKDIR /opt/antbb
COPY requirements.txt requirements-report.txt ./
RUN pip install --no-cache-dir -r requirements.txt && pip check

COPY . .
COPY --from=web /src/all-and-one/out /opt/antbb/all-and-one/out
RUN rm -f antbb.env .env \
    && mkdir -p /opt/antbb/data \
    && chown -R antbb:antbb /opt/antbb/data

USER antbb
# ANTBB_HOSTED=1: fail closed without ANTBB_ADMIN_PASSWORD_HASH, Secure +
# SameSite=Strict cookies, CSP/HSTS, Oversight + Scope enforced server-side.
ENV ANTBB_HOSTED=1 \
    ANTBB_HOST=127.0.0.1 \
    ANTBB_PORT=1001 \
    ALLONE_HOST=127.0.0.1 \
    ALLONE_PORT=1001 \
    ALLONE_WEB_ROOT=/opt/antbb/all-and-one/out \
    ANTBB_COLONY_ROOT=/opt/antbb \
    YELLOW_QUEEN_ROOT=/opt/antbb \
    ANTBB_QUARANTINE_DIR=/opt/antbb/data/quarantine \
    FORWARDED_ALLOW_IPS=127.0.0.1 \
    PYTHONPATH=/opt/antbb \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 1001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:1001/healthz', timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "api", "--host", "127.0.0.1", "--port", "1001"]
