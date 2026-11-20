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

# ---- Stage 1b: passive OSINT-Werkzeuge (Extras-Katalog), nur offizielle Quellen ----
# Go-Tools aus dem Go-Modul-Proxy (Quelle: GitHub-Repos der Autoren), feste Versionen.
FROM golang:1.26-bookworm AS osint-go
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOBIN=/out
RUN go install github.com/tomnomnom/assetfinder@v0.1.1 \
 && go install github.com/projectdiscovery/uncover/cmd/uncover@v1.2.1 \
 && go install github.com/s0md3v/smap/cmd/smap@v1.0.0-beta

# GitHub-Release-Binaries (arm64) mit fest gepinnter SHA-256.
FROM debian:trixie-slim AS osint-rel
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eu; arch="$(dpkg --print-architecture)"; mkdir -p /out; \
    if [ "$arch" = "arm64" ]; then \
      curl -fsSL -o fd.zip https://github.com/Findomain/Findomain/releases/download/11.0.0/findomain-aarch64.zip; \
      echo "c42f6287e03fc6a1646871cbc40b08349d43a214881da8d176a30fcbabd9a2f6  fd.zip" | sha256sum -c -; \
      curl -fsSL -o pi.tgz https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_arm64.tar.gz; \
      echo "bc8ed51e3e20fe4b82999aac16a7925f783562346563ba4b26e33c90434cd58b  pi.tgz" | sha256sum -c -; \
    else \
      curl -fsSL -o fd.zip https://github.com/Findomain/Findomain/releases/download/11.0.0/findomain-linux.zip; \
      curl -fsSL -o pi.tgz https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz; \
      curl -fsSL https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_checksums.txt \
        | grep " phoneinfoga_Linux_x86_64.tar.gz$" | sed "s/phoneinfoga_Linux_x86_64.tar.gz/pi.tgz/" | sha256sum -c -; \
    fi; \
    unzip -q fd.zip -d /out && tar xzf pi.tgz -C /out phoneinfoga && chmod 0755 /out/*

# PyPI-Tools: je Tool ein eigenes venv (keine Konflikte mit der App), feste Versionen.
FROM python:3.12-slim AS osint-py
RUN set -eu; for spec in instaloader==4.16 socialscan==2.0.1 waybackpack==0.6.4 waybackpy==3.0.6 \
      censys==2.3.0 shodan==1.31.0 social-analyzer==0.45 user-scanner==1.5.2.5 \
      nexfil==1.0.6; do \
      name="${spec%%==*}"; python -m venv "/opt/osint/$name"; \
      "/opt/osint/$name/bin/pip" install --no-cache-dir "setuptools<81" "$spec"; \
    done

# ---- Stage 2: Python runtime ----
FROM python:3.12-slim AS app
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin antbb
# Queen/OSINT/RE CLIs from Debian (multi-arch). python:3.12-slim is Debian
# Trixie: nikto and radare2 are not in the Trixie archive, so official
# nikto (GitHub sullo/nikto) and rizin live under /opt/antbb-tools and
# are bind-mounted with Ghidra — see docker-compose.yml.
RUN apt-get update && apt-get install -y --no-install-recommends         nmap sqlmap whatweb sslscan wafw00f gobuster         binwalk apktool yara gdb strace ltrace         clamav clamav-freshclam         openjdk-21-jdk-headless openjdk-25-jdk-headless         perl libnet-ssleay-perl libio-socket-ssl-perl         file binutils bsdmainutils xxd openssl iproute2 unzip         whois libimage-exiftool-perl         libpango-1.0-0 libpangocairo-1.0-0 libcairo2         libgdk-pixbuf-2.0-0 fonts-dejavu-core fontconfig         ca-certificates     && rm -rf /var/lib/apt/lists/*
# Passive OSINT aus dem Debian-Archiv (eigener Layer, damit der große
# apt-Layer oben im Cache bleibt).
RUN apt-get update && apt-get install -y --no-install-recommends recon-ng sublist3r \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/antbb
COPY requirements.txt requirements-report.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-report.txt && pip check

# Passive OSINT-Werkzeuge (Extras). Keine API-Keys im Image (shodan/censys/uncover
# laufen ohne Key nur eingeschränkt bzw. gar nicht – Keys setzt nur der Admin).
COPY --from=osint-go /out/ /usr/local/bin/
COPY --from=osint-rel /out/ /usr/local/bin/
COPY --from=osint-py /opt/osint /opt/osint
# Nur die Tool-Einstiegspunkte verlinken (keine Hilfs-Skripte der Abhängigkeiten).
RUN set -eu; for venv in /opt/osint/*; do \
      for exe in "$venv"/bin/*; do \
        b="$(basename "$exe")"; \
        case "$b" in instaloader|socialscan|waybackpack|waybackpy|censys|shodan|social-analyzer|user-scanner|nexfil) \
          [ -e "/usr/local/bin/$b" ] || ln -s "$exe" "/usr/local/bin/$b";; esac; \
      done; \
    done

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
