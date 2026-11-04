# Web UI listens on 127.0.0.1 inside the container. Pair with host networking
# (see docker-compose.yml) so that address is the host loopback.
FROM python:3.12-slim

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin antbb

WORKDIR /opt/antbb
COPY requirements.txt requirements-report.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /opt/antbb/data \
    && chown -R antbb:antbb /opt/antbb

USER antbb
ENV ANTBB_HOST=127.0.0.1 \
    ANTBB_PORT=1001 \
    ALLONE_PORT=1001 \
    PYTHONPATH=/opt/antbb \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 1001
CMD ["python", "-m", "api", "--host", "127.0.0.1", "--port", "1001"]
