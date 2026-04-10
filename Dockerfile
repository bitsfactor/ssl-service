FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https \
  && curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
  && curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends caddy \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY scripts/domain-manage.sh /app/scripts/domain-manage.sh
COPY scripts/container-entrypoint.sh /app/scripts/container-entrypoint.sh

RUN pip install --no-cache-dir . \
  && pip install --no-cache-dir "certbot>=2.11,<3.0" "certbot-dns-cloudflare>=2.11,<3.0" "PyYAML>=6.0.1,<7.0.0" "psycopg[binary]>=3.1.18,<4.0.0" \
  && chmod 0755 /app/scripts/domain-manage.sh /app/scripts/container-entrypoint.sh

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:2019/config/', timeout=3).read(1)" || exit 1

ENTRYPOINT ["/app/scripts/container-entrypoint.sh"]
