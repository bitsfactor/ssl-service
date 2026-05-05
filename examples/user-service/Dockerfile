FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. Even though the container is sandboxed and
# only listens on a localhost port (Caddy fronts it), root inside the
# container is one CVE away from being root in the namespace, and
# user-service handles passwords / sessions — minimal-privilege wins.
RUN useradd --uid 1100 --create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY requirements.txt .
RUN pip install --break-system-packages -r requirements.txt

# COPY runs as root and the host tar may have restrictive umask perms;
# use --chown so the ``app`` user can actually read the files at runtime.
COPY --chown=app:app app ./app
# Single-file SPA served at / — sign-up + login + account view. Lives
# in static/index.html so we can serve it via FastAPI's FileResponse
# without a separate web server.
COPY --chown=app:app static ./static
# Product manifest — /product/info reads this at runtime so the
# platform homepage (and Settings) can show a description without
# touching the DB.
COPY --chown=app:app .product.yaml ./.product.yaml

USER app

ENV PORT=8200
EXPOSE 8200

CMD ["python", "-m", "app"]
