# Bring your own runtime. Below is just a minimal example for a tiny
# Python web service. Replace with whatever your project actually needs.
#
# The only contract: the resulting image should respond to the
# healthcheck URL declared in .deploy.yaml.

FROM python:3.12-slim

WORKDIR /app

# System deps your app might need
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
    && rm -rf /var/lib/apt/lists/*

# App deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# App source
COPY . /app

# Healthcheck — also wired to the platform via .deploy.yaml.
HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
  CMD curl -fsS http://localhost:${PORT:-8080}/health || exit 1

CMD ["python", "-m", "app"]
