#!/usr/bin/env bash
# Standalone install script — for humans, NOT used by the platform.
#
# The platform deploys directly via the .deploy.yaml contract +
# docker compose. This file exists so an operator can also bring up the
# service by hand on a fresh box for debugging:
#
#     git clone <this repo> /opt/<service>
#     cd /opt/<service>
#     cp .env.example .env && $EDITOR .env
#     bash scripts/setup.sh

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -f .env ]]; then
  echo "ERROR: .env is missing. Copy .env.example and fill in the required values." >&2
  exit 1
fi

if ! command -v docker >/dev/null; then
  echo "ERROR: docker is not installed. Install Docker Engine first." >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a; source .env; set +a

echo "Building and starting service..."
docker compose pull --ignore-pull-failures || true
docker compose up -d --build

echo "Waiting for healthcheck..."
PORT="${PORT:-8080}"
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:${PORT}/health" >/dev/null 2>&1; then
    echo "Service healthy on :${PORT}"
    exit 0
  fi
  sleep 2
done
echo "ERROR: service did not become healthy within 60 seconds" >&2
docker compose logs --tail=50 app || true
exit 1
