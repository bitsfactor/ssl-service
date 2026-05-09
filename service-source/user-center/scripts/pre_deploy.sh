#!/usr/bin/env bash
# Run on the target node before `docker compose up`.
# user-center has no database of its own — it is a pure frontend that
# proxies to user-service internally. This script is intentionally
# minimal; it just validates the environment so a misconfigured deploy
# fails loudly before the container starts.
set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ -z "${USER_SERVICE_URL:-}" ]]; then
  echo "pre_deploy: USER_SERVICE_URL not set" >&2
  exit 1
fi

echo "pre_deploy: USER_SERVICE_URL=${USER_SERVICE_URL}"
echo "pre_deploy: done"
