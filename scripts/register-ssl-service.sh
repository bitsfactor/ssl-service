#!/usr/bin/env bash
# One-shot setup: register ssl-service in the admin's services table
# and load the .deploy.yaml manifest from GitHub. After this runs,
# the "Deploy ssl-service to selected" button on the Nodes page works.
#
# Requirements:
#   - .deploy.yaml + docker-compose.yml at repo root must already be on
#     the `main` branch of bitsfactor/ssl-service.
#   - admin server is running locally and the token is known.
#
# Usage:
#   export ADMIN_TOKEN=...
#   bash scripts/register-ssl-service.sh
#
# Re-running is safe — both endpoints are idempotent (POST creates,
# manifest re-fetch overwrites).
set -euo pipefail

ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:8088}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
REPO_URL="${REPO_URL:-https://github.com/bitsfactor/ssl-service}"
BRANCH="${BRANCH:-main}"

if [[ -z "${ADMIN_TOKEN}" ]]; then
  printf 'ERROR: set ADMIN_TOKEN (the same value as admin.token in config.yaml)\n' >&2
  exit 1
fi

curl_admin() {
  local method="$1"; shift
  local path="$1"; shift
  curl -sS -X "${method}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' \
    "${ADMIN_URL}${path}" "$@"
}

echo "==> 1. Registering service 'ssl-service'…"
curl_admin POST /api/services -d "$(cat <<JSON
{
  "name": "ssl-service",
  "github_repo_url": "${REPO_URL}",
  "default_branch": "${BRANCH}",
  "description": "ssl-service itself, deployed via standard docker compose manifest"
}
JSON
)" || true   # swallow conflict if already registered

echo
echo "==> 2. Pulling .deploy.yaml from ${REPO_URL}@${BRANCH}…"
curl_admin POST /api/services/ssl-service/manifest

echo
echo "Done. Open the admin UI → Nodes → tick boxes → 'Deploy ssl-service to selected'."
