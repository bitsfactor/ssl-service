#!/usr/bin/env bash
# Launcher for the local ssl-service admin UI.
#
# This script does ONLY three things — it must not modify the
# database, the venv, or anything else on disk:
#
#   1. Source ./.env so SSL_SERVICE_* env vars are exported
#   2. Free port 8088 if a previous admin is still listening on it
#   3. Launch the admin in env-only mode (`python -m ssl_proxy_controller --admin-only`)
#
# What it deliberately does NOT do:
#   - apply sql/schema.sql to the database (that's apply-schema.command)
#   - install / upgrade Python packages (that's scripts/setup.sh)
#   - write any temp config.yaml (the admin reads SSL_SERVICE_* directly)
#
# URL:   http://127.0.0.1:8088/
# Token: as set by SSL_SERVICE_ADMIN_TOKEN in .env (dev-token by default)
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_DIR="$(pwd)"
VENV_DIR="${REPO_DIR}/.venv"
ENV_FILE="${REPO_DIR}/.env"

# Homebrew paths for GUI-launched shells.
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

echo "================================================================"
echo "  ssl-service admin"
echo "================================================================"
echo

# --- 1. Source .env ---------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: ${ENV_FILE} not found."
  echo
  echo "Create a .env at the project root with at least:"
  echo
  cat <<'EOF'
SSL_SERVICE_PG_DSN=postgresql://USER:PASSWORD@HOST:5432/postgres?sslmode=require&options=-csearch_path%3DSCHEMA
SSL_SERVICE_MODE=readwrite
SSL_SERVICE_ENABLE_WEB_UI=true
SSL_SERVICE_ADMIN_TOKEN=dev-token
SSL_SERVICE_ADMIN_BIND=127.0.0.1
SSL_SERVICE_ADMIN_PORT=8088
SSL_SERVICE_LOG_LEVEL=INFO
SSL_SERVICE_STATE_DIR=/tmp/ssl-service-dev-pg/state
SSL_SERVICE_LOG_DIR=/tmp/ssl-service-dev-pg/logs
EOF
  echo
  echo "Press any key to close..."
  read -n 1 -s
  exit 1
fi
# Read .env line-by-line. We can't `source` it because docker-compose-
# style values are unquoted and may contain shell metacharacters like
# ``&`` (DSNs do — ``?sslmode=require&options=...``). Manual parse:
# split on the first ``=``; values are literal, surrounding quotes
# stripped if present.
while IFS= read -r _line || [[ -n "${_line}" ]]; do
  [[ -z "${_line}" || "${_line}" =~ ^[[:space:]]*# ]] && continue
  _line="${_line#export }"
  _key="${_line%%=*}"
  _val="${_line#*=}"
  _val="${_val%$'\r'}"
  if [[ "${_val}" == \"*\" ]] || [[ "${_val}" == \'*\' ]]; then
    _val="${_val:1:${#_val}-2}"
  fi
  export "${_key}=${_val}"
done < "${ENV_FILE}"
unset _line _key _val

if [[ -z "${SSL_SERVICE_PG_DSN:-}" ]]; then
  echo "ERROR: ${ENV_FILE} did not define SSL_SERVICE_PG_DSN."
  echo "Press any key to close..."
  read -n 1 -s
  exit 1
fi
# Tell the admin process where .env lives so it can read+edit it
# from the Databases page. Without this, the admin only sees the
# values (already in its env) and would have nothing to write back to.
export SSL_SERVICE_ENV_FILE="${ENV_FILE}"
echo "loaded .env from ${ENV_FILE}"
echo "  DSN: ${SSL_SERVICE_PG_DSN%%@*}@…"

# --- 2. Verify venv (we don't create or update it; that's setup.sh) ---
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo
  echo "ERROR: Python venv not found at ${VENV_DIR}."
  echo "Run \`scripts/setup-dev.sh bootstrap\` once to create it, then"
  echo "re-run start.command."
  echo "Press any key to close..."
  read -n 1 -s
  exit 1
fi
PY="${VENV_DIR}/bin/python"

# --- 3. Free port + launch admin -------------------------------------
PORT="${SSL_SERVICE_ADMIN_PORT:-8088}"
if command -v lsof >/dev/null 2>&1; then
  OWNER="$(lsof -nP -iTCP:${PORT} -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -n "${OWNER}" ]]; then
    echo "port ${PORT} in use by pid ${OWNER}; stopping it..."
    kill "${OWNER}" 2>/dev/null || true
    sleep 1
    kill -9 "${OWNER}" 2>/dev/null || true
  fi
fi

# Make sure the dev-only dirs exist before the admin tries to write
# logs/state into them. Cheap; doesn't touch anything outside /tmp.
mkdir -p "${SSL_SERVICE_STATE_DIR:-/tmp/ssl-service-dev-pg/state}" \
         "${SSL_SERVICE_LOG_DIR:-/tmp/ssl-service-dev-pg/logs}"

echo
echo "================================================================"
echo "  URL:    http://${SSL_SERVICE_ADMIN_BIND:-127.0.0.1}:${PORT}/"
echo "  Token:  ${SSL_SERVICE_ADMIN_TOKEN:-(unset)}"
echo "  DB:     ${SSL_SERVICE_PG_DSN%%@*}@…"
echo "================================================================"
echo
echo "Leave this window open. Press Ctrl-C to stop the server."
echo

# Env-only mode — admin reads SSL_SERVICE_* directly from process env.
exec "${PY}" -m ssl_proxy_controller --admin-only
