#!/usr/bin/env bash
# Launcher: ssl-service admin UI wired to Postgres (Supabase).
# Double-click this file to:
#   1. free port 8088 if something else is listening
#   2. apply sql/schema.sql into the ssl_service_test schema
#   3. start the admin HTTP server backed by the real DB
#
# The DSN is written to /tmp/ssl-service-dev-pg-config.yaml — not into the repo.
# URL:   http://127.0.0.1:8088/
# Token: dev-token
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_DIR="$(pwd)"
VENV_DIR="${REPO_DIR}/.venv"
CONFIG_PATH="/tmp/ssl-service-dev-pg-config.yaml"
STATE_DIR="/tmp/ssl-service-dev-pg/state"
LOG_DIR="/tmp/ssl-service-dev-pg/logs"

# Homebrew paths for GUI-launched shells.
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

echo "================================================================"
echo "  ssl-service admin — Postgres (schema is set by .env DSN)"
echo "================================================================"
echo

# --- DSN (bootstrap) -----------------------------------------------------
# We read the bootstrap DSN from the project's ``.env`` file — the
# same file that gets written into /opt/ssl-service/ on remote nodes
# when the platform deploys ssl-service there. Local mirror of the
# deployment convention.
#
# How the runtime resolves the working DSN: the admin connects on
# startup using SSL_SERVICE_PG_DSN, reads ``system_config['databases']``
# **from this home schema**, finds the entry whose ``selected`` flag
# is true, and (if different from the bootstrap DSN) live-swaps its
# working pool. The home schema never moves with that swap — the
# registry stays put.
ENV_FILE="${REPO_DIR}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: ${ENV_FILE} not found."
  echo
  echo "ssl-service needs SSL_SERVICE_PG_DSN in a .env at the project"
  echo "root (mirrors how the platform writes /opt/ssl-service/.env on"
  echo "remote deploys). Example contents:"
  echo
  cat <<'EOF'
SSL_SERVICE_PG_DSN=postgresql://USER:PASSWORD@HOST:5432/postgres?sslmode=require&options=-csearch_path%3DSCHEMA
SSL_SERVICE_ADMIN_TOKEN=dev-token
SSL_SERVICE_ADMIN_BIND=127.0.0.1
SSL_SERVICE_ADMIN_PORT=8088
SSL_SERVICE_MODE=readwrite
SSL_SERVICE_LOG_LEVEL=INFO
EOF
  echo
  echo "Create ${ENV_FILE} (with at least SSL_SERVICE_PG_DSN), then re-run."
  echo "Press any key to close this window..."
  read -n 1 -s
  exit 1
fi
# Source the .env so every line ``KEY=VALUE`` becomes an exported
# env var (set -a). Cheap and predictable; matches the docker-compose
# env_file convention.
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a
if [[ -z "${SSL_SERVICE_PG_DSN:-}" ]]; then
  echo "ERROR: ${ENV_FILE} did not define SSL_SERVICE_PG_DSN."
  echo "Press any key to close this window..."
  read -n 1 -s
  exit 1
fi
DSN="${SSL_SERVICE_PG_DSN}"
echo "bootstrap DSN (from .env): ${DSN%%@*}@…"

# --- Find Python 3.11+ + venv -------------------------------------------
PY=""
if [[ -x "${VENV_DIR}/bin/python" ]]; then
  VENV_VERSION="$("${VENV_DIR}/bin/python" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  if [[ "${VENV_VERSION}" =~ ^3\.(1[1-9]|[2-9][0-9])$ ]]; then
    PY="${VENV_DIR}/bin/python"
    echo "using existing venv: ${VENV_DIR} (python ${VENV_VERSION})"
  fi
fi

if [[ -z "${PY}" ]]; then
  for CANDIDATE in \
    python3.14 python3.13 python3.12 python3.11 \
    /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 \
    /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11
  do
    if command -v "${CANDIDATE}" >/dev/null 2>&1 || [[ -x "${CANDIDATE}" ]]; then
      V="$("${CANDIDATE}" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
      if [[ "${V}" =~ ^3\.(1[1-9]|[2-9][0-9])$ ]]; then
        echo "building venv with ${CANDIDATE} (python ${V})"
        rm -rf "${VENV_DIR}"
        "${CANDIDATE}" -m venv "${VENV_DIR}"
        "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
        "${VENV_DIR}/bin/pip" install --quiet -e "${REPO_DIR}"
        PY="${VENV_DIR}/bin/python"
        break
      fi
    fi
  done
fi

if [[ -z "${PY}" ]]; then
  echo "ERROR: need Python 3.11 or newer. Try 'brew install python@3.12' then re-run."
  echo "Press any key to close this window..."
  read -n 1 -s
  exit 1
fi

# psycopg + paramiko should already be installed because pyproject.toml
# pins them, but make sure in case someone ran with a stripped-down env.
"${VENV_DIR}/bin/pip" install --quiet "psycopg[binary]>=3.1.18,<4.0.0" >/dev/null 2>&1 || true
"${VENV_DIR}/bin/pip" install --quiet "psycopg_pool>=3.2.0,<4.0.0" >/dev/null 2>&1 || true
"${VENV_DIR}/bin/pip" install --quiet "paramiko>=3.4.0,<4.0.0" >/dev/null 2>&1 || true

# --- Free port 8088 ------------------------------------------------------
if command -v lsof >/dev/null 2>&1; then
  OWNER="$(lsof -nP -iTCP:8088 -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -n "${OWNER}" ]]; then
    echo "port 8088 is in use by pid ${OWNER}; stopping it..."
    kill "${OWNER}" 2>/dev/null || true
    sleep 1
    kill -9 "${OWNER}" 2>/dev/null || true
  fi
fi

# --- Apply schema --------------------------------------------------------
mkdir -p "${STATE_DIR}" "${LOG_DIR}"

echo "ensuring schema + tables exist in Supabase ..."
DSN="${DSN}" SCHEMA_PATH="${REPO_DIR}/sql/schema.sql" "${PY}" - <<'PY'
import os, sys, re, urllib.parse
try:
    import psycopg
except ImportError:
    print("ERROR: psycopg not installed in the venv. Re-run start.command once.", file=sys.stderr)
    sys.exit(1)

dsn = os.environ["DSN"]
schema_sql = open(os.environ["SCHEMA_PATH"]).read()

# Extract the schema name from the DSN's `options=-csearch_path=...`
# query parameter. Whichever schema the user pointed their .env at is
# the one we must `CREATE SCHEMA IF NOT EXISTS` for. Falls back to
# ``public`` if the DSN didn't pin a schema.
parsed = urllib.parse.urlparse(dsn)
qs = urllib.parse.parse_qs(parsed.query)
options = (qs.get("options") or [""])[0]
m = re.search(r"-csearch_path[%3D=]+([^&\s]+)", options) or re.search(r"search_path[%3D=]+([^&\s]+)", options)
schema_name = (m.group(1).strip('"') if m else "public") or "public"
print(f"target schema (from DSN): {schema_name}")

with psycopg.connect(dsn, connect_timeout=20) as conn:
    with conn.cursor() as cur:
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
        cur.execute(schema_sql)
    conn.commit()
print(f"schema ready: {schema_name}")
PY

# --- Write the config at a temp path (NOT inside the repo) ---------------
cat >"${CONFIG_PATH}" <<YAML
mode: readwrite
postgres:
  dsn: "${DSN}"
sync:
  poll_interval_seconds: 30
  renew_before_days: 30
  retry_backoff_seconds: 3600
  loop_error_backoff_seconds: 10
paths:
  state_dir: ${STATE_DIR}
  log_dir: ${LOG_DIR}
caddy:
  admin_url: http://127.0.0.1:2019
  reload_command: ["/usr/bin/true"]
acme:
  email: dev@example.com
  staging: true
  challenge_type: dns-01
  dns_provider: cloudflare
logging:
  level: INFO
  controller_log_path: ${LOG_DIR}/controller.log
  caddy_log_path: ${LOG_DIR}/caddy.log
admin:
  enabled: true
  bind: 127.0.0.1
  port: 8088
  token: dev-token
YAML
chmod 600 "${CONFIG_PATH}"

echo
echo "================================================================"
echo "  Starting admin (admin-only — no Caddy reload, no sync loop)"
echo "  URL:    http://127.0.0.1:8088/"
echo "  Token:  dev-token"
echo "  DB:     ${DSN%%@*}@…"
echo "  Config: ${CONFIG_PATH}"
echo "================================================================"
echo
echo "Leave this window open. Press Ctrl-C to stop the server."
echo

exec "${PY}" -m ssl_proxy_controller --admin-only --config "${CONFIG_PATH}"
