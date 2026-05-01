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
echo "  ssl-service admin — Postgres (ssl_service_test schema)"
echo "================================================================"
echo

# --- DSN (bootstrap) -----------------------------------------------------
# Always launch with the BOOTSTRAP DSN. The admin process boots, reads
# ``system_config['databases']`` from this DB, sees which entry is
# marked active_id, and (if it's a different DSN) live-swaps its
# connection pool. So 'Activate' in the Databases page persists in the
# database itself — no per-machine state on disk.
BOOTSTRAP_DSN='postgresql://postgres:qqwweeQQWWEE112233%40%40@db.vcktifcdhinmooixljto.supabase.co:5432/postgres?sslmode=require&options=-csearch_path%3Dssl_service_test'
DSN="${BOOTSTRAP_DSN}"
echo "bootstrap DSN: ${DSN%%@*}@…"

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

echo "ensuring ssl_service_test schema + tables exist in Supabase ..."
DSN="${DSN}" SCHEMA_PATH="${REPO_DIR}/sql/schema.sql" "${PY}" - <<'PY'
import os, sys
try:
    import psycopg
except ImportError:
    print("ERROR: psycopg not installed in the venv. Re-run start.command once.", file=sys.stderr)
    sys.exit(1)

dsn = os.environ["DSN"]
schema_sql = open(os.environ["SCHEMA_PATH"]).read()

with psycopg.connect(dsn, connect_timeout=20) as conn:
    with conn.cursor() as cur:
        # Create the dedicated schema; the DSN already sets search_path=ssl_service_test,
        # so every subsequent CREATE TABLE lands in the right place.
        cur.execute("CREATE SCHEMA IF NOT EXISTS ssl_service_test")
        cur.execute(schema_sql)
    conn.commit()
print("schema ready: ssl_service_test")
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
echo "  DB:     Supabase · schema ssl_service_test"
echo "  Config: ${CONFIG_PATH}"
echo "================================================================"
echo
echo "Leave this window open. Press Ctrl-C to stop the server."
echo

exec "${PY}" -m ssl_proxy_controller --admin-only --config "${CONFIG_PATH}"
