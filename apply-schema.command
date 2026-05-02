#!/usr/bin/env bash
# Apply sql/schema.sql to the database that .env points at.
#
# Run this once after a fresh clone, and again whenever sql/schema.sql
# changes (new tables, new columns, etc.). It is intentionally
# separate from start.command so launching the admin never silently
# mutates the database.
#
# What it does:
#   1. Source ./.env so SSL_SERVICE_PG_DSN is set
#   2. Extract the schema name from the DSN's search_path
#   3. CREATE SCHEMA IF NOT EXISTS <schema>
#   4. Run sql/schema.sql against that schema
#
# Idempotent — schema.sql is written entirely with CREATE TABLE IF NOT
# EXISTS / ALTER TABLE … ADD COLUMN IF NOT EXISTS, so re-running is
# safe and a no-op once everything is in place.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_DIR="$(pwd)"
VENV_DIR="${REPO_DIR}/.venv"
ENV_FILE="${REPO_DIR}/.env"

export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

echo "================================================================"
echo "  ssl-service — apply sql/schema.sql"
echo "================================================================"
echo

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: ${ENV_FILE} not found. Create it first (see start.command)."
  echo "Press any key to close..."
  read -n 1 -s
  exit 1
fi

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

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "ERROR: ${VENV_DIR} not found."
  echo "Run \`scripts/setup-dev.sh bootstrap\` once first."
  echo "Press any key to close..."
  read -n 1 -s
  exit 1
fi

echo "DSN: ${SSL_SERVICE_PG_DSN%%@*}@…"
echo

DSN="${SSL_SERVICE_PG_DSN}" SCHEMA_PATH="${REPO_DIR}/sql/schema.sql" "${VENV_DIR}/bin/python" - <<'PY'
import os, sys, re, urllib.parse
try:
    import psycopg
except ImportError:
    print("ERROR: psycopg not installed in the venv. Re-run scripts/setup.sh.",
          file=sys.stderr)
    sys.exit(1)

dsn = os.environ["DSN"]
schema_sql = open(os.environ["SCHEMA_PATH"]).read()

# Extract the schema name from the DSN's `options=-csearch_path=...`.
parsed = urllib.parse.urlparse(dsn)
qs = urllib.parse.parse_qs(parsed.query)
options = (qs.get("options") or [""])[0]
m = re.search(r"-csearch_path[%3D=]+([^&\s]+)", options) or re.search(r"search_path[%3D=]+([^&\s]+)", options)
schema_name = (m.group(1).strip('"') if m else "public") or "public"
print(f"target schema: {schema_name}")

with psycopg.connect(dsn, connect_timeout=20) as conn:
    with conn.cursor() as cur:
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
        cur.execute(schema_sql)
    conn.commit()
print(f"schema applied: {schema_name}")
PY

echo
echo "Done. Press any key to close..."
read -n 1 -s
