#!/usr/bin/env bash
# Bypass the ssl-service admin pool (Supabase TLS rotation keeps
# poisoning it) and deploy user-service to us01 via direct SSH from
# this Mac. Pulls the linked SSH key out of Postgres on the fly.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PY="${PWD}/.venv/bin/python"

# Read DSN from local .env
DSN="$(awk -F= '/^SSL_SERVICE_PG_DSN=/{print substr($0, index($0, "=") + 1); exit}' .env)"

# Resolve us01 SSH credentials (via linked ssh_keys table) and write
# the private key to a temp file with mode 600.
KEY_FILE="$(mktemp /tmp/us01-deploy-key.XXXXXX)"
trap 'rm -f "${KEY_FILE}"' EXIT
DSN="${DSN}" KEY_FILE="${KEY_FILE}" "${PY}" - <<'PY'
import os, psycopg
dsn = os.environ["DSN"]
out = os.environ["KEY_FILE"]
with psycopg.connect(dsn, connect_timeout=15) as conn:
  with conn.cursor() as cur:
    cur.execute(
      "SELECT k.private_key FROM ssh_keys k "
      "  JOIN node_ssh_keys l ON l.ssh_key_id = k.id "
      " WHERE l.node_name = 'us01' "
      " ORDER BY l.priority DESC NULLS LAST, l.added_at LIMIT 1",
    )
    row = cur.fetchone()
    if row is None:
      raise SystemExit("no SSH key linked to us01")
    open(out, "w").write(row[0] if isinstance(row[0], str) else row[0].decode())
os.chmod(out, 0o600)
print(f"wrote private key to {out}")
PY

SSH="ssh -i ${KEY_FILE} -p 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@64.186.227.16"

echo
echo "==> us01 / user-service: pull latest + recreate"
${SSH} 'set -e; cd /opt/user && \
  git fetch --all --tags --prune && \
  git checkout --detach origin/main && \
  echo "deployed_sha=$(git rev-parse HEAD)" && \
  docker compose up -d --build 2>&1 | tail -20'

echo
echo "==> us01 / user-service: health probe"
sleep 5
${SSH} 'curl -sS --max-time 8 -i http://127.0.0.1:8200/health'

echo
echo "==> verify SPA includes the new admin section"
${SSH} 'curl -sS --max-time 8 http://127.0.0.1:8200/ | grep -cE "admin-card|admin-pane-users|管理后台" || true'

echo
echo "Done. Press any key to close..."
read -n 1 -s
