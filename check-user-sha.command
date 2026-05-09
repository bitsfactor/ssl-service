#!/usr/bin/env bash
# Verify the user-service container is actually running the latest sha
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PY="${PWD}/.venv/bin/python"
DSN="$(awk -F= '/^SSL_SERVICE_PG_DSN=/{print substr($0, index($0, "=") + 1); exit}' .env)"
KEY_FILE="$(mktemp /tmp/us01-deploy-key.XXXXXX)"
trap 'rm -f "${KEY_FILE}"' EXIT
DSN="${DSN}" KEY_FILE="${KEY_FILE}" "${PY}" - <<'PY'
import os, psycopg
dsn = os.environ["DSN"]; out = os.environ["KEY_FILE"]
with psycopg.connect(dsn, connect_timeout=15) as conn:
  with conn.cursor() as cur:
    cur.execute(
      "SELECT k.private_key FROM ssh_keys k JOIN node_ssh_keys l ON l.ssh_key_id = k.id "
      " WHERE l.node_name = 'us01' ORDER BY l.priority DESC NULLS LAST, l.added_at LIMIT 1")
    open(out, "w").write(cur.fetchone()[0])
os.chmod(out, 0o600)
PY
SSH="ssh -i ${KEY_FILE} -p 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@64.186.227.16"
echo "git head:"
${SSH} 'cd /opt/user && git log -1 --oneline'
echo
echo "container status + image hash:"
${SSH} 'docker inspect user --format "{{.State.Status}} {{.Image}}"'
echo
echo "psycopg.errors.UniqueViolation grep:"
${SSH} "docker exec user grep -c 'UniqueViolation' /app/app/main.py 2>/dev/null || echo n/a"
echo
echo "force rebuild + restart"
${SSH} 'cd /opt/user && git pull --ff-only origin main && docker compose up -d --build --force-recreate 2>&1 | tail -10'
echo
echo "sleep 8s, retry duplicate grant"
${SSH} 'sleep 8 && curl -sS --max-time 6 http://127.0.0.1:8200/health'
echo
echo "Done. Press any key to close..."
read -n 1 -s
