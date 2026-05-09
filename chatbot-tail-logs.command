#!/usr/bin/env bash
# Tail chatbot container logs from xcenter.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PY="${PWD}/.venv/bin/python"

DSN="$(awk -F= '/^SSL_SERVICE_PG_DSN=/{print substr($0, index($0, "=") + 1); exit}' .env)"

KEY_FILE="$(mktemp /tmp/xcenter-key.XXXXXX)"
TARGET_FILE="$(mktemp /tmp/xcenter-target.XXXXXX)"
trap 'rm -f "${KEY_FILE}" "${TARGET_FILE}"' EXIT
DSN="${DSN}" KEY_FILE="${KEY_FILE}" TARGET_FILE="${TARGET_FILE}" "${PY}" - <<'PY'
import os, psycopg
dsn = os.environ["DSN"]
key_out = os.environ["KEY_FILE"]
tgt_out = os.environ["TARGET_FILE"]
with psycopg.connect(dsn, connect_timeout=15) as conn:
  with conn.cursor() as cur:
    # SSH private key for xcenter is stored inline on the nodes row
    # (no entry in node_ssh_keys for this node).
    cur.execute(
      'SELECT host, COALESCE(ssh_user, %s), ssh_port, ssh_private_key '
      'FROM "one-base".nodes WHERE name = %s',
      ("root", "xcenter"),
    )
    row = cur.fetchone()
    if row is None:
      raise SystemExit("xcenter node row missing")
    host, user, port, pk = row
    if not pk:
      raise SystemExit("xcenter has no inline ssh_private_key")
    open(key_out, "w").write(pk if isinstance(pk, str) else pk.decode())
    open(tgt_out, "w").write(f"{user} {host} {port}")
os.chmod(key_out, 0o600)
PY

read -r SSH_USER SSH_HOST SSH_PORT < "${TARGET_FILE}"
echo "==> tail chatbot logs on ${SSH_USER}@${SSH_HOST}:${SSH_PORT}"
ssh -i "${KEY_FILE}" -p "${SSH_PORT}" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  "${SSH_USER}@${SSH_HOST}" \
  'cd /opt/chatbot && docker compose logs --tail=200 chatbot 2>&1 | tail -200'

echo
echo "Done. Press any key to close..."
read -n 1 -s
