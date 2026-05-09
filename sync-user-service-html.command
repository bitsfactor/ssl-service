#!/usr/bin/env bash
# One-shot: sync our local examples/user-service/static/index.html to the
# standalone leoleoaabbcc/user-service repo, then redeploy.
#
# The standalone repo lives at https://github.com/leoleoaabbcc/user-service
# and is what /opt/user clones from on us01. The copy under
# examples/user-service/ in this ssl-service repo is the *authoring*
# source — once it's good, we push it to leoleoaabbcc/user-service and
# bump the running container.
#
# Pulls the existing PAT-tagged remote URL from us01 (already configured
# there) so we don't have to re-enter creds.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PY="${PWD}/.venv/bin/python"

DSN="$(awk -F= '/^SSL_SERVICE_PG_DSN=/{print substr($0, index($0, "=") + 1); exit}' .env)"

KEY_FILE="$(mktemp /tmp/us01-deploy-key.XXXXXX)"
trap 'rm -f "${KEY_FILE}" "${TMP_HTML:-/dev/null}"' EXIT
DSN="${DSN}" KEY_FILE="${KEY_FILE}" "${PY}" - <<'PY'
import os, psycopg
dsn = os.environ["DSN"]; out = os.environ["KEY_FILE"]
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
PY

SSH="ssh -i ${KEY_FILE} -p 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@64.186.227.16"
SCP="scp -i ${KEY_FILE} -P 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

LOCAL_HTML="${PWD}/examples/user-service/static/index.html"
if [[ ! -f "${LOCAL_HTML}" ]]; then
  echo "ERROR: ${LOCAL_HTML} missing"
  exit 2
fi

echo "==> uploading static/index.html to us01:/opt/user/static/index.html"
${SCP} "${LOCAL_HTML}" root@64.186.227.16:/opt/user/static/index.html

# Brand assets (Develop logo + favicons). Same files we ship with chatbot.
LOCAL_STATIC_DIR="${PWD}/examples/user-service/static"
for f in favicon.ico favicon-16.png favicon-32.png icon-192.png icon-512.png apple-touch-icon.png logo.png; do
  if [[ -f "${LOCAL_STATIC_DIR}/${f}" ]]; then
    echo "==> uploading static/${f}"
    ${SCP} "${LOCAL_STATIC_DIR}/${f}" "root@64.186.227.16:/opt/user/static/${f}"
  fi
done

echo
echo "==> commit + push to leoleoaabbcc/user-service main"
${SSH} 'set -e; cd /opt/user && \
  git config user.email "devchat@bitsfactor.com" && \
  git config user.name "DevChat" && \
  git checkout main 2>/dev/null || git checkout -B main && \
  git add static/ && \
  if git diff --cached --quiet; then \
    echo "(no changes to commit)"; \
  else \
    git commit -m "Develop branding: logo + favicons + brand strings" --quiet && \
    git push origin main; \
  fi'

echo
echo "==> rebuild + restart user-service container"
${SSH} 'set -e; cd /opt/user && docker compose up -d --build 2>&1 | tail -10'

echo
echo "==> verify"
sleep 3
${SSH} 'curl -sS --max-time 6 http://127.0.0.1:8200/ | grep -c "view === \"signup\"" || echo "(not in served HTML)"'

echo
echo "Done. Press any key to close..."
read -n 1 -s
