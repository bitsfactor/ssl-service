#!/usr/bin/env bash
# One-shot redeploy of the chatbot (DevChat) service to xcenter via the
# local ssl-service admin API. Used after pushing source changes to
# git@github.com:bitsfactor/chatbot.git so xcenter's deploy worker pulls
# origin/main and rebuilds the container.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ADMIN_URL="${SSL_SERVICE_ADMIN_URL:-http://127.0.0.1:8088}"
ADMIN_TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

python3 - <<PY
import json, subprocess
body = {
  "nodes": ["xcenter"],
  "revision": "origin/main",
  "triggered_by": "chatbot-redeploy.command",
  "env": {},
}
url = "${ADMIN_URL}/api/services/chatbot/deploy"
print("==> deploy chatbot -> [xcenter]")
r = subprocess.run([
  "curl", "-sS", "--max-time", "300",
  "-X", "POST",
  "-H", "Authorization: Bearer ${ADMIN_TOKEN}",
  "-H", "Content-Type: application/json",
  "-d", json.dumps(body),
  url,
])
print()
PY

echo
echo "Done. Press any key to close..."
read -n 1 -s
