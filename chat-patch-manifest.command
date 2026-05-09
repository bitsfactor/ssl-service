#!/bin/bash
# PATCH the chat service's stored deploy_yaml directly from the
# local file. ssl-service can't fetch raw.githubusercontent.com
# because the chat repo's clone URL is SSH-form (and rightly so —
# the deploy node uses SSH to clone). The HTTP manifest fetcher
# only knows how to parse https:// URLs, so we side-step it.
set -e
cd "$(dirname "$0")"

ADMIN_URL="http://127.0.0.1:8088"
TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

YAML_CONTENT="$(cat service-source/chat/.deploy.yaml)"

# Build the PATCH payload via Python so the YAML body gets correctly
# JSON-escaped (newlines, quotes, etc).
BODY="$(mktemp)"
python3 - "$YAML_CONTENT" >"$BODY" <<'PY'
import json, sys
print(json.dumps({"deploy_yaml": sys.argv[1]}))
PY

echo "==> PATCHing /api/services/chat with deploy_yaml ($(wc -l < service-source/chat/.deploy.yaml | tr -d ' ') lines)"
curl -fsS -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "@$BODY" \
  "$ADMIN_URL/api/services/chat" \
  | python3 -c 'import sys,json; j=json.load(sys.stdin); print("    ok, deploy_yaml fetched_at=" + str(j.get("deploy_yaml_fetched_at","-")))'

rm -f "$BODY"

echo
echo "Done. Press any key to close."
read -n 1 -s
