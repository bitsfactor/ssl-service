#!/bin/bash
# Bootstrap the `chat` service in ssl-service.
#
# Idempotent. Safe to re-run.
#
# Steps:
#   1. Add a database registry entry for chat (same DSN as primary
#      "one" entry but search_path=chat). Sidecar id to .chat-db-id.
#   2. Test the chat DSN.
#   3. PUT /api/system-config/chat.openai with {api_key, proxy_url}.
#   4. PUT /api/system-config/chat.encryption with auth_secret +
#      key_vaults_secret (generate fresh ones only if absent).
#
# Reads the primary DSN from ./.env so the password never round-
# trips through the agent. OpenAI key comes from .chat-openai-key.secret
# in this directory.

set -euo pipefail
cd "$(dirname "$0")"

ADMIN_URL="http://127.0.0.1:8088"
TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

ONE_DSN="$(awk -F= '/^SSL_SERVICE_PG_DSN=/{print substr($0, index($0,"=")+1)}' .env)"
[[ -n "$ONE_DSN" ]] || { echo "ERROR: SSL_SERVICE_PG_DSN missing from .env"; exit 1; }
CHAT_DSN="$(printf '%s\n' "$ONE_DSN" | sed -E 's/search_path%3D[^&]+/search_path%3Dchat/')"
[[ "$CHAT_DSN" != "$ONE_DSN" ]] || { echo "ERROR: failed to swap search_path"; exit 1; }

echo "==> [1/5] checking admin is up"
curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/status" >/dev/null

echo "==> [2/5] creating database registry entry 'chat' (idempotent)"
EXISTING_ID="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN_URL/api/databases" \
  | python3 -c 'import sys,json; j=json.load(sys.stdin); print(next((e["id"] for e in j.get("entries",[]) if e.get("label")=="chat"), ""))')"

if [[ -n "$EXISTING_ID" ]]; then
  echo "    already present: id=$EXISTING_ID"
  CHAT_DB_ID="$EXISTING_ID"
else
  RESP="$(curl -fsS -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "$ADMIN_URL/api/databases" <<EOF
{"label":"chat","dsn":"$CHAT_DSN"}
EOF
  )"
  CHAT_DB_ID="$(printf '%s' "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"
  echo "    created: id=$CHAT_DB_ID"
fi
echo "$CHAT_DB_ID" > .chat-db-id

echo "==> [3/5] testing chat DB connection"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$ADMIN_URL/api/databases/$CHAT_DB_ID/test" \
  | python3 -c 'import sys,json; j=json.load(sys.stdin); print("    ok" if j.get("ok") else "    test FAILED: " + json.dumps(j)); sys.exit(0 if j.get("ok") else 1)'

# --- system_config writes -------------------------------------------------

if [[ ! -f ".chat-openai-key.secret" ]]; then
  echo "ERROR: .chat-openai-key.secret missing. Drop the OpenAI key there:"
  echo "  echo -n 'sk-...' > $(pwd)/.chat-openai-key.secret"
  exit 1
fi
OPENAI_KEY="$(tr -d '\r\n' < .chat-openai-key.secret)"

put_cfg () {
  local key="$1"
  local body_file="$2"
  curl -fsS -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary "@$body_file" \
    "$ADMIN_URL/api/system-config/$key" >/dev/null
}

# Build chat.openai body via Python (proper JSON escaping of the
# secret), then PUT.
CHAT_OPENAI_BODY="$(mktemp)"
python3 - "$OPENAI_KEY" >"$CHAT_OPENAI_BODY" <<'PY'
import json, sys
print(json.dumps({"api_key": sys.argv[1], "proxy_url": "https://api.develop.cc/v1"}))
PY

echo "==> [4/5] writing system_config: chat.openai (api_key + proxy_url)"
put_cfg "chat.openai" "$CHAT_OPENAI_BODY"
rm -f "$CHAT_OPENAI_BODY"

# chat.encryption: only generate if not already set (rotation hurts).
EXISTING_ENC="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$ADMIN_URL/api/system-config/chat.encryption" 2>/dev/null || echo '{}')"
HAS_AUTH="$(printf '%s' "$EXISTING_ENC" | python3 -c 'import sys,json
try:
  j=json.load(sys.stdin); v=j.get("auth_secret","")
  print("yes" if v else "no")
except Exception:
  print("no")
')"
HAS_KV="$(printf '%s' "$EXISTING_ENC" | python3 -c 'import sys,json
try:
  j=json.load(sys.stdin); v=j.get("key_vaults_secret","")
  print("yes" if v else "no")
except Exception:
  print("no")
')"

if [[ "$HAS_AUTH" = "yes" && "$HAS_KV" = "yes" ]]; then
  echo "==> [5/5] chat.encryption already set, skipping"
else
  AUTH_SECRET="$(openssl rand -base64 32)"
  KV_SECRET="$(openssl rand -base64 32)"
  CHAT_ENC_BODY="$(mktemp)"
  python3 - "$AUTH_SECRET" "$KV_SECRET" >"$CHAT_ENC_BODY" <<'PY'
import json, sys
print(json.dumps({"auth_secret": sys.argv[1], "key_vaults_secret": sys.argv[2]}))
PY
  put_cfg "chat.encryption" "$CHAT_ENC_BODY"
  rm -f "$CHAT_ENC_BODY"
  echo "==> [5/5] generated chat.encryption.{auth_secret,key_vaults_secret}"
fi

echo
echo "==> Result"
echo "    chat database id : $CHAT_DB_ID"
echo "    system_config    : chat.openai (api_key, proxy_url)"
echo "                       chat.encryption (auth_secret, key_vaults_secret)"
echo
echo "Done. Press any key to close."
read -n 1 -s
