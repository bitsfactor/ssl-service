#!/bin/bash
# Re-PATCH the chat-db registry entry: switch dbname=postgres to
# dbname=chat. The shared "postgres" db's public schema is already
# taken by another app (28 tables incl. a no-PK `users` collision),
# so lobehub's drizzle migrations need a clean db. We pre-create
# the `chat` database in Supabase via psql; this script only fixes
# the registry entry to point at it.
#
# sslmode stays no-verify (node-pg-friendly).
set -euo pipefail
cd "$(dirname "$0")"

ADMIN_URL="http://127.0.0.1:8088"
TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"
CHAT_DB_ID="$(cat .chat-db-id)"

ONE_DSN="$(awk -F= '/^SSL_SERVICE_PG_DSN=/{print substr($0, index($0,"=")+1)}' .env)"
# Strip search_path option, swap sslmode, and re-target dbname.
CHAT_DSN="$(printf '%s\n' "$ONE_DSN" \
  | sed -E 's/[?&]options=[^&]*//' \
  | sed -E 's/sslmode=require/sslmode=no-verify/' \
  | sed -E 's|/postgres([?])|/chat\1|' \
  | sed -E 's/[?&]$//')"

if [[ "$CHAT_DSN" != *"/chat?"* || "$CHAT_DSN" != *"no-verify"* || "$CHAT_DSN" == *"options="* ]]; then
  echo "ERROR: failed to rewrite DSN — got [$(printf '%s' "$CHAT_DSN" | sed -E 's/:[^:@]+@/:***@/')]"
  exit 1
fi

BODY="$(mktemp)"
python3 - "$CHAT_DSN" >"$BODY" <<'PY'
import json, sys
print(json.dumps({"dsn": sys.argv[1]}))
PY

echo "==> PATCH /api/databases/$CHAT_DB_ID -> dbname=chat, sslmode=no-verify"
curl -fsS -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "@$BODY" \
  "$ADMIN_URL/api/databases/$CHAT_DB_ID" \
  | python3 -c 'import sys,json; j=json.load(sys.stdin); print("    label=" + j.get("label","-") + " mask=" + j.get("dsn_masked","-"))'

rm -f "$BODY"

echo "==> Test connection"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  "$ADMIN_URL/api/databases/$CHAT_DB_ID/test" \
  | python3 -c 'import sys,json; j=json.load(sys.stdin); print("    test " + ("ok" if j.get("ok") else "FAILED: " + json.dumps(j)))'

echo
echo "Done. Press any key to close."
read -n 1 -s
