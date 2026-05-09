#!/bin/bash
# Reset all stale agent / topic / message records in the chat DB
# to gpt-5.4 / openai. They were created during the brief window
# when DEFAULT_AGENT_CONFIG was still upstream lobehub default
# (claude-sonnet-4-5-20250929 / anthropic). Anthropic provider is
# now disabled, so calls silently 5xx and the chat bubble stays
# empty.
#
# Routes through ssl-service admin's /api/nodes/xcenter/run so we
# don't need direct SSH from the Mac. Output goes to stdout — no
# secret/cookie content is printed.
set -e

ADMIN="http://127.0.0.1:8088"
TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

read -r -d '' SQL <<'SQL_EOF' || true
UPDATE agents
   SET model = 'gpt-5.4', provider = 'openai'
 WHERE provider = 'anthropic'
    OR provider IS NULL
    OR model LIKE 'claude%'
    OR model LIKE 'gemini%';

UPDATE topics
   SET model = 'gpt-5.4', provider = 'openai'
 WHERE provider = 'anthropic'
    OR model LIKE 'claude%'
    OR model LIKE 'gemini%';

UPDATE messages
   SET model = 'gpt-5.4', provider = 'openai'
 WHERE provider = 'anthropic'
    OR model LIKE 'claude%'
    OR model LIKE 'gemini%';

SELECT 'stale_agents_remaining' AS k, count(*) AS v FROM agents WHERE provider = 'anthropic';
SELECT 'stale_topics_remaining' AS k, count(*) AS v FROM topics WHERE provider = 'anthropic';
SELECT 'stale_messages_remaining' AS k, count(*) AS v FROM messages WHERE provider = 'anthropic';
SQL_EOF

# Use a heredoc *outside* the JSON so we can pass it through to the
# remote bash. The remote command sources the chat container's .env,
# rewrites sslmode for psql, then pipes the SQL via stdin.
REMOTE_CMD=$(cat <<'OUTER'
bash -c '
set -a; source /opt/chat/.env; set +a
URL=$(echo "$DATABASE_URL" | sed "s/sslmode=no-verify/sslmode=require/")
psql "$URL" -q -At
'
OUTER
)

PAYLOAD=$(python3 - "$REMOTE_CMD" "$SQL" <<'PY'
import json, sys
remote_cmd, sql_body = sys.argv[1], sys.argv[2]
# We pipe SQL into the remote bash via stdin — admin /api/nodes/{name}/run
# doesn't support stdin, so fold SQL into a heredoc passed to bash.
combined = remote_cmd.rstrip() + " <<'__PSQL_INPUT__'\n" + sql_body + "\n__PSQL_INPUT__\n"
print(json.dumps({"command": combined, "timeout": 30}))
PY
)

echo "==> POST /api/nodes/xcenter/run with embedded SQL"
echo "$PAYLOAD" | curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  "$ADMIN/api/nodes/xcenter/run" \
  | python3 -c '
import sys, json
j = json.load(sys.stdin)
print("exit:", j.get("exit_code"))
print("stdout:", j.get("stdout",""))
if j.get("stderr"):
  print("stderr (first 200 chars):", j["stderr"][:200])
'

echo
echo "Done. Press any key to close."
read -n 1 -s
