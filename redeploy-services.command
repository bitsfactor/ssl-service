#!/usr/bin/env bash
# One-shot redeploy of user-service + xout to us01 + us-he via the
# local ssl-service admin API. Used during the user-system unification
# rollout (2026-05-06) to avoid hand-driving the Deploy modal.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ADMIN_URL="${SSL_SERVICE_ADMIN_URL:-http://127.0.0.1:8088}"
ADMIN_TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

deploy() {
  # Build the JSON body via python so quoting is bulletproof regardless of
  # what the env values look like.
  python3 - "$@" <<'PY'
import json, os, subprocess, sys
svc, nodes_json, env_json = sys.argv[1], sys.argv[2], sys.argv[3]
body = {
  "nodes": json.loads(nodes_json),
  # origin/main forces the deploy script to take the remote tracking
  # branch, sidestepping a stale local refs/heads/main on the node.
  "revision": "origin/main",
  "triggered_by": "e2e-rollout",
  "env": json.loads(env_json),
}
url = os.environ["ADMIN_URL"] + f"/api/services/{svc}/deploy"
print(f"==> deploy {svc} -> {nodes_json}")
r = subprocess.run([
  "curl", "-sS", "--max-time", "300",
  "-X", "POST",
  "-H", "Authorization: Bearer " + os.environ["ADMIN_TOKEN"],
  "-H", "Content-Type: application/json",
  "-d", json.dumps(body),
  url,
])
print()
PY
}

export ADMIN_URL ADMIN_TOKEN

# user-service needs USER_SERVICE_PG_DSN explicitly: the .deploy.yaml's
# secret entry uses an [id=...] selector that the inline resolver
# doesn't grok. Pass the database registry token; the inline resolver
# expands it to the full DSN at deploy time.
deploy user '["us01"]' '{"USER_SERVICE_PG_DSN":"database:f499f7431634"}'
# xout: default_env already carries XOUT_DATABASE_URL=database:f499f7431634.
deploy xout '["us01","us-he","ca2"]' '{}'

echo
echo "Done. Press any key to close..."
read -n 1 -s
