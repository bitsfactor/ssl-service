#!/usr/bin/env bash
# Verify xout containers picked up the new user list from auth_users.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ADMIN_URL="${SSL_SERVICE_ADMIN_URL:-http://127.0.0.1:8088}"
ADMIN_TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"
export ADMIN_URL ADMIN_TOKEN

run() {
  local node="$1" cmd="$2"
  python3 - "$node" "$cmd" <<'PY'
import json, os, subprocess, sys
node, cmd = sys.argv[1], sys.argv[2]
url = os.environ["ADMIN_URL"] + f"/api/nodes/{node}/run"
body = {"command": cmd, "timeout": 30}
r = subprocess.run([
  "curl", "-sS", "--max-time", "60",
  "-X", "POST",
  "-H", "Authorization: Bearer " + os.environ["ADMIN_TOKEN"],
  "-H", "Content-Type: application/json",
  "-d", json.dumps(body),
  url,
], capture_output=True, text=True)
try:
    j = json.loads(r.stdout)
    print(f"[{node}] exit={j.get('exit_code')}")
    out = (j.get("stdout") or "").strip()
    if out: print(out[:1500])
    err = (j.get("stderr") or "").strip()
    if err: print("STDERR:", err[:300])
except Exception:
    print(r.stdout[:600])
PY
}

echo "============= xout@us01: tail logs ============="
run us01 'docker logs --tail 60 xout 2>&1 | tail -40'

echo
echo "============= xout@us01: xray accepted users ============="
run us01 "docker exec xout sh -c 'xray api inboundinfo --server 127.0.0.1:10085 2>&1 | head -120 || true'"

echo
echo "============= last_synced_at heartbeats ============="
run us01 "docker logs --tail 30 xout 2>&1 | grep -E 'last_synced_at|heartbeat|tick|sync' | tail -10"

echo
echo "Done. Press any key to close..."
read -n 1 -s
