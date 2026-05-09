#!/usr/bin/env bash
# Run via the local ssl-service admin (already has SSH creds wired up).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ADMIN_URL="${SSL_SERVICE_ADMIN_URL:-http://127.0.0.1:8088}"
ADMIN_TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

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
    print(f"exit_code={j.get('exit_code')}")
    print("stdout:")
    print(j.get("stdout") or "")
    if j.get("stderr"):
        print("stderr:")
        print(j["stderr"][:600])
except Exception:
    print(r.stdout[:600])
PY
}

export ADMIN_URL ADMIN_TOKEN

echo "================ user@us01: docker ps ================"
run us01 'docker ps --filter name=user --format "{{.Names}} | {{.Status}} | {{.Ports}}"'

echo
echo "================ user@us01: last 80 log lines ================"
run us01 'docker logs --tail 80 user 2>&1'

echo
echo "================ user@us01: localhost:8200 ================"
run us01 'curl -sS --max-time 5 -i http://127.0.0.1:8200/health'

echo
echo "================ xout@us01: docker ps + git head ================"
run us01 'docker ps --filter name=xout --format "{{.Names}} | {{.Status}}"; echo "---"; cd /opt/xout && git log -1 --oneline; git rev-parse HEAD'

echo
echo "================ xout@us-he: git head + last logs ================"
run us-he 'cd /opt/xout && git log -1 --oneline; git rev-parse HEAD; echo "---"; docker logs --tail 20 xout 2>&1'

echo
echo "================ xout@ca2: git head + container status ================"
run ca2 'cd /opt/xout && git log -1 --oneline; git rev-parse HEAD; echo "---"; docker ps --filter name=xout --format "{{.Names}} | {{.Status}}"'

echo
echo "Done. Press any key to close..."
read -n 1 -s
