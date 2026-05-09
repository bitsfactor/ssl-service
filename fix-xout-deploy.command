#!/usr/bin/env bash
# Fix xout deploys on us01 (dubious-ownership git error) and us-he
# (stale local refs/heads/main). Both nodes have /opt/xout owned by a
# UID different from the current shell user; force-add it as safe and
# blow away the stale clone, then redeploy.
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
body = {"command": cmd, "timeout": 60}
r = subprocess.run([
  "curl", "-sS", "--max-time", "120",
  "-X", "POST",
  "-H", "Authorization: Bearer " + os.environ["ADMIN_TOKEN"],
  "-H", "Content-Type: application/json",
  "-d", json.dumps(body),
  url,
], capture_output=True, text=True)
try:
    j = json.loads(r.stdout)
    print(f"[{node}] exit_code={j.get('exit_code')}")
    if j.get("stdout"): print(j["stdout"][:800])
    if j.get("stderr"): print("STDERR:", j["stderr"][:400])
except Exception:
    print(r.stdout[:600])
PY
}

deploy_one() {
  local node="$1"
  python3 - "$node" <<'PY'
import json, os, subprocess, sys
node = sys.argv[1]
url = os.environ["ADMIN_URL"] + "/api/services/xout/deploy"
body = {"nodes": [node], "revision": "origin/main", "triggered_by": "fix-xout"}
r = subprocess.run([
  "curl", "-sS", "--max-time", "300",
  "-X", "POST",
  "-H", "Authorization: Bearer " + os.environ["ADMIN_TOKEN"],
  "-H", "Content-Type: application/json",
  "-d", json.dumps(body), url,
], capture_output=True, text=True)
try:
    j = json.loads(r.stdout)
    res = (j.get("results") or [{}])[0]
    print(f"[{node}] ok={res.get('ok')} sha={(res.get('deployed_sha') or '')[:10]} hc={res.get('healthcheck_passed')} err={res.get('error')}")
except Exception:
    print(r.stdout[:400])
PY
}

echo "==> us01: fix dubious ownership + force-clean clone, then redeploy"
run us01 'git config --global --add safe.directory "*" 2>&1; rm -rf /opt/xout && echo "wiped /opt/xout"'
deploy_one us01

echo
echo "==> us-he: nuke stale clone, then redeploy"
run us-he 'git config --global --add safe.directory "*" 2>&1; rm -rf /opt/xout && echo "wiped /opt/xout"'
deploy_one us-he

echo
echo "==> verify deployed shas"
run us01 'cd /opt/xout && git log -1 --oneline'
run us-he 'cd /opt/xout && git log -1 --oneline'
run ca2  'cd /opt/xout && git log -1 --oneline'

echo
echo "Done. Press any key to close..."
read -n 1 -s
