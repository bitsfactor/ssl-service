#!/usr/bin/env bash
# Force-restart the local ssl-service admin (port 8088). Used when the
# in-process /api/admin/restart os.execv path crashes because of a
# Python import error and never recovers.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

echo "==> existing listeners on 8088"
lsof -nP -iTCP:8088 -sTCP:LISTEN 2>/dev/null || echo "  (none)"

echo "==> killing any python admin matching ssl_proxy_controller"
pkill -f "ssl_proxy_controller --admin-only" 2>/dev/null || true
sleep 1

echo "==> launching start.command in background"
nohup ./start.command > /tmp/ssl-service-admin.log 2>&1 &
ADMIN_PID=$!
echo "  spawned pid=$ADMIN_PID, log=/tmp/ssl-service-admin.log"

echo "==> waiting for /api/admin/version to return ..."
for i in $(seq 1 30); do
  sleep 1
  if curl -sf -m 1 http://127.0.0.1:8088/api/admin/version >/dev/null 2>&1; then
    echo "  admin up after ${i}s"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "  TIMEOUT — last 40 log lines:"
    tail -40 /tmp/ssl-service-admin.log
    exit 2
  fi
done

echo "==> success"
sleep 2
rm -f -- "$0"
