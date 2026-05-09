#!/bin/bash
# Kill any existing chatbot dev server (port 3001 or 3002), then start a
# fresh one. Useful when the dev server is wedged or has loaded stale
# code from before a major refactor.
set -e
cd "$(dirname "$0")/service-source/chatbot"

for PORT in 3001 3002; do
  PID=$(lsof -ti tcp:$PORT 2>/dev/null || true)
  if [[ -n "$PID" ]]; then
    echo "==> killing existing dev server on :$PORT (pid $PID)"
    kill -9 $PID 2>/dev/null || true
    sleep 0.3
  fi
done

if [[ ! -f .env.local ]]; then
  echo "ERROR: .env.local missing."
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  if command -v corepack >/dev/null 2>&1; then
    corepack enable
    corepack prepare pnpm@10.32.1 --activate
  fi
fi

echo
echo "==> Starting fresh dev server on http://localhost:3001"
echo "    Hot-reload + new routes pick up immediately."
echo
exec pnpm dev --port 3001
