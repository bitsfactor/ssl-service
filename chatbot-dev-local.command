#!/bin/bash
# Install deps + start the chatbot Next.js dev server on http://localhost:3000.
# Reads service-source/chatbot/.env.local (gitignored) for secrets.
#
# Hot reload covers src/, components/, lib/, etc. Schema changes need a
# manual `pnpm db:migrate` (or just re-run this script — it doesn't migrate
# but db:migrate is a no-op when nothing's changed).

set -e
cd "$(dirname "$0")/service-source/chatbot"

if [[ ! -f .env.local ]]; then
  echo "ERROR: .env.local missing. Re-run chatbot-bootstrap.command first."
  exit 1
fi

# Make sure pnpm is available (corepack is built in to recent Node).
if ! command -v pnpm >/dev/null 2>&1; then
  if command -v corepack >/dev/null 2>&1; then
    corepack enable
    corepack prepare pnpm@10.32.1 --activate
  else
    echo "ERROR: pnpm not installed and corepack unavailable."
    echo "       Install pnpm first: npm i -g pnpm@10.32.1"
    exit 1
  fi
fi

echo "==> pnpm install"
pnpm install

echo
echo "==> Starting dev server on http://localhost:3000"
echo "    Press Ctrl+C to stop. The terminal stays open afterwards."
echo
exec pnpm dev
