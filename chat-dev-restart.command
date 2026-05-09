#!/bin/bash
# Clean + restart local dev. Use after big source edits when
# Turbopack's i18n cache hangs onto stale strings, or when the
# dev server was killed and we want it back fast.
set -e
cd "$(dirname "$0")/service-source/chat"

echo "==> Removing .bak files left by sed"
find . -name '*.bak' -not -path './node_modules/*' -delete 2>/dev/null || true

echo "==> Killing any lingering pnpm/next dev"
pkill -f "next dev" 2>/dev/null || true
pkill -f "pnpm dev:next" 2>/dev/null || true
sleep 1

echo "==> Clearing Turbopack/Next.js cache (.next + .turbo)"
rm -rf .next .turbo node_modules/.cache 2>/dev/null || true

echo "==> Starting full dev stack (Next.js :3010 + Vite SPA :9876)"
echo "    (Source patches applied, full restart so i18n bundle refreshes)"
echo
# pnpm dev runs scripts/devStartupSequence.mts which boots both. The
# previous version of this script ran only `pnpm dev:next`, which left
# the Vite SPA origin down — every / request crashed in getTemplate
# with ECONNREFUSED on VITE_DEV_ORIGIN. Don't go back to dev:next-only.
exec pnpm dev
