#!/usr/bin/env bash
# Hotfix: restore /sub/{token}, /sub-qr/*, /product/info routing through
# user-center to user-service. These were 404'ing after Caddy upstream
# swap because Next.js rewrites only caught /api/*.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [ -f .git/index.lock ]; then
  rm -f .git/index.lock
fi

echo "==> staging"
git add service-source/user-center/next.config.ts
git add scripts/dev

git diff --cached --stat | tail -5

echo "==> commit"
git commit -m "fix(user-center): proxy /sub /sub-qr /product/info to user-service

After the Caddy upstream swap (user.develop.cc -> user-center), the
Next.js rewrites in next.config.ts only caught /api/*. This silently
broke the public-facing endpoints that VPN clients (Clash, V2RayN,
etc.) rely on — they hit /sub/<token> directly without an /api/ prefix.

Add explicit rewrites for:
  - /sub/:token       — VPN subscription URL (Clash config)
  - /sub-qr/:path*    — QR-code rendering of the subscription
  - /product/info     — public product manifest

Verified post-deploy: GET /sub/dummy returns FastAPI's
{\"detail\":\"not found\"} (proving the rewrite reached user-service)
instead of Next.js's HTML 404 page."

echo "==> push"
git push origin main

echo "==> success"
sleep 2
rm -f -- "$0"
