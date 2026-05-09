#!/usr/bin/env bash
# Focused commit for user-center scaffolding + the create_service relaxation.
# Skips submodule paths (chatbot / web-shell) — those need their own commits.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [ -f .git/index.lock ]; then
  rm -f .git/index.lock
fi

# Drop the empty tmp file the subagent left behind.
rm -f service-source/user-center/_tmp_17_2d24dfa2a3a11f04df8665326e0b7084 \
      service-source/user-center/_tmp_*

echo "==> staging changes (skipping submodules)"
git add src/ssl_proxy_controller/admin.py
git add service-source/user-center
git add scripts/dev

echo "==> committed files preview"
git diff --cached --stat | tail -10

echo "==> commit"
git commit -m "feat(user-center): full Next.js account center at user.develop.cc

- service-source/user-center: new Next.js 16 + React 19 + Tailwind v4 app
  with 5 protected pages (Dashboard, Profile, Security, Billing, Preferences)
  + Register / Login / Verify-email, 5-language i18n (zh/en/ja/ko/de),
  next-themes light/dark, SiteHeader from vendored web-shell
- Server-side auth via cookie passthrough to user-service /api/me
- /api/* proxied via Next.js rewrites to USER_SERVICE_URL on the docker
  host (host.docker.internal:8200), so cookies stay same-origin
- Wires real user-service endpoints: /api/auth/signup + login + logout,
  /api/me (PATCH for profile edit), /api/me/sessions GET/DELETE,
  /api/auth/forgot-password for password change flow
- Defensive shape unwrappers for /api/me ({user,subscriptions}),
  /api/me/usage ({quotas,billing}), /api/products ({products}),
  /api/pricing ({models,discount_factor}); render also tolerates legacy
  field aliases on pricing rows
- Dockerfile: Node 22-alpine, multi-stage standalone, non-root nextjs
  user, exposes 3211; docker-compose with mem_limit 512m, cpus 1.0,
  no-new-privileges, log size cap, host.docker.internal extra_host
- ssl-service admin: create_service relaxation — accepts services with
  local_repo_dir + empty github_repo_url (deploy then ships the local
  tree over SSH); also passes default_node_name through on insert
- All pages force-dynamic (useSearchParams + cookie auth — no static
  prerender benefit anyway)
- Caddy route user.develop.cc -> xcenter:3211 (user-center serves UI,
  proxies /api/* to user-service:8200 internally)"

echo "==> push"
git push origin main

echo "==> success"
sleep 2
rm -f -- "$0"
