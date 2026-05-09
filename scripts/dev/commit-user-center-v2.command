#!/usr/bin/env bash
# v2 push: bootstrap consolidation, /account merge of profile+preferences,
# My Subscriptions card, products.ts mapping, chat header unified to use
# the regular ServicesMenu (no static "AI Hub" override).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [ -f .git/index.lock ]; then
  rm -f .git/index.lock
fi

# Drop the empty tmp file the subagent left behind.
rm -f service-source/user-center/_tmp_*

echo "==> staging changes (skipping submodules)"
git add service-source/user-center
git add service-source/web-shell
git add service-source/chatbot/components/chat/site-header-bridge.tsx 2>/dev/null || true
git add scripts/dev

# Submodule pointers usually need a separate commit-in-submodule. Skip
# the chatbot submodule pointer here so we don't accidentally pin it.

echo "==> committed files preview"
git diff --cached --stat | tail -15

echo "==> commit"
git commit -m "feat(user-center+chat): perf consolidation, /account merge, subscriptions card

user-center v2:
- lib/api/server.ts: getBootstrapData() wraps React cache() so the
  protected layout + every page collapses to one fetch each per request;
  Promise.all pulls /api/me + /api/me/usage + /api/products + /api/pricing
  in parallel; module-level 30s in-memory cache for products/pricing
- (protected)/layout.tsx: single auth gate via getBootstrapData(); pushes
  results down through a server BootstrapProvider context
- /profile + /preferences merged into /account (two cards on one page);
  old paths now redirect for back-compat
- account-nav: now 4 items (Dashboard / Account / Security / Billing)
- Dashboard: new 'My subscriptions' card iterates /api/me's subscriptions,
  joins description from /api/products by code, links to the right
  service per lib/products.ts (tier_* -> chat, xout-* -> xout coming-soon)
- web-shell DEFAULT_SERVICES: 'xout' entry added (comingSoon: true)
- 5-locale i18n updated for all the new keys (account.*, dashboard.my*)

chatbot:
- site-header-bridge: drop staticServiceLabel ('AI Hub' / 'AI 中心' etc).
  Chat now renders the same dropdown ServicesMenu pattern as user-center,
  for cross-service hopping (chat <-> account <-> home <-> xout)

Note on perf: SSR on xcenter is fast (~10ms direct); the 3-5s page load
is the transatlantic Caddy hop us01 -> xcenter:3211. Real fix is either
moving Caddy edge near xcenter, or adding a CDN. Left as a follow-up."

echo "==> push"
git push origin main

echo "==> success"
sleep 2
rm -f -- "$0"
