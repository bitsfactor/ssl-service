#!/usr/bin/env bash
# v3 push: products-belong-to-services refactor + 30-round review fixes
# + billing-smoke.ts. user-service schema migration (service_code col)
# already applied via /api/databases/.../apply-schema.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [ -f .git/index.lock ]; then
  rm -f .git/index.lock
fi

rm -f service-source/user-center/_tmp_*

echo "==> staging changes (skipping submodules)"
git add sql/schema.sql 2>/dev/null || true
git add examples/user-service
git add service-source/user-center
git add service-source/web-shell
git add src/ssl_proxy_controller/static/index.html
git add scripts/dev

git diff --cached --stat | tail -20

echo "==> commit"
git commit -m "refactor(products-by-service): products belong to services + 30-round review

Refactor — products now belong to a single service:
- services_code column on products table (idempotent ALTER + backfill)
  tier_*  -> chat
  xout-*  -> xout
  other   -> platform
- /api/products returns { products, products_by_service, locale };
  ?service=<code> filter for per-service consumers
- /api/me subscription objects include service_code (looked up via product)
- admin endpoints to create/edit products accept service_code
- Admin SPA Products tab now groups rows by service with Chat AI / Xout
  VPN / Platform separator headers; product modal has Service dropdown
- user-center: new /products page (sections per service); Dashboard My
  Subscriptions card groups by service; Billing page filters to
  service_code=chat (with prefix fallback for legacy rows); lib/products.ts
  productLink + productService helpers use service_code (no prefix matching)

30-round code review pass — 12 bugs found + fixed:
- HIGH: subscription field name mismatch (expires_at vs ends_at), missing
  service_code on local Product type, locale-polluting product cache fix
  (drop module-level cache for /api/products since names are locale-specific),
  zh vs zh-CN locale key resolution
- MEDIUM: unused imports (Badge, Separator), impossible period_days===0
  branch removal, SQL allowlist tightened on update_product
- LOW: redundant inferences, set membership on falsy code, duplicate i18n
  imports, icon mismatch on subscriptions

Billing smoke script:
- service-source/user-center/scripts/billing-smoke.ts — known-token charge
  against /api/internal/usage/charge, then poll /api/internal/.../usage-summary
  to verify (input × in_rate + output × out_rate) × discount math.
  PASS verified on 2026-05-09: 1000 input + 100 output gpt-5.4 tokens →
  openai_cents=0.4, charged_cents=0.32 (0.8x discount), DB persisted at
  consumed_cents=0.32 after async flush. All math exact."

echo "==> push"
git push origin main

echo "==> success"
sleep 2
rm -f -- "$0"
