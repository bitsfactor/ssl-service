#!/bin/bash
cd "$(dirname "$0")"
find .git -name '*.lock' -print -delete 2>/dev/null
echo "== git status =="
git status --short
echo
git add -A
git commit -m "feat(user-service): in-memory billing engine + token-based USD metering

Adds the back-end half of the Develop billing system (Phase A):

- model_pricing table: per-model OpenAI rates (input/cached/output
  per 1M tokens) stored as micro-USD bigints. Seeded with current
  standard-tier pricing for gpt-5.4/5.5 + variants and gpt-image-2.
- 4 tier products (tier_free \$0+\$2 trial, tier_basic \$5, tier_pro
  \$10, tier_premium \$20) with daily allowances in metadata.
- system_config['billing.discount_factor']=0.8 — global multiplier
  applied to OpenAI rates when charging users.
- billing.py: in-memory accumulator engine. Per-user cached quota
  (30s TTL), pending event buffer, pending delta map. Hot path
  hits no DB. Background asyncio task flushes every 5s or on
  buffer overflow. Restart loses ≤5s of charges (acceptable).
- /api/usage/charge: service-to-service charge endpoint.
- /api/internal/usage/charge + /api/internal/users/{ident}/usage-summary:
  variants that accept email-or-uuid (chatbot's User.id != our
  auth_users.id, so chatbot just sends session.user.email).
- /api/pricing: public — list active models and current discount.
- /api/me/usage: extended to include billing summary.
- Signup hook: auto-grants tier_free + creates lifetime trial
  quota.
- usage_quotas.reset_kind extended to allow 'daily'; adds
  unique-on-resource_id index for charge idempotency.
- _next_period_start handles 'daily' (UTC midnight reset)."
echo
git push origin main
echo
if [ \$? -eq 0 ]; then rm -- "\$0"; fi
read -n 1 -s -r -p "Press any key..."; echo
