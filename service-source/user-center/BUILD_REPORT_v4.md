# BUILD REPORT v4

Generated: 2026-05-09

---

## Job 1 — Token consumption surface in user-center

**Status: Complete**

### Files modified
- `examples/user-service/app/main.py` — Added `GET /api/me/usage-tokens` endpoint, `_build_token_usage_period()` helper, `_get_trial_credit()` helper (used by `/api/me/usage`).
- `service-source/user-center/lib/api/server.ts` — Added `TokenUsageRow`, `TokenUsagePeriod`, `UsageTokens` types; added `fetchUsageTokens()`; added `usageTokens` to `BootstrapData`; updated `getBootstrapData()` to fetch in parallel.
- `service-source/user-center/app/(protected)/billing/page.tsx` — Pass `usageTokens` prop to `BillingClient`.
- `service-source/user-center/app/(protected)/billing/billing-client.tsx` — Added `TokenUsageTable` component; added "Token usage" card with today + all-time tables.
- `service-source/user-center/lib/i18n/locales/en.ts` — Added `billing.tokenUsage`, `.todayTokens`, `.allTimeTokens`, `.modelLabel`, `.inputTokens`, `.cachedTokens`, `.outputTokens`, `.tokenCount`, `.imageCount` keys.
- `service-source/user-center/lib/i18n/locales/zh.ts`, `ja.ts`, `ko.ts`, `de.ts` — Matching keys in all 5 locales.

### Migrations needed
```sql
-- No schema changes. The endpoint reads from usage_events which already exists.
-- (accounts table migration required by Job 2 is a dependency if trial_credit
--  is also shown on /api/me/usage.)
```

---

## Job 2 — Trial $2 = account-level credit

**Status: Complete (schema migration required before deploy)**

### Files modified
- `examples/user-service/app/main.py` — Updated signup flow to INSERT into `accounts` table; updated `/api/me/usage` to attach `trial_credit_cents`; added `_get_trial_credit()` helper.
- `examples/user-service/app/billing.py` — Added `_fetch_trial_credit()`, `_deduct_trial_credit()` helpers; updated `charge_usage()` to deduct from trial credit first before touching the per-service daily quota.
- `service-source/user-center/lib/api/server.ts` — Added `trial_credit_cents?: number` to `UsageInfo` type.
- `service-source/user-center/app/(protected)/billing/billing-client.tsx` — Added "Account credit" card above the current-plan card; shows remaining trial credit and exhaustion message.
- `service-source/user-center/app/(protected)/dashboard-client.tsx` — Added amber banner showing trial credit when `trial_credit_cents > 0`.
- `service-source/user-center/lib/i18n/locales/{en,zh,ja,ko,de}.ts` — Added `billing.trialCredit`, `.trialCreditRemaining`, `.trialCreditExhausted`; `dashboard.trialCreditRemaining`, `.trialCreditLabel`.

### Migrations needed (apply in order, idempotent)
```sql
-- 1. Create accounts table
CREATE TABLE IF NOT EXISTS accounts (
  user_id     UUID        NOT NULL PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
  trial_credit_cents BIGINT NOT NULL DEFAULT 200,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Backfill existing users: each user who already has a tier_free
--    subscription gets an accounts row. If they have consumed_cents > 0
--    on their usage_quota we credit back what's left (max 200).
INSERT INTO accounts (user_id, trial_credit_cents)
SELECT
  s.user_id,
  GREATEST(0, 200 - COALESCE(q.current_period_consumed, 0)::bigint)
FROM subscriptions s
JOIN products p ON p.id = s.product_id
LEFT JOIN usage_quotas q ON q.user_id = s.user_id AND q.product_id = s.product_id
WHERE p.code = 'tier_free'
  AND s.status = 'active'
ON CONFLICT (user_id) DO NOTHING;

-- 3. For all other users (paid tiers, already consumed trial), give $0.
INSERT INTO accounts (user_id, trial_credit_cents)
SELECT id, 0 FROM auth_users
ON CONFLICT (user_id) DO NOTHING;

-- 4. (Optional) Remove lifetime_trial_cents from tier_free product metadata
--    so the UI no longer reads trial from there.
-- UPDATE products SET metadata = metadata - 'lifetime_trial_cents'
-- WHERE code = 'tier_free';
-- (Defer until charge logic is confirmed working in prod.)
```

### Notes on charge logic
- `charge_usage()` now first tries `_deduct_trial_credit()` (a synchronous DB write via CTE) before touching the in-memory daily quota.
- If trial covers the full charge: event is still logged to `usage_events` with `paid_from: trial_credit` in metadata, but `pending_delta` on the quota is NOT incremented.
- If trial is exhausted mid-charge: the remaining amount falls through to the quota as before.
- On quota exhaustion after partial trial deduction: the trial deduction is refunded (best-effort).

---

## Job 3 — Failed API calls must NOT be charged

**Status: Complete**

### Files modified
- `service-source/chatbot/lib/images/openai.ts` — Added `IMAGE_TIMEOUT_MS = 300_000`; added `imageTimeoutSignal()` helper; added `AbortSignal.timeout()` to both `fetch` calls; added auto-retry (attempt 1 → 2) in both `generateImageFromPrompt` and `editImageWithPrompt`.
- `service-source/chatbot/app/api/images/generate/route.ts` — Added `deleteImageJob` import; on failure (after both retry attempts): delete the job row from DB instead of marking failed; `chargeUsageBackground` is already ONLY in the success branch (inside `try`, after `completeImageJob`) — no charge ever fires on failure.
- `service-source/chatbot/app/(chat)/api/chat/route.ts` — Audited: `chargeUsageBackground` is inside `onFinish` (called by AI SDK only on successful stream completion) — already correct, no change needed.

### Audit of chargeUsage/chargeUsageBackground paths
| File | Call site | In success branch? |
|------|-----------|-------------------|
| `app/api/images/generate/route.ts` | After `completeImageJob()` in `try{}` | Yes |
| `app/(chat)/api/chat/route.ts` | Inside `onFinish` callback | Yes |

---

## Job 4 — Chat products labeled as "Chat channel"

**Status: Complete**

### Files modified
- `service-source/user-center/app/(protected)/billing/billing-client.tsx` — Changed "All plans" card title from `t("billing.allPlans")` to `t("billing.chatChannelPlans")`.
- `service-source/user-center/app/(protected)/dashboard-client.tsx` — Subscriptions are now grouped by `service_code` with section headers using `serviceLabel()` (Chat / Xout / Platform).
- `service-source/user-center/lib/i18n/locales/{en,zh,ja,ko,de}.ts` — Added `billing.chatChannelPlans`, `dashboard.serviceSectionChat`, `dashboard.serviceSectionXout`, `dashboard.serviceSectionPlatform`.

---

## Job 5 — Image quality default to "Standard"

**Status: Complete**

### Files modified
- `service-source/chatbot/components/images/create-tab.tsx` — Changed `useState<ImageQuality>("medium")` to `useState<ImageQuality>("low")`.

### Why "low"?
In `lib/images/types.ts`, the quality labels are:
- `low` → "标准" (Standard)
- `medium` → "高质量" (High quality)
- `high` → "极致" (Best/Ultra)

The user-facing label for `low` is "Standard/标准", which matches the requirement.

---

## TypeScript errors remaining

None expected. All new types are properly exported and consumed. The `_attempt` parameter is private (prefixed with `_`) so it won't appear in external call signatures.

Potential lint warning: `serviceLabel` function in `dashboard-client.tsx` uses a string-indexed call `t(key: string)`. Since `useT()` returns a typed function, the string keys from `serviceSectionChat/Xout/Platform` must be present in the Messages type — they are, as we added them to all 5 locales.

---

## Deploy + verify checklist

### 1. Apply DB migrations (run on user-service DB)
```sql
-- Job 2 migrations (see above) — MUST run before deploying user-service
CREATE TABLE IF NOT EXISTS accounts ( ... );
INSERT INTO accounts ... -- backfill
```

### 2. Deploy user-service
```bash
# On xcenter, in the user-service container dir:
# git pull + restart the container
docker compose pull && docker compose up -d --force-recreate user-service
```
Verify:
- `curl -b <session_cookie> https://user.develop.cc/api/me/usage-tokens` returns `{today: {...}, all_time: {...}}`
- `curl -b <session_cookie> https://user.develop.cc/api/me/usage` response includes `billing.trial_credit_cents`

### 3. Deploy user-center
```bash
docker compose pull && docker compose up -d --force-recreate user-center
```
Verify on https://user.develop.cc/billing:
- "Account credit" card appears above "Your plan" (if trial > 0)
- "Token usage" card appears with today/all-time tables
- "Chat channel plans" title (not "All plans")

Verify on https://user.develop.cc (dashboard):
- Amber "Trial credit remaining: $2.00" banner visible for new users
- My subscriptions shows section header "Chat — channel products"

### 4. Deploy chatbot
Push changes from `service-source/chatbot/` submodule and trigger redeploy.
Verify:
- Image quality picker defaults to "标准/Standard" (was "高质量")
- Generate an image that should succeed → charge fires, no entry in gallery for failures
- Manually test: if generation fails (e.g., invalid prompt to force error), confirm no charge POST to user-service

### 5. Smoke-test charge-on-success
1. Log into chat.develop.cc
2. Send a message → AI responds → verify `usage_events` row inserted and `accounts.trial_credit_cents` decreased
3. Generate an image → poll until done → verify charge row

### 6. Regression checks
- `/api/me/usage` still returns existing fields unchanged (backward-compat)
- Paid-tier users still have correct daily quota behavior (trial = 0 for them)
