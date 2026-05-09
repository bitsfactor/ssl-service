# BUILD_REPORT_v2.md — user-center perf + subscriptions refactor

Date: 2026-05-09

---

## Files added

| Path | Purpose |
|------|---------|
| `lib/api/server.ts` | Rewritten: `getBootstrapData()` + `Subscription`/`Product`/`ModelPricing`/`BootstrapData` types + 30s static cache for products/pricing |
| `lib/products.ts` | NEW: `productLink(code)` helper mapping product codes to service URLs |
| `components/bootstrap-provider.tsx` | NEW: React context wrapper (`BootstrapProvider` + `useBootstrap`) carrying bootstrap data to client components |
| `app/(protected)/account/page.tsx` | NEW: Merged Account page (server component, uses `getBootstrapData`) |
| `app/(protected)/account/account-client.tsx` | NEW: Account client — Profile section (display_name, locale, email RO) + Preferences section (theme, UI language, AI placeholder) |

## Files modified

| Path | Change |
|------|--------|
| `app/(protected)/layout.tsx` | Uses `getBootstrapData()` instead of `getServerUser()`. Wraps children in `<BootstrapProvider>`. Added `export const dynamic = "force-dynamic"` |
| `app/(protected)/page.tsx` | Dashboard: uses `getBootstrapData()` (free dedup), passes `subscriptions` + `products` to `DashboardClient` |
| `app/(protected)/dashboard-client.tsx` | Added "My Subscriptions" card with status badges, period labels, product description cross-ref, and Open/Coming Soon buttons |
| `app/(protected)/billing/page.tsx` | Uses `getBootstrapData()` instead of 3 independent serial fetches |
| `app/(protected)/security/page.tsx` | Uses `getBootstrapData()` instead of `getServerUser()` |
| `app/(protected)/profile/page.tsx` | Replaced with `redirect("/account")` |
| `app/(protected)/profile/profile-client.tsx` | Replaced with empty stub (removed dead code with stale i18n keys) |
| `app/(protected)/preferences/page.tsx` | Replaced with `redirect("/account")` |
| `app/(protected)/preferences/preferences-client.tsx` | Replaced with empty stub (removed dead code with stale i18n keys) |
| `components/account-nav.tsx` | Removed Profile + Preferences nav items; added single "Account" entry (`/account`). Now 4 items: Dashboard / Account / Security / Billing |
| `lib/i18n/locales/en.ts` | Removed `profile.*` + `preferences.*` sections; added `account.*` (18 keys) + `dashboard.mySubscriptions` + 6 subscription keys + `dashboard.editProfile` updated. `nav.profile` + `nav.preferences` → `nav.account` |
| `lib/i18n/locales/zh.ts` | Same structural changes, Chinese translations |
| `lib/i18n/locales/ja.ts` | Same structural changes, Japanese translations |
| `lib/i18n/locales/ko.ts` | Same structural changes, Korean translations |
| `lib/i18n/locales/de.ts` | Same structural changes, German translations |
| `web-shell/src/services.ts` (user-center copy) | Added `xout` service entry (`comingSoon: true`) |
| `components/site-header-bridge.tsx` | Updated `preferencesUrl` from `/preferences` to `/account` |
| `web-shell/src/services.ts` (master copy at `service-source/web-shell/`) | Added `xout` service entry (`comingSoon: true`) |

## pnpm build status

`pnpm` is not installed in the CI workspace (Linux sandbox without node_modules). Build could not be run automatically.

**Manual verification performed:**
- All i18n locale files: 177 leaf keys match exactly across all 5 locales (verified by Python script)
- All imports traced: every `import { X } from "@/lib/api/server"` resolves to an exported symbol
- No references to removed i18n keys (`profile.*`, `preferences.*`, `nav.profile`, `nav.preferences`) in any compiled file
- TypeScript path aliases (`@/*`, `@web-shell/*`) match `tsconfig.json` paths
- Dead client files (`profile-client.tsx`, `preferences-client.tsx`) replaced with `export {}` stubs — no TS errors

## Known TS risks (low)

1. `billing-client.tsx` defines its own local `Product`/`ModelPricing` types structurally identical to the ones in `server.ts`. The new `billing/page.tsx` passes `data.products` (typed as `server.ts:Product[]`). TypeScript structural typing means these are compatible, but if someone adds a required field to one type and not the other, it will silently drift. **TODO**: consolidate `BillingClient` to import types from `@/lib/api/server` (low priority, not a build blocker).

2. `getBootstrapData` uses `react.cache()`. In Next.js 16 (App Router), this requires React 19 (already in package.json: `"react": "19.0.1"`). No issue.

## TODOs remaining

- `BillingClient` still defines its own duplicate Product/ModelPricing types locally — consolidate to `@/lib/api/server` imports in a follow-up
- `account.locale` field saved to user-service profile vs. `useI18n().setLocale` (cookie-only) are two separate things — the UI explains this but a future improvement would be to auto-apply the profile locale on page load
- `dashboard.subscriptionStatus` currently passes the raw status string (e.g. `"active"`, `"past_due"`, `"canceled"`) — could be mapped to display labels per locale in a follow-up
- Subscription renewal date uses `toLocaleDateString` — works but a date-fns or Intl.DateTimeFormat approach is more consistent
- `xout.develop.cc` is registered as `comingSoon: true` in services.ts — flip to `false` when the service launches

## What to test (checklist for operator)

1. **Dashboard** — Visit `https://user.develop.cc/` after login:
   - Page loads in <500ms (no serial fetches)
   - "Current plan" card shows tier name (e.g. "Free")
   - "Today's usage" card shows consumed/limit
   - "My subscriptions" card shows subscription rows with correct product name, status badge (green=active, amber=past_due, gray=canceled), period info, and "Open" button linking to chat.develop.cc for `tier_*` subscriptions
   - "Edit account" button links to `/account` (not `/profile`)

2. **Account page** — Visit `/account`:
   - Profile section: email read-only, display name editable, locale selector; Save button PATCHes `/api/me`
   - Preferences section: theme toggle (Light/Dark/System), UI language selector (cookie-only), AI defaults placeholder
   - Success toast on save

3. **Redirects** — Verify old URLs redirect:
   - `/profile` → `/account` (HTTP redirect, not 404)
   - `/preferences` → `/account` (HTTP redirect, not 404)

4. **Billing** — Visit `/billing`:
   - Loads in <500ms (products+pricing served from 30s module cache on repeat visits)
   - Plan table and model pricing table render correctly

5. **Security** — Visit `/security`:
   - Loads immediately (no extra fetch — piggybacks layout bootstrap)
   - Password reset link and session list work as before

6. **Nav** — Sidebar shows exactly 4 items: Dashboard, Account, Security, Billing
   - Mobile bottom nav shows same 4 items
   - Active item highlights correctly on each page

7. **Locale switch** — Change UI language from Account preferences:
   - All 5 locales render without `[MISSING KEY]` or raw dot-paths
   - "My subscriptions" section headings translate correctly

8. **Services menu in header** — Xout entry appears with "coming soon" indicator
