# BUILD REPORT v3 — 2026-05-09

## Job 1: Products-belong-to-services refactor

### DB migration (`sql/schema.sql`)
- Added `service_code TEXT NOT NULL DEFAULT 'platform'` column to `products` with `ADD COLUMN IF NOT EXISTS` (idempotent).
- Backfill: `tier_*` → `'chat'`, `xout-*` → `'xout'`, others stay `'platform'`.
- Index: `idx_products_service_code ON products (service_code)`.

### Backend (`examples/user-service/app/main.py`)
- Added `_VALID_SERVICE_CODES = frozenset({"chat","xout","platform"})` and `_infer_service_code()` prefix helper.
- `ProductCreateRequest`: added `service_code` field with `@field_validator` that infers from code prefix when omitted.
- `ProductPatchRequest`: added optional `service_code` with frozenset validation.
- `GET /api/products`: accepts `?service=` filter; returns both legacy flat `products: [...]` and new `products_by_service: {...}` grouped dict; includes `service_code` per product.
- `GET /api/me`: subscriptions include `service_code` and `product_description`.
- `admin_list_products`: `ORDER BY service_code, id`.
- `admin_create_product`: inserts `service_code`.
- `admin_patch_product`: patches `service_code`; SQL-injection defence allowlist added.
- `admin_create_xout_product`: hardcodes `service_code = 'xout'`.

### user-center frontend
- **`lib/products.ts`**: added `resolveLocaleString()` helper (short→long BCP-47 expansion); rewrote `productService()` to prefer authoritative `service_code` field; added `productLink()` using `SERVICE_URLS` map.
- **`lib/api/server.ts`**: added `service_code` to `Product` and `Subscription` types; fixed `ends_at` → `expires_at` (API field name); moved products fetch out of `_staticCache` (locale-safe); kept pricing in `_staticCache` (locale-independent).
- **`app/(protected)/products/page.tsx`**: new SSR page with Suspense skeleton.
- **`app/(protected)/products/products-client.tsx`**: new client grouping products by service, `SERVICE_ORDER = ["chat","xout","platform"]`, per-service card sections with Open buttons; icons: MessageSquare / ShieldCheck / LayoutGrid.
- **`app/(protected)/dashboard-client.tsx`**: uses `resolveLocaleString` for product names and tier name; uses `expires_at` (was `ends_at`).
- **`app/(protected)/billing/billing-client.tsx`**: imports shared `Product`/`ModelPricing` types (dropped local duplicates); uses `resolveLocaleString`; removed unused `Separator` import.
- **`components/account-nav.tsx`**: added Products nav item (`/products`, `PackageIcon`).
- **i18n locales** (en/zh/ja/ko/de): added `nav.products` key and full `products` namespace (17 keys).

### Admin SPA (`src/ssl_proxy_controller/static/index.html`)
- `renderProductsView`: groups products by `service_code` with separator rows (Chat AI / Xout VPN / Platform).
- `openProductModal`: added Service picker (`chat`/`xout`/`platform`); sends `service_code` in POST/PATCH payload.

---

## Job 2: 30-Round Code Review — Findings & Fixes

| # | Severity | Location | Finding | Fix |
|---|----------|----------|---------|-----|
| 1 | HIGH | `lib/api/server.ts` | `Subscription.ends_at` — API actually returns `expires_at` (DB column name). Dashboard always showed "Lifetime" for all subscriptions. | Renamed field to `expires_at`; updated `dashboard-client.tsx` references. |
| 2 | HIGH | `billing-client.tsx` | Local `type Product` lacked `service_code`; TypeScript silently widened it to `any` on the filter line. | Removed local type; imports shared `Product` from `lib/api/server`. |
| 3 | MEDIUM | `products-client.tsx` | `Badge` imported but not used as JSX component (only `statusBadgeClass()` helper used). | Removed unused import. |
| 4 | HIGH | `lib/api/server.ts` | `_staticCache` for `/api/products` was shared across all users — if user A (zh) warmed the cache, user B (en) got zh-localised product names for 30 s. | Removed `cachedFetch` for products; replaced with direct `serverFetch` (React `cache()` handles per-request dedup). |
| 5 | LOW | `main.py admin_create_product` | `service_code = req.service_code or _infer_service_code(req.code)` — redundant since the Pydantic validator already infers it. Dead code, confusing. | Simplified to `service_code = req.service_code`. |
| 6 | MEDIUM | `products-client.tsx priceLabel` | Checked `period_days === 0` for lifetime pricing. Backend validator rejects `period_days < 1`, so this condition is never true. Lifetime products have `period_days = null`. | Changed to `!p.period_days`. |
| 7 | HIGH | `dashboard-client.tsx`, `billing-client.tsx`, `products-client.tsx` | All `productLabel`/`subProductLabel`/`getTierName` looked up locale maps by short code (`"zh"`, `"en"`) but the DB stores keys as `"zh-CN"`, `"en-US"`. Every lookup missed, falling back to product code as display name. | Added `resolveLocaleString()` to `lib/products.ts` with short→long BCP-47 expansion table; updated all call sites. |
| 8 | LOW | `products-client.tsx` | `xout` and `platform` both used `ShieldIcon` — visually identical, confusing. | `xout` → `ShieldCheckIcon`, `platform` → `LayoutGridIcon`. |
| 9 | LOW | `products-client.tsx` | `activeCodes.has(p.code ?? "")` — falsy `p.code` would insert `""` into the lookup, potentially matching an empty-code subscription row. | Changed to `!!p.code && activeCodes.has(p.code)`. |
| 10 | MEDIUM (security) | `main.py admin_patch_product` | Dynamic `set_clause` built from `data.keys()` (Pydantic model dump). Keys are model-constrained but the column name appears verbatim in SQL. | Added `_PATCHABLE` frozenset allowlist; unknown keys silently skipped. |
| 11 | LOW | `billing-client.tsx` | `Separator` imported, never used in JSX. | Removed. |
| 12 | LOW | `billing-client.tsx` | `useT` and `useI18n` were two separate imports from the same module. | Merged into one import. |

Rounds 13–30 (security, auth, accessibility, network, typing, SSR, visual): no additional actionable findings. `Badge variant="success"` and `Button size="xs"` confirmed present in component definitions. Pricing `_staticCache` confirmed locale-safe (global `discount_factor`, no per-user variation). i18n keys verified present in all 5 locales. Schema migration confirmed idempotent.

---

## Job 3: Billing Smoke Script

**File:** `scripts/billing-smoke.ts`

Executable via `npx tsx scripts/billing-smoke.ts`.

Steps:
1. `GET /api/pricing` — fetches model rates and discount factor; computes expected charge.
2. `GET /api/internal/users/{ident}/usage-summary` — reads `consumed_cents` before.
3. `POST /api/internal/usage/charge` — charges `INPUT_TOKENS` + `OUTPUT_TOKENS` against `MODEL_ID`.
4. `GET /api/internal/users/{ident}/usage-summary` — reads `consumed_cents` after.
5. Asserts: `delta == charged_cents` (±1¢) and `charged_cents ≈ pricing_math` (±2¢).

Prints `PASS` / `FAIL` with full line-item breakdown. Exits 0 on pass, 1 on any failure.

Required env vars: `USAGE_INGEST_TOKEN`, `USER_IDENT`. Optional: `USER_SERVICE_URL`, `MODEL_ID`, `INPUT_TOKENS`, `OUTPUT_TOKENS`.

---

## Files Changed

**Backend**
- `/sql/schema.sql` — migration block appended
- `/examples/user-service/app/main.py` — service_code throughout

**user-center**
- `lib/api/server.ts`
- `lib/products.ts`
- `app/(protected)/products/page.tsx` (new)
- `app/(protected)/products/products-client.tsx` (new)
- `app/(protected)/dashboard-client.tsx`
- `app/(protected)/billing/billing-client.tsx`
- `components/account-nav.tsx`
- `lib/i18n/locales/en.ts`
- `lib/i18n/locales/zh.ts`
- `lib/i18n/locales/ja.ts`
- `lib/i18n/locales/ko.ts`
- `lib/i18n/locales/de.ts`
- `scripts/billing-smoke.ts` (new)

**Admin SPA**
- `src/ssl_proxy_controller/static/index.html`
