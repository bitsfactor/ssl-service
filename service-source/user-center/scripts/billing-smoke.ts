#!/usr/bin/env tsx
/**
 * billing-smoke.ts — Token billing end-to-end smoke test.
 *
 * What it does:
 *   1. Reads usage BEFORE the charge.
 *   2. POSTs a known token charge to /api/internal/usage/charge.
 *   3. Reads usage AFTER the charge.
 *   4. Computes expected_charged_cents from the model pricing returned
 *      by /api/pricing, applies the user's discount_factor.
 *   5. Asserts that consumed_cents delta matches expected_charged_cents
 *      (within a 1¢ rounding tolerance).
 *
 * Usage:
 *   USER_SERVICE_URL=http://localhost:8200 \
 *   USAGE_INGEST_TOKEN=<secret> \
 *   USER_IDENT=test@example.com \
 *   MODEL_ID=gpt-4o \
 *   npx tsx scripts/billing-smoke.ts
 *
 * Environment variables:
 *   USER_SERVICE_URL     Internal base URL (no trailing slash).
 *                        Default: http://host.docker.internal:8200
 *   USAGE_INGEST_TOKEN   The X-Service-Token secret (USAGE_INGEST_TOKEN env in user-service).
 *   USER_IDENT           Email or user-service UUID to charge.
 *   MODEL_ID             Pricing model to use. Default: gpt-4o
 *   INPUT_TOKENS         Input token count for the test charge. Default: 1000
 *   OUTPUT_TOKENS        Output token count. Default: 500
 */

const BASE_URL = process.env.USER_SERVICE_URL ?? "http://host.docker.internal:8200";
const TOKEN = process.env.USAGE_INGEST_TOKEN ?? "";
const USER_IDENT = process.env.USER_IDENT ?? "";
const MODEL_ID = process.env.MODEL_ID ?? "gpt-4o";
const INPUT_TOKENS = parseInt(process.env.INPUT_TOKENS ?? "1000", 10);
const OUTPUT_TOKENS = parseInt(process.env.OUTPUT_TOKENS ?? "500", 10);

if (!TOKEN) {
  console.error("FAIL: USAGE_INGEST_TOKEN is required");
  process.exit(1);
}
if (!USER_IDENT) {
  console.error("FAIL: USER_IDENT (email or UUID) is required");
  process.exit(1);
}

const HEADERS = {
  "Content-Type": "application/json",
  "X-Service-Token": TOKEN,
};

async function apiGet(path: string): Promise<unknown> {
  const res = await fetch(`${BASE_URL}${path}`, { headers: HEADERS });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GET ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

async function apiPost(path: string, body: unknown): Promise<unknown> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`POST ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

interface PricingModel {
  model_id: string;
  input_rate_per_1m_usd?: number;
  output_rate_per_1m_usd?: number;
}

interface PricingResponse {
  discount_factor: number;
  models: PricingModel[];
}

interface UsageSummary {
  consumed_cents: number;
  remaining_cents: number;
  limit_cents: number;
  tier_code: string;
}

interface ChargeResult {
  ok: boolean;
  charged_cents: number;
  openai_cents: number;
  remaining_cents: number;
  limit_cents: number;
  tier_code: string;
}

function pass(msg: string) {
  console.log(`  PASS  ${msg}`);
}

function fail(msg: string) {
  console.error(`  FAIL  ${msg}`);
}

async function main() {
  console.log(`\nBilling smoke test`);
  console.log(`  user-service : ${BASE_URL}`);
  console.log(`  user_ident   : ${USER_IDENT}`);
  console.log(`  model        : ${MODEL_ID}`);
  console.log(`  input_tokens : ${INPUT_TOKENS}`);
  console.log(`  output_tokens: ${OUTPUT_TOKENS}`);
  console.log("");

  let failures = 0;

  // ── Step 1: Fetch pricing ─────────────────────────────────────────────────
  console.log("Step 1: Fetch /api/pricing");
  let pricing: PricingResponse;
  try {
    pricing = await apiGet("/api/pricing") as PricingResponse;
    pass(`Got ${pricing.models.length} model(s), discount_factor=${pricing.discount_factor}`);
  } catch (err) {
    fail(`Could not fetch pricing: ${err}`);
    process.exit(1);
  }

  const model = pricing.models.find((m) => m.model_id === MODEL_ID);
  if (!model) {
    fail(`Model "${MODEL_ID}" not found in pricing. Available: ${pricing.models.map((m) => m.model_id).join(", ")}`);
    process.exit(1);
  }

  const inputRate = model.input_rate_per_1m_usd ?? 0;
  const outputRate = model.output_rate_per_1m_usd ?? 0;
  const discountFactor = pricing.discount_factor ?? 1;

  // Expected charge in cents = (tokens/1M * rate_usd * 100) * discount
  const expectedCents = Math.round(
    ((INPUT_TOKENS / 1_000_000) * inputRate * 100 +
      (OUTPUT_TOKENS / 1_000_000) * outputRate * 100) *
    discountFactor
  );

  pass(
    `Model rates: input=$${inputRate}/1M output=$${outputRate}/1M ` +
    `discount=${(discountFactor * 100).toFixed(0)}% → expected ≈ ${expectedCents}¢`
  );

  // ── Step 2: Fetch usage BEFORE ────────────────────────────────────────────
  console.log("\nStep 2: Fetch usage BEFORE charge");
  let beforeUsage: UsageSummary;
  try {
    beforeUsage = await apiGet(
      `/api/internal/users/${encodeURIComponent(USER_IDENT)}/usage-summary`
    ) as UsageSummary;
    pass(`consumed_before=${beforeUsage.consumed_cents}¢  tier=${beforeUsage.tier_code}`);
  } catch (err) {
    fail(`Could not fetch usage summary: ${err}`);
    process.exit(1);
  }

  if (beforeUsage.limit_cents === 0) {
    console.log("  NOTE  User is on unlimited tier — delta check will still run but remaining stays ∞");
  }

  // ── Step 3: POST charge ────────────────────────────────────────────────────
  console.log("\nStep 3: POST /api/internal/usage/charge");
  let chargeResult: ChargeResult;
  try {
    chargeResult = await apiPost("/api/internal/usage/charge", {
      user_ident: USER_IDENT,
      model: MODEL_ID,
      input_tokens: INPUT_TOKENS,
      output_tokens: OUTPUT_TOKENS,
      cached_input_tokens: 0,
      duration_seconds: 0,
      resource_id: "billing-smoke-test",
      metadata: { smoke_test: true },
    }) as ChargeResult;
    pass(`ok=${chargeResult.ok}  charged=${chargeResult.charged_cents}¢  remaining=${chargeResult.remaining_cents}¢`);
  } catch (err) {
    fail(`Charge failed: ${err}`);
    process.exit(1);
  }

  if (!chargeResult.ok) {
    fail("Charge response has ok=false");
    failures++;
  }

  // ── Step 4: Fetch usage AFTER ─────────────────────────────────────────────
  // Allow up to 2s for the in-memory accumulator to be visible (it should be
  // immediate since get_usage_summary reads the in-memory buffer).
  console.log("\nStep 4: Fetch usage AFTER charge");
  let afterUsage: UsageSummary;
  try {
    afterUsage = await apiGet(
      `/api/internal/users/${encodeURIComponent(USER_IDENT)}/usage-summary`
    ) as UsageSummary;
    pass(`consumed_after=${afterUsage.consumed_cents}¢`);
  } catch (err) {
    fail(`Could not fetch usage summary after charge: ${err}`);
    process.exit(1);
  }

  // ── Step 5: Assert delta ──────────────────────────────────────────────────
  console.log("\nStep 5: Assert delta");
  const delta = afterUsage.consumed_cents - beforeUsage.consumed_cents;
  const tolerance = 1; // 1¢ rounding tolerance

  console.log(`  consumed_before : ${beforeUsage.consumed_cents}¢`);
  console.log(`  consumed_after  : ${afterUsage.consumed_cents}¢`);
  console.log(`  delta           : ${delta}¢`);
  console.log(`  charged_cents   : ${chargeResult.charged_cents}¢`);
  console.log(`  expected_cents  : ~${expectedCents}¢`);

  // Check: delta == charged_cents (the authoritative figure from the charge response)
  if (Math.abs(delta - chargeResult.charged_cents) <= tolerance) {
    pass(`Delta (${delta}¢) matches charged_cents (${chargeResult.charged_cents}¢) within ${tolerance}¢`);
  } else {
    fail(
      `Delta mismatch: consumed delta=${delta}¢ but charged_cents=${chargeResult.charged_cents}¢ ` +
      `(diff=${Math.abs(delta - chargeResult.charged_cents)}¢ > tolerance=${tolerance}¢)`
    );
    failures++;
  }

  // Check: charged_cents close to our manual calculation (sanity check on pricing math)
  if (expectedCents > 0 && Math.abs(chargeResult.charged_cents - expectedCents) <= tolerance + 1) {
    pass(`Charged (${chargeResult.charged_cents}¢) matches pricing math (${expectedCents}¢)`);
  } else if (expectedCents === 0 && chargeResult.charged_cents === 0) {
    pass("Zero-cost model charged 0¢ as expected");
  } else if (expectedCents === 0) {
    fail(
      `Pricing math says 0¢ but charged_cents=${chargeResult.charged_cents}¢ — ` +
      `check model rates in /api/admin/billing/pricing`
    );
    failures++;
  } else {
    fail(
      `Pricing math mismatch: expected ~${expectedCents}¢ but got ${chargeResult.charged_cents}¢ ` +
      `(diff=${Math.abs(chargeResult.charged_cents - expectedCents)}¢)`
    );
    failures++;
  }

  // ── Result ────────────────────────────────────────────────────────────────
  console.log("");
  if (failures === 0) {
    console.log("RESULT: PASS — billing pipeline is working correctly");
    process.exit(0);
  } else {
    console.error(`RESULT: FAIL — ${failures} assertion(s) failed`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
