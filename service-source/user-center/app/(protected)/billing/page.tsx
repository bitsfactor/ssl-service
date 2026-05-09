import { serverFetch } from "@/lib/api/server";
import type { UsageInfo } from "@/lib/api/server";
import { BillingClient } from "./billing-client";

export const metadata = { title: "Billing" };

type Product = {
  id: string;
  tier_code: string;
  tier_name: Record<string, string>;
  price_cents_per_month: number;
  limit_cents_per_day: number;
  discount_factor: number;
  is_active: boolean;
  sort_order: number;
};

type ModelPricing = {
  model: string;
  input_per_million: number;
  cached_per_million: number;
  output_per_million: number;
};

// user-service returns wrapper shapes, not flat arrays — unwrap each one.
//   /api/me/usage  -> { quotas: [...], billing: { tier_code, ..., consumed_cents, ... } }
//   /api/products  -> { products: [...], locale }
//   /api/pricing   -> { models: [...], discount_factor }

async function getUsage(): Promise<UsageInfo | null> {
  try {
    const res = await serverFetch("/api/me/usage");
    if (!res.ok) return null;
    const body = (await res.json()) as { billing?: UsageInfo } | UsageInfo;
    if (
      body &&
      typeof body === "object" &&
      "billing" in body &&
      body.billing
    ) {
      return body.billing as UsageInfo;
    }
    return body as UsageInfo;
  } catch {
    return null;
  }
}

async function getProducts(): Promise<Product[]> {
  try {
    const res = await serverFetch("/api/products");
    if (!res.ok) return [];
    const body = (await res.json()) as { products?: unknown[] } | unknown[];
    const list = Array.isArray(body)
      ? body
      : ((body as { products?: unknown[] })?.products ?? []);
    return list as Product[];
  } catch {
    return [];
  }
}

async function getPricing(): Promise<ModelPricing[]> {
  try {
    const res = await serverFetch("/api/pricing");
    if (!res.ok) return [];
    const body = (await res.json()) as { models?: unknown[] } | unknown[];
    const list = Array.isArray(body)
      ? body
      : ((body as { models?: unknown[] })?.models ?? []);
    return list as ModelPricing[];
  } catch {
    return [];
  }
}

export default async function BillingPage() {
  const [usage, products, pricing] = await Promise.all([
    getUsage(),
    getProducts(),
    getPricing(),
  ]);

  return (
    <BillingClient usage={usage} products={products} pricing={pricing} />
  );
}
