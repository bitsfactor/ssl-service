import { getBootstrapData } from "@/lib/api/server";
import { BillingClient } from "./billing-client";

export const metadata = { title: "Billing" };
export const dynamic = "force-dynamic";

export default async function BillingPage() {
  // getBootstrapData is cached by React cache() — free dedup with layout.
  const data = await getBootstrapData();
  if (!data) return null;

  return (
    <BillingClient
      usage={data.usage}
      usageTokens={data.usageTokens}
      products={data.products}
      pricing={data.pricing}
    />
  );
}
