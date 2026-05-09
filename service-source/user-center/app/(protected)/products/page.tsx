import { getBootstrapData } from "@/lib/api/server";
import { ProductsClient } from "./products-client";
import { Skeleton } from "@/components/ui/skeleton";
import { Suspense } from "react";

export const metadata = { title: "Products" };
export const dynamic = "force-dynamic";

export default async function ProductsPage() {
  const data = await getBootstrapData();
  if (!data) return null;

  return (
    <Suspense
      fallback={
        <div className="p-6 space-y-4">
          <Skeleton className="h-8 w-48 rounded" />
          <Skeleton className="h-48 w-full rounded-2xl" />
          <Skeleton className="h-48 w-full rounded-2xl" />
        </div>
      }
    >
      <ProductsClient
        products={data.products}
        subscriptions={data.subscriptions}
        usage={data.usage}
      />
    </Suspense>
  );
}
