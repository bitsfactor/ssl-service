import { Suspense } from "react";
import { getBootstrapData } from "@/lib/api/server";
import { DashboardClient } from "./dashboard-client";
import { Skeleton } from "@/components/ui/skeleton";

export const metadata = {
  title: "Dashboard",
};

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  // getBootstrapData is cached by React cache() — layout already called it,
  // so this is a free dedup, not an extra network round-trip.
  const data = await getBootstrapData();

  // Auth guard is handled by the (protected) layout — data should always
  // be non-null here, but we type-narrow defensively.
  if (!data) return null;

  return (
    <Suspense
      fallback={
        <div className="p-6 space-y-4">
          <Skeleton className="h-32 w-full rounded-2xl" />
          <Skeleton className="h-24 w-full rounded-2xl" />
          <Skeleton className="h-16 w-48 rounded-xl" />
        </div>
      }
    >
      <DashboardClient
        user={data.user}
        usage={data.usage}
        subscriptions={data.subscriptions}
        products={data.products}
      />
    </Suspense>
  );
}
