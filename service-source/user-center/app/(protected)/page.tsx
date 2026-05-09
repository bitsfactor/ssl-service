import { Suspense } from "react";
import { getServerUser, serverFetch } from "@/lib/api/server";
import type { UsageInfo } from "@/lib/api/server";
import { DashboardClient } from "./dashboard-client";
import { Skeleton } from "@/components/ui/skeleton";

async function getUsage(): Promise<UsageInfo | null> {
  try {
    const res = await serverFetch("/api/me/usage");
    if (!res.ok) return null;
    // user-service wraps usage as { quotas, billing } — unwrap to billing.
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

export const metadata = {
  title: "Dashboard",
};

export default async function DashboardPage() {
  const [user, usage] = await Promise.all([getServerUser(), getUsage()]);

  // Auth guard is handled by the (protected) layout — user should always
  // be non-null here, but we type-narrow defensively.
  if (!user) return null;

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
      <DashboardClient user={user} usage={usage} />
    </Suspense>
  );
}
