import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { getBootstrapData } from "@/lib/api/server";
import { SiteHeaderBridge } from "@/components/site-header-bridge";
import { AccountNav, AccountNavMobile } from "@/components/account-nav";
import { BootstrapProvider } from "@/components/bootstrap-provider";
import type { AuthState } from "@web-shell/types";

/**
 * Layout for all authenticated pages.
 *
 * Fetches all bootstrap data (user, usage, subscriptions, products,
 * pricing) in a single concurrent Promise.all — wrapped in React cache()
 * so any nested page that also calls getBootstrapData() gets the same
 * promise for free (no double-fetch).
 *
 * If the user is not authenticated, redirects to /login with return_to.
 */
export const dynamic = "force-dynamic";

export default async function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const data = await getBootstrapData();

  if (!data) {
    // Build the return_to from the incoming request path.
    const hdrs = await headers();
    const pathname = hdrs.get("x-invoke-path") ?? "/";
    redirect(`/login?return_to=${encodeURIComponent(pathname)}`);
  }

  const { user } = data;

  const auth: AuthState = {
    signedIn: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.display_name ?? undefined,
    },
  };

  return (
    <BootstrapProvider data={data}>
      <div className="flex min-h-screen flex-col">
        <SiteHeaderBridge auth={auth} />
        <div className="flex flex-1">
          {/* Sidebar nav — hidden on mobile, shown md+ */}
          <aside className="hidden w-56 shrink-0 border-r border-border/60 md:block">
            <AccountNav />
          </aside>
          {/* Main content */}
          <main className="flex-1 overflow-hidden">
            {children}
          </main>
        </div>
        {/* Mobile bottom navigation */}
        <AccountNavMobile />
      </div>
    </BootstrapProvider>
  );
}
