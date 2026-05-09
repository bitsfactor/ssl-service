import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { getServerUser } from "@/lib/api/server";
import { SiteHeaderBridge } from "@/components/site-header-bridge";
import { AccountNav, AccountNavMobile } from "@/components/account-nav";
import type { AuthState } from "@web-shell/types";

/**
 * Layout for all authenticated pages. Fetches the current user
 * server-side. If there is no valid session, redirects to /login
 * with `return_to` so the user lands back here after signing in.
 */
export default async function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await getServerUser();

  if (!user) {
    // Build the return_to from the incoming request path.
    const hdrs = await headers();
    const pathname = hdrs.get("x-invoke-path") ?? "/";
    redirect(`/login?return_to=${encodeURIComponent(pathname)}`);
  }

  const auth: AuthState = {
    signedIn: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.display_name ?? undefined,
    },
  };

  return (
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
  );
}
