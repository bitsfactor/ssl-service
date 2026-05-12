/**
 * Auth layout — login / register / verify-email pages.
 *
 * Renders the shared site header even though the user is anonymous,
 * so language + theme toggles are reachable before sign-in. The
 * UserMenu falls back to a single "Sign in" pill in the anonymous
 * branch.
 */
import { SiteHeaderBridge } from "@/components/site-header-bridge";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col">
      <SiteHeaderBridge auth={{ signedIn: false }} />

      <main className="flex flex-1 items-center justify-center p-4">
        {children}
      </main>

      <footer className="py-4 text-center text-xs text-muted-foreground">
        &copy; {new Date().getFullYear()} BitsFactor LLC
      </footer>
    </div>
  );
}
