"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  HomeIcon,
  UserIcon,
  ShieldIcon,
  CreditCardIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useT } from "@/lib/i18n/i18n-provider";

const navItems = [
  { href: "/", icon: HomeIcon, key: "nav.dashboard" },
  { href: "/account", icon: UserIcon, key: "nav.account" },
  { href: "/security", icon: ShieldIcon, key: "nav.security" },
  { href: "/billing", icon: CreditCardIcon, key: "nav.billing" },
] as const;

export function AccountNav() {
  const pathname = usePathname();
  const t = useT();

  return (
    <nav className="flex flex-col gap-0.5 p-3 pt-4">
      {navItems.map(({ href, icon: Icon, key }) => {
        const current = href === "/" ? pathname === "/" : pathname.startsWith(href);
        return (
          <Link
            key={href}
            href={href}
            aria-current={current ? "page" : undefined}
            className={cn(
              "flex h-9 items-center gap-2.5 rounded-lg px-3 text-sm transition-colors",
              current
                ? "bg-muted/70 font-medium text-foreground"
                : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
            )}
          >
            <Icon className="size-4 shrink-0" />
            <span>{t(key)}</span>
          </Link>
        );
      })}
    </nav>
  );
}

/**
 * Mobile bottom nav (shown on small screens instead of the sidebar).
 * Displays icons only to save horizontal space.
 */
export function AccountNavMobile() {
  const pathname = usePathname();
  const t = useT();

  return (
    <nav className="flex items-center justify-around border-t border-border/60 bg-background/85 px-2 py-1 backdrop-blur-md md:hidden">
      {navItems.map(({ href, icon: Icon, key }) => {
        const current = href === "/" ? pathname === "/" : pathname.startsWith(href);
        return (
          <Link
            key={href}
            href={href}
            aria-current={current ? "page" : undefined}
            aria-label={t(key)}
            className={cn(
              "flex flex-col items-center gap-0.5 rounded-lg p-2 text-xs transition-colors",
              current
                ? "text-foreground"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Icon className="size-5 shrink-0" />
            <span className="text-[10px]">{t(key)}</span>
          </Link>
        );
      })}
    </nav>
  );
}
