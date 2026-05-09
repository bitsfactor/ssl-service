"use client";

import { DEFAULT_BRAND } from "../branding";
import { DEFAULT_SERVICES } from "../services";
import { cn } from "../lib/cn";
import type {
  AuthState,
  BrandConfig,
  HeaderNavItem,
  LocaleEntry,
  LocaleId,
  ServiceEntry,
} from "../types";
import { LocaleSwitcher } from "./locale-switcher";
import { ServicesMenu } from "./services-menu";
import { ThemeToggle } from "./theme-toggle";
import { UserMenu } from "./user-menu";

/**
 * Site-wide top header. Same component on every Develop service —
 * left logo, middle service-switcher + service-internal nav, right
 * locale + theme + user. Designed to live OUTSIDE any sidebar so it
 * spans the full viewport width.
 *
 * Required wiring on the host:
 *   - Tailwind `content` array must include `../web-shell/src/**`.
 *   - `next-themes` must be set up at the layout level (web-shell's
 *     ThemeToggle just consumes `useTheme()`).
 *   - The host owns locale persistence (`onLocaleSelect` should write
 *     the cookie + reload, or whatever the host does today).
 *   - Sign-out is also host-driven via `onSignOut`.
 */
export function SiteHeader({
  brand = DEFAULT_BRAND,
  services = DEFAULT_SERVICES,
  currentServiceId,
  navItems = [],
  navItemsLeading,
  navItemsTrailing,
  auth,
  locale,
  locales,
  onLocaleSelect,
  signInUrl,
  signUpUrl,
  accountUrl,
  preferencesUrl,
  onSignOut,
  className,
}: {
  brand?: BrandConfig;
  services?: ServiceEntry[];
  currentServiceId: string;
  /** Service-internal nav items, rendered after the services menu. */
  navItems?: HeaderNavItem[];
  /** Optional slot rendered BEFORE navItems — host can drop a
   *  visibility selector or similar here. */
  navItemsLeading?: React.ReactNode;
  /** Optional slot rendered AFTER navItems — useful for breadcrumbs. */
  navItemsTrailing?: React.ReactNode;
  auth: AuthState;
  locale: LocaleId;
  locales: LocaleEntry[];
  onLocaleSelect: (next: LocaleId) => void;
  signInUrl: string;
  signUpUrl: string;
  accountUrl: string;
  preferencesUrl?: string;
  onSignOut: () => void;
  className?: string;
}) {
  return (
    <header
      className={cn(
        "flex h-12 w-full shrink-0 items-center gap-3 border-border/40 border-b bg-background/85 px-3 backdrop-blur-md md:h-14 md:px-4",
        className
      )}
      data-component="site-header"
    >
      {/* Left: brand */}
      <a
        aria-label={brand.name}
        className="flex h-9 items-center gap-2 rounded-md pr-2 pl-1 transition-colors hover:bg-muted/60"
        href={brand.homeUrl}
      >
        {/* biome-ignore lint/performance/noImgElement: tiny logo, host-served */}
        <img
          alt=""
          className="size-7 rounded-md"
          src={brand.logoUrl}
        />
        <span className="hidden font-semibold text-foreground text-sm tracking-tight sm:block">
          {brand.name}
        </span>
      </a>

      {/* Middle: services menu + service-internal nav */}
      <div className="flex min-w-0 flex-1 items-center gap-1">
        <div className="h-5 w-px bg-border/60" />
        <ServicesMenu
          currentServiceId={currentServiceId}
          locale={locale}
          services={services}
        />
        {navItemsLeading}
        {navItems.length > 0 ? (
          <nav className="ml-1 hidden items-center gap-0.5 md:flex">
            {navItems.map((item) => (
              <a
                aria-current={item.current ? "page" : undefined}
                className={cn(
                  "flex h-8 items-center rounded-md px-2.5 text-sm transition-colors",
                  item.current
                    ? "bg-muted/70 text-foreground"
                    : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
                )}
                href={item.href}
                key={item.id}
              >
                {item.label}
              </a>
            ))}
          </nav>
        ) : null}
        {navItemsTrailing ? (
          <div className="ml-1">{navItemsTrailing}</div>
        ) : null}
      </div>

      {/* Right: locale + theme + user */}
      <div className="flex shrink-0 items-center gap-1">
        <LocaleSwitcher
          locale={locale}
          locales={locales}
          onSelect={onLocaleSelect}
        />
        <ThemeToggle locale={locale} />
        <div className="ml-1">
          <UserMenu
            accountUrl={accountUrl}
            auth={auth}
            locale={locale}
            onSignOut={onSignOut}
            preferencesUrl={preferencesUrl}
            signInUrl={signInUrl}
            signUpUrl={signUpUrl}
          />
        </div>
      </div>
    </header>
  );
}
