"use client";

/**
 * Adapter component that wires user-center's auth + i18n + sign-out
 * into the shared <SiteHeader> from `@web-shell/*`. The auth state is
 * passed in as a prop from the server component that fetched /api/me.
 */

import { useRouter } from "next/navigation";
import { useCallback } from "react";

import { LOCALES, type LocaleId } from "@/lib/i18n/config";
import { useI18n } from "@/lib/i18n/i18n-provider";
import { SiteHeader } from "@web-shell/header/site-header";
import type { AuthState, LocaleEntry } from "@web-shell/types";

const LOCALE_ENTRIES: LocaleEntry[] = LOCALES.map((l) => ({
  id: l.id as LocaleId,
  nativeName: l.nativeName,
}));

export function SiteHeaderBridge({
  auth,
  className,
}: {
  auth: AuthState;
  className?: string;
}) {
  const { locale, setLocale } = useI18n();
  const router = useRouter();

  const handleSignOut = useCallback(async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
    }
  }, [router]);

  return (
    <SiteHeader
      accountUrl="/"
      auth={auth}
      className={className}
      currentServiceId="account"
      locale={locale as LocaleId}
      locales={LOCALE_ENTRIES}
      onLocaleSelect={(next) => setLocale(next as LocaleId)}
      onSignOut={handleSignOut}
      preferencesUrl="/preferences"
      signInUrl="/login"
      signUpUrl="/register"
    />
  );
}
