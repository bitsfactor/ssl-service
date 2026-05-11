"use client";

/**
 * Mirror next-themes' `theme` value into a cookie scoped to the apex
 * (`.develop.cc` in prod) so the user's light/dark/system choice is
 * shared between every BitsFactor subdomain — chat.develop.cc and
 * user.develop.cc currently, more later.
 *
 * Why a cookie and not localStorage:
 * next-themes stores in `localStorage`, which is keyed by origin, so
 * chat.develop.cc and user.develop.cc would each keep their own copy.
 * Cookies with `Domain=.develop.cc` are sent to every subdomain.
 *
 * Mount order: render this *inside* the `<ThemeProvider>` so the
 * `useTheme()` hook resolves to the host's provider. The component
 * renders nothing.
 *
 * Sync semantics (cookie is the cross-subdomain source of truth):
 *   - on mount: if cookie value differs from next-themes' current
 *     theme, call setTheme(cookieValue). There can be a brief flash
 *     from the localStorage value to the cookie value if the two
 *     disagree, which is acceptable.
 *   - on theme change: write `theme=<value>` to the apex cookie with
 *     a 1-year TTL.
 */

import { useTheme } from "next-themes";
import { useEffect } from "react";

const COOKIE_NAME = "theme";
const COOKIE_MAX_AGE = 365 * 24 * 60 * 60;

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const prefix = `${name}=`;
  for (const part of document.cookie.split("; ")) {
    if (part.startsWith(prefix)) return decodeURIComponent(part.slice(prefix.length));
  }
  return null;
}

function apexDomain(): string {
  if (typeof window === "undefined") return "";
  const host = window.location.hostname;
  // host-only on plain localhost / 127.0.0.1 / single-label hosts so
  // the cookie doesn't get rejected. Browsers won't accept a
  // Domain=localhost cookie anyway.
  if (host === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return "";
  // Same-site sharing only needs the top private suffix (e.g.
  // ".develop.cc" covers chat.develop.cc + user.develop.cc). Take the
  // last two labels — good enough for our `.cc` apex without pulling
  // in a public-suffix list.
  const parts = host.split(".");
  if (parts.length < 2) return "";
  return `.${parts.slice(-2).join(".")}`;
}

export function ThemeSync(): null {
  const { theme, setTheme } = useTheme();

  // Cookie → next-themes on mount. Runs once; we deliberately don't
  // depend on `theme` so the cookie wins exactly once at boot and
  // every subsequent in-tab change flows the other direction.
  // biome-ignore lint/correctness/useExhaustiveDependencies: see comment
  useEffect(() => {
    const cookieTheme = readCookie(COOKIE_NAME);
    if (cookieTheme && cookieTheme !== theme) {
      setTheme(cookieTheme);
    }
  }, []);

  // next-themes → cookie on every change.
  useEffect(() => {
    if (!theme) return;
    const domain = apexDomain();
    const parts = [
      `${COOKIE_NAME}=${encodeURIComponent(theme)}`,
      "path=/",
      `max-age=${COOKIE_MAX_AGE}`,
      "SameSite=Lax",
    ];
    if (domain) parts.push(`domain=${domain}`);
    if (window.location.protocol === "https:") parts.push("Secure");
    document.cookie = parts.join("; ");
  }, [theme]);

  return null;
}
