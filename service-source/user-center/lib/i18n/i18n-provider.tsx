"use client";

import { createContext, useCallback, useContext, useMemo } from "react";
import {
  DEFAULT_LOCALE,
  type LocaleId,
  LOCALE_COOKIE,
} from "./config";
import {
  getMessagesForLocale,
  interpolate,
  lookupMessage,
  type Messages,
} from "./messages";

type I18nContextValue = {
  locale: LocaleId;
  messages: Messages;
  /** Translate a dot-path key, with optional `{name}` placeholders. */
  t: (path: string, vars?: Record<string, string | number>) => string;
  /** Switch locale: write a long-lived cookie and reload. */
  setLocale: (next: LocaleId) => void;
};

const I18nContext = createContext<I18nContextValue | null>(null);

/**
 * Wraps the app with the active locale's message bundle. Locale is
 * decided server-side and passed in. Switching writes the cookie and
 * reloads so server-rendered metadata stays in sync.
 */
export function I18nProvider({
  locale,
  children,
}: {
  locale: LocaleId;
  children: React.ReactNode;
}) {
  const messages = useMemo(() => getMessagesForLocale(locale), [locale]);
  const t = useCallback(
    (path: string, vars?: Record<string, string | number>) =>
      interpolate(lookupMessage(messages, path), vars),
    [messages]
  );
  const setLocale = useCallback((next: LocaleId) => {
    // 1 year, root path, lax — travels on top-level navigations.
    const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    document.cookie = `${LOCALE_COOKIE}=${next}; expires=${expires.toUTCString()}; path=/; samesite=lax`;
    window.location.reload();
  }, []);
  const value = useMemo(
    () => ({ locale, messages, t, setLocale }),
    [locale, messages, t, setLocale]
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    // Fallback for pre-provider renders (e.g. snapshot tests).
    const messages = getMessagesForLocale(DEFAULT_LOCALE);
    return {
      locale: DEFAULT_LOCALE,
      messages,
      t: (path: string, vars?: Record<string, string | number>) =>
        interpolate(lookupMessage(messages, path), vars),
      setLocale: () => { /* no-op */ },
    };
  }
  return ctx;
}

export function useT() {
  return useI18n().t;
}
