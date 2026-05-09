import "server-only";

import { cookies, headers } from "next/headers";
import {
  DEFAULT_LOCALE,
  isLocaleId,
  type LocaleId,
  LOCALE_COOKIE,
  pickLocaleFromAcceptLanguage,
} from "./config";

/**
 * Resolve the active locale on the server. Order of preference:
 *   1. Explicit cookie set by the locale switcher.
 *   2. Accept-Language header.
 *   3. DEFAULT_LOCALE.
 *
 * Always async because Next 16 made `cookies()`/`headers()` async.
 */
export async function getServerLocale(): Promise<LocaleId> {
  const cookieStore = await cookies();
  const cookieValue = cookieStore.get(LOCALE_COOKIE)?.value;
  if (isLocaleId(cookieValue)) return cookieValue;
  try {
    const hdrs = await headers();
    return pickLocaleFromAcceptLanguage(hdrs.get("accept-language"));
  } catch {
    return DEFAULT_LOCALE;
  }
}
