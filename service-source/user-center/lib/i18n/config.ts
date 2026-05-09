// user-center i18n: locale registry. Mirror of chatbot's config.ts
// (same locale IDs, same cookie name so the locale cookie set on
// chat.develop.cc is honoured here and vice-versa).

export type LocaleId = "zh" | "en" | "ja" | "ko" | "de";

export const LOCALES: Array<{
  id: LocaleId;
  englishName: string;
  nativeName: string;
}> = [
  { id: "zh", englishName: "Chinese", nativeName: "中文" },
  { id: "en", englishName: "English", nativeName: "English" },
  { id: "ja", englishName: "Japanese", nativeName: "日本語" },
  { id: "ko", englishName: "Korean", nativeName: "한국어" },
  { id: "de", englishName: "German", nativeName: "Deutsch" },
];

export const LOCALE_IDS: LocaleId[] = LOCALES.map((l) => l.id);
export const DEFAULT_LOCALE: LocaleId = "en";
// Same cookie as chatbot so a shared browser session stays in sync.
export const LOCALE_COOKIE = "devchat_locale";

export function isLocaleId(value: unknown): value is LocaleId {
  return (
    typeof value === "string" &&
    (LOCALE_IDS as string[]).includes(value)
  );
}

/**
 * Pick the best supported locale given a raw Accept-Language header.
 * We check direct hits first (en, zh, ja, ko, de), then the language
 * tag prefix (e.g. zh-Hant, zh-CN both → zh).
 */
export function pickLocaleFromAcceptLanguage(
  acceptLanguage: string | null | undefined
): LocaleId {
  if (!acceptLanguage) return DEFAULT_LOCALE;
  const parsed = acceptLanguage
    .split(",")
    .map((part) => {
      const [tag, ...rest] = part.trim().split(";");
      const qMatch = rest.find((r) => r.trim().startsWith("q="));
      const q = qMatch ? Number(qMatch.split("=")[1]) : 1;
      return { tag: tag.toLowerCase(), q: Number.isFinite(q) ? q : 0 };
    })
    .filter((x) => x.tag.length > 0)
    .sort((a, b) => b.q - a.q);
  for (const { tag } of parsed) {
    if (isLocaleId(tag)) return tag;
    const prefix = tag.split("-")[0];
    if (isLocaleId(prefix)) return prefix;
  }
  return DEFAULT_LOCALE;
}
