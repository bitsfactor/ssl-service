/**
 * Product helpers — URL mapping and service attribution.
 *
 * IMPORTANT: helpers prefer the authoritative `service_code` from the
 * product object (populated by /api/products since 2026-05-09) over
 * code-prefix heuristics. The prefix fallback is kept only for products
 * that predate the migration or arrive from a stale cache.
 */

/**
 * Resolve a localised string map using user-center's short locale codes
 * ("zh", "en", "ja", "ko", "de") against maps that may use BCP-47 long
 * form keys ("zh-CN", "en-US") stored by the user-service backend.
 *
 * Lookup order: exact short code → long-form expansion → "en" → "en-US"
 * → first available value → empty string.
 */
export function resolveLocaleString(
  map: Record<string, string> | undefined | null,
  locale: string
): string {
  if (!map) return "";
  // Direct short-code match (for maps that already use short codes)
  if (map[locale]) return map[locale];
  // Expand short code to long form: zh → zh-CN, en → en-US, etc.
  const LONG_FORM: Record<string, string> = {
    zh: "zh-CN",
    en: "en-US",
    ja: "ja-JP",
    ko: "ko-KR",
    de: "de-DE",
  };
  const long = LONG_FORM[locale];
  if (long && map[long]) return map[long];
  // English fallbacks
  if (map["en"]) return map["en"];
  if (map["en-US"]) return map["en-US"];
  // First available
  const first = Object.values(map)[0];
  return first ?? "";
}

export type ProductLink = {
  url: string | null;
  comingSoon: boolean;
};

/** Map a service code → canonical service URL and coming-soon flag. */
const SERVICE_URLS: Record<string, { url: string; comingSoon: boolean }> = {
  chat:     { url: "https://chat.develop.cc/", comingSoon: false },
  xout:     { url: "https://xout.develop.cc/", comingSoon: true  },
  platform: { url: "", comingSoon: false },
};

/**
 * Return the product's owning service code.
 * Prefers `service_code` from the API; falls back to code-prefix
 * heuristics for backward compat.
 */
export function productService(
  codeOrProduct: string | { code?: string; service_code?: string }
): string {
  if (typeof codeOrProduct === "object") {
    if (codeOrProduct.service_code) return codeOrProduct.service_code;
    return productService(codeOrProduct.code ?? "");
  }
  const code = codeOrProduct;
  if (code.startsWith("tier_")) return "chat";
  if (code.startsWith("xout-")) return "xout";
  return "platform";
}

/**
 * Return a link target for a product.
 * Accepts a product object (preferred) or a bare code string.
 */
export function productLink(
  codeOrProduct: string | { code?: string; service_code?: string }
): ProductLink {
  const svc = productService(codeOrProduct);
  const info = SERVICE_URLS[svc];
  if (!info || !info.url) return { url: null, comingSoon: false };
  return { url: info.url, comingSoon: info.comingSoon };
}
