/**
 * Product-code → URL mapping for the "My Subscriptions" card.
 *
 * Rules:
 *   tier_*   → https://chat.develop.cc/ (AI tier unlocks DevChat)
 *   xout-*   → https://xout.develop.cc/ (coming soon)
 *   anything else → no link
 *
 * Add new products here as the platform grows.
 */
export type ProductLink = {
  url: string | null;
  comingSoon: boolean;
};

export function productLink(code: string): ProductLink {
  if (code.startsWith("tier_")) {
    return { url: "https://chat.develop.cc/", comingSoon: false };
  }
  if (code.startsWith("xout-")) {
    return { url: "https://xout.develop.cc/", comingSoon: true };
  }
  return { url: null, comingSoon: false };
}
