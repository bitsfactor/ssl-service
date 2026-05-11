import type { BrandConfig } from "./types";

/**
 * Default brand for every Develop service. If a consumer needs to
 * override (e.g. demo deployment), pass a different `BrandConfig` to
 * the `<SiteHeader>` directly.
 *
 * `logoUrl` is a relative path; each consuming app should mirror the
 * file at the same path under its own `/public/` so the URL resolves
 * on every subdomain. The asset is the 256px Develop mark generated
 * for v1.5 — see project memory for provenance.
 */
export const DEFAULT_BRAND: BrandConfig = {
  name: "Develop",
  company: "BitsFactor LLC",
  tagline: "Your team's AI workspace",
  logoUrl: "/logo.png",
  // Every service's header brand mark deep-links to the chat app.
  // Earlier this pointed at the marketing site (develop.cc); users
  // expected clicking the logo from user-center / future surfaces to
  // take them straight to chatting, so we route there directly.
  homeUrl: "https://chat.develop.cc",
};
