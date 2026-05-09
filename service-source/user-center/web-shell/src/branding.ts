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
  homeUrl: "https://develop.cc",
};
