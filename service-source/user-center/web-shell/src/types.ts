// Shared types for the web-shell. Kept tiny on purpose — every
// consumer of this package depends on these shapes, so additions need
// to be load-bearing, not aspirational.

export type LocaleId = "en" | "zh" | "ja" | "ko" | "de";

export type LocaleEntry = {
  id: LocaleId;
  /** Display name in the locale itself, e.g. "中文". */
  nativeName: string;
};

export type BrandConfig = {
  /** Display name of the umbrella product, e.g. "Develop". */
  name: string;
  /** Owning company, shown in footers / login pages. */
  company: string;
  /** Optional one-liner shown under the brand name. */
  tagline?: string;
  /** Public URL of the logo (square, transparent PNG). Served by the
   *  consumer's `/public/` so it works on every Develop subdomain. */
  logoUrl: string;
  /** URL of the home service — clicking the logo goes here. */
  homeUrl: string;
};

/**
 * One Develop service in the umbrella. The ServicesMenu in the header
 * shows the current entry as a chip and lets the user jump to any of
 * the others. Anything not in this list isn't part of the unified
 * shell (e.g. internal tooling).
 */
export type ServiceEntry = {
  /** Stable identifier — also drives which entry is "current". */
  id: string;
  /** Label shown in the menu in the user's locale. */
  label: Record<LocaleId, string>;
  /** One-line description shown under the label in the dropdown. */
  description?: Record<LocaleId, string>;
  /** Absolute URL of the service home, e.g. https://chat.develop.cc. */
  url: string;
  /**
   * If true, the entry shows up in the menu but isn't yet a real
   * destination (we render it disabled / "coming soon"). Useful while
   * a service is still being built.
   */
  comingSoon?: boolean;
};

export type UserInfo = {
  /** Stable user id from user-service. */
  id: string;
  /** Email is the only field we always have. */
  email: string;
  /** Optional display name. */
  name?: string;
  /** Optional avatar URL. We render a coloured monogram if missing. */
  avatarUrl?: string;
};

export type SignedOutInfo = { signedIn: false };
export type SignedInInfo = { signedIn: true; user: UserInfo };
export type AuthState = SignedOutInfo | SignedInInfo;

/** A single nav item the consuming service injects into the header
 *  middle slot — e.g. chat shows "Chat" + "Images" here. */
export type HeaderNavItem = {
  id: string;
  label: string;
  href: string;
  /** True if this item represents the page the user is on right now. */
  current?: boolean;
};
