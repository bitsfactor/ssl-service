// Public surface of @bitsfactor/web-shell. Each consumer imports
// from "@web-shell/*" via the path alias they declare in their own
// tsconfig — see chatbot/tsconfig.json for the canonical setup.

export { DEFAULT_BRAND } from "./branding";
export { DEFAULT_SERVICES } from "./services";
export { HEADER_STRINGS } from "./i18n/strings";
export type { HeaderStrings } from "./i18n/strings";
export { cn, emailToHue } from "./lib/cn";
export { LocaleSwitcher } from "./header/locale-switcher";
export { ServicesMenu } from "./header/services-menu";
export { SiteHeader } from "./header/site-header";
export { ThemeToggle } from "./header/theme-toggle";
export { UserMenu } from "./header/user-menu";
export type {
  AuthState,
  BrandConfig,
  HeaderNavItem,
  LocaleEntry,
  LocaleId,
  ServiceEntry,
  SignedInInfo,
  SignedOutInfo,
  UserInfo,
} from "./types";
