# @bitsfactor/web-shell

Shared React components for the unified Develop site shell — header,
service registry, locale + theme + user menus. Imported by `chatbot`,
`home`, `user-center`.

This is a **path-aliased** package, not an npm package: each consumer
declares `@web-shell/*` in `tsconfig.json` and adds `../web-shell/src`
to its Tailwind content array. We don't publish to a registry; the
source is read straight from this folder.

## Layout

- `src/types.ts` — shared types (`ServiceEntry`, `UserInfo`,
  `BrandConfig`, `LocaleEntry`).
- `src/branding.ts` — Develop / BitsFactor LLC defaults (logo URL,
  tagline, etc.).
- `src/services.ts` — registry of all Develop services with id, label,
  url, locale-aware names.
- `src/header/site-header.tsx` — the main `<SiteHeader>` component.
- `src/header/services-menu.tsx` — current-service chip + dropdown to
  switch.
- `src/header/user-menu.tsx` — avatar + name + dropdown
  (settings/sign-out, or login/register link if anonymous).
- `src/header/locale-switcher.tsx` — language picker (cookie + reload).
- `src/header/theme-toggle.tsx` — light/dark toggle backed by
  `next-themes`.
- `src/i18n/strings.ts` — header-local strings in 5 locales (`en`,
  `zh`, `ja`, `ko`, `de`).

## Peer dependencies (consumer must provide)

- `react`, `react-dom`
- `next-themes` — used by `<ThemeToggle>`.
- `lucide-react` — icons.
- `radix-ui` — dropdown primitives.
- Tailwind CSS — classes.
