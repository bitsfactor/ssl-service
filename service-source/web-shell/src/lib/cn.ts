/**
 * Lightweight class-name joiner. We don't pull in clsx/tailwind-merge
 * here because every consumer already ships them and we want zero
 * runtime deps in `@bitsfactor/web-shell`.
 */
export function cn(...args: Array<string | undefined | null | false>): string {
  return args.filter(Boolean).join(" ");
}

/**
 * Hash an email into a hue (0-359) for the avatar gradient. Same
 * algorithm chatbot used in its sidebar-user-nav so an existing user
 * keeps the same colour after the header migration.
 */
export function emailToHue(email: string): number {
  let hash = 0;
  for (const char of email) {
    hash = char.charCodeAt(0) + ((hash << 5) - hash);
  }
  return Math.abs(hash) % 360;
}
