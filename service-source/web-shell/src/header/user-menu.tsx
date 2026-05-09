"use client";

import { LogOutIcon, SettingsIcon, UserIcon } from "lucide-react";
import { DropdownMenu as DropdownPrimitive } from "radix-ui";

import { HEADER_STRINGS } from "../i18n/strings";
import { cn, emailToHue } from "../lib/cn";
import type { AuthState, LocaleId } from "../types";

/**
 * Right side of the header. Two states:
 *
 *   - Signed in: avatar + name/email chip with a dropdown that has
 *     "My account" (deep-link to user-center), "Preferences", and
 *     "Sign out".
 *   - Anonymous: simple "Sign in" + "Sign up" pair.
 *
 * The host wires the actual URLs — different services may want
 * `/login` (chatbot, app-internal) vs the absolute `user.develop.cc`
 * URL (anything cross-domain). Sign-out is also host-driven because
 * each app handles its own session teardown.
 */
export function UserMenu({
  auth,
  locale,
  signInUrl,
  signUpUrl,
  accountUrl,
  preferencesUrl,
  onSignOut,
}: {
  auth: AuthState;
  locale: LocaleId;
  signInUrl: string;
  signUpUrl: string;
  accountUrl: string;
  preferencesUrl?: string;
  onSignOut: () => void;
}) {
  const t = HEADER_STRINGS[locale];

  if (!auth.signedIn) {
    return (
      <div className="flex items-center gap-1">
        <a
          className="flex h-8 items-center rounded-md px-3 text-muted-foreground text-sm transition-colors hover:bg-muted/70 hover:text-foreground"
          href={signInUrl}
        >
          {t.signIn}
        </a>
        <a
          className="flex h-8 items-center rounded-md bg-foreground px-3 text-background text-sm transition-opacity hover:opacity-90"
          href={signUpUrl}
        >
          {t.signUp}
        </a>
      </div>
    );
  }

  const { user } = auth;
  const display = user.name || user.email;
  const hue = emailToHue(user.email || "");

  return (
    <DropdownPrimitive.Root>
      <DropdownPrimitive.Trigger asChild>
        <button
          aria-label={t.openMenu}
          className="flex h-8 max-w-[200px] items-center gap-2 rounded-full border border-border/40 bg-card/60 pr-3 pl-1 text-foreground text-sm transition-colors hover:bg-muted/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
          type="button"
        >
          {user.avatarUrl ? (
            // biome-ignore lint/performance/noImgElement: small avatar
            <img
              alt=""
              className="size-6 rounded-full object-cover"
              src={user.avatarUrl}
            />
          ) : (
            <span
              aria-hidden
              className="flex size-6 items-center justify-center rounded-full text-[11px] text-white"
              style={{
                background: `linear-gradient(135deg, oklch(0.55 0.13 ${hue}), oklch(0.4 0.1 ${hue + 40}))`,
              }}
            >
              {(display[0] ?? "?").toUpperCase()}
            </span>
          )}
          <span className="truncate">{display}</span>
        </button>
      </DropdownPrimitive.Trigger>
      <DropdownPrimitive.Portal>
        <DropdownPrimitive.Content
          align="end"
          className="z-50 w-56 rounded-xl border border-border/60 bg-card/95 p-1 shadow-[var(--shadow-float)] backdrop-blur-xl"
          sideOffset={6}
        >
          <div className="border-border/40 border-b px-3 py-2">
            <div className="truncate font-medium text-sm">{display}</div>
            {user.name && user.email !== display ? (
              <div className="truncate text-muted-foreground text-xs">
                {user.email}
              </div>
            ) : null}
          </div>

          <DropdownPrimitive.Item asChild>
            <a
              className={cn(
                "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none transition-colors data-[highlighted]:bg-muted/70"
              )}
              href={accountUrl}
            >
              <UserIcon className="size-3.5 text-muted-foreground" />
              {t.myAccount}
            </a>
          </DropdownPrimitive.Item>

          {preferencesUrl ? (
            <DropdownPrimitive.Item asChild>
              <a
                className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none transition-colors data-[highlighted]:bg-muted/70"
                href={preferencesUrl}
              >
                <SettingsIcon className="size-3.5 text-muted-foreground" />
                {t.preferences}
              </a>
            </DropdownPrimitive.Item>
          ) : null}

          <DropdownPrimitive.Separator className="my-1 h-px bg-border/40" />

          <DropdownPrimitive.Item
            className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none transition-colors data-[highlighted]:bg-muted/70"
            onSelect={() => onSignOut()}
          >
            <LogOutIcon className="size-3.5 text-muted-foreground" />
            {t.signOut}
          </DropdownPrimitive.Item>
        </DropdownPrimitive.Content>
      </DropdownPrimitive.Portal>
    </DropdownPrimitive.Root>
  );
}
