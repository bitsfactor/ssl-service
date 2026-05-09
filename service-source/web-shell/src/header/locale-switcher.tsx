"use client";

import { CheckIcon, LanguagesIcon } from "lucide-react";
import { DropdownMenu as DropdownPrimitive } from "radix-ui";

import { HEADER_STRINGS } from "../i18n/strings";
import type { LocaleEntry, LocaleId } from "../types";

/**
 * Header-version of the locale switcher. Triggers a host-supplied
 * `onSelect(locale)` because cookie + reload semantics differ between
 * apps (chatbot uses `LOCALE_COOKIE` + `window.location.reload()`,
 * other consumers may store the choice differently).
 */
export function LocaleSwitcher({
  locale,
  locales,
  onSelect,
}: {
  locale: LocaleId;
  locales: LocaleEntry[];
  onSelect: (next: LocaleId) => void;
}) {
  const t = HEADER_STRINGS[locale];
  const current = locales.find((l) => l.id === locale);
  return (
    <DropdownPrimitive.Root>
      <DropdownPrimitive.Trigger asChild>
        <button
          aria-label={t.language}
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
          title={t.language + (current ? ` · ${current.nativeName}` : "")}
          type="button"
        >
          <LanguagesIcon className="size-4" />
        </button>
      </DropdownPrimitive.Trigger>
      <DropdownPrimitive.Portal>
        <DropdownPrimitive.Content
          align="end"
          className="z-50 w-44 rounded-xl border border-border/60 bg-card/95 p-1 shadow-[var(--shadow-float)] backdrop-blur-xl"
          sideOffset={6}
        >
          <div className="px-2 pt-1.5 pb-1 text-muted-foreground text-[11px]">
            {t.language}
          </div>
          {locales.map((l) => {
            const active = l.id === locale;
            return (
              <DropdownPrimitive.Item
                className="flex cursor-pointer items-center justify-between rounded-md px-2 py-1.5 text-sm outline-none transition-colors data-[highlighted]:bg-muted/70 data-[disabled]:opacity-50"
                key={l.id}
                onSelect={() => onSelect(l.id)}
              >
                <span>{l.nativeName}</span>
                {active && <CheckIcon className="size-3.5" />}
              </DropdownPrimitive.Item>
            );
          })}
        </DropdownPrimitive.Content>
      </DropdownPrimitive.Portal>
    </DropdownPrimitive.Root>
  );
}
