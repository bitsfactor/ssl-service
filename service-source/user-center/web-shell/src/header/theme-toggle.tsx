"use client";

import { MonitorIcon, MoonIcon, SunIcon } from "lucide-react";
import { useTheme } from "next-themes";
import { DropdownMenu as DropdownPrimitive } from "radix-ui";

import { HEADER_STRINGS } from "../i18n/strings";
import { cn } from "../lib/cn";
import type { LocaleId } from "../types";

/**
 * Light/dark/system toggle, backed by `next-themes`. The button shows
 * the icon for the *resolved* theme (so users see what they'd toggle
 * away from); the dropdown lets them lock to system if they prefer.
 *
 * `next-themes` must be set up in the host's root layout — this
 * component just consumes the hook.
 */
export function ThemeToggle({ locale }: { locale: LocaleId }) {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const t = HEADER_STRINGS[locale];

  const Icon = resolvedTheme === "dark" ? MoonIcon : SunIcon;

  return (
    <DropdownPrimitive.Root>
      <DropdownPrimitive.Trigger asChild>
        <button
          aria-label={t.theme}
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted/70 hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
          title={t.theme}
          type="button"
        >
          <Icon className="size-4" />
        </button>
      </DropdownPrimitive.Trigger>
      <DropdownPrimitive.Portal>
        <DropdownPrimitive.Content
          align="end"
          className="z-50 w-40 rounded-xl border border-border/60 bg-card/95 p-1 shadow-[var(--shadow-float)] backdrop-blur-xl"
          sideOffset={6}
        >
          {(
            [
              { id: "light", label: t.themeLight, Icon: SunIcon },
              { id: "dark", label: t.themeDark, Icon: MoonIcon },
              { id: "system", label: t.themeSystem, Icon: MonitorIcon },
            ] as const
          ).map((opt) => (
            <DropdownPrimitive.Item
              className={cn(
                "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none transition-colors data-[highlighted]:bg-muted/70",
                theme === opt.id && "bg-muted/40"
              )}
              key={opt.id}
              onSelect={() => setTheme(opt.id)}
            >
              <opt.Icon className="size-3.5 text-muted-foreground" />
              <span>{opt.label}</span>
            </DropdownPrimitive.Item>
          ))}
        </DropdownPrimitive.Content>
      </DropdownPrimitive.Portal>
    </DropdownPrimitive.Root>
  );
}
