"use client";

import { ChevronDownIcon, GridIcon } from "lucide-react";
import { DropdownMenu as DropdownPrimitive } from "radix-ui";
import { useMemo } from "react";

import { HEADER_STRINGS } from "../i18n/strings";
import { cn } from "../lib/cn";
import type { LocaleId, ServiceEntry } from "../types";

/**
 * Left-edge of the header middle section. Shows the current service
 * as a chip with a chevron; clicking it opens a panel listing every
 * other service the user can jump to.
 */
export function ServicesMenu({
  services,
  currentServiceId,
  locale,
}: {
  services: ServiceEntry[];
  currentServiceId: string;
  locale: LocaleId;
}) {
  const t = HEADER_STRINGS[locale];
  const current = useMemo(
    () => services.find((s) => s.id === currentServiceId),
    [services, currentServiceId]
  );

  // Defensive: if a consumer passes an unknown id we still render the
  // menu rather than throwing — better degraded than broken.
  const currentLabel = current?.label?.[locale] ?? currentServiceId;

  return (
    <DropdownPrimitive.Root>
      <DropdownPrimitive.Trigger asChild>
        <button
          aria-label={t.switchService}
          className="flex h-8 items-center gap-1.5 rounded-md px-2 text-foreground text-sm transition-colors hover:bg-muted/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
          type="button"
        >
          <GridIcon className="size-3.5 text-muted-foreground" />
          <span className="font-medium">{currentLabel}</span>
          <ChevronDownIcon className="size-3.5 text-muted-foreground" />
        </button>
      </DropdownPrimitive.Trigger>
      <DropdownPrimitive.Portal>
        <DropdownPrimitive.Content
          align="start"
          className="z-50 w-72 rounded-xl border border-border/60 bg-card/95 p-1.5 shadow-[var(--shadow-float)] backdrop-blur-xl"
          sideOffset={6}
        >
          <div className="px-2 pt-1.5 pb-2">
            <div className="font-medium text-foreground text-xs">
              {t.switchService}
            </div>
            <div className="mt-0.5 text-muted-foreground text-[11px]">
              {t.switchServiceDesc}
            </div>
          </div>
          <div className="flex flex-col gap-0.5">
            {services.map((s) => {
              const isCurrent = s.id === currentServiceId;
              const disabled = !!s.comingSoon && !isCurrent;
              const label = s.label?.[locale] ?? s.id;
              const desc = s.description?.[locale];
              const inner = (
                <div className="flex w-full flex-col gap-0.5 px-2 py-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span
                      className={cn(
                        "font-medium",
                        disabled && "text-muted-foreground"
                      )}
                    >
                      {label}
                    </span>
                    {isCurrent ? (
                      <span className="rounded-full bg-primary/15 px-1.5 py-0.5 text-[10px] text-foreground/80">
                        ●
                      </span>
                    ) : disabled ? (
                      <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        {t.comingSoon}
                      </span>
                    ) : null}
                  </div>
                  {desc ? (
                    <div className="line-clamp-1 text-[11px] text-muted-foreground">
                      {desc}
                    </div>
                  ) : null}
                </div>
              );
              return (
                <DropdownPrimitive.Item
                  asChild
                  disabled={disabled}
                  key={s.id}
                  onSelect={(e) => {
                    if (disabled || isCurrent) {
                      e.preventDefault();
                    }
                  }}
                >
                  {disabled || isCurrent ? (
                    <div
                      className={cn(
                        "flex cursor-default select-none rounded-md outline-none",
                        isCurrent && "bg-muted/60",
                        disabled && "opacity-60"
                      )}
                    >
                      {inner}
                    </div>
                  ) : (
                    <a
                      className="flex select-none rounded-md outline-none transition-colors hover:bg-muted/70 focus-visible:bg-muted/70"
                      href={s.url}
                    >
                      {inner}
                    </a>
                  )}
                </DropdownPrimitive.Item>
              );
            })}
          </div>
        </DropdownPrimitive.Content>
      </DropdownPrimitive.Portal>
    </DropdownPrimitive.Root>
  );
}
