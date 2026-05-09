"use client";

import { ExternalLinkIcon, MessageSquareIcon, ShieldCheckIcon, LayoutGridIcon } from "lucide-react";
import { useT, useI18n } from "@/lib/i18n/i18n-provider";
import { productService, resolveLocaleString } from "@/lib/products";
import type { Product, Subscription, UsageInfo } from "@/lib/api/server";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";

/** Format cents as "$X.XX" */
function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

/** Localised product name — handles both short codes ("en") and long form ("en-US") keys. */
function productLabel(p: Product, locale: string): string {
  if (typeof p.name === "string") return p.name;
  if (p.name && typeof p.name === "object") {
    return resolveLocaleString(p.name as Record<string, string>, locale) || p.code || "";
  }
  return p.code ?? "";
}

/** Section config per service */
const SERVICE_ORDER = ["chat", "xout", "platform"] as const;

type ServiceConfig = {
  labelKey: "products.chatSection" | "products.xoutSection" | "products.platformSection";
  openKey: "products.openChat" | "products.openXout" | null;
  url: string | null;
  comingSoon: boolean;
  Icon: React.ComponentType<{ className?: string }>;
};

const SERVICE_CONFIG: Record<string, ServiceConfig> = {
  chat: {
    labelKey: "products.chatSection",
    openKey: "products.openChat",
    url: "https://chat.develop.cc/",
    comingSoon: false,
    Icon: MessageSquareIcon,
  },
  xout: {
    labelKey: "products.xoutSection",
    openKey: "products.openXout",
    url: "https://xout.develop.cc/",
    comingSoon: true,
    Icon: ShieldCheckIcon,
  },
  platform: {
    labelKey: "products.platformSection",
    openKey: null,
    url: null,
    comingSoon: false,
    Icon: LayoutGridIcon,
  },
};

function statusBadgeClass(status: string): string {
  if (status === "active")
    return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30";
  return "bg-muted text-muted-foreground";
}

export function ProductsClient({
  products,
  subscriptions,
  usage,
}: {
  products: Product[];
  subscriptions: Subscription[];
  usage: UsageInfo | null;
}) {
  const t = useT();
  const { locale } = useI18n();

  // Active subscription codes for quick lookup.
  const activeCodes = new Set(
    subscriptions.filter((s) => s.status === "active").map((s) => s.product_code)
  );

  // Group products by service_code.
  const grouped: Record<string, Product[]> = {};
  for (const p of products) {
    const svc = productService(p);
    grouped[svc] = grouped[svc] ?? [];
    grouped[svc].push(p);
  }

  const sortedServices = SERVICE_ORDER.filter(
    (svc) => grouped[svc] && grouped[svc].length > 0
  );

  // Also capture any service not in SERVICE_ORDER (future proofing).
  const unknownServices = Object.keys(grouped).filter(
    (svc) => !SERVICE_ORDER.includes(svc as (typeof SERVICE_ORDER)[number])
  );

  const allServices = [...sortedServices, ...unknownServices];

  function priceLabel(p: Product): string {
    if (!p.price_cents || p.price_cents === 0) return t("products.freeLabel");
    if (p.kind === "one_time") {
      return t("products.priceOnce", { price: formatCents(p.price_cents) });
    }
    if (p.kind === "period" && !p.period_days) {
      return t("products.priceLifetime");
    }
    return t("products.pricePer", { price: formatCents(p.price_cents) });
  }

  function descriptionFor(p: Product): string {
    const desc = p.description;
    if (!desc) return "";
    if (typeof desc === "string") return desc;
    return resolveLocaleString(desc as Record<string, string>, locale);
  }

  return (
    <div className="p-4 md:p-8 max-w-2xl fade-up">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("products.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("products.subtitle")}
        </p>
      </div>

      {allServices.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            {t("products.noProducts")}
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {allServices.map((svc) => {
            const cfg = SERVICE_CONFIG[svc] ?? SERVICE_CONFIG.platform;
            const { Icon } = cfg;
            const svcProducts = (grouped[svc] ?? []).slice().sort(
              (a, b) =>
                (a.metadata?.tier_rank ?? 0) - (b.metadata?.tier_rank ?? 0)
            );

            return (
              <Card key={svc}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <Icon className="size-4 text-muted-foreground" />
                      <CardTitle className="text-base">
                        {t(cfg.labelKey)}
                      </CardTitle>
                    </div>
                    {cfg.openKey && cfg.url ? (
                      cfg.comingSoon ? (
                        <span className="inline-flex items-center rounded-md border border-border/60 px-2.5 py-1 text-xs text-muted-foreground">
                          {t("products.comingSoon")}
                        </span>
                      ) : (
                        <Button size="sm" variant="outline" asChild>
                          <a
                            href={cfg.url}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {t(cfg.openKey)}
                            <ExternalLinkIcon className="ml-1 size-3" />
                          </a>
                        </Button>
                      )
                    ) : null}
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  {svcProducts.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      {t("products.serviceGroupEmpty")}
                    </p>
                  ) : (
                    <ul className="space-y-2">
                      {svcProducts.map((p) => {
                        const isActive = !!p.code && activeCodes.has(p.code);
                        const isCurrent =
                          (!!p.code && usage?.tier_code === p.code) || isActive;
                        const desc = descriptionFor(p);

                        return (
                          <li
                            key={p.id ?? p.code}
                            className="flex items-center gap-3 rounded-xl border border-border/60 p-3"
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-sm font-medium">
                                  {productLabel(p, locale)}
                                </span>
                                {isCurrent ? (
                                  <span
                                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${statusBadgeClass("active")}`}
                                  >
                                    {t("products.current")}
                                  </span>
                                ) : null}
                              </div>
                              {desc ? (
                                <p className="mt-0.5 text-xs text-muted-foreground">
                                  {desc}
                                </p>
                              ) : null}
                              <p className="mt-1 text-xs font-mono text-muted-foreground">
                                {priceLabel(p)}
                              </p>
                            </div>
                            <div className="shrink-0">
                              {isCurrent ? null : (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled
                                  title="Contact support to upgrade"
                                >
                                  {t("products.upgrade")}
                                </Button>
                              )}
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
