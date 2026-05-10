"use client";

import Link from "next/link";
import { ExternalLinkIcon, UserIcon, TrendingUpIcon, PackageIcon } from "lucide-react";
import { useT, useI18n } from "@/lib/i18n/i18n-provider";
import type { UserProfile, UsageInfo, Subscription, Product } from "@/lib/api/server";
import { productLink, productService, resolveLocaleString } from "@/lib/products";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/** Format a cent value as a friendly dollar amount, e.g. 150 → "$1.50" */
function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function UsageBar({
  consumed,
  limit,
}: {
  consumed: number;
  limit: number;
}) {
  // limit of 0 means unlimited
  if (limit === 0) return null;
  const pct = Math.min(100, Math.round((consumed / limit) * 100));
  const barColor =
    pct >= 90
      ? "bg-destructive"
      : pct >= 70
        ? "bg-amber-500 dark:bg-amber-400"
        : "bg-primary";
  return (
    <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-muted">
      <div
        className={`h-full rounded-full transition-all ${barColor}`}
        style={{ width: `${pct}%` }}
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </div>
  );
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "active") return "default";
  if (status === "past_due") return "outline";
  return "secondary";
}

function statusBadgeClass(status: string): string {
  if (status === "active") return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30";
  if (status === "past_due") return "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30";
  return "bg-muted text-muted-foreground";
}

function productLabel(p: Product, locale: string): string {
  if (typeof p.name === "string") return p.name;
  if (p.name && typeof p.name === "object") {
    return resolveLocaleString(p.name as Record<string, string>, locale) || p.code || "";
  }
  return p.code ?? "";
}

function serviceLabel(serviceCode: string | undefined, t: (key: string) => string): string {
  if (serviceCode === "chat") return t("dashboard.serviceSectionChat");
  if (serviceCode === "xout") return t("dashboard.serviceSectionXout");
  return t("dashboard.serviceSectionPlatform");
}

export function DashboardClient({
  user,
  usage,
  subscriptions,
  products,
}: {
  user: UserProfile;
  usage: UsageInfo | null;
  subscriptions: Subscription[];
  products: Product[];
}) {
  const t = useT();
  const { locale } = useI18n();

  // Resolve tier name for the user's locale. tier_name uses "zh-CN"/"en-US"
  // keys from the DB; resolveLocaleString handles short→long code expansion.
  function getTierName(u: UsageInfo): string {
    return resolveLocaleString(u.tier_name, locale) || u.tier_code;
  }

  // Cross-reference subscription with /api/products for description
  function productDescriptionFor(sub: Subscription): string {
    const found = products.find((p) => p.code === sub.product_code);
    return found?.description ?? "";
  }

  function subProductLabel(sub: Subscription): string {
    // product_name is a JSONB map with "zh-CN"/"en-US" keys from the backend.
    // resolveLocaleString handles the short→long form expansion.
    return resolveLocaleString(sub.product_name, locale) || sub.product_code;
  }

  function periodLabel(sub: Subscription): string {
    if (sub.kind === "lifetime" || (!sub.expires_at && sub.kind !== "recurring")) {
      return t("dashboard.subscriptionLifetime");
    }
    if (sub.expires_at) {
      const d = new Date(sub.expires_at);
      return t("dashboard.subscriptionRenews", {
        date: d.toLocaleDateString(locale === "zh" ? "zh-CN" : locale, {
          year: "numeric",
          month: "short",
          day: "numeric",
        }),
      });
    }
    // recurring with no expires_at = ongoing, no renewal date yet known
    return t("dashboard.subscriptionLifetime");
  }

  return (
    <div className="p-4 md:p-8 max-w-2xl fade-up">
      {/* Welcome */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">
          {user.display_name
            ? t("dashboard.welcomeTitle", { name: user.display_name })
            : t("dashboard.welcomeTitleNoName")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">{user.email}</p>
      </div>

      {/* Trial credit banner (Job 2) */}
      {usage && typeof usage.trial_credit_cents === "number" && usage.trial_credit_cents > 0 ? (
        <div className="mb-4 flex items-center justify-between rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3">
          <div>
            <p className="text-sm font-medium text-amber-700 dark:text-amber-400">
              {t("dashboard.trialCreditRemaining")}
            </p>
          </div>
          <span className="font-semibold tabular-nums text-amber-700 dark:text-amber-400">
            ${(usage.trial_credit_cents / 100).toFixed(2)}
          </span>
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Plan card */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle>{t("dashboard.currentPlan")}</CardTitle>
              <TrendingUpIcon className="size-4 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            {usage ? (
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-sm font-semibold h-auto px-2 py-0.5">
                  {getTierName(usage)}
                </Badge>
                {usage.discount_factor < 1 ? (
                  <Badge variant="outline" className="text-xs">
                    {t("billing.discountBadge", {
                      discount: Math.round((1 - usage.discount_factor) * 100),
                    })}
                  </Badge>
                ) : null}
              </div>
            ) : (
              <span className="text-sm text-muted-foreground">
                {t("dashboard.planLoading")}
              </span>
            )}
            <p className="mt-3 text-xs text-muted-foreground">
              {usage?.reset_kind === "daily"
                ? t("dashboard.resetDaily")
                : usage?.reset_kind === "monthly"
                  ? t("dashboard.resetMonthly")
                  : usage
                    ? t("dashboard.resetNever")
                    : ""}
            </p>
          </CardContent>
        </Card>

        {/* Usage card */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle>{t("dashboard.dailyUsage")}</CardTitle>
              <span className="text-xs text-muted-foreground">USD</span>
            </div>
          </CardHeader>
          <CardContent>
            {usage ? (
              <>
                <div className="text-lg font-semibold tabular-nums">
                  {usage.limit_cents === 0
                    ? t("dashboard.unlimited")
                    : t("dashboard.usageOf", {
                        consumed: formatCents(usage.consumed_cents),
                        limit: formatCents(usage.limit_cents),
                      })}
                </div>
                {usage.limit_cents > 0 ? (
                  <>
                    <UsageBar
                      consumed={usage.consumed_cents}
                      limit={usage.limit_cents}
                    />
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t("dashboard.usageRemaining", {
                        remaining: formatCents(usage.remaining_cents),
                      })}
                    </p>
                  </>
                ) : null}
              </>
            ) : (
              <span className="text-sm text-muted-foreground">
                {t("dashboard.usageLoading")}
              </span>
            )}
          </CardContent>
        </Card>
      </div>

      {/* My Subscriptions */}
      <Card className="mt-4">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle>{t("dashboard.mySubscriptions")}</CardTitle>
            <PackageIcon className="size-4 text-muted-foreground" />
          </div>
        </CardHeader>
        <CardContent>
          {subscriptions.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("dashboard.subscriptionsEmpty")}
            </p>
          ) : (() => {
            // Group by service_code so we can render section headers (Job 4).
            const grouped = new Map<string, Subscription[]>();
            for (const sub of subscriptions) {
              const svc = sub.service_code ?? "platform";
              if (!grouped.has(svc)) grouped.set(svc, []);
              grouped.get(svc)!.push(sub);
            }
            return (
              <div className="space-y-4">
                {Array.from(grouped.entries()).map(([svc, subs]) => (
                  <div key={svc}>
                    <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      {serviceLabel(svc, t)}
                    </p>
                    <ul className="space-y-2">
                      {subs.map((sub) => {
                        const link = productLink({ code: sub.product_code, service_code: sub.service_code });
                        const description = productDescriptionFor(sub);
                        return (
                          <li
                            key={sub.id}
                            className="flex items-start gap-3 rounded-xl border border-border/60 p-3"
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-sm font-medium">
                                  {subProductLabel(sub)}
                                </span>
                                <span
                                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${statusBadgeClass(sub.status)}`}
                                >
                                  {t("dashboard.subscriptionStatus", {
                                    status: sub.status,
                                  })}
                                </span>
                              </div>
                              {description ? (
                                <p className="mt-0.5 text-xs text-muted-foreground">
                                  {description}
                                </p>
                              ) : null}
                              <p className="mt-1 text-xs text-muted-foreground">
                                {periodLabel(sub)}
                              </p>
                            </div>
                            <div className="shrink-0">
                              {link.url ? (
                                link.comingSoon ? (
                                  <span className="inline-flex items-center rounded-md border border-border/60 px-2.5 py-1 text-xs text-muted-foreground">
                                    {t("dashboard.subscriptionComingSoon")}
                                  </span>
                                ) : (
                                  <Button size="sm" variant="outline" asChild>
                                    <a
                                      href={link.url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                    >
                                      {t("dashboard.subscriptionOpen")}
                                      <ExternalLinkIcon className="ml-1 size-3" />
                                    </a>
                                  </Button>
                                )
                              ) : null}
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
              </div>
            );
          })()}
        </CardContent>
      </Card>

      {/* CTAs */}
      <div className="mt-6 flex flex-wrap gap-3">
        <Button asChild>
          <a
            href="https://chat.develop.cc"
            target="_blank"
            rel="noopener noreferrer"
          >
            {t("dashboard.openChat")}
            <ExternalLinkIcon className="ml-1.5 size-3.5" />
          </a>
        </Button>
        <Button variant="outline" asChild>
          <Link href="/account">
            <UserIcon className="size-3.5" />
            {t("dashboard.editProfile")}
          </Link>
        </Button>
      </div>
    </div>
  );
}
