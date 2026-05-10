"use client";

import { useT, useI18n } from "@/lib/i18n/i18n-provider";
import type { UsageInfo, Product, ModelPricing, UsageTokens, TokenUsagePeriod } from "@/lib/api/server";
import { resolveLocaleString } from "@/lib/products";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { InfoIcon } from "lucide-react";

function productLabel(p: Product, locale: string): string {
  if (typeof p.name === "string") return p.name;
  if (p.name && typeof p.name === "object") {
    return resolveLocaleString(p.name as Record<string, string>, locale) || p.code || "";
  }
  return p.code ?? "";
}


function modelLabel(p: ModelPricing): string {
  return p.model_id ?? p.model ?? "";
}
function modelInput(p: ModelPricing): number | null {
  return p.input_rate_per_1m_usd ?? p.input_per_million ?? null;
}
function modelCached(p: ModelPricing): number | null {
  return p.cached_input_rate_per_1m_usd ?? p.cached_per_million ?? null;
}
function modelOutput(p: ModelPricing): number | null {
  return p.output_rate_per_1m_usd ?? p.output_per_million ?? null;
}
function fmtUsd(n: number | null | undefined): string {
  return n == null ? "—" : `$${n.toFixed(2)}`;
}

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function UsageBar({ consumed, limit }: { consumed: number; limit: number }) {
  if (limit === 0) return null;
  const pct = Math.min(100, Math.round((consumed / limit) * 100));
  const barColor =
    pct >= 90
      ? "bg-destructive"
      : pct >= 70
        ? "bg-amber-500 dark:bg-amber-400"
        : "bg-primary";
  return (
    <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
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

const fmt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });

function TokenUsageTable({ period }: { period: TokenUsagePeriod }) {
  const t = useT();
  if (period.by_model.length === 0) {
    return (
      <p className="text-sm text-muted-foreground py-2">{t("billing.tokenNoData")}</p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border/60 text-muted-foreground text-xs uppercase tracking-wide">
            <th className="pb-2 text-left font-medium">{t("billing.modelLabel")}</th>
            <th className="pb-2 text-right font-medium">{t("billing.inputTokens")}</th>
            <th className="pb-2 text-right font-medium">{t("billing.cachedTokens")}</th>
            <th className="pb-2 text-right font-medium">{t("billing.outputTokens")}</th>
            <th className="pb-2 text-right font-medium">¢</th>
          </tr>
        </thead>
        <tbody>
          {period.by_model.map((row) => (
            <tr key={row.model_id} className="border-b border-border/40 last:border-0">
              <td className="py-2 pr-4 font-mono text-xs">{row.model_id}</td>
              <td className="py-2 text-right tabular-nums text-xs">
                {row.images != null
                  ? `${fmt.format(row.images)} img`
                  : fmt.format(row.input_tokens)}
              </td>
              <td className="py-2 text-right tabular-nums text-xs">
                {row.cached_input_tokens ? fmt.format(row.cached_input_tokens) : "—"}
              </td>
              <td className="py-2 text-right tabular-nums text-xs">
                {row.images != null
                  ? "—"
                  : fmt.format(row.output_tokens)}
              </td>
              <td className="py-2 text-right tabular-nums text-xs">
                {row.cents.toFixed(2)}
              </td>
            </tr>
          ))}
        </tbody>
        <tfoot>
          <tr className="border-t border-border/60 font-medium text-xs">
            <td className="pt-2 text-muted-foreground">Total</td>
            <td className="pt-2 text-right tabular-nums">{fmt.format(period.total_input_tokens)}</td>
            <td className="pt-2 text-right tabular-nums">{fmt.format(period.total_cached_input_tokens)}</td>
            <td className="pt-2 text-right tabular-nums">{fmt.format(period.total_output_tokens)}</td>
            <td className="pt-2 text-right tabular-nums">{period.total_cents.toFixed(2)}</td>
          </tr>
        </tfoot>
      </table>
    </div>
  );
}

export function BillingClient({
  usage,
  usageTokens,
  products,
  pricing,
}: {
  usage: UsageInfo | null;
  usageTokens: UsageTokens | null;
  products: Product[];
  pricing: ModelPricing[];
}) {
  const t = useT();
  const { locale } = useI18n();

  function getTierName(tierName: Record<string, string>): string {
    return resolveLocaleString(tierName, locale);
  }

  const discountPct = usage
    ? Math.round((1 - usage.discount_factor) * 100)
    : 0;

  return (
    <div className="p-4 md:p-8 max-w-2xl fade-up">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("billing.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("billing.subtitle")}
        </p>
      </div>

      {/* Account credit card (trial credit — Job 2) */}
      {usage && typeof usage.trial_credit_cents === "number" ? (
        <Card className="mb-6">
          <CardHeader className="pb-3">
            <CardTitle>{t("billing.trialCredit")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t("billing.trialCreditRemaining")}</span>
              <span className="font-semibold tabular-nums">
                {formatCents(usage.trial_credit_cents)}
              </span>
            </div>
            {usage.trial_credit_cents === 0 ? (
              <p className="mt-2 text-xs text-muted-foreground">
                {t("billing.trialCreditExhausted")}
              </p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {/* Current plan + usage */}
      {usage ? (
        <Card className="mb-6">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle>{t("billing.currentPlan")}</CardTitle>
              {discountPct > 0 ? (
                <Badge variant="success">
                  {t("billing.discountBadge", { discount: discountPct })}
                </Badge>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-baseline gap-2">
              <span className="text-xl font-semibold">
                {getTierName(usage.tier_name)}
              </span>
            </div>

            <div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{t("billing.dailyAllowance")}</span>
                <span className="font-medium tabular-nums">
                  {usage.limit_cents === 0
                    ? "∞"
                    : formatCents(usage.limit_cents)}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{t("billing.consumedToday")}</span>
                <span className="tabular-nums">{formatCents(usage.consumed_cents)}</span>
              </div>
              <div className="mt-1 flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{t("billing.remainingToday")}</span>
                <span className="tabular-nums font-medium">
                  {usage.limit_cents === 0
                    ? "∞"
                    : formatCents(usage.remaining_cents)}
                </span>
              </div>
              {usage.limit_cents > 0 ? (
                <UsageBar
                  consumed={usage.consumed_cents}
                  limit={usage.limit_cents}
                />
              ) : null}
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Token usage card (Job 1) */}
      {usageTokens ? (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>{t("billing.tokenUsage")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <h3 className="mb-2 text-sm font-medium">{t("billing.todayTokens")}</h3>
              <TokenUsageTable period={usageTokens.today} />
            </div>
            <div>
              <h3 className="mb-2 text-sm font-medium">{t("billing.allTimeTokens")}</h3>
              <TokenUsageTable period={usageTokens.all_time} />
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Chat channel plans table (was "All plans" — Job 4) */}
      {products.length > 0 ? (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>{t("billing.chatChannelPlans")}</CardTitle>
            <CardDescription>{t("billing.upgradeNote")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-muted-foreground text-xs uppercase tracking-wide">
                    <th className="pb-2 text-left font-medium">{t("billing.planName")}</th>
                    <th className="pb-2 text-right font-medium">{t("billing.planAllowance")}</th>
                    <th className="pb-2 text-right font-medium">{t("billing.planDiscount")}</th>
                    <th className="pb-2 text-right font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {products
                    .filter((p) =>
                      // Prefer authoritative service_code; fall back to prefix for older rows.
                      (p.service_code ? p.service_code === "chat" : (p.code ?? "").startsWith("tier_"))
                    )
                    .slice()
                    .sort(
                      (a, b) =>
                        (a.metadata?.tier_rank ?? 0) -
                        (b.metadata?.tier_rank ?? 0)
                    )
                    .map((p) => {
                      const isCurrent = usage?.tier_code === p.code;
                      const allowanceCents =
                        p.metadata?.daily_allowance_cents ??
                        p.metadata?.lifetime_trial_cents;
                      const allowanceLabel = allowanceCents
                        ? p.metadata?.daily_allowance_cents
                          ? formatCents(allowanceCents)
                          : `${formatCents(allowanceCents)} (one-time)`
                        : "—";
                      const priceLabel =
                        p.price_cents == null
                          ? "—"
                          : p.price_cents === 0
                            ? t("billing.freePlanName")
                            : `${formatCents(p.price_cents)}/mo`;
                      return (
                        <tr
                          key={p.id ?? p.code}
                          className="border-b border-border/40 last:border-0"
                        >
                          <td className="py-3 pr-4 font-medium">
                            {productLabel(p, locale)}
                            {isCurrent ? (
                              <Badge
                                variant="outline"
                                className="ml-2 text-[10px]"
                              >
                                {t("billing.currentBadge")}
                              </Badge>
                            ) : null}
                            <p className="mt-0.5 text-[11px] text-muted-foreground">
                              {priceLabel}
                            </p>
                          </td>
                          <td className="py-3 text-right tabular-nums">
                            {allowanceLabel}
                          </td>
                          <td className="py-3 text-right tabular-nums">
                            {discountPct > 0 ? `${discountPct}%` : "—"}
                          </td>
                          <td className="py-3 text-right">
                            {isCurrent ? null : (
                              <Button
                                variant="outline"
                                size="xs"
                                disabled
                              >
                                {t("billing.upgradeButton")}
                              </Button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Model pricing */}
      {pricing.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("billing.modelPricing")}</CardTitle>
            <CardDescription>
              {discountPct > 0
                ? t("billing.pricingNote", { discount: discountPct })
                : t("billing.pricingNoteNoDiscount")}
              {" "}
              <span className="text-muted-foreground/70">
                ({t("billing.pricingUnit")})
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/60 text-muted-foreground text-xs uppercase tracking-wide">
                    <th className="pb-2 text-left font-medium">{t("billing.modelName")}</th>
                    <th className="pb-2 text-right font-medium">{t("billing.inputPrice")}</th>
                    <th className="pb-2 text-right font-medium">{t("billing.cachedPrice")}</th>
                    <th className="pb-2 text-right font-medium">{t("billing.outputPrice")}</th>
                  </tr>
                </thead>
                <tbody>
                  {pricing.map((p) => {
                    const label = modelLabel(p);
                    return (
                      <tr
                        key={label}
                        className="border-b border-border/40 last:border-0"
                      >
                        <td className="py-2.5 pr-4 font-mono text-xs">
                          {label}
                        </td>
                        <td className="py-2.5 text-right tabular-nums text-xs">
                          {fmtUsd(modelInput(p))}
                        </td>
                        <td className="py-2.5 text-right tabular-nums text-xs">
                          {fmtUsd(modelCached(p))}
                        </td>
                        <td className="py-2.5 text-right tabular-nums text-xs">
                          {fmtUsd(modelOutput(p))}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="py-8">
            <div className="flex flex-col items-center gap-2 text-center">
              <InfoIcon className="size-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {t("billing.pricingLoading")}
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
