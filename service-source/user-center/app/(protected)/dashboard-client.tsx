"use client";

import Link from "next/link";
import { ExternalLinkIcon, UserIcon, TrendingUpIcon } from "lucide-react";
import { useT } from "@/lib/i18n/i18n-provider";
import type { UserProfile, UsageInfo } from "@/lib/api/server";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
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

export function DashboardClient({
  user,
  usage,
}: {
  user: UserProfile;
  usage: UsageInfo | null;
}) {
  const t = useT();
  const displayName = user.display_name || user.email;

  // Resolve tier name for the user's locale (fallback chain: locale → en → tier_code)
  function getTierName(u: UsageInfo, locale: string): string {
    return (
      u.tier_name?.[locale] ??
      u.tier_name?.["en"] ??
      u.tier_code
    );
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
                  {getTierName(usage, user.locale ?? "en")}
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
          <Link href="/profile">
            <UserIcon className="size-3.5" />
            {t("dashboard.editProfile")}
          </Link>
        </Button>
      </div>
    </div>
  );
}
