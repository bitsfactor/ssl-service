"use client";

import { useT, useI18n } from "@/lib/i18n/i18n-provider";
import type { Order } from "@/lib/api/server";
import { resolveLocaleString } from "@/lib/products";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function OrdersClient({ orders }: { orders: Order[] }) {
  const t = useT();
  const { locale } = useI18n();

  return (
    <div className="mx-auto max-w-3xl">
      <Card>
        <CardHeader>
          <CardTitle>{t("billing.ordersTitle")}</CardTitle>
          <CardDescription>{t("billing.ordersSubtitle")}</CardDescription>
        </CardHeader>
        <CardContent>
          {orders.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {t("billing.ordersEmpty")}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">{t("billing.ordersDate")}</th>
                    <th className="pb-2 pr-3 font-medium">{t("billing.ordersTier")}</th>
                    <th className="pb-2 pr-3 font-medium">{t("billing.ordersDuration")}</th>
                    <th className="pb-2 pr-3 text-right font-medium">{t("billing.ordersAmount")}</th>
                    <th className="pb-2 text-right font-medium">{t("billing.ordersStatus")}</th>
                  </tr>
                </thead>
                <tbody>
                  {orders.map((o) => {
                    const tierName =
                      typeof o.product_name === "object" && o.product_name
                        ? resolveLocaleString(o.product_name as Record<string, string>, locale) || o.product_code
                        : (o.product_name as string | null) || o.product_code;
                    const amt = (o.amount_cents / 100).toFixed(2);
                    const dateStr = o.created_at
                      ? new Date(o.created_at).toLocaleDateString(locale, {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                        })
                      : "";
                    return (
                      <tr key={o.id} className="border-b last:border-b-0">
                        <td className="py-2.5 pr-3 text-xs text-muted-foreground">{dateStr}</td>
                        <td className="py-2.5 pr-3 text-xs">{tierName}</td>
                        <td className="py-2.5 pr-3 text-xs">
                          {o.duration_months}{" "}
                          {t(o.duration_months === 1 ? "billing.ordersMonth" : "billing.ordersMonths")}
                          {o.discount_pct > 0 && (
                            <span className="ml-1.5 rounded-full bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">
                              -{o.discount_pct}%
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 pr-3 text-right tabular-nums text-xs">
                          {o.currency.toUpperCase()} ${amt}
                        </td>
                        <td className="py-2.5 text-right">
                          <Badge variant={o.status === "paid" ? "default" : "outline"}>
                            {o.status}
                          </Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
