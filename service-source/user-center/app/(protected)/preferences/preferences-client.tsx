"use client";

import { useTheme } from "next-themes";
import { toast } from "sonner";
import { useT, useI18n } from "@/lib/i18n/i18n-provider";
import { LOCALES } from "@/lib/i18n/config";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SunIcon, MoonIcon, MonitorIcon, InfoIcon } from "lucide-react";
import { cn } from "@/lib/utils";

const THEMES = [
  { id: "light", icon: SunIcon },
  { id: "dark", icon: MoonIcon },
  { id: "system", icon: MonitorIcon },
] as const;

export function PreferencesClient() {
  const t = useT();
  const { theme, setTheme } = useTheme();
  const { locale, setLocale } = useI18n();

  return (
    <div className="p-4 md:p-8 max-w-lg fade-up">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("preferences.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("preferences.subtitle")}
        </p>
      </div>

      {/* Appearance */}
      <Card className="mb-4">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t("preferences.themeSection")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1.5">
            <p className="text-sm font-medium">{t("preferences.themeLabel")}</p>
            <div className="flex gap-2">
              {THEMES.map(({ id, icon: Icon }) => {
                const active = theme === id;
                const label = t(
                  id === "light"
                    ? "preferences.themeLight"
                    : id === "dark"
                      ? "preferences.themeDark"
                      : "preferences.themeSystem"
                );
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => {
                      setTheme(id);
                      toast.success(t("preferences.saved"));
                    }}
                    aria-pressed={active}
                    className={cn(
                      "flex h-20 flex-1 flex-col items-center justify-center gap-1.5 rounded-xl border-2 text-xs transition-all",
                      active
                        ? "border-primary bg-muted/60 font-medium text-foreground"
                        : "border-border/60 text-muted-foreground hover:border-border hover:bg-muted/40"
                    )}
                  >
                    <Icon className="size-5" />
                    <span>{label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Language */}
      <Card className="mb-4">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t("preferences.languageSection")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1.5">
            <p className="text-sm font-medium">{t("preferences.languageLabel")}</p>
            <Select
              value={locale}
              onValueChange={(next) => {
                setLocale(next as (typeof LOCALES)[number]["id"]);
              }}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LOCALES.map((l) => (
                  <SelectItem key={l.id} value={l.id}>
                    {l.nativeName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* AI defaults — placeholder */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t("preferences.defaultModelSection")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-start gap-2 rounded-lg bg-muted/40 p-3">
            <InfoIcon className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
            <p className="text-xs text-muted-foreground">
              {t("preferences.defaultModelNote")}
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
