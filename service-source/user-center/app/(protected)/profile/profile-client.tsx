"use client";

import { useState } from "react";
import { toast } from "sonner";
import { useT } from "@/lib/i18n/i18n-provider";
import { LOCALES } from "@/lib/i18n/config";
import type { UserProfile } from "@/lib/api/server";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { UserCircleIcon } from "lucide-react";

export function ProfileClient({ user }: { user: UserProfile }) {
  const t = useT();
  const [displayName, setDisplayName] = useState(user.display_name ?? "");
  const [locale, setLocale] = useState(user.locale ?? "en");
  const [saving, setSaving] = useState(false);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await fetch("/api/me", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: displayName.trim() || null,
          locale,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(
          (body as { detail?: string }).detail ?? `HTTP ${res.status}`
        );
      }
      toast.success(t("profile.saved"));
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("profile.saveError")
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-4 md:p-8 max-w-lg fade-up">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("profile.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("profile.subtitle")}
        </p>
      </div>

      {/* Avatar placeholder */}
      <Card className="mb-6">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t("profile.avatarTitle")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <div className="flex size-16 items-center justify-center rounded-full bg-muted text-muted-foreground">
              <UserCircleIcon className="size-10" />
            </div>
            <p className="text-xs text-muted-foreground">
              {t("profile.avatarNote")}
            </p>
          </div>
        </CardContent>
      </Card>

      <form onSubmit={handleSave} className="space-y-5">
        {/* Email — read-only */}
        <div className="space-y-1.5">
          <Label htmlFor="email">{t("profile.email")}</Label>
          <Input
            id="email"
            type="email"
            value={user.email}
            readOnly
            disabled
            className="cursor-not-allowed opacity-60"
          />
          <p className="text-[11px] text-muted-foreground">
            {t("profile.emailNote")}
          </p>
        </div>

        {/* Display name */}
        <div className="space-y-1.5">
          <Label htmlFor="displayName">{t("profile.displayName")}</Label>
          <Input
            id="displayName"
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder={t("profile.displayNamePlaceholder")}
            maxLength={80}
          />
        </div>

        {/* Locale */}
        <div className="space-y-1.5">
          <Label htmlFor="locale">{t("profile.locale")}</Label>
          <Select value={locale} onValueChange={setLocale}>
            <SelectTrigger id="locale" className="w-full">
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

        <div className="flex justify-end pt-2">
          <Button type="submit" disabled={saving}>
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </form>
    </div>
  );
}
