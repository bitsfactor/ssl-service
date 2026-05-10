"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { toast } from "sonner";
import { useT } from "@/lib/i18n/i18n-provider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function RegisterClient() {
  const t = useT();
  const router = useRouter();
  const searchParams = useSearchParams();
  const _rawReturnTo = searchParams.get("return_to") ?? "/";
  // Sanitize: only allow relative paths to prevent open-redirect attacks.
  const returnTo = _rawReturnTo.startsWith("/") && !_rawReturnTo.startsWith("//") ? _rawReturnTo : "/";

  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{
    displayName?: string;
    email?: string;
    password?: string;
    form?: string;
  }>({});

  function validate() {
    const e: typeof errors = {};
    if (!email.trim()) e.email = t("common.required");
    if (!password) e.password = t("common.required");
    else if (password.length < 8) e.password = t("auth.passwordTooShort");
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function handleSubmit(ev: React.FormEvent) {
    ev.preventDefault();
    if (!validate()) return;
    setLoading(true);
    setErrors({});
    try {
      // user-service exposes /api/auth/signup (not /register).
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim(),
          password,
          display_name: displayName.trim() || undefined,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { detail?: string }).detail ?? t("auth.registerError");
        setErrors({ form: msg });
        return;
      }
      // Registration succeeded — navigate.
      router.replace(returnTo);
    } catch {
      toast.error(t("common.networkError"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="w-full max-w-sm fade-up">
      <div className="mb-8 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("auth.registerTitle")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("auth.registerSubtitle")}
        </p>
      </div>

      <div className="rounded-2xl border border-border bg-card p-6 shadow-[var(--shadow-card)]">
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          {errors.form ? (
            <div className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {errors.form}
            </div>
          ) : null}

          <div className="space-y-1.5">
            <Label htmlFor="display_name">{t("auth.displayNameLabel")}</Label>
            <Input
              id="display_name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder={t("auth.displayNamePlaceholder")}
              autoComplete="name"
              disabled={loading}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="email">{t("auth.emailLabel")}</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={t("auth.emailPlaceholder")}
              autoComplete="email"
              aria-invalid={!!errors.email}
              disabled={loading}
            />
            {errors.email ? (
              <p className="text-xs text-destructive">{errors.email}</p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="password">{t("auth.passwordLabel")}</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t("auth.newPasswordPlaceholder")}
              autoComplete="new-password"
              aria-invalid={!!errors.password}
              disabled={loading}
            />
            {errors.password ? (
              <p className="text-xs text-destructive">{errors.password}</p>
            ) : null}
          </div>

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? t("auth.creatingAccount") : t("auth.registerButton")}
          </Button>
        </form>
      </div>

      <p className="mt-4 text-center text-sm text-muted-foreground">
        {t("auth.hasAccount")}{" "}
        <Link
          href={`/login${returnTo !== "/" ? `?return_to=${encodeURIComponent(returnTo)}` : ""}`}
          className="text-foreground underline-offset-3 hover:underline"
        >
          {t("auth.signInLink")}
        </Link>
      </p>
    </div>
  );
}
