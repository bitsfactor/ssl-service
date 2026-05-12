"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { toast } from "sonner";
import { useT } from "@/lib/i18n/i18n-provider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

function sanitizeReturnTo(raw: string): string {
  if (raw.startsWith("/") && !raw.startsWith("//")) return raw;
  try {
    const u = new URL(raw);
    if (u.protocol === "https:" && u.hostname.endsWith(".develop.cc")) {
      return raw;
    }
  } catch {
    /* fall through */
  }
  return "/";
}

export function LoginClient() {
  const t = useT();
  const router = useRouter();
  const searchParams = useSearchParams();
  const _rawReturnTo = searchParams.get("return_to") ?? "/";
  // Allow either a relative path OR a full https URL on a *.develop.cc
  // subdomain (cross-product SSO bounces back here with one of those).
  // Anything else falls back to "/" to block open-redirect attacks.
  const returnTo = sanitizeReturnTo(_rawReturnTo);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<{ email?: string; password?: string; form?: string }>({});

  function validate() {
    const e: typeof errors = {};
    if (!email.trim()) e.email = t("common.required");
    if (!password) e.password = t("common.required");
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function handleSubmit(ev: React.FormEvent) {
    ev.preventDefault();
    if (!validate()) return;
    setLoading(true);
    setErrors({});
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { detail?: string }).detail ?? t("auth.loginError");
        setErrors({ form: msg });
        return;
      }
      // Login succeeded — navigate to return_to (or dashboard).
      // Relative paths use Next's client router (no full reload);
      // cross-product returns (e.g. chat's SSO exchange URL) need
      // window.location.href so the browser actually leaves
      // user.develop.cc with the new .develop.cc cookie in hand.
      if (/^https?:\/\//.test(returnTo)) {
        window.location.href = returnTo;
      } else {
        router.replace(returnTo);
      }
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
          {t("auth.loginTitle")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("auth.loginSubtitle")}
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
              placeholder={t("auth.passwordPlaceholder")}
              autoComplete="current-password"
              aria-invalid={!!errors.password}
              disabled={loading}
            />
            {errors.password ? (
              <p className="text-xs text-destructive">{errors.password}</p>
            ) : null}
          </div>

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? t("auth.loggingIn") : t("auth.loginButton")}
          </Button>
        </form>
      </div>

      <p className="mt-4 text-center text-sm text-muted-foreground">
        {t("auth.noAccount")}{" "}
        <Link
          href={`/register${returnTo !== "/" ? `?return_to=${encodeURIComponent(returnTo)}` : ""}`}
          className="text-foreground underline-offset-3 hover:underline"
        >
          {t("auth.signUpLink")}
        </Link>
      </p>
    </div>
  );
}
