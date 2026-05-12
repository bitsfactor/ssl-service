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

type Step = "form" | "code";

export function RegisterClient() {
  const t = useT();
  const router = useRouter();
  const searchParams = useSearchParams();
  const _rawReturnTo = searchParams.get("return_to") ?? "/";
  // Allow relative paths OR full https URLs on a *.develop.cc subdomain
  // (chat sends users here with return_to=chat's SSO exchange URL).
  const returnTo = sanitizeReturnTo(_rawReturnTo);

  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  // Once OTP-confirm succeeds we replace the form with a spinner and
  // start the cross-domain navigation. Same UX motivation as the
  // login page: hide the lingering OTP form during the ~200-500ms
  // it takes to bounce through chat's SSO exchange.
  const [redirecting, setRedirecting] = useState(false);
  const [resending, setResending] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [errors, setErrors] = useState<{
    email?: string;
    password?: string;
    code?: string;
    form?: string;
  }>({});

  function validateForm() {
    const e: typeof errors = {};
    if (!email.trim()) e.email = t("common.required");
    if (!password) e.password = t("common.required");
    else if (password.length < 8) e.password = t("auth.passwordTooShort");
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function handleStart(ev: React.FormEvent) {
    ev.preventDefault();
    if (!validateForm()) return;
    setLoading(true);
    setErrors({});
    try {
      const res = await fetch("/api/auth/signup-start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim(),
          password,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { detail?: string }).detail ?? t("auth.registerError");
        setErrors({ form: msg });
        return;
      }
      setStep("code");
      startResendCooldown();
    } catch {
      toast.error(t("common.networkError"));
    } finally {
      setLoading(false);
    }
  }

  async function handleConfirm(ev: React.FormEvent) {
    ev.preventDefault();
    if (code.length !== 6) {
      setErrors({ code: t("auth.signupCodeWrongLength") });
      return;
    }
    setLoading(true);
    setErrors({});
    try {
      const res = await fetch("/api/auth/signup-confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), code }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body as { detail?: string }).detail ?? t("auth.registerError");
        setErrors({ code: msg });
        setLoading(false);
        return;
      }
      setRedirecting(true);
      if (/^https?:\/\//.test(returnTo)) {
        window.location.href = returnTo;
      } else {
        router.replace(returnTo);
      }
    } catch {
      toast.error(t("common.networkError"));
      setLoading(false);
    }
  }

  async function handleResend() {
    if (resending || resendCooldown > 0) return;
    setResending(true);
    setErrors({});
    try {
      const res = await fetch("/api/auth/signup-resend", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      if (res.ok) {
        toast.success(t("auth.signupCodeResent"));
        startResendCooldown();
      } else {
        const body = await res.json().catch(() => ({}));
        toast.error((body as { detail?: string }).detail ?? t("auth.registerError"));
      }
    } catch {
      toast.error(t("common.networkError"));
    } finally {
      setResending(false);
    }
  }

  function startResendCooldown() {
    setResendCooldown(60);
    const tick = () => {
      setResendCooldown((s) => {
        if (s <= 1) return 0;
        setTimeout(tick, 1000);
        return s - 1;
      });
    };
    setTimeout(tick, 1000);
  }

  if (redirecting) {
    return (
      <div className="flex w-full max-w-sm flex-col items-center gap-3 fade-up py-10 text-center">
        <div
          aria-label={t("auth.redirecting")}
          className="size-7 animate-spin rounded-full border-2 border-muted-foreground/30 border-t-foreground"
        />
        <p className="text-sm text-muted-foreground">{t("auth.redirecting")}</p>
      </div>
    );
  }

  return (
    <div className="w-full max-w-sm fade-up">
      <div className="mb-8 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("auth.registerTitle")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {step === "form"
            ? t("auth.registerSubtitle")
            : t("auth.signupCodeSubtitle", { email })}
        </p>
      </div>

      <div className="rounded-2xl border border-border bg-card p-6 shadow-[var(--shadow-card)]">
        {step === "form" ? (
          <form onSubmit={handleStart} className="space-y-4" noValidate>
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
              {loading ? t("auth.signupSending") : t("auth.signupSendCode")}
            </Button>
          </form>
        ) : (
          <form onSubmit={handleConfirm} className="space-y-4" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="code">{t("auth.signupCodeLabel")}</Label>
              <Input
                id="code"
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                placeholder="000000"
                autoComplete="one-time-code"
                aria-invalid={!!errors.code}
                disabled={loading}
                className="tracking-[0.4em] text-center text-lg"
              />
              {errors.code ? (
                <p className="text-xs text-destructive">{errors.code}</p>
              ) : null}
            </div>

            <Button type="submit" className="w-full" disabled={loading || code.length !== 6}>
              {loading ? t("auth.signupConfirming") : t("auth.signupConfirm")}
            </Button>

            <div className="flex items-center justify-between pt-1 text-xs">
              <button
                type="button"
                onClick={() => {
                  setStep("form");
                  setCode("");
                  setErrors({});
                }}
                className="text-muted-foreground hover:text-foreground"
              >
                {t("auth.signupChangeEmail")}
              </button>
              <button
                type="button"
                onClick={handleResend}
                disabled={resending || resendCooldown > 0}
                className="text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
              >
                {resendCooldown > 0
                  ? t("auth.signupResendIn", { seconds: resendCooldown })
                  : t("auth.signupResend")}
              </button>
            </div>
          </form>
        )}
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
