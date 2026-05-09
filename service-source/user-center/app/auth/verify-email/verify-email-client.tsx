"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useT } from "@/lib/i18n/i18n-provider";

type Status = "verifying" | "success" | "error";

export function VerifyEmailClient() {
  const t = useT();
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const [status, setStatus] = useState<Status>("verifying");
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMsg(t("auth.verifyMissingToken"));
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        if (cancelled) return;
        if (res.ok) {
          setStatus("success");
          setTimeout(() => router.replace("/"), 2000);
        } else {
          const body = await res.json().catch(() => ({}));
          setErrorMsg(
            (body as { detail?: string }).detail ?? t("auth.verifyError")
          );
          setStatus("error");
        }
      } catch {
        if (cancelled) return;
        setErrorMsg(t("common.networkError"));
        setStatus("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  return (
    <div className="w-full max-w-sm fade-up text-center">
      {status === "verifying" && (
        <p className="text-sm text-muted-foreground">{t("auth.verifying")}</p>
      )}
      {status === "success" && (
        <div className="rounded-2xl border border-border bg-card p-6 shadow-[var(--shadow-card)]">
          <p className="text-sm font-medium text-foreground">
            {t("auth.verifySuccess")}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {t("auth.redirecting")}
          </p>
        </div>
      )}
      {status === "error" && (
        <div className="rounded-2xl border border-destructive/40 bg-destructive/10 p-6">
          <p className="text-sm font-medium text-destructive">
            {t("auth.verifyFailedTitle")}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">{errorMsg}</p>
        </div>
      )}
    </div>
  );
}
