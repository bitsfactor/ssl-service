"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useT } from "@/lib/i18n/i18n-provider";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  MonitorIcon,
  SmartphoneIcon,
  TrashIcon,
  MailIcon,
} from "lucide-react";

type Session = {
  id: string;
  created_at?: string;
  last_seen_at?: string;
  user_agent?: string;
  ip?: string;
  is_current?: boolean;
};

export function SecurityClient({ email }: { email: string }) {
  const t = useT();
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [resetSent, setResetSent] = useState(false);
  const [resetSending, setResetSending] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [signingOutAll, setSigningOutAll] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/me/sessions", { cache: "no-store" });
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const body = await res.json();
        if (cancelled) return;
        // user-service may return an array OR a wrapper {sessions:[...]} —
        // accept both shapes so the UI doesn't break on API shape drift.
        const list = Array.isArray(body) ? body : (body?.sessions ?? []);
        setSessions(list);
      } catch (err) {
        if (!cancelled) {
          setSessionsError(err instanceof Error ? err.message : "load_failed");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSendPasswordReset() {
    setResetSending(true);
    try {
      // user-service's password-change flow goes through email — we POST
      // /api/auth/forgot-password to mail a one-time link, and the user
      // completes the change at /auth/reset-password?token=... .
      const res = await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      // forgot-password returns 204 even on unknown email to avoid leaking
      // account existence; we treat any 2xx as success.
      if (!res.ok && res.status !== 204) {
        throw new Error(`HTTP ${res.status}`);
      }
      setResetSent(true);
      toast.success(t("security.resetEmailSent"));
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("security.resetEmailError")
      );
    } finally {
      setResetSending(false);
    }
  }

  async function handleRevoke(id: string) {
    setRevokingId(id);
    try {
      const res = await fetch(
        `/api/me/sessions/${encodeURIComponent(id)}`,
        { method: "DELETE" }
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      setSessions((prev) => (prev ?? []).filter((s) => s.id !== id));
      toast.success(t("security.sessionRevoked"));
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("security.sessionRevokeError")
      );
    } finally {
      setRevokingId(null);
    }
  }

  async function handleSignOutAll() {
    if (
      typeof window !== "undefined" &&
      !window.confirm(t("security.signOutAllConfirm"))
    ) {
      return;
    }
    setSigningOutAll(true);
    try {
      // DELETE /api/me/sessions revokes every session including the
      // current one — then the next request to a protected page will
      // bounce the browser to /login.
      const res = await fetch("/api/me/sessions", { method: "DELETE" });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      toast.success(t("security.signOutAllSuccess"));
      // Bounce to login since this session is now revoked too.
      window.location.href = "/login";
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : t("security.signOutAllError")
      );
    } finally {
      setSigningOutAll(false);
    }
  }

  function deviceIconFor(ua: string | undefined) {
    if (!ua) return MonitorIcon;
    if (/iPhone|Android|Mobile/i.test(ua)) return SmartphoneIcon;
    return MonitorIcon;
  }

  function uaLabel(ua: string | undefined): string {
    if (!ua) return t("security.unknownDevice");
    // Lightweight, locale-neutral parse — the full UA is exposed via title.
    if (/iPhone/i.test(ua)) return "iPhone";
    if (/Android/i.test(ua)) return "Android";
    if (/Macintosh/i.test(ua)) return "macOS";
    if (/Windows/i.test(ua)) return "Windows";
    if (/Linux/i.test(ua)) return "Linux";
    return t("security.unknownDevice");
  }

  return (
    <div className="p-4 md:p-8 max-w-2xl fade-up">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("security.title")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {t("security.subtitle")}
        </p>
      </div>

      {/* Password change — via email reset (single source of truth in user-service) */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("security.changePassword")}</CardTitle>
          <CardDescription>
            {t("security.changePasswordViaEmailNote")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {resetSent ? (
            <div className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
              <MailIcon className="mt-0.5 size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
              <div className="min-w-0">
                <p className="text-sm font-medium">
                  {t("security.resetEmailSent")}
                </p>
                <p className="mt-1 text-xs text-muted-foreground break-all">
                  {email}
                </p>
              </div>
            </div>
          ) : (
            <Button
              type="button"
              onClick={handleSendPasswordReset}
              disabled={resetSending}
            >
              <MailIcon className="size-4" aria-hidden />
              {resetSending
                ? t("security.sendingResetEmail")
                : t("security.sendResetEmail")}
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Active sessions — live from /api/me/sessions */}
      <Card>
        <CardHeader>
          <CardTitle>{t("security.activeSessions")}</CardTitle>
          <CardDescription>{t("security.sessionsNote")}</CardDescription>
        </CardHeader>
        <CardContent>
          {sessions === null && !sessionsError ? (
            <div className="space-y-2">
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-full" />
            </div>
          ) : sessionsError ? (
            <p className="text-sm text-destructive">
              {t("security.sessionsLoadError")}: {sessionsError}
            </p>
          ) : sessions && sessions.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("security.sessionsEmpty")}
            </p>
          ) : (
            <ul className="space-y-2">
              {(sessions ?? []).map((s) => {
                const Icon = deviceIconFor(s.user_agent);
                const lastSeen = s.last_seen_at
                  ? new Date(s.last_seen_at)
                  : null;
                return (
                  <li
                    key={s.id}
                    className="flex items-center gap-3 rounded-lg border border-border/60 p-3"
                  >
                    <Icon
                      aria-hidden
                      className="size-5 shrink-0 text-muted-foreground"
                    />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">
                        {uaLabel(s.user_agent)}
                        {s.is_current ? (
                          <span className="ml-2 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
                            {t("security.thisDevice")}
                          </span>
                        ) : null}
                      </p>
                      <p
                        className="mt-0.5 truncate text-xs text-muted-foreground"
                        title={s.user_agent ?? ""}
                      >
                        {lastSeen
                          ? t("security.lastSeenAt", {
                              when: lastSeen.toLocaleString(),
                            })
                          : t("security.lastSeenUnknown")}
                        {s.ip ? ` · ${s.ip}` : ""}
                      </p>
                    </div>
                    {s.is_current ? null : (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={revokingId === s.id}
                        onClick={() => handleRevoke(s.id)}
                        aria-label={t("security.revokeSession")}
                        title={t("security.revokeSession")}
                      >
                        <TrashIcon className="size-4" aria-hidden />
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

          <Separator className="my-4" />

          <Button
            variant="destructive"
            size="sm"
            onClick={handleSignOutAll}
            disabled={signingOutAll}
          >
            {signingOutAll
              ? t("security.signOutAllPending")
              : t("security.signOutAll")}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
