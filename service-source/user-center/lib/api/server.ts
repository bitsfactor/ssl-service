import "server-only";

import { cookies } from "next/headers";

/**
 * Base URL for server-side fetches to the user-service.
 *
 * WHY THIS IS NOT user.develop.cc:
 *   In production, user-center and user-service are both running on
 *   xcenter, connected via docker compose `extra_hosts:
 *   [host.docker.internal:host-gateway]`. Using the public hostname
 *   would create a hairpin loop through Caddy TLS termination.
 *   Instead we go direct over the internal docker network.
 *
 *   In local dev, set USER_SERVICE_URL=http://127.0.0.1:8200 in .env.local.
 */
function userServiceUrl(): string {
  return (
    process.env.USER_SERVICE_URL ?? "http://host.docker.internal:8200"
  );
}

/**
 * Forward the browser's session cookie to the user-service.
 * user-center and user-service share the same domain (user.develop.cc)
 * so the session cookie travels back automatically — we just need to
 * forward it on server-side fetches.
 */
export async function serverFetch(
  path: string,
  init?: RequestInit
): Promise<Response> {
  const cookieStore = await cookies();
  const cookieHeader = cookieStore
    .getAll()
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");

  const url = `${userServiceUrl()}${path}`;
  return fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers as Record<string, string>),
      // Forward session cookies so user-service recognises the caller.
      Cookie: cookieHeader,
    },
    // Opt out of Next.js fetch caching — auth state changes frequently.
    cache: "no-store",
  });
}

/**
 * Fetch the current user from user-service. Returns null if the user
 * is not authenticated or if the request fails.
 *
 * NB: user-service's `/api/me` returns `{user: {...}, subscriptions: [...]}`
 * (NOT a flat UserProfile). We unwrap `.user` here so callers can keep
 * working with a flat profile object.
 */
export async function getServerUser(): Promise<UserProfile | null> {
  try {
    const res = await serverFetch("/api/me");
    if (!res.ok) return null;
    const body = (await res.json()) as
      | { user?: UserProfile }
      | UserProfile;
    if (body && typeof body === "object" && "user" in body && body.user) {
      return body.user as UserProfile;
    }
    return body as UserProfile;
  } catch {
    return null;
  }
}

export type UserProfile = {
  id: string;
  email: string;
  display_name: string | null;
  locale: string | null;
  created_at: string;
  is_admin: boolean;
};

export type UsageInfo = {
  tier_code: string;
  tier_name: Record<string, string>;
  tier_metadata: Record<string, unknown>;
  limit_cents: number;
  consumed_cents: number;
  remaining_cents: number;
  reset_kind: "daily" | "monthly" | "never";
  current_period_start: string;
  discount_factor: number;
};
