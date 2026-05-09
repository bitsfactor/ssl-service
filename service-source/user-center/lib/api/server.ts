import "server-only";

import { cache } from "react";
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

// ---------------------------------------------------------------------------
// Static (module-level) cache for rarely-changing data.
// Keys: "/api/products" | "/api/pricing". TTL: 30 seconds.
// ---------------------------------------------------------------------------
type CacheEntry<T> = { data: T; expiresAt: number };
const _staticCache = new Map<string, CacheEntry<unknown>>();
const STATIC_TTL_MS = 30_000;

async function cachedFetch<T>(
  path: string,
  transform: (body: unknown) => T,
  fallback: T
): Promise<T> {
  const now = Date.now();
  const hit = _staticCache.get(path);
  if (hit && hit.expiresAt > now) return hit.data as T;
  try {
    const res = await serverFetch(path);
    if (!res.ok) return fallback;
    const body: unknown = await res.json();
    const data = transform(body);
    _staticCache.set(path, { data, expiresAt: now + STATIC_TTL_MS });
    return data;
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UserProfile = {
  id: string;
  email: string;
  display_name: string | null;
  locale: string | null;
  created_at: string;
  is_admin: boolean;
};

export type Subscription = {
  id: number;
  product_code: string;
  product_name: Record<string, string>;
  product_description?: Record<string, string> | string;
  /** Which platform service owns this product: 'chat' | 'xout' | 'platform' */
  service_code?: string;
  kind: string;       // "recurring" | "one_time" | "lifetime" | …
  status: string;     // "active" | "past_due" | "canceled" | …
  starts_at: string;
  /** API field name from user-service is expires_at (DB column name). */
  expires_at: string | null;
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

export type Product = {
  id?: number | string;
  code?: string;
  /** Which platform service owns this product: 'chat' | 'xout' | 'platform' */
  service_code?: string;
  name?: string | Record<string, string>;
  kind?: string;
  period_days?: number | null;
  currency?: string;
  price_cents?: number;
  description?: string;
  metadata?: {
    daily_allowance_cents?: number;
    lifetime_trial_cents?: number;
    tier_rank?: number;
  };
  active?: boolean;
};

export type ModelPricing = {
  // canonical (current shape)
  model_id?: string;
  display_name?: Record<string, string> | null;
  modality?: string;
  input_rate_per_1m_usd?: number;
  cached_input_rate_per_1m_usd?: number;
  output_rate_per_1m_usd?: number;
  // legacy aliases
  model?: string;
  input_per_million?: number;
  cached_per_million?: number;
  output_per_million?: number;
};

export type BootstrapData = {
  user: UserProfile;
  subscriptions: Subscription[];
  usage: UsageInfo | null;
  products: Product[];
  pricing: ModelPricing[];
};

// ---------------------------------------------------------------------------
// Individual fetchers (used by getBootstrapData)
// ---------------------------------------------------------------------------

async function fetchMe(): Promise<{ user: UserProfile; subscriptions: Subscription[] } | null> {
  try {
    const res = await serverFetch("/api/me");
    if (!res.ok) return null;
    const body = (await res.json()) as
      | { user?: UserProfile; subscriptions?: Subscription[] }
      | UserProfile;
    if (body && typeof body === "object" && "user" in body && body.user) {
      return {
        user: body.user as UserProfile,
        subscriptions: ((body as { subscriptions?: Subscription[] }).subscriptions ?? []),
      };
    }
    return { user: body as UserProfile, subscriptions: [] };
  } catch {
    return null;
  }
}

async function fetchUsage(): Promise<UsageInfo | null> {
  try {
    const res = await serverFetch("/api/me/usage");
    if (!res.ok) return null;
    const body = (await res.json()) as { billing?: UsageInfo } | UsageInfo;
    if (body && typeof body === "object" && "billing" in body && body.billing) {
      return body.billing as UsageInfo;
    }
    return body as UsageInfo;
  } catch {
    return null;
  }
}

function _parseProductList(body: unknown): Product[] {
  // New shape: { products: [...], products_by_service: {...} }
  // Legacy shape: [...] or { products: [...] }
  const list = Array.isArray(body)
    ? body
    : ((body as { products?: unknown[] })?.products ?? []);
  return list as Product[];
}

async function fetchProducts(): Promise<Product[]> {
  // Products are locale-sensitive (names resolved per user locale server-side).
  // Do NOT use the module-level _staticCache here — it would mix locales across
  // concurrent users. React cache() already deduplicates within one request.
  try {
    const res = await serverFetch("/api/products");
    if (!res.ok) return [];
    return _parseProductList(await res.json());
  } catch {
    return [];
  }
}

/** Fetch only products belonging to one service (avoids mixing concerns). */
export async function fetchProductsByService(service: string): Promise<Product[]> {
  try {
    const res = await serverFetch(`/api/products?service=${encodeURIComponent(service)}`);
    if (!res.ok) return [];
    return _parseProductList(await res.json());
  } catch {
    return [];
  }
}

async function fetchPricing(): Promise<ModelPricing[]> {
  return cachedFetch<ModelPricing[]>(
    "/api/pricing",
    (body) => {
      const list = Array.isArray(body)
        ? body
        : ((body as { models?: unknown[] })?.models ?? []);
      return list as ModelPricing[];
    },
    []
  );
}

// ---------------------------------------------------------------------------
// getBootstrapData — single function for all protected pages.
//
// React cache() deduplicates concurrent awaits within the same request
// so the layout + any page that calls it both get the same Promise.
// ---------------------------------------------------------------------------
export const getBootstrapData = cache(async (): Promise<BootstrapData | null> => {
  const [meResult, usage, products, pricing] = await Promise.all([
    fetchMe(),
    fetchUsage(),
    fetchProducts(),
    fetchPricing(),
  ]);
  if (!meResult) return null;
  return {
    user: meResult.user,
    subscriptions: meResult.subscriptions,
    usage,
    products,
    pricing,
  };
});

/**
 * Convenience: get just the user (used by pages that only need auth guard).
 * Falls through to getBootstrapData so it's still deduplicated.
 */
export async function getServerUser(): Promise<UserProfile | null> {
  const data = await getBootstrapData();
  return data?.user ?? null;
}
