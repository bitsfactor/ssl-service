// Public liveness endpoint. Mirrors user-service's /health so monitoring,
// Caddy upstream probes, and any clients that historically hit /health on
// user.develop.cc keep working after the routing swap to user-center.
//
// /api/health (under app/api/) is the structured one with `{service:"user-center"}`;
// this one is the simple boolean-style probe matching the upstream contract.
export const dynamic = "force-static";
export function GET() {
  return Response.json({ status: "ok" });
}
