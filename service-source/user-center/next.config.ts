import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Ship via Next.js standalone output so the Docker runtime image is
  // just node + .next/standalone — no pnpm / devDeps needed at runtime.
  output: "standalone",

  poweredByHeader: false,
  devIndicators: false,

  logging: {
    fetches: { fullUrl: false },
    incomingRequests: false,
  },

  // Proxy back-end paths to user-service. user.develop.cc historically
  // served BOTH the FastAPI app and the React user-center; after the
  // Caddy upstream swap to user-center, every public path that previously
  // resolved on user-service must be explicitly forwarded here, or it
  // 404s on the Next router.
  //
  // Forwarded:
  //   /api/*            — auth/login, /api/me, billing, etc. (Next.js
  //                       resolves local app/api/** routes FIRST so
  //                       /api/health remains served by user-center).
  //   /sub/:token       — VPN subscription URL clients (Clash, V2RayN,
  //                       etc.) hit this to fetch their config. Critical
  //                       — clients must not be redirected.
  //   /sub-qr/*.svg     — QR-code rendering of the subscription URL.
  //   /product/info     — public product manifest used by external
  //                       integrations.
  //
  // Default in prod (xcenter): http://host.docker.internal:8200 (user
  // container exposes 0.0.0.0:8200 on the docker host).
  // Local dev: set USER_SERVICE_URL=http://127.0.0.1:8200 in .env.local.
  async rewrites() {
    const userServiceUrl =
      process.env.USER_SERVICE_URL ?? "http://host.docker.internal:8200";
    return [
      {
        source: "/api/:path*",
        destination: `${userServiceUrl}/api/:path*`,
      },
      {
        source: "/sub/:token",
        destination: `${userServiceUrl}/sub/:token`,
      },
      {
        source: "/sub-qr/:path*",
        destination: `${userServiceUrl}/sub-qr/:path*`,
      },
      {
        source: "/product/info",
        destination: `${userServiceUrl}/product/info`,
      },
    ];
  },
};

export default nextConfig;
