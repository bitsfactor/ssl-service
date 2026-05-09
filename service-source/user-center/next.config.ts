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

  // Proxy /api/* to the user-service running at USER_SERVICE_URL.
  //
  // Next.js resolves local app/api/** routes BEFORE evaluating rewrites,
  // so /api/health is handled by this app directly and never forwarded.
  // All other /api/* paths (login, logout, me, auth/*, etc.) flow through
  // to user-service at USER_SERVICE_URL.
  //
  // In production: USER_SERVICE_URL=http://host.docker.internal:8200
  // In local dev:  set USER_SERVICE_URL=http://127.0.0.1:8200 in .env.local
  async rewrites() {
    const userServiceUrl =
      process.env.USER_SERVICE_URL ?? "http://host.docker.internal:8200";
    return [
      {
        source: "/api/:path*",
        destination: `${userServiceUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
