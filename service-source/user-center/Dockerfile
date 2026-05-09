# Multi-stage build for the user-center Next.js app.
# Final image is the Next.js "standalone" output — small, no devDeps,
# runs `node server.js` on port 3211.
#
# Build context = service-source/user-center/ (cloned from
# git@github.com:bitsfactor/user-center.git on every deploy).

# ----- 1) install all deps (incl. dev) for the build -----
FROM node:22-alpine AS deps
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.32.1 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile


# ----- 2) build (next build → .next/standalone) -----
FROM node:22-alpine AS builder
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.32.1 --activate

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm exec next build


# ----- 3) runtime -----
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3211

RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static     ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public           ./public

USER nextjs
EXPOSE 3211

CMD ["node", "server.js"]
