FROM oven/bun:1 AS base

WORKDIR /app

# ─── Stage 1: Install all dependencies ───────────────────────────────────────

FROM base AS deps

COPY package.json bun.lock turbo.json tsconfig.json ./
COPY packages/api/package.json packages/api/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/policy-engine/package.json packages/policy-engine/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/vault/package.json packages/vault/package.json
COPY packages/webhooks/package.json packages/webhooks/package.json

RUN bun install --frozen-lockfile

# ─── Stage 2: Build ───────────────────────────────────────────────────────────

FROM base AS build

COPY --from=deps /app/node_modules ./node_modules
COPY package.json bun.lock turbo.json tsconfig.json ./
COPY packages/api packages/api
COPY packages/auth packages/auth
COPY packages/db packages/db
COPY packages/policy-engine packages/policy-engine
COPY packages/shared packages/shared
COPY packages/sdk packages/sdk
COPY packages/vault packages/vault
COPY packages/webhooks packages/webhooks

RUN bunx turbo run build --filter=@steward/api

# ─── Stage 3: Runtime ─────────────────────────────────────────────────────────

FROM base AS runtime

ENV NODE_ENV=production
ENV PORT=3200

COPY package.json bun.lock turbo.json ./
COPY packages/api/package.json packages/api/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/policy-engine/package.json packages/policy-engine/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/vault/package.json packages/vault/package.json
COPY packages/webhooks/package.json packages/webhooks/package.json

RUN bun install --frozen-lockfile --production

COPY --from=build /app/packages/api packages/api
COPY --from=build /app/packages/auth packages/auth
COPY --from=build /app/packages/db packages/db
COPY --from=build /app/packages/policy-engine packages/policy-engine
COPY --from=build /app/packages/shared packages/shared
COPY --from=build /app/packages/sdk packages/sdk
COPY --from=build /app/packages/vault packages/vault
COPY --from=build /app/packages/webhooks packages/webhooks

USER bun

EXPOSE 3200

# /health = process alive, /ready = db + migrations + vault ready
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD bun -e "const r = await fetch('http://127.0.0.1:3200/ready'); if (!r.ok) process.exit(1);"

# Default: full mode with external Postgres (DATABASE_URL required).
# For embedded/PGLite mode: override CMD with ["bun", "packages/api/src/embedded.ts"]
CMD ["bun", "packages/api/src/index.ts"]
