FROM oven/bun:1 AS base

WORKDIR /app

FROM base AS deps

COPY package.json bun.lock turbo.json tsconfig.json ./
COPY packages/api/package.json packages/api/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/dashboard/package.json packages/dashboard/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/policy-engine/package.json packages/policy-engine/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/vault/package.json packages/vault/package.json
COPY packages/webhooks/package.json packages/webhooks/package.json
COPY web/package.json web/package.json

RUN bun install --frozen-lockfile

FROM base AS build

COPY --from=deps /app/node_modules ./node_modules
COPY package.json bun.lock turbo.json tsconfig.json ./
COPY packages/api packages/api
COPY packages/auth packages/auth
COPY packages/dashboard/package.json packages/dashboard/package.json
COPY packages/db packages/db
COPY packages/policy-engine packages/policy-engine
COPY packages/shared packages/shared
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/vault packages/vault
COPY packages/webhooks packages/webhooks
COPY web/package.json web/package.json

RUN bunx turbo run build --filter=@steward/api

FROM base AS runtime

ENV NODE_ENV=production
ENV PORT=3200

COPY package.json bun.lock turbo.json ./
COPY packages/api/package.json packages/api/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/dashboard/package.json packages/dashboard/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/policy-engine/package.json packages/policy-engine/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/vault/package.json packages/vault/package.json
COPY packages/webhooks/package.json packages/webhooks/package.json
COPY web/package.json web/package.json

RUN bun install --frozen-lockfile --production

COPY --from=build /app/packages/api packages/api
COPY --from=build /app/packages/auth packages/auth
COPY --from=build /app/packages/db packages/db
COPY --from=build /app/packages/policy-engine packages/policy-engine
COPY --from=build /app/packages/shared packages/shared
COPY --from=build /app/packages/vault packages/vault
COPY --from=build /app/packages/webhooks packages/webhooks

USER bun

EXPOSE 3200

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD bun -e "const response = await fetch('http://127.0.0.1:3200/health'); if (!response.ok) process.exit(1);"

CMD ["bun", "packages/api/src/index.ts"]
