# ──────────────────────────────────────────────────────────────────────────────
# Steward — Multi-stage Dockerfile
#
# Stages:
#   base      common base image + workdir
#   deps      install ALL dependencies (including dev) for building
#   build     compile TypeScript, run turbo build
#   runtime   production image — only prod deps + compiled output, non-root user
#
# Entry points:
#   API   (default): bun packages/api/src/index.ts   — port 3200
#   Proxy (override): bun packages/proxy/src/index.ts — port 8080
#
# Build:
#   docker build -t steward:latest .
#
# Run API:
#   docker run -e STEWARD_MASTER_PASSWORD=xxx -e DATABASE_URL=xxx steward:latest
#
# Run Proxy:
#   docker run -e STEWARD_MASTER_PASSWORD=xxx -e DATABASE_URL=xxx \
#     steward:latest bun packages/proxy/src/index.ts
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 0: Base ─────────────────────────────────────────────────────────────
FROM oven/bun:1.2-alpine AS base

WORKDIR /app

# ── Stage 1: Dependencies (all — includes dev deps for build) ─────────────────
FROM base AS deps

# Copy manifests only — layer-cached until lockfile changes
COPY package.json bun.lock turbo.json tsconfig.json ./

# Package manifests for every workspace package
COPY packages/api/package.json       packages/api/package.json
COPY packages/auth/package.json      packages/auth/package.json
COPY packages/db/package.json        packages/db/package.json
COPY packages/policy-engine/package.json packages/policy-engine/package.json
COPY packages/proxy/package.json     packages/proxy/package.json
COPY packages/redis/package.json     packages/redis/package.json
COPY packages/shared/package.json    packages/shared/package.json
COPY packages/vault/package.json     packages/vault/package.json
COPY packages/webhooks/package.json  packages/webhooks/package.json

# Strip frontend/example workspaces not present in server builds
# (web, packages/sdk, and packages/examples/* are excluded via .dockerignore)
RUN sed -i '/"web"/d; /"packages\/examples\/\*"/d; /"packages\/sdk"/d' package.json

# Note: --frozen-lockfile is omitted because we patched package.json above
# (removed frontend workspaces). bun.lock still pins all versions.
RUN bun install

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Bun executes TypeScript directly — no compilation step needed.
# All "build" scripts in Steward packages are tsc --noEmit (type-check only),
# not compilation, so we skip turbo build entirely.
FROM oven/bun:1.2-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3200

# Bring in node_modules from the deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy root manifests
COPY package.json bun.lock turbo.json tsconfig.json ./
RUN sed -i '/"web"/d; /"packages\/examples\/\*"/d; /"packages\/sdk"/d' package.json

# Copy source for all server packages
COPY packages/api         packages/api
COPY packages/auth        packages/auth
COPY packages/db          packages/db
COPY packages/policy-engine packages/policy-engine
COPY packages/proxy       packages/proxy
COPY packages/redis       packages/redis
COPY packages/shared      packages/shared
COPY packages/vault       packages/vault
COPY packages/webhooks    packages/webhooks

# ── Non-root user ─────────────────────────────────────────────────────────────
# bun image already has a 'bun' user (uid 1000); use it.
USER bun

# ── Ports ─────────────────────────────────────────────────────────────────────
# API: 3200   Proxy: 8080
EXPOSE 3200 8080

# ── Health check ──────────────────────────────────────────────────────────────
# Uses /ready for the API (deep check: db + migrations + vault).
# Proxy overrides CMD, so it checks /health on its own port at startup.
# The CMD-level health check targets whichever process is running:
#   API   → check :3200/ready
#   Proxy → check :8080/health  (set via compose healthcheck override)
HEALTHCHECK --interval=30s --timeout=10s --start-period=45s --retries=3 \
  CMD bun -e "const r=await fetch('http://127.0.0.1:'+( \
    process.env.STEWARD_PROXY_PORT \
      ? process.env.STEWARD_PROXY_PORT \
      : (process.env.PORT||'3200') \
  )+(process.env.STEWARD_PROXY_PORT?'/health':'/ready') \
  );process.exit(r.ok?0:1);"

# ── Default command: API server ───────────────────────────────────────────────
# Override for proxy: CMD ["bun", "packages/proxy/src/index.ts"]
CMD ["bun", "packages/api/src/index.ts"]
