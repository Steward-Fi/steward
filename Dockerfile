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
FROM oven/bun:1.3-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS base

WORKDIR /app

# ── Stage 1: Dependencies (all — includes dev deps for build) ─────────────────
FROM base AS deps

# Cache buster (set via build-arg in CI to force fresh install)
ARG CACHE_BUST=1

# Copy manifests only — layer-cached until lockfile changes
COPY package.json bun.lock turbo.json tsconfig.json ./

# Frozen installs require every workspace manifest to match the lockfile,
# including workspaces that are not compiled into the API image.
COPY web/package.json web/package.json

# Package manifests for every workspace package. ALL package.json files declared
# by the `workspaces` glob in the root package.json must be present, or
# --frozen-lockfile rejects the install (CC8.1 supply-chain integrity).
COPY packages/adapters/package.json          packages/adapters/package.json
COPY packages/agent-trader/package.json      packages/agent-trader/package.json
COPY packages/api/package.json               packages/api/package.json
COPY packages/attestation/package.json       packages/attestation/package.json
COPY packages/auth/package.json              packages/auth/package.json
COPY packages/cli/package.json               packages/cli/package.json
COPY packages/db/package.json                packages/db/package.json
COPY packages/eliza-plugin/package.json      packages/eliza-plugin/package.json
COPY packages/erc8004/package.json           packages/erc8004/package.json
COPY packages/erc8183/package.json           packages/erc8183/package.json
COPY packages/mcp/package.json               packages/mcp/package.json
COPY packages/plugin-capabilities/package.json packages/plugin-capabilities/package.json
COPY packages/plugin-example/package.json     packages/plugin-example/package.json
COPY packages/plugin-sdk/package.json         packages/plugin-sdk/package.json
COPY packages/plugin-trading/package.json     packages/plugin-trading/package.json
COPY packages/plugin-wxmr/package.json        packages/plugin-wxmr/package.json
COPY packages/provider-github/package.json    packages/provider-github/package.json
COPY packages/provider-slack/package.json     packages/provider-slack/package.json
COPY packages/provider-google/package.json    packages/provider-google/package.json
COPY packages/provider-aws/package.json       packages/provider-aws/package.json
COPY packages/provider-x/package.json         packages/provider-x/package.json
COPY packages/proxy-client/package.json       packages/proxy-client/package.json
COPY packages/policy-engine/package.json     packages/policy-engine/package.json
COPY packages/proxy/package.json             packages/proxy/package.json
COPY packages/react-native/package.json      packages/react-native/package.json
COPY packages/react/package.json             packages/react/package.json
COPY packages/redis/package.json             packages/redis/package.json
COPY packages/seed/package.json              packages/seed/package.json
COPY packages/shared/package.json            packages/shared/package.json
COPY packages/signer-frost/package.json      packages/signer-frost/package.json
COPY packages/solana-signer/package.json     packages/solana-signer/package.json
COPY packages/sdk/package.json               packages/sdk/package.json
COPY packages/trade-sessions/package.json    packages/trade-sessions/package.json
COPY packages/vault/package.json             packages/vault/package.json
COPY packages/venue-hyperliquid/package.json packages/venue-hyperliquid/package.json
COPY packages/venue-polymarket/package.json  packages/venue-polymarket/package.json
COPY packages/webhooks/package.json          packages/webhooks/package.json
COPY packages/examples/                      packages/examples/

RUN bun install --frozen-lockfile --ignore-scripts

# ── Stage 2: Build ────────────────────────────────────────────────────────────
FROM base AS build

COPY package.json bun.lock turbo.json tsconfig.json ./

# Copy package.json files for workspace resolution — every workspace declared
# in the root package.json must be present for --frozen-lockfile to succeed.
COPY packages/adapters/package.json          packages/adapters/package.json
COPY packages/agent-trader/package.json      packages/agent-trader/package.json
COPY packages/api/package.json               packages/api/package.json
COPY packages/attestation/package.json       packages/attestation/package.json
COPY packages/auth/package.json              packages/auth/package.json
COPY packages/cli/package.json               packages/cli/package.json
COPY packages/db/package.json                packages/db/package.json
COPY packages/eliza-plugin/package.json      packages/eliza-plugin/package.json
COPY packages/erc8004/package.json           packages/erc8004/package.json
COPY packages/erc8183/package.json           packages/erc8183/package.json
COPY packages/mcp/package.json               packages/mcp/package.json
COPY packages/plugin-capabilities/package.json packages/plugin-capabilities/package.json
COPY packages/plugin-example/package.json     packages/plugin-example/package.json
COPY packages/plugin-sdk/package.json         packages/plugin-sdk/package.json
COPY packages/plugin-trading/package.json     packages/plugin-trading/package.json
COPY packages/plugin-wxmr/package.json        packages/plugin-wxmr/package.json
COPY packages/provider-github/package.json    packages/provider-github/package.json
COPY packages/provider-slack/package.json     packages/provider-slack/package.json
COPY packages/provider-google/package.json    packages/provider-google/package.json
COPY packages/provider-aws/package.json       packages/provider-aws/package.json
COPY packages/provider-x/package.json         packages/provider-x/package.json
COPY packages/proxy-client/package.json       packages/proxy-client/package.json
COPY packages/policy-engine/package.json     packages/policy-engine/package.json
COPY packages/proxy/package.json             packages/proxy/package.json
COPY packages/react-native/package.json      packages/react-native/package.json
COPY packages/react/package.json             packages/react/package.json
COPY packages/redis/package.json             packages/redis/package.json
COPY packages/seed/package.json              packages/seed/package.json
COPY packages/shared/package.json            packages/shared/package.json
COPY packages/signer-frost/package.json      packages/signer-frost/package.json
COPY packages/solana-signer/package.json     packages/solana-signer/package.json
COPY packages/sdk/package.json               packages/sdk/package.json
COPY packages/trade-sessions/package.json    packages/trade-sessions/package.json
COPY packages/vault/package.json             packages/vault/package.json
COPY packages/venue-hyperliquid/package.json packages/venue-hyperliquid/package.json
COPY packages/venue-polymarket/package.json  packages/venue-polymarket/package.json
COPY packages/webhooks/package.json          packages/webhooks/package.json
COPY packages/examples/                      packages/examples/

# Keep the real web importer so the frozen lockfile remains authoritative.
COPY web/package.json web/package.json

# Install deps fresh in build stage (bun symlinks don't survive COPY --from in BuildKit)
RUN bun install --frozen-lockfile --ignore-scripts

# Copy full source for all packages needed by api + proxy
COPY packages/adapters    packages/adapters
COPY packages/api         packages/api
COPY packages/attestation packages/attestation
COPY packages/auth        packages/auth
COPY packages/db          packages/db
COPY packages/plugin-capabilities packages/plugin-capabilities
COPY packages/plugin-example     packages/plugin-example
COPY packages/plugin-trading packages/plugin-trading
COPY packages/plugin-wxmr packages/plugin-wxmr
COPY packages/provider-github packages/provider-github
COPY packages/provider-slack packages/provider-slack
COPY packages/provider-google packages/provider-google
COPY packages/provider-aws packages/provider-aws
COPY packages/provider-x packages/provider-x
COPY packages/proxy-client packages/proxy-client
COPY packages/policy-engine packages/policy-engine
COPY packages/proxy       packages/proxy
COPY packages/redis       packages/redis
COPY packages/shared      packages/shared
COPY packages/sdk         packages/sdk
COPY packages/trade-sessions    packages/trade-sessions
COPY packages/vault       packages/vault
COPY packages/venue-hyperliquid packages/venue-hyperliquid
COPY packages/venue-polymarket packages/venue-polymarket
COPY packages/webhooks    packages/webhooks

# Create workspace symlinks (Bun 1.3 doesn't auto-link in Docker)
RUN mkdir -p node_modules/@stwd && \
    ln -sf ../../packages/adapters      node_modules/@stwd/adapters && \
    ln -sf ../../packages/attestation   node_modules/@stwd/attestation && \
    ln -sf ../../packages/shared        node_modules/@stwd/shared && \
    ln -sf ../../packages/sdk           node_modules/@stwd/sdk && \
    ln -sf ../../packages/auth          node_modules/@stwd/auth && \
    ln -sf ../../packages/db            node_modules/@stwd/db && \
    ln -sf ../../packages/vault         node_modules/@stwd/vault && \
    ln -sf ../../packages/redis         node_modules/@stwd/redis && \
    ln -sf ../../packages/proxy         node_modules/@stwd/proxy && \
    ln -sf ../../packages/webhooks      node_modules/@stwd/webhooks && \
    ln -sf ../../packages/policy-engine     node_modules/@stwd/policy-engine && \
    ln -sf ../../packages/plugin-capabilities node_modules/@stwd/plugin-capabilities && \
    ln -sf ../../packages/plugin-example node_modules/@stwd/plugin-example && \
    ln -sf ../../packages/plugin-trading    node_modules/@stwd/plugin-trading && \
    ln -sf ../../packages/plugin-wxmr       node_modules/@stwd/plugin-wxmr && \
    ln -sf ../../packages/provider-github   node_modules/@stwd/provider-github && \
    ln -sf ../../packages/provider-slack    node_modules/@stwd/provider-slack && \
    ln -sf ../../packages/provider-google   node_modules/@stwd/provider-google && \
    ln -sf ../../packages/provider-aws      node_modules/@stwd/provider-aws && \
    ln -sf ../../packages/provider-x         node_modules/@stwd/provider-x && \
    ln -sf ../../packages/proxy-client      node_modules/@stwd/proxy-client && \
    ln -sf ../../packages/trade-sessions    node_modules/@stwd/trade-sessions && \
    ln -sf ../../packages/venue-hyperliquid node_modules/@stwd/venue-hyperliquid && \
    ln -sf ../../packages/venue-polymarket  node_modules/@stwd/venue-polymarket

# Build api and proxy (and their deps) via turborepo
RUN bunx turbo run build --filter=@stwd/api --filter=@stwd/proxy

# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
FROM oven/bun:1.3-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3200
# The application defaults to loopback for safe direct/local execution. A
# container image must accept traffic from the container network (Railway,
# Kubernetes, Compose, and similar runtimes), so make the published image's
# network boundary explicit. Operators can still override this at runtime.
ENV STEWARD_BIND_HOST=0.0.0.0

# Install production dependencies only (no dev/build tools)
COPY package.json bun.lock turbo.json tsconfig.json ./

# Keep the real web importer so the frozen production install cannot rewrite
# the lockfile to match an invented workspace manifest.
COPY web/package.json web/package.json

COPY packages/adapters/package.json          packages/adapters/package.json
COPY packages/agent-trader/package.json      packages/agent-trader/package.json
COPY packages/api/package.json               packages/api/package.json
COPY packages/attestation/package.json       packages/attestation/package.json
COPY packages/auth/package.json              packages/auth/package.json
COPY packages/cli/package.json               packages/cli/package.json
COPY packages/db/package.json                packages/db/package.json
COPY packages/eliza-plugin/package.json      packages/eliza-plugin/package.json
COPY packages/erc8004/package.json           packages/erc8004/package.json
COPY packages/erc8183/package.json           packages/erc8183/package.json
COPY packages/mcp/package.json               packages/mcp/package.json
COPY packages/plugin-capabilities/package.json packages/plugin-capabilities/package.json
COPY packages/plugin-example/package.json     packages/plugin-example/package.json
COPY packages/plugin-sdk/package.json         packages/plugin-sdk/package.json
COPY packages/plugin-trading/package.json     packages/plugin-trading/package.json
COPY packages/plugin-wxmr/package.json        packages/plugin-wxmr/package.json
COPY packages/provider-github/package.json    packages/provider-github/package.json
COPY packages/provider-slack/package.json     packages/provider-slack/package.json
COPY packages/provider-google/package.json    packages/provider-google/package.json
COPY packages/provider-aws/package.json       packages/provider-aws/package.json
COPY packages/provider-x/package.json         packages/provider-x/package.json
COPY packages/proxy-client/package.json       packages/proxy-client/package.json
COPY packages/policy-engine/package.json     packages/policy-engine/package.json
COPY packages/proxy/package.json             packages/proxy/package.json
COPY packages/react-native/package.json      packages/react-native/package.json
COPY packages/react/package.json             packages/react/package.json
COPY packages/redis/package.json             packages/redis/package.json
COPY packages/seed/package.json              packages/seed/package.json
COPY packages/shared/package.json            packages/shared/package.json
COPY packages/signer-frost/package.json      packages/signer-frost/package.json
COPY packages/solana-signer/package.json     packages/solana-signer/package.json
COPY packages/sdk/package.json               packages/sdk/package.json
COPY packages/trade-sessions/package.json    packages/trade-sessions/package.json
COPY packages/vault/package.json             packages/vault/package.json
COPY packages/venue-hyperliquid/package.json packages/venue-hyperliquid/package.json
COPY packages/venue-polymarket/package.json  packages/venue-polymarket/package.json
COPY packages/webhooks/package.json          packages/webhooks/package.json
COPY packages/examples/                      packages/examples/

COPY --from=deps /app/bun.lock ./bun.lock

# Copy compiled output from build stage
COPY --from=build /app/packages/adapters    packages/adapters
COPY --from=build /app/packages/api         packages/api
COPY --from=build /app/packages/attestation packages/attestation
COPY --from=build /app/packages/auth        packages/auth
COPY --from=build /app/packages/db          packages/db
COPY --from=build /app/packages/plugin-capabilities packages/plugin-capabilities
COPY --from=build /app/packages/plugin-example packages/plugin-example
COPY --from=build /app/packages/plugin-trading packages/plugin-trading
COPY --from=build /app/packages/plugin-wxmr packages/plugin-wxmr
COPY --from=build /app/packages/provider-github packages/provider-github
COPY --from=build /app/packages/provider-slack packages/provider-slack
COPY --from=build /app/packages/provider-google packages/provider-google
COPY --from=build /app/packages/provider-aws packages/provider-aws
COPY --from=build /app/packages/provider-x packages/provider-x
COPY --from=build /app/packages/proxy-client packages/proxy-client
COPY --from=build /app/packages/policy-engine packages/policy-engine
COPY --from=build /app/packages/proxy       packages/proxy
COPY --from=build /app/packages/redis       packages/redis
COPY --from=build /app/packages/shared      packages/shared
COPY --from=build /app/packages/sdk         packages/sdk
COPY --from=build /app/packages/trade-sessions    packages/trade-sessions
COPY --from=build /app/packages/vault       packages/vault
COPY --from=build /app/packages/venue-hyperliquid packages/venue-hyperliquid
COPY --from=build /app/packages/venue-polymarket packages/venue-polymarket
COPY --from=build /app/packages/webhooks    packages/webhooks

# Create workspace symlinks manually — bun 1.3 doesn't auto-link workspace packages
RUN mkdir -p node_modules/@stwd && \
    ln -sf ../../packages/adapters      node_modules/@stwd/adapters && \
    ln -sf ../../packages/attestation   node_modules/@stwd/attestation && \
    ln -sf ../../packages/shared        node_modules/@stwd/shared && \
    ln -sf ../../packages/sdk           node_modules/@stwd/sdk && \
    ln -sf ../../packages/auth          node_modules/@stwd/auth && \
    ln -sf ../../packages/db            node_modules/@stwd/db && \
    ln -sf ../../packages/vault         node_modules/@stwd/vault && \
    ln -sf ../../packages/redis         node_modules/@stwd/redis && \
    ln -sf ../../packages/api           node_modules/@stwd/api && \
    ln -sf ../../packages/proxy         node_modules/@stwd/proxy && \
    ln -sf ../../packages/webhooks      node_modules/@stwd/webhooks && \
    ln -sf ../../packages/policy-engine node_modules/@stwd/policy-engine && \
    ln -sf ../../packages/plugin-capabilities node_modules/@stwd/plugin-capabilities && \
    ln -sf ../../packages/plugin-trading    node_modules/@stwd/plugin-trading && \
    ln -sf ../../packages/plugin-wxmr       node_modules/@stwd/plugin-wxmr && \
    ln -sf ../../packages/provider-github   node_modules/@stwd/provider-github && \
    ln -sf ../../packages/provider-slack    node_modules/@stwd/provider-slack && \
    ln -sf ../../packages/provider-google   node_modules/@stwd/provider-google && \
    ln -sf ../../packages/provider-aws      node_modules/@stwd/provider-aws && \
    ln -sf ../../packages/provider-x         node_modules/@stwd/provider-x && \
    ln -sf ../../packages/proxy-client      node_modules/@stwd/proxy-client && \
    ln -sf ../../packages/trade-sessions    node_modules/@stwd/trade-sessions && \
    ln -sf ../../packages/venue-hyperliquid node_modules/@stwd/venue-hyperliquid && \
    ln -sf ../../packages/venue-polymarket  node_modules/@stwd/venue-polymarket && \
    ln -sf ../../packages/eliza-plugin  node_modules/@stwd/eliza-plugin 2>/dev/null; true

# Install the production dependency closure AFTER copying the built packages.
# `COPY --from=build /app/packages/*` lines above overwrite each package dir
# (including its per-package node_modules) with the BUILD stage's version, whose
# third-party-dep symlinks (e.g. packages/api/node_modules/drizzle-orm) point at the
# build stage's `.bun` store paths that don't exist here — leaving DANGLING
# symlinks (ENOENT reading drizzle-orm at boot). Re-installing rebuilds the
# per-package node_modules symlinks against THIS stage's `.bun` store, so runtime
# resolution is correct + deterministic regardless of resolution drift. Doing
# this exactly once also avoids retaining a complete, immediately-obsolete
# dependency layer in the exported image.
RUN bun install --production --frozen-lockfile --ignore-scripts \
    --filter @stwd/api --filter @stwd/proxy

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
