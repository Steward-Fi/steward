# ──────────────────────────────────────────────────────────────────────────────
# Steward – Docker image
# Multi-stage build: install deps + typecheck → slim runtime
# ──────────────────────────────────────────────────────────────────────────────

# Stage 1 – install + build ────────────────────────────────────────────────────
FROM oven/bun:1.1 AS builder

WORKDIR /app

# Copy workspace root files first (for bun workspace resolution)
COPY package.json bun.lock* bunfig.toml* turbo.json ./

# Copy all packages (bun workspaces need the full tree for linking)
COPY packages/ packages/

# Install all dependencies (including devDependencies for type-checking)
RUN bun install --frozen-lockfile || bun install

# Type-check (non-emitting – Bun runs TS directly at runtime)
RUN bun run build

# Stage 2 – runtime ───────────────────────────────────────────────────────────
FROM oven/bun:1.1-slim

WORKDIR /app

# Copy workspace root
COPY --from=builder /app/package.json /app/bun.lock* /app/bunfig.toml* /app/turbo.json ./

# Copy all packages (source + node_modules)
COPY --from=builder /app/packages/ packages/
COPY --from=builder /app/node_modules/ node_modules/

# Env defaults (overridable at runtime)
ENV PORT=3200 \
    NODE_ENV=production \
    DATABASE_URL="" \
    STEWARD_MASTER_PASSWORD=""

EXPOSE 3200

# Health check – hit /health every 30s, allow 5s for response
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "const r=await fetch('http://localhost:3200/health');process.exit(r.ok?0:1)" || exit 1

# Run the API entrypoint
CMD ["bun", "run", "packages/api/src/index.ts"]
