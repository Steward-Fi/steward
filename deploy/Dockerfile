# Steward – Docker image (API + Proxy)
FROM oven/bun:1.3-alpine AS builder
WORKDIR /app
COPY package.json bun.lock* bunfig.toml* turbo.json tsconfig.json ./
COPY packages/ packages/

# Stub the `web` workspace (Next.js app — not needed in API/proxy image but
# referenced by the workspace glob). Keep every other workspace present so
# --frozen-lockfile succeeds — that is the supply-chain integrity guarantee
# (CC8.1). Do not rewrite package.json workspaces; that breaks the lockfile.
RUN mkdir -p web && \
    printf '{"name":"web","version":"0.0.0","private":true}\n' > web/package.json

RUN bun install --frozen-lockfile
RUN bun run build

FROM oven/bun:1.3-alpine
WORKDIR /app
COPY --from=builder /app/package.json /app/bun.lock* /app/bunfig.toml* /app/turbo.json ./
COPY --from=builder /app/packages/ packages/
COPY --from=builder /app/node_modules/ node_modules/

ENV PORT=3200 NODE_ENV=production
EXPOSE 3200 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "const r=await fetch('http://localhost:'+(process.env.STEWARD_PROXY_PORT||process.env.PORT||'3200')+'/health');process.exit(r.ok?0:1)" || exit 1

CMD ["bun", "run", "packages/api/src/index.ts"]
