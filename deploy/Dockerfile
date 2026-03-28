# Steward – Docker image (API + Proxy)
FROM oven/bun:1.2 AS builder
WORKDIR /app
COPY package.json bun.lock* bunfig.toml* turbo.json ./
COPY packages/ packages/

# Remove packages not needed for API/proxy to avoid resolution errors.
# sdk is excluded by .dockerignore but other packages reference it,
# so we create a stub package.json for it.
RUN sed -i '/"web"/d; /"packages\/examples/d' package.json && \
    rm -rf packages/examples packages/agent-trader packages/react packages/eliza-plugin packages/seed && \
    if [ ! -d packages/sdk ]; then \
      mkdir -p packages/sdk && \
      printf '{"name":"@stwd/sdk","version":"0.0.0","private":true}\n' > packages/sdk/package.json; \
    fi

RUN bun install --no-frozen-lockfile
RUN bun run build || true

FROM oven/bun:1.2-slim
WORKDIR /app
COPY --from=builder /app/package.json /app/bun.lock* /app/bunfig.toml* /app/turbo.json ./
COPY --from=builder /app/packages/ packages/
COPY --from=builder /app/node_modules/ node_modules/

ENV PORT=3200 NODE_ENV=production
EXPOSE 3200 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "const r=await fetch('http://localhost:'+(process.env.STEWARD_PROXY_PORT||process.env.PORT||'3200')+'/health');process.exit(r.ok?0:1)" || exit 1

CMD ["bun", "run", "packages/api/src/index.ts"]
