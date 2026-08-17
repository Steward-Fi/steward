# Steward Enterprise Reference

This profile is the hardened compose path for PR6. It includes PostgreSQL, Redis, a one-shot migration job, the API, the credential proxy, Caddy TLS termination, health/readiness checks, and a `backup` service that writes `pg_dump` files into `deploy/enterprise-reference/backups`.

Docker Compose 2.33.1 or newer is required. The profile uses `gw_priority` to
make the egress-capable network the deterministic default gateway for its
dual-homed API, proxy, migration, and backup containers.

```bash
bun install
bun run packages/cli/src/index.ts init --env deploy/enterprise-reference/.env --force
docker compose --env-file deploy/enterprise-reference/.env \
  -f deploy/enterprise-reference/docker-compose.yml \
  --profile enterprise-reference up -d
bun run packages/cli/src/index.ts doctor --strict --env deploy/enterprise-reference/.env
```

Useful follow-up commands:

```bash
docker compose --env-file deploy/enterprise-reference/.env \
  -f deploy/enterprise-reference/docker-compose.yml \
  --profile backup run --rm backup

# Supply a REAL, unique tenant API key you generated yourself. Never ship or
# reuse a placeholder/`change-me` value — it becomes a usable machine credential.
bun run packages/cli/src/index.ts tenant create --id acme --name Acme --api-key "$(openssl rand -hex 24 | sed 's/^/stw_tenant_/')"
bun run packages/cli/src/index.ts audit bundle --from 1 --out bundle.json
node scripts/verify-evidence-bundle.mjs bundle.json
```

Current API differences to know:

- `steward approvals approve` wraps `POST /approvals/:txId/approve`, but the API intentionally refuses vault transaction execution there. Vault approvals must be executed through `POST /vault/:agentId/approve/:txId` so policy can be rechecked before signing.
- `steward policy set` creates a policy template through `/policies`; when `--agent-id` is supplied it immediately assigns that template through `/policies/:id/assign`.
- Secret routes are the existing `/secrets/routes` credential-injection routes. The compose profile does not add new proxy internals.
