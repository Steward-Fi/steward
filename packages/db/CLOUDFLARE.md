# Running migrations against Neon (Workers deployments)

The Workers entry (`packages/api/src/worker.ts`) intentionally does NOT run
`runMigrations()` at boot:

- Workers cold-boot is on the request path; blocking on a migration would push
  every request past the 30s subrequest budget.
- Workers cannot use the postgres-js TCP migrator at all — `drizzle-orm/postgres-js/migrator`
  reads files via `node:fs` (unsupported on Workers) and opens TCP sockets
  (also unsupported).

The `wrangler.toml` shipped with this repo sets `SKIP_MIGRATIONS = "1"` so the
Bun entry honors the same guard if ever deployed in a Workers-style envelope.

## Run migrations and activation out of band

Use a host-bearing TCP URL and the checked-in one-shot commands. Never expose
the bootstrap or migration credential to the Worker, and never run plugin
migrations as the routine application role.

```bash
export MIGRATION_DATABASE_URL="postgres://ADMIN:PASS@ep-XYZ.us-east-2.aws.neon.tech/dbname?sslmode=verify-full"
DATABASE_URL= bun --cwd packages/api run migrate:production:core

# Run scripts/postgres/rls-bootstrap.sql as the schema-owning administrator,
# then replace MIGRATION_DATABASE_URL with the created migration-role URL.
DATABASE_URL= STEWARD_PLUGINS='capabilities,trading' \
  bun --cwd packages/api run migrate:production:plugins

# Run rls-activate.sql as the administrator with both role variables, then
# deploy the Worker with only the restricted app-role DATABASE_URL.
```

## CI integration

A typical GitHub Actions workflow:

```yaml
- name: Apply Steward core migrations
  run: DATABASE_URL= bun --cwd packages/api run migrate:production:core
  env:
    MIGRATION_DATABASE_URL: ${{ secrets.NEON_ADMIN_TCP_URL }}
```

Run this BEFORE `wrangler deploy` so the new schema is in place when the
Worker starts serving traffic. There is no rollback step — Drizzle
migrations are forward-only.

Migration `0009_auth_kv_store.sql` creates the auth store before deploy. The
runtime role has no schema-creation privilege and must not rely on lazy DDL.

## Transaction-capable RLS transport

`createNeonTransactionDbForRequest()` provides a request-scoped Neon WebSocket
pool with exactly one connection. It supports Drizzle callback transactions and
is therefore eligible for `withTenantRlsTransaction(..., "neon-websocket", ...)`.
The handle exposes an idempotent `close()` which callers must await before a
Worker request finishes. Connection acquisition is capped at 10 seconds; query,
statement, lock, idle-connection, and idle-in-transaction phases are capped at
30 seconds (with PostgreSQL cancellation scheduled slightly earlier). Production
TLS policy is evaluated from the Worker bindings passed to the handle, not from
a Node compatibility shim's `process.env`; because Cloudflare does not provide
`NODE_ENV` automatically, missing `NODE_ENV` defaults to production enforcement.

Both `neon-http` and `neon-websocket` are bound through request-local async
context. The context is revoked as soon as the owning callback settles, so any
detached async task fails before reusing a database handle after cleanup.
Before enabling the WebSocket driver, every database-backed fire-and-forget
task must be made part of the owning callback (or an explicitly owned Worker
lifetime); revocation prevents stale-handle use but cannot preserve unawaited
work.

`withRequestDatabase()` propagates that explicit handle through the async
request so existing services calling `getDb()` resolve the request-owned
Drizzle database rather than an isolate-global singleton. Concurrent contexts
are isolated, nested replacement and raw `getSql()` bypass are rejected, and
the Worker fetch/cron entrypoints await handle cleanup on success or failure.

The shipped production Worker uses `DATABASE_DRIVER=neon-websocket` and rejects
`neon-http`. Fetch and scheduled entrypoints allocate an explicit request-owned
handle, verify the restricted application role and complete activated policy
catalog for the exact database binding, and only then enter authenticated
tenant transactions or per-tenant background jobs. Readiness is cached by the
exact driver+database authority, so a rotated Worker binding is revalidated;
failed checks are evicted and retry fail closed. Apply migrations, bootstrap
roles, and activation out of band as described in
`docs/security/database-rls-rollout.mdx`; the Worker credential must be the
NOINHERIT/NOBYPASSRLS application role and must never own protected relations.
