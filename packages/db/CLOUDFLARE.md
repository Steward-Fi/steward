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

## Run migrations from CI / a one-shot script

`drizzle-kit migrate` is the canonical way. It connects via standard Postgres
TCP using `DATABASE_URL` and applies any pending files in
`packages/db/drizzle/` in lexicographic order, tracking applied versions in
`__drizzle_migrations`.

```bash
# 1. Get a TCP-capable Postgres URL for your Neon database.
#    (Neon's pooler URL works; the HTTP-only URL does not — drizzle-kit needs
#     a real connection.)
export DATABASE_URL="postgres://USER:PASS@ep-XYZ.us-east-2.aws.neon.tech/dbname?sslmode=verify-full"

# 2. Apply all pending migrations.
cd packages/db
bun run migrate:neon
# equivalent: bunx drizzle-kit migrate
```

## Bootstrap the auth_kv_store table

`packages/auth/src/store-backends.ts` lazily creates the `auth_kv_store` table
on first use via `CREATE TABLE IF NOT EXISTS`. This works on Workers too (the
neon-http driver supports DDL), but for predictable cold-start latency you can
optionally pre-create it during the migration step. There is no separate
migration file for it today — the table definition is inline in
`PostgresBackend.ensureTable()`.

## CI integration

A typical GitHub Actions workflow:

```yaml
- name: Apply Steward DB migrations
  run: bun run migrate:neon
  env:
    DATABASE_URL: ${{ secrets.NEON_TCP_URL }}
```

Run this BEFORE `wrangler deploy` so the new schema is in place when the
Worker starts serving traffic. There is no rollback step — Drizzle
migrations are forward-only.

## Schema compatibility with neon-http

The neon-http driver uses Neon's serverless HTTP transport. The constructs
that would not work over HTTP, and Steward's actual posture on each, are:

- `LISTEN` / `NOTIFY` — not used anywhere.
- `COPY` streaming — not used anywhere.
- Advisory locks — **used, contrary to an earlier version of this note**
  (SEC-166):
  - `pg_advisory_lock` is taken by the TCP migrator (`src/migrate.ts`,
    `src/plugin-migrate.ts`). That runs pre-deploy over a real TCP connection
    (see above), never from the Worker, so neon-http is unaffected.
  - `pg_advisory_xact_lock` is taken by the audit chain on EVERY non-PGLite
    append (`src/audit-chain.ts`), to serialize per-tenant chain extensions.
    On Workers it never executes: drizzle's neon-http driver throws
    `No transactions support in neon-http driver` from `db.transaction()`,
    so `writeAuditEvent` / `withTenantAuditedTransaction` reject before the
    lock — or the INSERT — runs. Audited writes on Workers therefore FAIL
    CLOSED (the audited action is denied); the chain is never silently
    skipped. This contract is pinned by
    `src/__tests__/audit-chain-workers.test.ts`. A drizzle upgrade that adds
    neon-http transaction support breaks that test on purpose: the Workers
    audit posture (including whether the advisory lock still serializes
    correctly over the HTTP transport) must be re-reviewed before adopting it.
- Long-running multi-statement transactions — the audit chain relies on them
  on postgres-js; on neon-http they fail closed as described above.
