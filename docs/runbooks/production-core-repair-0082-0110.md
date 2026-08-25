# Production core repair: 0082, skip 0083, 0084–0110

This runbook covers one observed legacy production discontinuity: migration
0082 is absent, migration 0083 is already present, and migrations 0084–0110
are absent. It is not a general migration command. The bundle is pinned to
Steward source head `53399910ab9288297981e1b5679b293ec732e414` and refuses any
other catalog shape.

The repair is a prerequisite for, not part of, the schema-aware 0111–0114 auth
bootstrap. It does not activate RLS, modify the shared Eliza Drizzle ledger, or
make a release ready by itself.

> **Production compatibility gate: NO-GO until an external receipt passes.**
> The catalog manifest proves the database transformation, not application
> rollback compatibility. The exact current production rollback image must be
> exercised on an isolated production restore, and the machine-readable gate
> in this runbook must pass, before this bundle can be called cutover-eligible.

## Trust boundary

The operator entrypoint is `@stwd/db/steward-core-repair`. It:

- verifies SHA-256 for immutable 0082–0110 source files;
- verifies the exact 0082-absent/0083-present catalog discontinuity;
- verifies all 47 catalog records introduced or changed by the existing 0083;
- verifies the exact pre-repair value for every one of the 391 catalog keys the
  bundle changes;
- repeats aggregate data gates after excluding application writes with table
  locks;
- applies exact 0082 and exact 0084–0110 in one serializable transaction while
  skipping 0083;
- renders only the reviewed target-schema bindings in 0091 and 0110;
- resolves the configured target through `pg_catalog.current_schema()` before
  changing `search_path`; requires the effective operator to own the target
  schema (or its database-owned `public` schema), rejects third-party `CREATE`
  grants, target-object grants to unreviewed roles, and target relations,
  functions, or types owned by other roles, then sets a target-only
  `search_path` so PostgreSQL keeps its implicit `pg_catalog` lookup precedence
  while unqualified DDL lands in the target schema; it holds the session
  advisory lock, transaction, and unlock on one reserved connection; an
  injected client is closed rather than returned to its pool when transaction
  or unlock cleanup is uncertain;
- compares the complete actual catalog delta to the checked-in public or
  steward manifest before it records provenance or commits; and
- records source hash, rendered hash, target schema, source head, and bundle
  hash in schema-local `__steward_core_repair_migrations` rows.

The marker table is provenance, not the acceptance gate. A second invocation
validates every exact post-repair catalog record before reporting
`already_applied`. Do not change application readiness to trust only this
table. The shared `drizzle.__drizzle_migrations` ledger belongs to Eliza in the
observed production database and is never read or written by this bundle.

The generated 0084–0110 slice reproduces the independent preflight envelope:
152 columns, 70 explicit constraints, one enum label, 14 functions, 39 indexes,
11 relations, and 14 triggers. PostgreSQL 18 also exposes NOT NULL constraints
as catalog records; the exact manifest retains and checks those additional
records instead of dropping them from the gate.

## Mandatory preconditions

Do not run the applying command until all of these are true:

1. The branch and generated catalog manifest have independent review on the
   exact head. Regenerate and review the manifest after any migration-source or
   PostgreSQL-major change.
2. A current encrypted production backup has passed a restore drill. Record
   the database recovery set, old Steward deployment ID, exact image digest,
   and source commit without placing secrets in the receipt.
3. The read-only command below reports `eligible` against a production-shaped
   disposable clone, then against production during the authorized maintenance
   window. A read-only result does not reserve the state; the applying
   transaction repeats every gate under locks.
4. The exact old production image and exact candidate image complete the
   compatibility exercise below against an isolated production restore. The
   old image is intentionally **not** fully compatible with governed provider
   execution after 0084; the accepted posture is forward-only with provider
   execution drained throughout any rollback. The receipt validator must pass.
5. The schema-aware 0111–0114 bundle and candidate readiness contract are
   independently reviewed. This repair stops at 0110.
6. Production writers are drained or a maintenance window is active. The
   bundle uses a five-second lock timeout and fails rather than waiting behind
   traffic indefinitely.
7. The named production approver has explicitly authorized the database
   mutation. Staging approval or merge approval is not production approval.

Use a protected passfile or secret-manager injection. Never place a database
password in command history, screenshots, receipts, or pull requests.

## Read-only inspection

The command defaults to read-only repeatable-read inspection. The expected
schema is mandatory:

```bash
export DATABASE_URL=FROM_SECRET_MANAGER
export STEWARD_CORE_REPAIR_EXPECTED_SCHEMA=steward
bun --cwd packages/db migrate:steward-core-repair
```

For the observed production envelope, inspection fails unless:

- 0082 is absent and exact 0083 is present;
- every 0084–0110 pre-state catalog record matches the generated manifest;
- there are no legacy `execution_ready` bindings without the new policy
  evidence;
- there are no existing external-custody nonces that would lack the new
  identity digest;
- there are no Google consequential-write operations requiring the 0102 data
  rewrite; and
- every EVM nonce namespace has exactly one resolvable tenant owner.

The reviewed manifest also requires the optional `capability_grants` plugin
table to be absent. Migration 0110 conditionally mutates that table when it is
installed, so a database with the plugin needs a separately generated catalog
and representative-data review; this bundle refuses to guess.

Any changed aggregate or catalog record requires a new read-only audit and
review; do not relax the gate to force the migration through.

## Apply

The only mutation switch is the exact value `YES`. Set it only in the approved
maintenance session:

```bash
export DATABASE_URL=FROM_SECRET_MANAGER
export STEWARD_CORE_REPAIR_EXPECTED_SCHEMA=steward
export STEWARD_CORE_REPAIR_APPLY=YES
bun --cwd packages/db migrate:steward-core-repair
```

The applying transaction acquires a named advisory lock, resolves and checks
the target schema, excludes writes to affected baseline tables, repeats all
catalog and aggregate checks, applies 0082 plus 0084–0110, asserts the exact
post-state and exact delta, writes the Steward-owned ledger, and then commits.
If any statement, hash, precondition, postcondition, or ledger assertion fails,
PostgreSQL rolls back the complete transaction.

After commit, run the read-only command again. It must report
`already_applied`, and the independently reviewed candidate readiness endpoint
must still pass its full core-manifest and schema-aware auth-bootstrap checks.
Do not substitute the repair ledger for `/ready`.

## Candidate startup and readiness contract

Apply the schema-aware 0111–0114 operator migration only after this core repair
reports `already_applied`:

```bash
export DATABASE_URL=FROM_SECRET_MANAGER
export STEWARD_CORE_REPAIR_EXPECTED_SCHEMA=steward
bun --cwd packages/db migrate:steward-schema
```

Run this command with the same effective owner-bound database role that will
start the candidate. The command and readiness probe require the configured
data schema to resolve exactly to the pinned schema, require that role to own
the bootstrap schema and functions, and reject PUBLIC or third-party grants on
that bootstrap surface. A split app/migrator role is not part of this release's
reviewed grant contract and therefore fails closed.

The production candidate must disable the ordinary shared-ledger migrator and
select the explicit Steward-owned readiness contract:

```bash
export NODE_ENV=production
export SKIP_MIGRATIONS=1
export STEWARD_MIGRATION_READINESS_MODE=steward-owned
export STEWARD_CORE_REPAIR_EXPECTED_SCHEMA=steward
```

In this mode the Bun entrypoint performs a fresh, bounded inspection before it
opens its listener. Startup requires both:

- the exact #917 core-repair ledger and exact live reviewed 0082–0110 catalog;
- the exact #915 schema-owned marker chain, exact bootstrap function bodies and
  security properties, and the physical nullable `authenticators.rp_id`
  column.

Neither check reads or writes Eliza's shared `drizzle.__drizzle_migrations`
ledger. Production `SKIP_MIGRATIONS` without an explicit readiness mode is a
configuration error. `/ready` repeats the same checks through a bounded,
single-flight cache and exposes only boolean results without the configured
probe token.

Steward-owned mode also fails startup if an enabled plugin owns a separate
schema or migration journal without its own reviewed readiness contract. For
this release, `capabilities` is such a plugin; disable it for the cutover unless
its schema-specific contract is independently added and reviewed. Schema-less
plugins remain eligible.

Keep the Railway deployment healthcheck configured (at minimum `/health`) so a
candidate that exits before its listener cannot displace the healthy image.
Before routing traffic, require authenticated `/ready` status 200 plus provider
discovery and the auth acceptance probes from the forward-only exercise below.

## Disposable PostgreSQL proof

The focused test creates and destroys isolated databases for both layouts. It
builds the exact through-0081 floor, installs 0083 without 0082, preserves a
sentinel shared Eliza ledger, runs a read-only inspection, applies the repair,
checks all source/rendered hashes and catalog postconditions, exercises a
deterministically owned EVM nonce namespace, and proves idempotent inspection.
It also proves missing 0083 and an unresolved nonce namespace fail before any
repair DDL or ledger row is retained.

Run it against the same PostgreSQL major version as production:

```bash
export DATABASE_URL=DISPOSABLE_POSTGRES_ADMIN_URL
bun test packages/db/src/__tests__/steward-core-repair.test.ts
```

The test account must be allowed to create and drop disposable databases. Never
point the test at production.

## Old-image compatibility and rollback

The database repair is additive but not safely downgradable. Application
rollback leaves the repaired database in place; there is no reverse SQL step.

The pinned production rollback baseline is:

- image
  `ghcr.io/steward-fi/steward@sha256:51557626b6c3215d432c7f4077b1cf44a059051d5a763384335a88270b371ca1`;
- source `a7b1b4d5232a234e0e3e86e600f58ef9ce8f68ad`; and
- `packages/api/src/services/provider-approval.ts` blob
  `7d7ae3a8cbba456c6eea6aa705a5d8b948c095be` (SHA-256
  `7c9ca23d25a07440d000e3150a0d2d2d9076f8e3e8223111063b6c5471f23ccc`).

### Why a fully compatible rolling contract is impossible

That rollback source transitions `approved -> execution_ready` by updating the
status, revision, and resume metadata, then mints a v2 authorization. It cannot
write the execute-time policy decision ID, revision hash, decision document,
decision hash, or evaluation time introduced by 0084. Those values are the
result of the new policy evaluation; a database default or trigger cannot
reconstruct them without fabricating authority evidence.

An expand-only phase can add nullable evidence columns without disturbing the
old image. It cannot safely preserve old governed execution after the contract:

- keeping the 0084 fence blocks the old resume write;
- allowing an evidence-less `execution_ready` or `executing` transition lets the
  old binary mint and dispatch authority without the new evidence; and
- silently rewriting that transition to another state would make the old API
  report success for an action that was not authorized.

Therefore no two-phase rollout can preserve the old image's full provider-write
semantics without weakening the new authority invariant. The regression test
`production rollback image resume shape fails closed after the 0084 authority
fence` executes the old update shape, requires SQL failure, and proves the row
remains `approved`; the adjacent candidate test proves an evidence-bearing
transition still succeeds. Do not relax that fence to make rollback appear
green.

Health, readiness, provider discovery, email/passkey session creation, refresh,
and a chat write are outside that governed transition, but they still require
proof from the exact image rather than an inference from catalog shape. The
gate command fails closed when no external receipt is supplied:

```bash
bun --cwd packages/db check:steward-core-repair-old-image

# Copy production-core-repair-old-image-receipt.example.json outside the
# repository, fill it from captured evidence, and keep any sensitive companion
# artifacts in protected storage.
export STEWARD_CORE_REPAIR_OLD_IMAGE_RECEIPT=/protected/path/old-image-proof.json
export STEWARD_CORE_REPAIR_OLD_IMAGE_EVIDENCE=/protected/path/old-image-evidence.tar.zst
export STEWARD_CORE_REPAIR_CANDIDATE_IMAGE=ghcr.io/steward-fi/steward@sha256:<approved-digest>
export STEWARD_CORE_REPAIR_CANDIDATE_SOURCE=<approved-40-character-commit>
bun --cwd packages/db check:steward-core-repair-old-image
```

The receipt validator pins both image digests and source commits, the repair
version, target schema, and catalog-manifest hash. It hashes the supplied
evidence artifact itself and requires that exact digest in the receipt. It also
requires matching rollback-image probes before and after repair, the same full
probe set on the exact candidate after 0111–0114, automatic migrations disabled
for both images, proof that the legacy provider resume is blocked by 0084, a
successful candidate evidence-bearing resume/execution, an explicit
forward-only rollback mode, and an independent approval bound to the exact
candidate source and evidence hash. The receipt is a procedural attestation
reviewed with its evidence; it is not a cryptographic signature, so branch
protection must independently show the matching external approval. Until it
passes, the production gate is
**NO-GO** even when the repair command reports `eligible`.

### Forward-only blue/green exercise

Before production authorization:

1. Restore a current production recovery set into an isolated database with the
   same PostgreSQL major version and `steward,public` search path.
2. Start the exact current production image against the untouched clone with
   automatic migrations disabled. Capture `/health`, `/ready`, provider
   discovery, email/passkey session creation and refresh, and a read-only chat
   smoke.
3. Drain governed provider execution and stop all database writers. Keep the
   drain active for every remaining step and for any rollback to the old image.
4. Apply this exact bundle to the clone and restart the same old image without
   running its migrator. Repeat health, readiness, providers, email/passkey
   session creation, refresh, and chat-write probes. Require the exact legacy
   provider resume shape to fail at the 0084 fence without changing the row.
5. Apply the separately reviewed 0111–0114 schema-aware bundle to the repaired
   clone, then start the exact candidate image as the green deployment. Prove
   an evidence-bearing provider resume and execution and require full
   `/health`, `/ready`, auth, provider, and migration receipts.
6. Return to the old image once, with provider execution still drained, and
   repeat only the accepted rollback-scope probes. Generate the external JSON
   receipt, hash it, obtain independent review, and run the gate command above.
7. In production, keep blue available only as a limited auth/health rollback;
   do not re-enable provider execution until green is accepted. A failed green
   deployment requires a forward fix or continued provider drain, not a claim
   of full old-image compatibility.

If the applying transaction fails before commit, retain the old image and
investigate; the database should be unchanged. If application acceptance fails
after commit, the old digest may be restored only with provider execution still
frozen; it is not a full functional rollback. Never run destructive reverse
DDL. Restore the full pre-migration recovery set only as a separately authorized
disaster-recovery action with all writers stopped and all post-backup writes
explicitly discarded.
