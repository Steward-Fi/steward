# Backup, restore, and disaster recovery

This runbook is for self-hosted Steward operators. Test it against the exact
release and database major version used in production. A backup that has not
been restored in a drill is not a recovery plan.

> **Critical:** a database dump is not a complete Steward backup. Keep the
> database, its schema/release metadata, and the out-of-band secrets below as
> one versioned recovery set. The secrets are not stored in the database. Loss
> of an encryption root can make otherwise intact ciphertext permanently
> unrecoverable.

## Recovery set and trust boundaries

### PostgreSQL

Back up the whole database in one consistent `pg_dump`. Do not select only
"important" tables. The coherent unit includes, among other tables:

- encrypted wallet keys, chain keys, OAuth tokens, credentials, routes, policy,
  tenant, agent, workspace, provider-account, operation, grant, and binding rows;
- `approval_queue`, `pending_proxy_requests`, transactions, and intents, which
  preserve the approval lifecycle and encrypted queued request bodies;
- `execution_authorization_nonces`, including its consumed state and the v2
  `dispatch_state` (`none`, `claimed`, `dispatched`, terminal, or
  `outcome_unknown`);
- `audit_events`, `audit_chain_heads`, `audit_checkpoints`, provider-action audit
  rows/outbox, and proxy audit rows.

A table-only dump can sever foreign keys, approval-to-intent bindings, nonce
replay protection, or audit continuity. Never restore a nonce or approvals table
from a different point in time than the rest of the database.

Record alongside the dump:

- Steward git commit or image digest and release version;
- PostgreSQL server major version and `pg_dump --version`;
- latest applied migration (`packages/db/drizzle/` for PostgreSQL, and
  `__steward_migrations` for PGLite);
- backup start/end UTC timestamps and a SHA-256 digest of the encrypted archive;
- the recovery-set identifier shared with the secret escrow and, if retained,
  Redis snapshot.

### Out-of-band secrets

Export secrets through the operator's secret store, not by printing `.env` to a
terminal or copying values into a ticket. Store the export encrypted, separately
from the database dump, with at least two tested custodians. Files containing
secrets must be owned by the service account and mode `0600`; parent directories
must be `0700`.

The current `steward doctor` and Compose production roots are:

| Name | Recovery effect if the value used by the backup is lost |
| --- | --- |
| `STEWARD_MASTER_PASSWORD` | **Unrecoverable ciphertext:** encrypted wallet/chain keys, vault credentials, OAuth tokens, and encrypted pending proxy bodies cannot be decrypted. A replacement password does not recover them. |
| `STEWARD_KDF_SALT` | **Unrecoverable ciphertext when a non-default salt was used:** it is part of master-key derivation. Restore the exact salt with the matching master password. Never fall back to the legacy built-in salt during recovery. |
| `STEWARD_EXECUTION_AUTH_SECRET` | Existing signed execution authorizations cannot be verified. Preserve the complete comma-separated `keyId:secret` verification list for the longest live authorization window. The first key is active for signing. If lost, fail closed and invalidate/recreate affected work rather than bypass verification. |
| `STEWARD_AUDIT_HMAC_KEY` | Historical audit-event HMAC chains cannot be recomputed or verified. Database rows and signed checkpoints remain available, but the symmetric chain-integrity check is lost. A new key cannot authenticate old events. |
| `STEWARD_AUDIT_SIGNING_KEY` | Existing checkpoint rows and exported bundles remain verifiable with their embedded public keys, but the restored instance cannot create continuity checkpoints with the old identity. Loss is not ciphertext loss, but key continuity is unrecoverable. Configure the same PKCS#8 PEM or 64-hex-character Ed25519 seed. |
| `STEWARD_JWT_SECRET` | Existing user/agent/session JWTs cannot be verified. Restoring a different value forces reauthentication/token reissue; never substitute `STEWARD_MASTER_PASSWORD` in production. |
| `STEWARD_EMAIL_CODE_SECRET` | Pending email login codes and magic-link challenges cannot be verified after restoring a different value. Restore the exact strong secret or deliberately invalidate all pending email login state before reopening. |
| `POSTGRES_PASSWORD` and the four credentials represented by `STEWARD_ADMIN_DATABASE_URL`, `MIGRATION_DATABASE_URL`, `DATABASE_URL`, and `STEWARD_PLATFORM_DATABASE_URL` | Restore the distinct database administrator, restricted migrator, tenant application, and platform authority logins. Never reuse one URL/role for another authority. Passwords may be reset by a database administrator without changing encrypted application data, but all four URLs must be restored consistently to Compose/CLI configuration. Do not put passwords in command history. |

Also escrow every enabled deployment-specific credential that is needed after a
restore, including `STEWARD_PLATFORM_KEYS`, tenant API keys returned only once,
`STEWARD_PROXY_REQUEST_SIGNING_SECRETS`, OAuth client secrets, email credentials,
webhook key overrides, and optional sidecar credentials. Their loss has the effect of
that subsystem's documented rotation or re-enrollment path, not database
decryption. `STEWARD_PLATFORM_KEYS` and raw tenant API keys are not recoverable
from stored hashes.

The KDF salt is configuration, not a per-row database salt. Row-level IVs,
authentication tags, and salts are already in the full database dump, but they
do not replace `STEWARD_MASTER_PASSWORD` plus `STEWARD_KDF_SALT`.

## PostgreSQL backup

Use a `pg_dump` client with the same major version as the server. PostgreSQL
supports restoring a logical dump into a newer server in many cases, but test
that path; do not restore with an older `pg_restore` than the `pg_dump` that
created the archive.

Use a protected passfile instead of embedding a password in the URI or command.
The placeholders below are non-secret identifiers:

```bash
install -d -m 0700 /secure/steward-backups
install -m 0600 /dev/null /secure/steward-backups/pgpass
# Populate pgpass through the secret store, format:
# DB_HOST:DB_PORT:DB_NAME:DB_USER:DB_PASSWORD
export PGPASSFILE=/secure/steward-backups/pgpass
export PGHOST=DB_HOST PGPORT=5432 PGDATABASE=DB_NAME PGUSER=DB_USER
umask 077
pg_dump --format=custom --compress=9 --no-owner \
  --file=/secure/steward-backups/steward-RECOVERY_SET.dump
sha256sum /secure/steward-backups/steward-RECOVERY_SET.dump \
  > /secure/steward-backups/steward-RECOVERY_SET.dump.sha256
chmod 0600 /secure/steward-backups/steward-RECOVERY_SET.dump*
```

`pg_dump` is transactionally consistent for PostgreSQL data. For the smallest
uncertainty window around in-flight external dispatches, stop API and proxy
writers before the dump. A hot dump is usable, but recovery must still treat any
captured in-flight dispatch as uncertain.

For the root Compose stack, keep application writers stopped while dumping from
the bundled PostgreSQL 16 container:

```bash
docker compose stop steward-api steward-proxy
umask 077
docker compose exec -T postgres pg_dump \
  -U "${POSTGRES_USER:-steward}" -d "${POSTGRES_DB:-steward}" \
  --format=custom --compress=9 --no-owner \
  > /secure/steward-backups/steward-RECOVERY_SET.dump
chmod 0600 /secure/steward-backups/steward-RECOVERY_SET.dump
# Restart only after the dump and any required Redis snapshot are complete.
docker compose start steward-api steward-proxy
```

The password remains inside Compose/container configuration and is not echoed.
Do not use `docker compose down -v`; `-v` deletes named data volumes.

### Redis

PostgreSQL is the durable source for Steward records. Redis nevertheless holds
rate-limit, spend-tracking, and challenge/cache state. Losing live spend counters
can weaken enforcement until their windows expire. During a coordinated backup,
freeze API/proxy writers and either capture a tested Redis snapshot with the
same recovery-set identifier or document a conservative cold-start policy that
keeps the proxy unavailable until affected spend windows expire. Never bring up
a restored proxy with silently empty counters when a spending-limit policy
expects prior usage.

## Embedded PGLite backup

PGLite is intended for local/development use and does not use the Compose
PostgreSQL volume. Its persistent directory is `STEWARD_PGLITE_PATH`, defaulting
to `~/.steward/data`. `STEWARD_PGLITE_MEMORY=true` has no durable state and
cannot be backed up after the process exits.

Do not copy a live PGLite directory. Stop the sole API/embedded process, confirm
no process has the directory open, and archive the entire directory, including
its migration metadata:

```bash
umask 077
# Stop the service/process that runs `bun run start:local` first.
tar --create --zstd --file /secure/steward-backups/pglite-RECOVERY_SET.tar.zst \
  --directory /var/lib/steward pglite-data
chmod 0600 /secure/steward-backups/pglite-RECOVERY_SET.tar.zst
sha256sum /secure/steward-backups/pglite-RECOVERY_SET.tar.zst \
  > /secure/steward-backups/pglite-RECOVERY_SET.tar.zst.sha256
```

Replace `/var/lib/steward/pglite-data` with the configured path. Restore only to
a stopped instance, preserve ownership/mode, and start the same Steward release
first. A PGLite directory archive is not a portable `pg_restore` archive.

## Restore order

1. **Declare an incident and freeze writers.** Block inbound traffic at the
   operator-controlled reverse proxy/firewall, then stop every Steward API,
   proxy, worker, and embedded process. Stop external schedulers and agents that
   submit work. Keep them stopped through reconciliation.
2. **Choose one recovery set.** Verify checksums, timestamps, release/database
   versions, secret-set identifier, and chain of custody. Never combine a newer
   database with older nonce/audit tables or a mismatched root-secret set.
3. **Prepare compatible software.** Restore into the recorded PostgreSQL major
   version with a `pg_restore` version at least as new as the dump producer.
   Check out the recorded Steward release. Do not let a newer API migrate the
   target before the base restore is complete.
4. **Restore the database while the application is stopped.** Restore into an
   empty database. For a replacement database owned by the intended role:

   ```bash
   export PGPASSFILE=/secure/steward-backups/pgpass
   export PGHOST=DB_HOST PGPORT=5432 PGDATABASE=DB_NAME PGUSER=DB_USER
   pg_restore --exit-on-error --clean --if-exists --no-owner --no-privileges \
     --dbname=DB_NAME /secure/steward-backups/steward-RECOVERY_SET.dump
   ```

   `--clean` is destructive to the selected target. Triple-check `PGHOST` and
   `PGDATABASE`; never point this command at a healthy production database.
5. **Restore environment secrets before application startup.** Install the exact
   `STEWARD_MASTER_PASSWORD`, `STEWARD_KDF_SALT`, audit keys, execution-auth key
   list, JWT secret, database credentials, and enabled subsystem credentials.
   Set files to `0600`. Do not print values in logs or shell tracing.
6. **Resolve migration compatibility.** First run the recorded release against
   the restored schema. Compare the migration ledger to the checked-out
   `packages/db/drizzle/` files. Then upgrade one tested release step at a time.
   Run `DATABASE_URL="$STEWARD_MIGRATION_DATABASE_URL" bun run --cwd packages/api migrate`
   with the restored plugin selection, reconcile ownership using
   `rls-bootstrap.sql` through the provider-superuser-equivalent operator, and
   activate through the direct migration login. Keep both privileged URLs out
   of the API, set `SKIP_MIGRATIONS=true`, and start it only after all three
   steps succeed. Never run an older release against a schema already migrated
   by a newer release.
7. **Restore or conservatively reset Redis.** Restore the matched snapshot, or
   enforce the documented cold-start hold for spend windows. Redis recovery must
   not delay inspection of durable PostgreSQL state.
8. **Start API only, with dispatch blocked.** Keep the external proxy, agents,
   workers, and ingress frozen. Confirm `/health` and `/ready`, then run doctor
   and the database/audit checks below.
9. **Reconcile approvals and execution state.** Follow the next section. Do not
   make direct SQL status edits merely to make rows look terminal.
10. **Resume in stages.** Enable API ingress, then proxy ingress and workers only
    after a named operator signs off. Monitor denied/replayed authorization,
    audit-verification, spend-limit, decrypt, and migration errors.

For PGLite, replace step 4 with extraction of the complete archive into an empty
configured `STEWARD_PGLITE_PATH`, using the original owner and permissions.

## In-flight reconciliation, fail closed

A crash-consistent restore cannot prove what an external provider did after the
backup boundary. Steward therefore makes **no exactly-once recovery claim**.
Database single-use and idempotency controls prevent known duplicate dispatches,
but cannot turn an uncertain external side effect into proof.

While the proxy remains frozen, inventory at least:

```sql
SELECT id, intent_id, execution_id, status, dispatch_state, issued_at,
       expires_at, dispatched_at, outcome_recorded_at, provider_idempotency_key
FROM execution_authorization_nonces
WHERE version = 2
  AND (status = 'active'
       OR dispatch_state IN ('claimed', 'dispatched', 'outcome_unknown'))
ORDER BY issued_at;

SELECT id, approval_kind, intent_id, status, requested_at, resolved_at,
       expires_at, consumed_at
FROM approval_queue
WHERE status IN ('pending', 'approved')
ORDER BY requested_at;

SELECT id, status, expires_at, approved_at, executed_at
FROM pending_proxy_requests
WHERE status IN ('pending', 'approved', 'executing')
ORDER BY created_at;
```

Disposition rules:

- `claimed`, `dispatched`, and `outcome_unknown` executions are **never blindly
  retried or reset to `none`**. Quarantine them. Check the provider using its
  operation/request/idempotency identifier and independent records. If a
  supported reconciliation path can establish the outcome, use that path and
  retain its audit evidence. The current repository does not expose a generic
  operator reconciliation command, so do not invent one or update rows by hand.
  If the outcome cannot be proven, leave it failed closed and create a new human-
  reviewed intent only after assessing duplicate-side-effect risk.
- A `claimed` row is not proof that dispatch happened, and a missing terminal
  event is not proof that it did not. Treat both directions as uncertain.
- Expired active authorizations must not be extended or replayed. The governed
  dispatch claim checks database time and fails closed. Recreate approval and
  authorization through the normal flow when safe.
- Pending/approved approvals and queued proxy requests may have expired or may
  bind to policy, routes, secrets, operations, or external facts that changed
  after the backup. Let normal lifecycle validation expire/reject stale work.
  Require fresh review for restored approved-but-unconsumed work; do not resume
  it merely because the restored status says `approved`.
- Record the incident decision, evidence checked, and replacement intent IDs in
  the audit/incident record. Preserve the restored database snapshot for
  forensics.

## Verification before reopening

Run the existing doctor from the restored release. It reports presence/length,
not secret values:

```bash
bun packages/cli/src/index.ts doctor --strict --env /secure/steward.env --json
curl --fail http://127.0.0.1:3200/health
curl --fail http://127.0.0.1:3200/ready
```

Doctor checks configuration and health, not decryptability of every ciphertext.
Using a dedicated test tenant/agent, perform a read/decrypt/sign smoke test that
does not broadcast value, plus an OAuth/secret decrypt test for each enabled
backend. Failure means keep ingress closed.

For every tenant, read the expected head while writers remain frozen:

```sql
SELECT tenant_id, expected_seq, expected_count, floor_seq,
       encode(head_hmac, 'hex') AS head_hmac
FROM audit_chain_heads
ORDER BY tenant_id;
```

Call the existing authenticated `POST /audit/verify` endpoint starting at
`fromSeq=1`, with `requireHead=true`. The endpoint accepts at most 10,000 rows,
so use contiguous ranges and set the final `toSeq` to that tenant's exact
`expected_seq`; do not use a guessed upper bound. It recomputes the HMAC chain
and checks the in-database high-water mark. Keep authentication in a protected
curl config or operator client, not command history. Every result must be valid,
cover the requested range, and report no break. This check requires the original
`STEWARD_AUDIT_HMAC_KEY`.

Then create and verify signed evidence bundles with the existing CLI/offline
verifier. The CLI invokes `scripts/verify-evidence-bundle.mjs` when `--verify` is
set. Export contiguous ranges of at most 10,000 events, ending the final range at
the exact head sequence:

```bash
umask 077
bun packages/cli/src/index.ts audit bundle \
  --from FIRST_SEQUENCE --to LAST_SEQUENCE_IN_RANGE \
  --out /secure/steward-backups/post-restore-audit-RANGE.json --verify
```

This requires tenant authentication configured for the CLI and the restored
`STEWARD_AUDIT_SIGNING_KEY`. Compare the latest restored checkpoint/public-key
identity and chain head with a pre-incident bundle held outside the database.
An offline bundle can validate its embedded signature and content commitment,
but does not by itself prove that no newer database tail was lost. A mismatch,
missing expected tail, unknown signer, HMAC failure, or head failure blocks
reopening.

Also verify row counts/critical inventories against the backup manifest, inspect
migration status, ensure no service used a development secret fallback, and test
spend-limit behavior before unfreezing the proxy.

## Tested disaster-recovery drill checklist

Run this at an interval justified by the RPO/RTO target and after material schema,
key, migration, or deployment changes. Never drill by restoring over production.

- [ ] Assign incident commander, database operator, secret custodian, and
      independent verifier.
- [ ] Create a tagged recovery set and record release/image, PostgreSQL and tool
      versions, migration tip, timestamps, checksums, and escrow identifier.
- [ ] Provision an isolated target with outbound provider calls blocked.
- [ ] Restore the full PostgreSQL dump, exact out-of-band secret set, and matched
      Redis snapshot or documented conservative hold.
- [ ] Start the recorded Steward release first; capture migration and readiness
      output. If testing an upgrade, perform it only after base restore succeeds.
- [ ] Run strict doctor, `/health`, `/ready`, ciphertext smoke tests, authenticated
      `/audit/verify?fromSeq=1&requireHead=true` for every tenant, and offline
      evidence-bundle verification.
- [ ] Compare critical table counts, audit heads/checkpoints, and expected latest
      transaction/approval/nonce timestamps with the source manifest.
- [ ] Inject or retain representative pending approval plus `claimed`,
      `dispatched`, and `outcome_unknown` nonce cases. Confirm the drill procedure
      quarantines them and sends no provider request.
- [ ] Confirm expired authorization and stale approval paths fail closed.
- [ ] Confirm proxy remains blocked with missing execution-auth/audit roots and
      with unavailable required Redis spend state.
- [ ] Exercise staged ingress reopening using a non-value test operation, then
      close ingress again and preserve evidence.
- [ ] Measure detection, restore, verification, reconciliation, and total recovery
      times. Record actual recovered timestamp and data loss.
- [ ] Destroy the isolated copy and secret material under the operator's secure
      media procedure. File owners and due dates for every failed step.

A drill passes only when all required checks execute and pass. A skipped secret,
audit, nonce, or approval assertion is a failed drill.

## RPO/RTO worksheet

Fill this per deployment. Do not copy aspirational values into an SLA until a
drill demonstrates them.

| Item | Target | Last measured | Owner/evidence |
| --- | --- | --- | --- |
| Maximum PostgreSQL data loss (RPO) | `___` | `___` | `___` |
| Secret escrow update lag (must not exceed DB recovery-set lag) | `___` | `___` | `___` |
| Redis spend/challenge-state loss or conservative hold | `___` | `___` | `___` |
| Incident detection and writer freeze | `___` | `___` | `___` |
| Database/PGLite restore | `___` | `___` | `___` |
| Secret installation and decrypt smoke tests | `___` | `___` | `___` |
| Audit verification and checkpoint comparison | `___` | `___` | `___` |
| In-flight approval/dispatch reconciliation | `___` | `___` | `___` |
| Staged service recovery (RTO) | `___` | `___` | `___` |
| Backup retention and last successful drill date | `___` | `___` | `___` |

RPO is bounded by the oldest component in a coherent recovery set, not just the
latest database dump. RTO includes human review of uncertain external dispatches;
do not hide that time by reopening the proxy before reconciliation.
