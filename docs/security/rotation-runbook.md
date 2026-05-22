# Secret Rotation Runbook

Operational procedures for rotating the Steward master password and adjacent
secrets. Covers SOC2 CC6.1 (secret management) requirements.

## 1. Master password / KDF salt rotation

Re-encrypts every record encrypted with `STEWARD_MASTER_PASSWORD` +
`STEWARD_KDF_SALT` using a new password/salt pair.

**Tables touched** (auto-discovered, override with `--table`):

- `encrypted_keys` — legacy per-agent EVM keys
- `encrypted_chain_keys` — per-(agent, chain, venue) keys
- `secrets` — tenant API keys / credentials (`SecretVault`)
- `accounts` — OAuth provider access + refresh tokens

### 1.1 Pre-flight

1. Schedule a maintenance window. Signing and OAuth refresh will fail mid-run
   for the rows currently locked in the active batch (~100 rows at a time).
2. Take a logical DB backup: `pg_dump --format=custom` of at minimum the four
   tables above. Verify restore on a scratch instance.
3. Pause writes to the affected tables. The simplest path: scale the API
   deployment to zero replicas, or block traffic at the LB. (The advisory
   lock only blocks other rotation runs, not normal traffic.)
4. Generate the new salt: `openssl rand -hex 32`. Generate the new password
   from a high-entropy source and store in your secret manager.

### 1.2 Run order

```bash
export DATABASE_URL=postgres://...
export STEWARD_MASTER_PASSWORD=<OLD>
export STEWARD_KDF_SALT=<OLD_SALT>
export STEWARD_MASTER_PASSWORD_NEW=<NEW>
export STEWARD_KDF_SALT_NEW=<NEW_SALT>

# 1. Dry-run: decrypts everything with OLD, never writes. Failures here
#    indicate a row that already cannot be decrypted with the OLD key —
#    investigate before proceeding.
bun run scripts/rotate-master-password.ts --dry-run

# 2. Real run.
bun run scripts/rotate-master-password.ts

# 3. Verify the audit chain captured start/complete pairs for every table.
#    Use the verifyAuditChain helper (packages/api/src/services/audit.ts)
#    against tenantId="system".
```

Each table emits one `system.master_password_rotation.start` and one
`system.master_password_rotation.complete` event. The `complete` event's
metadata contains `rowCount`, `firstId`, `lastId` for the processed range.

### 1.3 Cutover

1. Swap env values in your secret manager:
   `STEWARD_MASTER_PASSWORD` ← NEW, `STEWARD_KDF_SALT` ← NEW.
   Unset the `*_NEW` variables.
2. Restart the API replicas. They will pick up the new env and the new key.
3. Smoke-test: list secrets, sign a test transaction, complete an OAuth
   refresh.
4. Keep the old password+salt in cold storage for at least 30 days before
   destruction, in case a forensic decrypt is needed against the pre-rotation
   backup.

### 1.4 Failure mid-run

The script exits non-zero with:

```
ROLLBACK REQUIRED: rotation failed in table=<NAME> processed=<id-range>: <msg>
```

Recovery procedure:

1. The audit `start` event for `<NAME>` will be present without a matching
   `complete`. The id range printed is the inclusive set already re-encrypted
   with NEW.
2. To revert just that range, run the tool again with OLD and NEW swapped
   AND scoped to the affected table:

   ```bash
   export STEWARD_MASTER_PASSWORD=<NEW>
   export STEWARD_KDF_SALT=<NEW_SALT>
   export STEWARD_MASTER_PASSWORD_NEW=<OLD>
   export STEWARD_KDF_SALT_NEW=<OLD_SALT>
   bun run scripts/rotate-master-password.ts --table <NAME>
   ```

   Re-encrypted rows decrypt with NEW; un-processed rows still decrypt with
   OLD (which is now `_NEW`). The decryption of the un-processed tail will
   fail loudly — at that point the table is uniformly back on OLD.

   Alternative: restore the table from the pre-flight `pg_dump`. Faster
   when the failure is early.

3. Investigate root cause before re-attempting (most common: a row whose
   plaintext was corrupted independently and won't decrypt with either
   key — pull it aside, then resume).

## 2. JWT secret rotation

Symmetric HS256/HS512 signing secret used by the auth layer. No DB
re-encryption needed — tokens are signed in-flight only.

1. Set `STEWARD_JWT_SECRET_NEXT` alongside the current `STEWARD_JWT_SECRET`.
   Deploy. The verifier accepts either; the signer still uses the old one.
2. Wait for cache + active session TTLs (default 1h access tokens, 30d
   refresh tokens) — or, to force, invalidate refresh tokens by truncating
   `refresh_tokens` and notifying users.
3. Promote: set `STEWARD_JWT_SECRET` to the NEXT value, unset `_NEXT`,
   redeploy.
4. (Optional) Audit-log a `system.jwt_rotation.complete` event with the
   cutover timestamp.

## 3. OAuth provider client secret rotation

Per-provider OAuth client secret (e.g. Google, GitHub) stored in env.

1. Generate a new client secret in the provider console alongside the old one
   (most providers support overlap).
2. Update `STEWARD_OAUTH_<PROVIDER>_CLIENT_SECRET` in the secret manager.
   Redeploy.
3. Existing refresh tokens in `accounts.refresh_token_encrypted` remain
   valid — providers tie the refresh token to the client_id, not the secret.
4. Revoke the old secret in the provider console after one full deploy cycle.

## 4. Platform / API key rotation

Per-tenant API keys hashed in `tenants.api_key_hash`.

1. Mint a new key via the admin path, store its hash in
   `tenants.api_key_hash` (this is a swap, not an overlap — the column is
   single-valued today).
2. Distribute the new key to the tenant out-of-band.
3. For the audit-chain HMAC key (`STEWARD_AUDIT_HMAC_KEY`): rotation requires
   a chain break. Record a `system.audit_hmac_rotation.cutover` event with
   the new key, then update the verifier to accept the pre-cutover chain
   under the old key and the post-cutover chain under the new key. Historical
   verification splits at the cutover sequence number.

## 5. Order of operations under simultaneous compromise

If you suspect multiple secrets are leaked (e.g. host compromise):

1. Rotate JWT secret + revoke all refresh tokens (kills active sessions).
2. Rotate master password (re-encrypts at-rest material).
3. Rotate OAuth client secrets (cuts off provider-side replay).
4. Rotate tenant API keys (kills outstanding API access).
5. File the incident timeline against the audit chain via
   `verifyAuditChain` to prove no rows were forged during the response.
