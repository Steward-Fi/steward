# Root secret key rotation

This runbook is for self-hosted Steward operators. It describes behavior present in the code at `81cfa1a`. It does not claim that rotation is online where the implementation has no keyring.

## Rules before any rotation

1. Announce a maintenance window and stop API, proxy, worker, and webhook writers unless a section explicitly describes overlap.
2. Follow [`backup-restore.md`](./backup-restore.md), including a scratch restore. Keep the old root with that backup.
3. Generate new values off-host where possible. Never put them in shell history, command arguments, logs, tickets, or this document.
4. Run `steward doctor --strict` against the staged environment. Doctor reports presence and byte length, never secret content. A green doctor does not prove that encrypted rows decrypt.
5. Keep all replicas on one configuration generation. Mixed roots fail closed unpredictably.

## Capability matrix

| Root | Protects and consumers | Supported rotation | Old data or sessions |
|---|---|---|---|
| `STEWARD_MASTER_PASSWORD` | Wallet keys, secret vault, OAuth tokens, tenant email keys, request-signing keys, pending proxy bodies, and webhook secrets when no dedicated webhook root is set | Offline, transactional re-encryption with the script below | Preserved only after complete re-encryption |
| `STEWARD_KDF_SALT` | scrypt roots for the same encrypted inventory | Not independent. Rotate only with the master-password script | Old ciphertext becomes undecryptable without old salt |
| `STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY` and `STEWARD_WEBHOOK_SECRET_KDF_SALT` | `webhook_configs.secret` | Offline re-encryption by the same script using matching `*_NEW` values | Preserved after re-encryption |
| `STEWARD_JWT_SECRET` (`STEWARD_SESSION_SECRET` is deprecated fallback) | Symmetric access and session JWT signing and verification | Restart cutover, no overlap keyring | Existing JWTs are invalid immediately; users reauthenticate |
| `STEWARD_IDENTITY_JWT_PRIVATE_KEY` | Optional RS256 or ES256 identity tokens | Restart cutover; verifier overlap is external through public-key/JWKS trust | Old tokens verify only while old public key remains trusted |
| `STEWARD_EXECUTION_AUTH_SECRET` | Provider execution authorization v2 HMAC commitments | Online keyring overlap. First entry signs, every entry verifies | Old commitments verify while their key entry remains and TTL has not expired |
| `STEWARD_AUDIT_HMAC_KEY` | Database audit-chain links and HMAC checkpoints | No keyring and no transparent rotation | Historical chain requires old key. A direct replacement creates an unverifiable boundary |
| `STEWARD_AUDIT_SIGNING_KEY` | Ed25519 offline evidence bundle signatures | Restart cutover with external public-key trust overlap | Old evidence requires old public key forever |
| `STEWARD_PROXY_REQUEST_SIGNING_SECRETS` (singular fallback also consumed) | Proxy request HMAC authentication | Comma-separated overlap, as parsed by proxy middleware | Requests signed by removed roots fail |
| `STEWARD_REQUEST_SIGNING_SECRETS` (singular fallback also consumed) | API authorization-signature HMAC authentication | Comma-separated overlap | Requests signed by removed roots fail |
| Tenant request-signing keys | Encrypted DB keys accepted in `active` or `retiring` state | Online per-key overlap through tenant config API | Revoked or expired keys stop verifying |
| OAuth client secrets: `APPLE_CLIENT_SECRET`, `DISCORD_CLIENT_SECRET`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_SECRET`, `INSTAGRAM_CLIENT_SECRET`, `LINE_CLIENT_SECRET`, `LINKEDIN_CLIENT_SECRET`, `SPOTIFY_CLIENT_SECRET`, `TIKTOK_CLIENT_SECRET`, `TWITCH_CLIENT_SECRET`, `TWITTER_CLIENT_SECRET`, and `X_CLIENT_SECRET` | OAuth or OIDC code exchange and refresh | Provider-dependent overlap, Steward restart required | Existing tokens are not guaranteed to survive. Test the provider rather than assuming |
| `TELEGRAM_BOT_TOKEN`, `TWILIO_AUTH_TOKEN` | Telegram login proof and Twilio SMS authentication | Coordinated provider update and restart, no Steward keyring | Login or delivery fails on mismatch |
| Webhook signing secrets, including optional `WAIFU_WEBHOOK_SECRET` integration | Outbound or integration signatures, encrypted in DB for core webhooks | Replace configuration and coordinate receiver overlap | Receivers that trust only the old value reject new deliveries |
| `STEWARD_METRICS_TOKEN` | Optional security metrics endpoint bearer auth | Restart cutover, no server keyring | Old token stops immediately |
| `STEWARD_PLATFORM_KEY(S)`, `STEWARD_DEFAULT_TENANT_KEY`, client `STEWARD_TOKEN`/`STEWARD_API_TOKEN` | Platform, tenant, and CLI API authentication | Use multiple platform entries where configured; default tenant and client token have no overlap | Removed key stops immediately |
| `MONERO_WALLET_RPC_PASSWORD`, `POLYMARKET_SIGNING_SERVER_TOKEN` | Optional signing sidecar authentication | Sidecar and Steward coordinated restart | In-flight sidecar calls fail |
| Optional KMS/HSM, database, Upstash/Redis, S3, SMTP, and provider credentials | Their named external service | Controlled by that backend, not Steward | Follow backend procedure and restart consumers |

## Master password and KDF rotation

### Scope and limitations

`scripts/rotate-master-password.ts` inventories these persistent classes:

- `encrypted_keys`, including legacy wallet keys
- `encrypted_chain_keys`, including tenant, chain, and venue AAD
- every `secrets` version, including soft-deleted rows
- OAuth access and refresh fields in `accounts`
- `tenant_request_signing_keys`
- encrypted `pending_proxy_requests` bodies
- JSON-wrapped Resend keys in `tenant_configs.email_config`
- `webhook_configs.secret`, including supported legacy plaintext rows which are encrypted during write mode

It first authenticates the complete selected inventory without writes. Write mode repeats that preflight, then re-encrypts all classes in one database transaction. Any authentication or write failure rolls back the transaction. Repeated invocation is idempotent because ciphertext that authenticates under the new root is skipped. Output contains table names, row identifiers, and counts only, never plaintext or root values. AEAD metadata is regenerated while each row's production AAD is preserved.

In-memory or Redis MFA challenges and import sessions are also encrypted with the master root but are not enumerable through the database script. Drain their TTL or explicitly clear those ephemeral stores during the maintenance window. This is why the procedure is offline. External keystore backends configured through `STEWARD_KMS_PROVIDER` are not re-encrypted by this script. Follow that backend's rotation procedure instead and prove decrypt/sign operations before retiring its old root.

### Preconditions

1. Stop all Steward writers. The advisory lock prevents a second rotation script, not application writes.
2. Drain or clear encrypted MFA, device-authorization, and import-session records.
3. Confirm a tested backup and record row counts for every inventory table.
4. If webhooks use dedicated roots, set the current `STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY` and `STEWARD_WEBHOOK_SECRET_KDF_SALT`. To rotate those too, set their `*_NEW` counterparts. If they fall back to master/KDF, no extra values are needed.
5. Export roots from a protected, non-recorded environment. Prefer a secret-manager injection mechanism over interactive shell text.

### Exact procedure

```sh
export DATABASE_URL='postgresql://...'
export STEWARD_MASTER_PASSWORD="$OLD_MASTER_FROM_SECRET_MANAGER"
export STEWARD_KDF_SALT="$OLD_KDF_SALT_FROM_SECRET_MANAGER"
export STEWARD_MASTER_PASSWORD_NEW="$NEW_MASTER_FROM_SECRET_MANAGER"
export STEWARD_KDF_SALT_NEW="$NEW_KDF_SALT_FROM_SECRET_MANAGER"

# Mandatory no-write inventory and authentication pass.
bun run scripts/rotate-master-password.ts --dry-run

# Only continue if every table reports failed=0.
bun run scripts/rotate-master-password.ts --confirm
```

Do not use `--table` in write mode. It is intentionally rejected because partial inventory rotation is unsafe. While the old and `*_NEW` variables are still present, run the no-write command one more time. It must report every encrypted row as already rotated and zero failures:

```sh
bun run scripts/rotate-master-password.ts --dry-run
```

Then atomically replace the deployed master and KDF variables with the new values, remove all `*_NEW` values, restart every consumer, and run `steward doctor --strict`. The rotation script cannot run after removing `*_NEW` because it deliberately requires both root generations. Perform non-value-bearing smoke tests: decrypt secret metadata through its normal consumer, sign with a test wallet, refresh a disposable OAuth account, verify request signing, complete a disposable proxy approval, and deliver a disposable webhook.

### Rollback

Before application cutover, a transaction failure needs no data rollback. Fix the cause and rerun. After database success but before all replicas use the new root, finish the configuration cutover rather than serving mixed roots. If post-cutover verification fails, stop every consumer and restore the database backup together with the old master and old KDF salt. Never restore only one half of that pair. Retain the old pair as long as backups encrypted under it are retained.

Blast radius of an incorrect root is all local encrypted custody and credentials. The script does not rotate KMS/HSM-managed material.

## Execution authorization v2

The actual format is a comma-separated list of `keyId:secret` entries. A bare value gets key ID `v2-default`. The first usable entry is the only signing key. All listed entries can verify. Duplicate key IDs are ignored after the first.

1. Generate a new root and unique key ID.
2. Deploy the same list to every API minter and proxy verifier, with new first and old second: `new-id:<new>,old-id:<old>`.
3. Confirm new commitments carry `new-id`. Confirm one pre-cutover commitment still verifies. The contract test is `packages/shared/src/__tests__/provider-execution-auth-rotation.test.ts`.
4. Wait longer than the maximum execution-authorization TTL and account for clock skew and queued work.
5. Deploy `new-id:<new>` only. Confirm an old commitment now fails.

Rollback during overlap is `old-id:<old>,new-id:<new>`. That makes old active again and new verify-only. Removing old too early causes an execution outage for outstanding commitments. Merely placing old second prevents it from signing because `signProviderExecutionCommitmentV2` requires the commitment key ID to equal the first entry.

## JWT and session roots

Steward has no symmetric JWT verification keyring and does not consume `STEWARD_JWT_SECRET_NEXT`. Rotate in a maintenance window:

1. Stop issuance and all replicas.
2. Replace `STEWARD_JWT_SECRET` with at least 32 high-entropy characters.
3. Revoke or delete persisted refresh sessions using the supported session revocation path.
4. Restart all replicas and run doctor.
5. Require reauthentication.

Rollback means restoring the old secret, but tokens minted under the new secret then fail. A compromise response should not roll back to a compromised root. `STEWARD_SESSION_SECRET` is only a deprecated compatibility fallback and should be removed. Embedded development can fall back to the master password, but production cannot.

For optional asymmetric identity JWTs, publish and distribute the new public key before replacing `STEWARD_IDENTITY_JWT_PRIVATE_KEY`. Keep the old public key trusted until every old token expires. Steward does not provide that external verifier trust store.

## Audit HMAC and checkpoints

`STEWARD_AUDIT_HMAC_KEY` creates the chain links. Checkpoints using that HMAC do not create an independent trust root. Current code has one key and no key ID, so seamless rotation is unsupported. Replacing it makes historical verification under the new process fail.

Controlled break-glass procedure:

1. Stop audit writers and export a final checkpoint and sequence under the old key.
2. Preserve the old key in restricted archive storage for historical verification.
3. Record the cutover time, last old sequence/hash, and new key fingerprint in an external incident record.
4. Replace the key and restart.
5. Treat pre-cutover and post-cutover evidence as two verification epochs. Verify each epoch with its own key.

There is no automated rollback or multi-epoch verifier in Steward today. Do not describe this as continuous chain verification.

## Ed25519 audit signing

Generate a new Ed25519 private key, derive its public key and SHA-256 fingerprint without exposing the private key, and distribute the public key plus fingerprint through the verifier's authenticated channel. Keep both public keys trusted before restart. Replace `STEWARD_AUDIT_SIGNING_KEY`, restart, export a disposable evidence bundle, and verify it with the new public key. Verify a historical bundle with the old public key too.

The old private key can be destroyed after policy permits, but the old public key must remain in verifier trust stores for as long as old evidence must verify. A leaked old private key means old signatures cannot by themselves prove when evidence was created. Rotation limits future exposure but does not repair already compromised provenance.

## Request-signing roots

### Proxy and API request-signing environment keyrings

The proxy parser accepts comma-separated secrets from `STEWARD_PROXY_REQUEST_SIGNING_SECRETS`, with singular `STEWARD_PROXY_REQUEST_SIGNING_SECRET` as fallback. API authorization-signature middleware separately accepts `STEWARD_REQUEST_SIGNING_SECRETS` and its singular fallback. Add the new root to the relevant list while retaining old, update clients to sign with new, observe old-key usage reach zero, then remove old and restart. These keyrings have no key IDs, so verification tries configured roots. Roll back by re-adding old. Rotating one family does not rotate the other.

### Tenant request-signing keys

Create a new tenant request-signing key, distribute it, and leave the old row `retiring`. The middleware verifies unrevoked, unexpired `active` and `retiring` rows. Move clients to the new key, then revoke old. The master-password script re-encrypts these key values and preserves AAD. A premature revoke rejects old client requests immediately.

## OAuth client secrets

Steward consumes the OAuth client-secret variables enumerated in the matrix with their matching client IDs. `X_CLIENT_SECRET` belongs to provider-account X connect, while `TWITTER_CLIENT_SECRET` belongs to the login provider.

1. Confirm the provider supports two simultaneously valid client secrets. If not, schedule downtime.
2. Create the new provider-side secret without revoking old.
3. Update the Steward secret manager and restart all OAuth consumers.
4. Complete a new authorization and a refresh with a disposable account.
5. Revoke old at the provider and repeat the tests.

Do not assume refresh tokens survive a client-secret rotation. Provider behavior differs. Rollback is possible only while the provider still accepts old. The provider client secret is separate from encrypted provider access/refresh tokens in `accounts`, which are covered by master-password re-encryption.

## Webhook, metrics, platform, and sidecar roots

Webhook signing values are per configuration. Coordinate receiver dual verification, replace the webhook secret, deliver a signed test, then remove old trust at the receiver. Their database encryption root is handled separately in the master procedure.

For `STEWARD_METRICS_TOKEN`, update scraper and server during one restart window. No overlap exists. Confirm unauthenticated and old-token requests fail and new-token requests succeed without logging token text.

For platform keys, use the multiple-entry form where available: add new, migrate callers, then remove old. `STEWARD_DEFAULT_TENANT_KEY` has no overlap facility and requires coordinated downtime. These are authentication credentials, not encryption roots.

For `TELEGRAM_BOT_TOKEN` and `TWILIO_AUTH_TOKEN`, create or rotate the provider credential, update every API replica together, then test a disposable login or message. Neither has a Steward overlap keyring. Rollback is provider-dependent and compromise response must not restore a compromised token.

For `MONERO_WALLET_RPC_PASSWORD` or `POLYMARKET_SIGNING_SERVER_TOKEN`, stop Steward calls, change sidecar authentication, update Steward, restart sidecar and Steward, and perform a read-only health check before signing. In-flight calls are the blast radius. Database, Upstash/Redis, SMTP, S3, KMS, HSM, and other optional provider credentials are rotated at their owning service. Confirm actual overlap support there and restart every Steward consumer. `STEWARD_TOKEN`/`STEWARD_API_TOKEN` are CLI-side bearer credentials: issue a replacement server credential first, update the client, prove a harmless authenticated read, then revoke old. Doctor does not prove external-service authentication.
