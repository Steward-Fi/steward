# Steward audit evidence

Steward keeps one tenant-scoped audit evidence plane. Do not add a parallel audit log for new custody work. Production paths write through `writeAuditEvent` / `appendAuditEventWithinTx` from `packages/db/src/audit-chain.ts`, which appends to `audit_events` and advances `audit_chain_heads` in the same locked operation.

## Event chain

Each `audit_events` row has:

- `tenant_id`, `seq`
- `prev_hash`, the previous row's HMAC, or zeroes for the first live row
- `hmac`, HMAC-SHA256 over `prev_hash` plus the canonical event fields
- actor, action, resource, request, and metadata fields

`audit_chain_heads` is the out-of-band high-water mark. It records expected head sequence, count, head HMAC, and retention floor. Verification compares rows to this head, so it catches both row tampering and tail truncation. A plain in-band chain walk cannot detect deleting the newest rows, so the head row is mandatory evidence.

The HMAC key is `STEWARD_AUDIT_HMAC_KEY`. This is intentionally symmetric: online verification can recompute row HMACs, but exported bundles never reveal the key.

## Checkpoints

Evidence bundles include an Ed25519 checkpoint over the tenant head and a content digest of the exported events. Checkpoints are persisted append-only in `audit_checkpoints`.

Current signing key source is `STEWARD_AUDIT_SIGNING_KEY`, parsed by `packages/api/src/services/audit-checkpoint.ts` as PKCS#8 PEM, raw hex seed, or base64 seed. This is operationally the existing Steward secret/keystore configuration surface, not a new database key plane. Alternative considered: storing a generated checkpoint key row in a new table. Rejected for E1 because it would add a second persistent key plane and complicate backup/rotation semantics.

For KMS-backed deployments, keep the env secret in the deployment secret manager or KMS envelope path alongside the existing Steward custody configuration. Rotate it using `docs/runbooks/key-rotation.md` and preserve old public keys for historical bundles.

## Export format

Use:

```bash
bun packages/cli/src/index.ts audit bundle --from 1 --to 10000 --out evidence.json --verify
```

or fetch `GET /audit/bundle?from=1&to=10000` with tenant authentication.

The bundle is JSON:

```json
{
  "version": 1,
  "tenantId": "tenant-id",
  "range": { "from": 1, "to": 10000, "includesHead": true },
  "canonicalizationSpec": "...",
  "events": [
    {
      "seq": 1,
      "prevHash": "...",
      "hmac": "...",
      "actorType": "agent",
      "actorId": "agent-id",
      "action": "capability.enroll",
      "resourceType": "agent",
      "resourceId": "agent-id",
      "metadata": { "decision": "allow" },
      "ipAddress": null,
      "userAgent": null,
      "requestId": null,
      "createdAt": "2026-07-30T00:00:00.000Z"
    }
  ],
  "checkpoint": {
    "payload": {
      "v": 1,
      "tenantId": "tenant-id",
      "seq": 1,
      "headHmac": "...",
      "expectedCount": 1,
      "floorSeq": 0,
      "timestamp": "2026-07-30T00:00:00.000Z",
      "softwareVersion": "...",
      "eventsDigest": "...",
      "eventsFromSeq": 1,
      "eventsToSeq": 1
    },
    "signature": "base64-ed25519-signature",
    "publicKey": "-----BEGIN PUBLIC KEY-----..."
  },
  "generatedAt": "2026-07-30T00:00:00.000Z"
}
```

For third-party JSON Lines custody, write one event per line from `events` and keep the checkpoint payload/signature/publicKey as a manifest:

```bash
jq -c '.events[]' evidence.json > evidence.events.jsonl
jq '{version, tenantId, range, canonicalizationSpec, checkpoint, generatedAt}' evidence.json > evidence.checkpoint-manifest.json
```

The standalone verifier consumes the full JSON bundle. If an auditor requires separate JSONL plus manifest, reconstruct `{...manifest, events:[...]}` before verification or retain the original bundle as the canonical artifact.

## Verification

Dedicated CLI:

```bash
bun packages/cli/src/index.ts evidence verify --bundle evidence.json
bun packages/cli/src/index.ts evidence verify --bundle evidence.json --fp TRUSTED_PUBLIC_KEY_SHA256
```

Equivalent direct verifier:

```bash
node scripts/verify-evidence-bundle.mjs evidence.json --fp TRUSTED_PUBLIC_KEY_SHA256
```

Exit codes:

- `0`: verification passed
- `1`: evidence failed verification
- `2`: usage or parse error

The verifier checks checkpoint signature, event content digest, sequence continuity, event linkage, and head binding when the bundle reaches the signed head. It does not recompute row HMACs because the HMAC key must remain secret. Online operators can additionally call `POST /audit/verify?fromSeq=1&toSeq=N&requireHead=true` to recompute HMACs against the database.

## Production emitters

Live event classes are emitted through existing audit chokepoints:

- Agent enrollment: `packages/api/src/routes/agent-enroll.ts`, `capability.enroll` allow/deny.
- Capability manifest issuance/renewal/revocation: `packages/plugin-capabilities/src/manifest-routes.ts` and `issuance.ts`, mapped to core audit via `ctx.writeAuditEvent`.
- Capability CRUD and grant changes: `packages/plugin-capabilities/src/routes.ts`, `ctx.writeAuditEvent`.
- Capability invocations and C1 verdict metadata: `packages/plugin-capabilities/src/invoke.ts` and `store.recordInvocation`, persisted in `capability_invocations` with verdict columns.
- Vault/proxy/governed execution: `packages/proxy/src/handlers/release.ts` and `packages/proxy/src/handlers/governed-execution.ts`, using `withTenantAuditedTransaction` / `appendRequiredAudit`.
- Provider action evidence: `/audit/bundle` and provider-action evidence routes share `signAuditBundle`.

Audited operations that depend on the chain use awaited writes or audited transactions and fail closed when the evidence append fails. Fire-and-forget `trackAuditEvent` is only for telemetry breadcrumbs that are not security authorization evidence.
