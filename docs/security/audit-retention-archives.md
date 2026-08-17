# Audit retention archives

Steward audit events are retained indefinitely unless an owner or administrator explicitly enables a tenant retention policy. Retention is tenant-scoped, requires a recent-MFA session, and never treats an environment flag as proof of backup.

## Safe workflow

1. Configure `STEWARD_AUDIT_SIGNING_KEY` with an Ed25519 private key, give it a stable `STEWARD_AUDIT_SIGNING_KEY_ID`, and bind that id to the public key in `STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS`. Publish the key id and SHA-256 fingerprint of its SPKI public key through an independent channel.
2. Configure `STEWARD_AUDIT_ARCHIVE_ACK_TRUSTED_KEYS` with public keys controlled by an independent immutable-storage service. Steward must not have the corresponding private keys.
3. An owner or administrator with recent MFA calls `PUT /audit/retention-policy` with `enabled`, `retentionDays` (30–3650), and `archiveChunkSize` (1–10,000). Every update increments a revision; an archive sealed under a stale or disabled revision cannot authorize deletion.
4. `POST /audit/retention/run` selects only the calling tenant's expired contiguous prefix. Steward writes newline-delimited JSON chunks, hashes every exact chunk, signs a versioned manifest, and commits every chunk plus the sealed receipt. This first run returns the archive id and deletes **zero** source events.
5. Use `steward audit export --from N --to N --out DIR --verify --fp HEX --key-id ID`. Export is resumable: existing chunks are reused only when their SHA-256 hashes match the signed manifest. Copy the complete verified directory into versioned, immutable external storage.
6. The external storage service signs a `steward.audit-archive-durability.v1` acknowledgement binding the exact archive id, tenant, manifest digest, immutable URI, object version, and acknowledgement time. Submit it with `steward audit acknowledge --archive-id ID --file signed-ack.json`. A database-generated or unsigned acknowledgement is not accepted.
7. Repeat `POST /audit/retention/run`. In one transaction Steward locks the tenant, policy, archive, and **all** chunk rows; re-hashes and parses every JSONL event; verifies the trusted manifest and external acknowledgement; appends authorization evidence; deletes the exact live prefix; advances the floor; marks the archive pruned; and appends completion evidence. Any error rolls back all of those changes.
8. List archives with `steward audit list`. Restore an interrupted export with `steward audit restore --in DIR`; chunk uploads are digest-checked and idempotent. Restored archives are permanently marked `imported` and can never authorize deletion from a live chain.

Archive chunks are capped at 1 MiB so every archive emitted by Steward remains
restorable through the public API's bounded request surface. `archiveChunkSize`
is a maximum event count; Steward splits earlier when the encoded byte limit is
reached and fails closed if one audit event alone cannot fit.
Signed manifests are capped at 2,048 chunks and 768 KiB, leaving headroom for
the response/request envelope under the CLI and API 1 MiB transport ceiling.

You can also download `GET /audit/archives/:archiveId` and each `GET /audit/archives/:archiveId/chunks/:index` directly. Store the response as `manifest.json` and chunks under the filenames in `manifest.chunks`. Verify offline:

```sh
node scripts/verify-audit-archive.mjs manifest.json . \
  --expected-key-fingerprint <trusted-spki-sha256> \
  --expected-key-id <trusted-key-id>
```

The verifier checks the trusted signing-key fingerprint, Ed25519 signature, canonical manifest digest, safe chunk names, exact bytes and hashes, tenant/range/count consistency, and chain linkage. A bundle without an independently trusted fingerprint is self-signed evidence and must not be treated as proof of operator identity.

`steward audit export --verify` therefore requires `--fp` from an independent
trusted channel. For troubleshooting byte integrity only, use the explicitly
weaker `--integrity-only` flag; its output states that signer identity was not
authenticated. A key id alone is not a trust anchor because it is part of the
signed, attacker-replaceable envelope.

## Durability and limits

The sealed receipt and chunks live in the primary database so a transient filesystem write cannot masquerade as a complete archive. They are not sufficient durability: pruning additionally requires a signed acknowledgement from a separately trusted external-storage identity. Database replication alone is not an independent archive.

The archive proves that the signed JSONL is byte-for-byte the chain prefix Steward sealed. It does not make an operator who controls both the HMAC and signing keys unable to fabricate history. Key custody, independently published fingerprints, immutable backups, and external checkpoints remain necessary for stronger non-repudiation.

Retention reduces the live personal-data footprint but archived audit records may still contain personal data. Tenant operators remain responsible for lawful retention periods, access control, encryption at rest, backup deletion schedules, legal holds, and data-subject obligations.
