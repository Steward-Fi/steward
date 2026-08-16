# Audit retention archives

Steward audit events are retained indefinitely unless an owner or administrator explicitly enables a tenant retention policy. Retention is tenant-scoped, requires a recent-MFA session, and never treats an environment flag as proof of backup.

## Safe workflow

1. Configure `STEWARD_AUDIT_SIGNING_KEY` with an Ed25519 private key and publish the SHA-256 fingerprint of its SPKI public key through an independent channel.
2. An owner or administrator with recent MFA calls `PUT /audit/retention-policy` with `enabled`, `retentionDays` (30–3650), and `archiveChunkSize` (1–10,000).
3. `POST /audit/retention/run` selects only the calling tenant's expired contiguous prefix. Steward writes newline-delimited JSON chunks, hashes every exact chunk, signs a versioned manifest, and commits the chunks and sealed receipt before deletion is attempted.
4. A separate transaction locks the tenant chain, confirms that the sealed receipt begins at the current floor and matches the live ending HMAC, deletes the exact range, advances the floor, and marks the receipt pruned atomically. A crash before this transaction leaves all source events. A rollback leaves neither a partial delete nor an advanced floor. Repeating either operation is idempotent.
5. Download `GET /audit/archives/:archiveId` and each `GET /audit/archives/:archiveId/chunks/:index`. Store the response `data` as `manifest.json` and chunks under the filenames in `manifest.chunks`.
6. Verify offline:

```sh
node scripts/verify-audit-archive.mjs manifest.json . \
  --expected-key-fingerprint <trusted-spki-sha256>
```

The verifier checks the trusted signing-key fingerprint, Ed25519 signature, canonical manifest digest, safe chunk names, exact bytes and hashes, tenant/range/count consistency, and chain linkage. A bundle without an independently trusted fingerprint is self-signed evidence and must not be treated as proof of operator identity.

## Durability and limits

The sealed receipt and chunks live in the primary database so pruning cannot be authorized by a transient filesystem write or operator assertion. Operators must still export and back up sealed archives to independently durable storage before destroying or restoring the database. Database replication alone is not an independent archive.

The archive proves that the signed JSONL is byte-for-byte the chain prefix Steward sealed. It does not make an operator who controls both the HMAC and signing keys unable to fabricate history. Key custody, independently published fingerprints, immutable backups, and external checkpoints remain necessary for stronger non-repudiation.

Retention reduces the live personal-data footprint but archived audit records may still contain personal data. Tenant operators remain responsible for lawful retention periods, access control, encryption at rest, backup deletion schedules, legal holds, and data-subject obligations.
