# Attestation-bound sealed state

## Package placement audit

Sealed agent state belongs in a new `@stwd/sealed-state`, not `@stwd/vault`. Vault protects signing keys and credentials with tenant policy, database records, and signing/exercise APIs. Agent memory and runtime snapshots are opaque blobs whose release condition is a runtime measurement. Putting them in Vault would conflate operator credential custody with runtime disk encryption. The new package consumes `@stwd/attestation` measurement types while keeping encryption and runtime-key derivation independently replaceable.

## Envelope

`SealedState` generates a random AES-256-GCM data-encryption key (DEK) for every blob. The blob is encrypted with the DEK and the DEK is wrapped with a backend-derived key-encryption key (KEK). Provider id, purpose, image digest, and configuration/compose hash are authenticated as AAD. Any ciphertext, tag, or metadata corruption fails closed.

The production `dstack-tdx` backend calls the dstack Guest Agent `/Info`, requires its current `os_image_hash` and `compose_hash` to equal the requested measurement, then calls `/GetKey` with a measurement- and purpose-separated path. dstack derives that key from the application key held by its KMS. A different measured application cannot derive the same KEK. The application key and wrapping root are not stored by Steward.

`INSECURE-noop-dev` derives a deterministic test KEK from an explicit development secret and simulated measurement. It throws in `NODE_ENV=production`. It exists only for local tests and mismatch proofs.

## Live consumer

`packages/api/src/embedded.ts` is the production entry for `bun run start:local`. With `STEWARD_SEALED_PGLITE_PATH` set, it runs PGLite in memory, unseals a prior database snapshot before startup, and atomically seals a new snapshot during the API shutdown hook. No plaintext PGLite directory is persisted. The default backend is `dstack-tdx`; `STEWARD_SEALED_STATE_BACKEND=noop-dev` requires `STEWARD_SEALED_STATE_DEV_SECRET` and is development-only.

This is an additive, opt-in migration. Existing plaintext PGLite directories are not silently imported because doing that could leave an unnoticed plaintext copy. Operators must deliberately migrate/export and securely retire the old directory.

## Threat model

Protects a copied encrypted snapshot from:

- storage, backup, or volume disclosure;
- a runtime with a different image or compose/config measurement;
- accidental ciphertext or authenticated-header modification;
- database-at-rest inspection by an operator who does not control the dstack application key.

The dstack verifier and measurement registry remain responsible for deciding whether a measurement is approved. Sealing enforces equality and cryptographic custody, not approval policy.

## Explicit non-goals

- **Same-measurement malicious host/runtime:** a runtime that can legitimately obtain the same dstack application key can unseal the state. Rollbacks and cloned authorized instances require deployment policy and KMS revocation controls.
- **Use-time compromise:** plaintext necessarily exists in enclave memory while PGLite or an agent uses it. RCE inside the measured runtime can read it.
- Hiding access patterns, blob sizes, or timestamps.
- Crash-consistent continuous database journaling. The pilot seals on graceful shutdown; abrupt power loss can lose changes since boot, so it is not yet the recommended high-availability database profile.
- Automatic deletion of legacy plaintext data or operator backups.
