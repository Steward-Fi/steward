# @stwd/signer-frost

**PROTOTYPE.** Dev keys only — not production custody yet.

FROST-secp256k1 (Schnorr) 2-of-3 threshold `SignerBackend` for `@stwd/vault`,
using the Zcash Foundation `frost-secp256k1` Rust crate behind a thin TS client.
Implements the D1 decision (`projects/steward/D1-MPC-DECISION-2026-07-30.md`).

- **Interface:** `SignerBackend` in `@stwd/vault` — the honest threshold analog of
  `KeystoreBackend`. Defining property: `capabilities.canReturnRawKey: false`.
  There is no code path that assembles or exports a private key.
- **Layout:**
  - `sidecar/` — Rust binary `frost-signer` (ZF frost crate): `keygen` + `share`
    HTTP service. Secret shares + all secret crypto stay here.
  - `src/` — TS: `FrostSignerBackend` (coordinator over PUBLIC data) + client.
- **Ops / ceremony / EIP-1271 story:** see `THRESHOLD-SIGNING.md`.

## Proven by the E2E test (`src/__tests__/frost-e2e.test.ts`, real sidecars)

- 2-of-3 produces a Schnorr signature that verifies against the group key.
- 1-of-3 **fails** (below-threshold rejection enforced by the ZF crate, not a
  hand-rolled check).
- `verify()` rejects tampered signatures / wrong messages (non-vacuous).

## Not in scope (documented, not proven here)

- On-chain Safe / EIP-1271 `isValidSignature` verification (ref:
  `safe-research/safe-frost`).
- DKG (prototype uses trusted-dealer keygen, labeled honestly).
- Resharing/rotation (interface seam present, `supportsReshare: false`).
- Solana `frost-ed25519` (crate pinned, not exercised end-to-end yet).

## Why a Rust sidecar

No audited, maintained pure-JS threshold library exists worth trusting on a
custody critical path (verified 2026-07-30). The mature audited libs are Rust
(ZF, Lockness) / Go (Taurus, Circle). The sidecar also supports the TEE model:
each share can live in its own enclave.

## Build & run

```
bun run sidecar:build          # cargo build --release
bun test                       # spawns its own sidecars
```

See `THRESHOLD-SIGNING.md` for the full runbook, version-pinning + re-verify
warning (RUSTSEC), and the collusion / share-host-death ops notes.
