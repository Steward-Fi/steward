# Threshold Signing (Pillar D / D2 prototype)

**Status:** PROTOTYPE. Dev/dummy keys only. Not for production custody yet.
**Scheme:** FROST-secp256k1 (Schnorr), 2-of-3, via the Zcash Foundation `frost-secp256k1` Rust crate.
**Decision doc:** `projects/steward/D1-MPC-DECISION-2026-07-30.md` (read it — this doc implements it).

This package (`@stwd/signer-frost`) is the D2 prototype of Steward's threshold
signer. It implements the `SignerBackend` interface from `@stwd/vault` on top of
N small Rust sidecar processes, each holding one FROST secret share.

## Why FROST-secp256k1 and not threshold ECDSA

D1 chose FROST-secp256k1 behind a Safe / EIP-1271 smart account over threshold
ECDSA (CGGMP21-class) for the first prototype. The short version:

- **Threshold ECDSA is CVE-prone.** The heavy machinery (Paillier, range/ZK
  proofs, 4+ rounds) has a live track record of critical implementation bugs.
  Most relevant: **RUSTSEC-2025-0129 / CVE-2025-66016** (Nov 2025) in
  `LFDT-Lockness/cggmp21` — a *missing ZK check let a single malicious signer
  reconstruct the full private key*. Fixed in cggmp21 ≥ 0.6.3 / cggmp24 ≥
  0.7.0-alpha.2. A whole class of "one bad participant defeats the threshold"
  bugs lives in this space. We do not want that class on the critical path first.
- **FROST is simpler and less bug-prone.** 2 rounds, no Paillier, a clean
  audited core (ZF, partial NCC audit of the 0.6.0 family). It produces a
  *Schnorr* signature.
- **The catch:** Ethereum native-EOA verification is ECDSA-only, so a FROST
  Schnorr signature cannot sign a plain EOA transaction. It controls EVM assets
  via a **smart account** (Safe + EIP-1271, or `safe-research/safe-frost`'s
  on-chain FROST verifier). That is the intended deployment shape.
- **CGGMP21 is only for a hard native-EOA requirement**, which this prototype
  does NOT have. If it ever does, swap the sidecar to a pinned Lockness cggmp21
  behind the *same* `SignerBackend` interface (ECDSA output, `recid` populated).

## Architecture

```
  TS (@stwd/vault call site)
        │  SignerBackend.sign(ref, digest)
        ▼
  FrostSignerBackend (@stwd/signer-frost, TS)     ← coordinator over PUBLIC data only
        │  HTTP/JSON on localhost
        ├──────────────┬──────────────┐
        ▼              ▼              ▼
   frost-signer   frost-signer   frost-signer      ← Rust sidecars (ZF frost crate)
   share #1       share #2       share #3          ← each holds ONE secret share
   (enclave A)    (enclave B)    (enclave C)       ← future: each in its own TEE
```

- The **secret shares and all secret operations stay in Rust** (the audited ZF
  crate). The TS side only ever handles PUBLIC data: round1 commitments, the
  serialized signing package, public signature shares, and the final signature.
- Each share is a **separate process** — a stand-in for a separate enclave. In
  production each share host should be its own TEE (dstack CVM / Nitro), ideally
  across independent operators / clouds / jurisdictions (see Pillar B/C and
  "Share storage" below).
- **Why a Rust sidecar and not a WASM/npm lib:** verified on 2026-07-30, the
  mature, audited threshold libraries are Rust (ZF, Lockness) and Go (Taurus,
  Circle). `frost-secp256k1` has a maintained WASM target in principle, but there
  is no *audited, maintained* pure-JS FROST/threshold-ECDSA library worth
  trusting on a custody critical path. The sidecar shape also aligns with Pillar
  B: each share can live in its own enclave. This is a deliberate D1 call.

### Sidecar HTTP API (localhost only)

| Method | Path | Data | Secret? |
|---|---|---|---|
| GET | `/health` | liveness + identifier | no |
| POST | `/commit` | round1: returns public commitments + a nonce id | nonces stay in-process |
| POST | `/signing-package` | build SigningPackage from commitments + message | public op |
| POST | `/sign` | round2: returns this share's signature share | uses in-process share |
| POST | `/aggregate` | combine signature shares → group signature (verifies) | public op |
| POST | `/verify` | verify a provided signature against the group key | public op |

The share (`KeyPackage`) never leaves the sidecar process. There is no export
endpoint by construction.

## Keygen ceremony

The prototype uses **trusted-dealer keygen** (`frost-signer keygen`), labeled
honestly: a single process generates all shares and distributes them to files.
This is fine for a dev prototype but is NOT how a real deployment should work,
because the dealer momentarily knows all shares.

```
frost-signer keygen --threshold 2 --participants 3 --out ./shares
# writes ./shares/group.json (public) + ./shares/share-<id>.json (secret, per share)
```

**Production path (not in this prototype):** run **DKG** (distributed key
generation) so no single party ever knows more than its own share. The ZF crate
supports DKG (2-round); the `SignerBackend.generate()` method is the seam where a
DKG backend would run the ceremony across the sidecars instead of loading a
pre-dealt group. The interface is DKG-ready; the prototype implementation is
trusted-dealer.

## Share storage expectations

- **Prototype:** shares are plain JSON files on local disk, dev keys only. Do not
  put real value behind this.
- **Production (ties to Pillar B/C):** each share lives sealed inside its own
  enclave (dstack CVM / AWS Nitro), released only to the attested sidecar at
  boot. Enclave compromise of one host yields at most ONE share → below threshold
  → no signature, no key. TEE + threshold compose: TEE protects each share
  at rest/in-use; threshold ensures one broken enclave is insufficient.
- **Collusion reality (from D1 §4.3):** if Steward operates all three share
  hosts, 2-of-3 collapses to "whoever controls any two Steward hosts can sign."
  Real collusion resistance requires ≥1 **independent operator** (e.g. a partner,
  a cold hardware signer, or a managed backend as one owner). The prototype is
  honest about this: 2-of-3-all-ours improves *availability* and *no-single-host-
  key-assembly*, not confidentiality vs a TEE-single-key.

## Resharing / rotation

- Changing the share set or threshold is a **resharing (proactive refresh)
  ceremony**, not a key rotation — the group public key (and derived address) can
  be preserved. The ZF crate supports refresh/reshare; it is interactive and must
  be rehearsed. The `SignerBackend.reshare?()` method is the seam (not
  implemented in the prototype — `capabilities.supportsReshare: false`).
- **You cannot rotate "the wallet" the way you rotate a Safe owner.** This is the
  key operational reason D1 pairs FROST *with* a Safe: the Safe layer is the clean
  rotation + recovery surface (owners rotated on-chain via `swapOwner`), and a
  Safe owner slot can later be upgraded from a plain key to the FROST signer
  (EIP-1271 / safe-frost) without disturbing the other owners.

## What happens when a share host dies

- **2-of-3 tolerates losing ONE host** for signing (2 remain ≥ threshold).
- **Losing TWO hosts bricks the key** — a 2-of-3 with two dead hosts is
  permanent loss. There is no private key to "restore from backup."
- Therefore: **monitor share-host liveness, and run a resharing ceremony BEFORE a
  second host is lost.** Recovery options: (a) threshold-encrypted backup of
  shares to cold storage; (b) enough redundancy that one loss is survivable
  (2-of-3 already gives this for a *single* loss); (c) lean on the Safe layer as
  the on-chain recovery backstop for the fee wallet.

## EIP-1271 / Safe verification path — proven vs documented

**What the prototype PROVES (in `frost-e2e.test.ts`, real sidecars):**
- 2 of 3 shares produce a valid FROST-secp256k1 Schnorr signature that
  cryptographically verifies against the 33-byte compressed group public key.
- 1 of 3 shares CANNOT produce a valid signature (the ZF crate rejects a
  below-threshold signing package / a lone signature share at aggregation — this
  is a real cryptographic failure, not a hand-rolled count check).
- `verify()` rejects a mutated signature and a signature over the wrong message
  (non-vacuous).
- The signature/pubkey FORMAT the on-chain verifier expects: a **65-byte**
  signature (compressed R (33) ‖ scalar z (32)) plus a 33-byte compressed group
  key. (Note: 65 bytes, NOT 64 — 64-byte x-only-R is BIP-340/Taproot, the
  separate `frost-secp256k1-tr` crate.)

**What is DOCUMENTED but NOT proven on-chain here (out of prototype scope):**
- An actual Safe deployment + `isValidSignature` (EIP-1271) call verifying the
  FROST signature on-chain. The reference for this is `safe-research/safe-frost`
  (a Solidity FROST verifier on secp256k1 that can also abuse the `ecrecover`
  precompile for cheap EC-mul) plus the Safe EIP-1271 `isValidSignature` path.
  Wiring a live testnet Safe is the natural next step after this prototype.
- A near-term, zero-new-crypto mitigation (do this BEFORE MPC ships) is to
  rotate the platform fee wallet to a plain **Safe 2-of-3** multisig — see D1 §6.

## Version pinning & re-verify (IMPORTANT)

- Pinned: `frost-secp256k1 = "=3.0.0"`, `frost-ed25519 = "=3.0.0"` (ZF), verified
  present on crates.io on **2026-07-30** via `cargo search`/`cargo info`.
- The NCC partial audit covered the **0.6.0** line of the ZF frost-core +
  ciphersuite family; **3.0.0 is a later release of the same family** — re-verify
  the audit scope and any RUSTSEC advisories for the *exact* pinned version before
  any production use.
- **D1's warning stands: do not trust version pins / audit claims after ~30
  days.** Subscribe to RUSTSEC, re-check `frost` releases + advisories at build
  time. Threshold crypto moves fast and has had recent critical CVEs.

## Solana follow-on

The same sidecar pins `frost-ed25519` (same ZF family). FROST-ed25519's output is
a *standard* ed25519 signature that Solana verifies natively — the cleanest
threshold story of any chain. The prototype wires secp256k1 end-to-end; ed25519
is the immediate stretch (add a `--scheme ed25519` keygen path + an ed25519
ciphersuite build of the share service).

## Running it

```
# 1. build the sidecar
cargo build --release --manifest-path sidecar/Cargo.toml

# 2. trusted-dealer keygen (dev keys)
sidecar/target/release/frost-signer keygen --threshold 2 --participants 3 --out ./shares

# 3. start three share services (each = one enclave stand-in)
frost-signer share --share-file ./shares/share-0000...0001.json --port 7401 &
frost-signer share --share-file ./shares/share-0000...0002.json --port 7402 &
frost-signer share --share-file ./shares/share-0000...0003.json --port 7403 &

# 4. use FrostSignerBackend from TS (see @stwd/vault KEYSTORE-BACKENDS.md)

# tests (spawn their own sidecars):
bun test
```
