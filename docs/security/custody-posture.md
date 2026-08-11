# Secrets-at-Rest Custody Posture

**Status:** Living document. Last reviewed 2026-07-16.
**Scope:** Steward `packages/vault` signing-key custody on current `develop`.
**Audience:** operators choosing a custody backend, and security reviewers
asking "where does a private key exist in plaintext, ever?"

If anything here disagrees with the code, the code is right and this document
is wrong. Please file an issue.

---

## The one question this document answers

> For every custody mode Steward supports, **where does the signing private key
> exist as plaintext bytes, and who can read it?**

Steward's honest posture (see `VISION.md`) is:

> Local wallet keys are encrypted with AES-256-GCM. Optional AWS KMS envelope
> wrapping, an operator-supplied PKCS#11 wrapping adapter, and an
> external-custody interface are available. **Local and KMS envelope modes
> expose plaintext key material to the application at sign time.** Steward does
> not claim MPC custody or native HSM signing.

This guide turns that one paragraph into an operator-usable map from **threat →
backend**, and states the plaintext boundary precisely per mode.

---

## The plaintext boundary (read this first)

There are two distinct plaintext exposures. Do not conflate them:

1. **Plaintext at rest** — the private key sitting decryptable in Steward's own
   database / storage, recoverable by anyone who has the ciphertext *and* the
   key-derivation input (`STEWARD_MASTER_PASSWORD` + `STEWARD_KDF_SALT`).
2. **Plaintext at sign time** — the private key materialized as a `string` in
   the API process's heap for the duration of a signing call, recoverable by
   anyone who can scrape that process's memory (a code-exec bug, a malicious
   dependency, a core dump, a `/proc/<pid>/mem` read, a debugger).

**Steward's vault decrypts to a plaintext key string in-process for every
built-in signing mode.** Concretely, every signing path in `packages/vault`
calls `this.keyStore.decrypt(...)` and receives a plaintext private key
(`packages/vault/src/vault.ts`; `KeyStore.decrypt` in
`packages/vault/src/keystore.ts`; `KmsEnvelopeKeystore.decrypt` in
`packages/vault/src/keystore-kms.ts`, which unwraps the data key and then
AES-decrypts the private key **inside this process**). The only mode that keeps
plaintext out of the Steward process entirely is **external custody**, where
signing is delegated to a provider that returns a signed transaction and the
private key never enters Steward's address space
(`packages/vault/src/external-key-custody.ts`).

### Correction to a common shorthand

A frequent shorthand says "only PKCS#11 and external custody avoid plaintext."
That is **not accurate** and this guide will not repeat it. In Steward's
implementation, PKCS#11 is used as a **key-wrapping adapter under the
KMS-envelope backend** — the HSM wraps/unwraps the AES *data key*, but the
private key is still AES-decrypted to plaintext **in the Steward process** at
sign time. PKCS#11 removes plaintext-**at-rest** of the data key; it does **not**
remove plaintext-**at-sign-time** of the private key. Only external custody does
that.

---

## Threat-model table

| Mode | Env selector | Plaintext **at rest** in Steward DB | Plaintext **at sign time** in Steward process | KMS/HSM boundary | What it removes | What it does NOT remove |
|------|--------------|-------------------------------------|-----------------------------------------------|------------------|-----------------|-------------------------|
| **local** | (default; no `STEWARD_KMS_PROVIDER`) | **Yes**, effectively — key is AES-256-GCM ciphertext, but the unwrap material (`STEWARD_MASTER_PASSWORD` + `STEWARD_KDF_SALT`) is also on the same host/env, so a host compromise recovers keys offline | **Yes** | none | at-rest confidentiality vs. a **stolen DB backup alone** (no env/secrets) | host compromise, memory scrape, malicious dependency, master-password disclosure |
| **kms-envelope:aws** | `STEWARD_KMS_PROVIDER=aws` + `STEWARD_KMS_KEY_ID`/`STEWARD_AWS_KMS_KEY_ARN` | **No** — each key is wrapped by a per-record data key that only AWS KMS can unwrap; a stolen DB is inert without live KMS access | **Yes** | data-key wrap/unwrap happens in AWS KMS; the KMS master key never leaves KMS | offline DB compromise, offline master-password compromise (data key needs live KMS `Decrypt`), KMS-side audit + revocation | **memory scrape at sign time** (key is AES-decrypted in-process after the data key is unwrapped), a compromised Steward process with live KMS creds |
| **kms-envelope:pkcs11** | `STEWARD_KMS_PROVIDER=pkcs11` + `STEWARD_PKCS11_MODULE`/`_PIN`/`_KEY_LABEL` (+ operator-supplied `Pkcs11ClientLike`) | **No** — data key is wrapped/unwrapped by the HSM via `C_WrapKey`/`C_UnwrapKey`; stolen DB is inert without the HSM | **Yes** | data-key wrap/unwrap happens inside the HSM; the wrapping key never leaves the HSM | offline DB compromise, offline master-password compromise, HSM-side access control + tamper resistance for the **wrapping** key | **memory scrape at sign time** (private key is AES-decrypted in-process), a compromised Steward process with live HSM session |
| **external custody** | `VaultConfig.externalKeyCustodyProvider` (code-wired; not a `STEWARD_KMS_PROVIDER` value) | **No** — Steward never holds private key material; it holds an opaque handle (`ExternalKeyHandleDescriptor`) | **No** | signing happens entirely in the external provider; Steward sends the unsigned tx and receives a signed result | plaintext-at-rest **and** plaintext-at-sign-time in the Steward process; key exfiltration via Steward memory | trust in the external provider itself, the provider's own key handling, network/path to the provider |

> **Note on `kms-envelope:pkcs11` in this release:** the built-in PKCS#11 path
> requires an operator-supplied `Pkcs11ClientLike` adapter for `C_WrapKey` /
> `C_UnwrapKey`. Without it, the backend fails closed
> (`packages/vault/src/keystore-kms.ts`). Steward ships the seam, not a bundled
> HSM driver.

---

## Deployment guidance: threat → backend

Pick the weakest mode whose residual risk you can accept, then harden.

- **You accept that a full host compromise = key compromise** (single-tenant,
  low-value keys, dev/staging, air-gapped operator control):
  → **local** is defensible. In production you must explicitly acknowledge it
  (see the gate below).

- **You need a stolen database / backup / leaked master password to be
  insufficient to recover keys offline:**
  → **kms-envelope:aws** (managed) or **kms-envelope:pkcs11** (self-hosted HSM).
  A stolen DB is inert without live KMS/HSM access, and KMS/HSM gives you
  audit + revocation of the wrapping key. This is the recommended default for
  any deployment holding meaningful value that stays self-hostable.

- **Your threat model includes a compromised Steward process itself** (memory
  scrape, malicious dependency, hostile co-tenant with code exec), i.e. you
  cannot accept plaintext key bytes in Steward's address space **ever**:
  → **external custody.** This is the only mode that removes
  plaintext-at-sign-time. It moves trust to the external signer; evaluate that
  provider on its own terms.

Regardless of mode, always set in production:

- `STEWARD_MASTER_PASSWORD` — never the dev fallback
  (`STEWARD_ALLOW_DEV_SECRETS`).
- `STEWARD_KDF_SALT` — unique per deployment, `openssl rand -hex 32`. Required
  in production; the vault refuses to boot without it
  (`packages/vault/src/keystore.ts`).

---

## The production local-custody acknowledgement gate

**Precedent:** the financial adapter registry fails closed to a *disabled*
adapter in production unless mocks are explicitly opted in via
`STEWARD_ALLOW_MOCK_ADAPTERS=true` (`packages/adapters/src/registry.ts`). That
turns "silently running mocks for real money" into a deliberate decision.

Custody now has the analogous gate. A silently-weak root of trust is a
worse-than-mock failure, so the gate is **fail-closed, not warning-only**:

> **In production, booting the weakest custody mode (`local`, plaintext key at
> sign time) without an explicit acknowledgement is refused.**

**Rule** (`assertProductionCustodyAcknowledged` in
`packages/api/src/services/vault-factory.ts`):

- `NODE_ENV === "production"` **and** resolved mode is `local` **and**
  `STEWARD_ACK_LOCAL_CUSTODY` is not `"true"` ⇒ **startup throws** (fail closed).
  The root of trust must never boot weak *silently*.
- Stronger modes (`kms-envelope:aws`, `kms-envelope:pkcs11`) boot **without**
  the ack — selecting them already requires explicit KMS/HSM configuration, so
  the operator has already made a deliberate choice.
- Development / test are **unchanged** — the gate only fires under
  `NODE_ENV === "production"`, so local ergonomics are untouched.
- An **unknown / unsupported** `STEWARD_KMS_PROVIDER` already fails closed
  before this gate (`configuredMode` throws on an unsupported provider).

### Why an ACK, not an ALLOW?

The `STEWARD_ALLOW_*` family unblocks an otherwise-refused *capability*. Local
mode is not a refused capability — it works everywhere. `STEWARD_ACK_LOCAL_CUSTODY`
is an **acknowledgement of posture**: "I understand this process holds plaintext
keys and I am choosing to run it anyway." The distinct verb keeps the meaning
honest and greppable.

```bash
# Production, deliberately accepting local plaintext custody:
NODE_ENV=production
STEWARD_MASTER_PASSWORD=<32+ char secret>
STEWARD_KDF_SALT=<openssl rand -hex 32>
STEWARD_ACK_LOCAL_CUSTODY=true   # explicit, auditable acknowledgement

# Production, stronger posture (no ack needed):
NODE_ENV=production
STEWARD_MASTER_PASSWORD=<32+ char secret>
STEWARD_KDF_SALT=<openssl rand -hex 32>
STEWARD_KMS_PROVIDER=aws
STEWARD_KMS_KEY_ID=alias/steward-prod
```

The boot log line records the resolved posture without any secret material,
e.g. `[steward] vault mode=local plaintext_at_sign_time=true
local_custody_acknowledged=true capabilities=...`.

---

## Honest limitations

- **Every built-in mode exposes plaintext at sign time.** KMS-envelope and
  PKCS#11 protect the key **at rest**; they do **not** protect it against a
  compromised Steward process. Only external custody does.
- **No MPC, no threshold signing, no native HSM signing** is implemented in
  this repo. The `KeystoreBackend` interface is a plug for operators to bring
  their own (`packages/vault/src/keystore-backend.ts`); shipping a threshold
  protocol from inside the monorepo would be theater — the security of MPC comes
  from independent operators, an operational concern outside the codebase.
- **No operator-proof / tamper-evident custody claim.** Audit logs record
  signing events; they are not a cryptographic proof against a
  root-privileged operator.
- **The gate is a posture acknowledgement, not a mitigation.** Setting
  `STEWARD_ACK_LOCAL_CUSTODY=true` does not make local mode safer — it records
  that you accepted its residual risk.
- **External custody trust is transitive.** It removes Steward-process exposure
  but adds full trust in the external signer and the path to it. Evaluate that
  provider directly.

---

## Where the boundary lives in code

| Concern | File |
|---------|------|
| AES-256-GCM at-rest keystore + KDF | `packages/vault/src/keystore.ts` |
| Pluggable backend contract | `packages/vault/src/keystore-backend.ts` |
| KMS/PKCS#11 envelope (unwrap + in-process AES decrypt) | `packages/vault/src/keystore-kms.ts` |
| External custody (no plaintext in-process) | `packages/vault/src/external-key-custody.ts` |
| Signing paths that decrypt to plaintext | `packages/vault/src/vault.ts` (`this.keyStore.decrypt`) |
| Mode resolution + production ack gate | `packages/api/src/services/vault-factory.ts` |
| Precedent: adapter mock gate | `packages/adapters/src/registry.ts` |
