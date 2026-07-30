# Sealed Secret Store

`@stwd/vault` ships a **sealed secret store** for NON-key operator secrets — API
tokens, Discord bot tokens, webhook signing secrets, and other credentials that
Steward must *use* but that no one should be able to *read back*.

It is the Phase-0 custody primitive from the sovereign-custody plan
(`DSTACK-CANONICAL-2026-07-29.md` §4B): move secrets off Railway env vars into a
store sealed to a key on the operator's own host, decrypted at boot into memory
only. The interface is designed so Phase-1 can swap the file backend for a
TEE-KMS-sealed backend **without changing the API or any caller**.

## The model: write + exercise, never read back

```
operator machine                 store (disk / KMS)            steward runtime
────────────────                 ──────────────────            ───────────────
plaintext secret                                                (in memory only)
   │  encrypt to recipient
   ▼  (age / X25519)
armored ciphertext  ── putSealed ──▶  ciphertext at rest
                                          │  decrypt-at-boot
                                          ▼
                                      exercise(path, use) ──▶ use(plaintext) → RESULT
```

Three properties, in order of importance:

1. **No read-back API.** There is `putSealed` and there is `exercise`. There is
   **no** `get`/`read`/`reveal` that returns a plaintext value. This asymmetry
   *is* the security property: a compromised control plane cannot exfiltrate the
   vault by calling a getter, because the getter does not exist. `exercise`
   decrypts into a local variable, hands it to a caller-supplied closure, and
   the closure returns a *result* (e.g. an HTTP response) — never the secret.

2. **Zero plaintext transit.** The onboarding CLI encrypts the secret
   **directly to the store's public recipient on the operator machine**. The
   plaintext is read from stdin or a file, never from a flag (which would land
   in shell history) or an env var. The store only ever ingests ciphertext.

3. **Zero plaintext at rest.** Only armored [age](https://age-encryption.org)
   ciphertext + non-secret metadata (path, version, timestamps) touch disk. The
   private identity is provisioned out of band and, on the production path,
   decrypted at boot into memory only.

## Default OSS backend: age file store

`AgeFileSecretStore` uses the age file-encryption format via the pure-TypeScript
[`age-encryption`](https://github.com/FiloSottile/typage) library, which depends
only on the noble crypto primitives already used across `@stwd/vault`. No native
binary, no cloud dependency, **no vendor lock-in**. Any operator can encrypt to
the store with the standard `age -r <recipient>` CLI and decrypt any entry with
the standard `age -d -i <identity>` CLI. This is the mandated `--no-cloud` path.

On-disk layout (under `storeDir`):

```
recipient.txt          age1... public recipient (safe to publish)
secrets/<enc>.age      armored age ciphertext, one file per secret
secrets/<enc>.json     metadata sidecar (path, version, timestamps, note)
```

`<enc>` is the URL-safe base64 of the logical path, so slash-separated paths map
to flat, collision-free file names.

### Identity sourcing (decrypt-at-boot)

The running process only needs the private identity to `exercise` (decrypt).
`putSealed` / `list` / `stat` / `rotate` work with the public recipient alone, so
an onboarding-only host can run without ever loading the identity. Sources:

| `identitySource`                         | Use                                   |
| ---------------------------------------- | ------------------------------------- |
| `{ kind: "env", var: "…" }`              | decrypt-at-boot from env (Phase-0)    |
| `{ kind: "file", path: "…" }`            | identity file (e.g. tmpfs)            |
| `{ kind: "identity", identity: "…" }`    | inline (tests / KMS handoff)          |
| `{ kind: "none" }`                       | onboarding-only, cannot exercise      |

## CLI

```sh
# One-time: generate an identity/recipient. Prints the identity ONCE — seal it
# yourself (TEE KMS, hardware token, offline backup). The store keeps only the recipient.
steward secrets init --store .steward/secret-store

# Onboard a secret. Plaintext from stdin (recommended) or --file. NEVER a flag.
printf %s "$DISCORD_TOKEN" | steward secrets put discord/soliza-bot-token --desc "soliza"
steward secrets put api/openai --file ./openai.key

steward secrets recipient                 # print the public recipient (for `age -r`)
steward secrets list                       # metadata only, never values
steward secrets rotate api/openai --file ./new.key
steward secrets rm api/openai

# There is deliberately NO `steward secrets get`.
```

## Migration from env vars

`packages/cli/scripts/migrate-env-secrets.ts` onboards secrets from a manifest of
**names only** (no values). Values come from operator stdin (recommended) or, for
an operator-run cutover on a machine that already holds them, `--from-env`.

```jsonc
// secrets.manifest.json — NAMES ONLY, never values
{ "secrets": [
  { "name": "DISCORD_SOLIZA_TOKEN", "path": "discord/soliza-bot-token", "description": "…" },
  { "name": "OPENAI_API_KEY",       "path": "api/openai" }
]}
```

```sh
bun packages/cli/scripts/migrate-env-secrets.ts --manifest secrets.manifest.json \
  --store .steward/secret-store --dry-run          # validate + print plan
```

Rehearse with **dummy** secrets. The live cutover of real credentials is
orchestrator-only. The tool refuses any manifest that carries a `value` field.

## Backend interface — and how the TEE backend slots in

Everything above sits behind `SecretStoreBackend`:

```ts
interface SecretStoreBackend {
  readonly id: string;
  recipient(): Promise<string>;                                  // public sealing key
  putSealed(path, ciphertext, opts?): Promise<Metadata>;         // ingest ciphertext
  stat(path): Promise<Metadata | null>;                          // metadata only
  list(): Promise<Metadata[]>;                                   // metadata only
  rotateSealed(path, ciphertext): Promise<Metadata>;             // bump version
  delete(path): Promise<boolean>;
  exercise<T>(path, use: (plaintext) => T | Promise<T>): Promise<T>;   // the ONLY plaintext path
}
```

**Phase-1 (TEE-KMS) swap.** A dstack/TDX deployment implements the same
interface with the age identity sealed behind the enclave KMS:

- `recipient()` returns the **enclave's** public sealing key. Operators still run
  `steward secrets put` and encrypt to it on their own machine — the CLI does not
  change.
- `putSealed` / `list` / `rotateSealed` / `delete` are unchanged (they never need
  the private identity).
- `exercise` asks the KMS to release the identity, which it does **only to a CVM
  whose remote attestation matches the registered measurement** — so even the
  host operator cannot decrypt. The plaintext still lives only inside the closure.

Because callers depend on `SecretStoreBackend`, not on `AgeFileSecretStore`, the
swap is a wiring change (which implementation to construct at boot), not an API
change. The file backend remains the always-available `--no-cloud` fallback and
the self-host recipe's default.

## Relationship to the other vault secret machinery

- **`KeyStore` / `KeystoreBackend`** — wraps private *signing* keys, exercised
  through the signing path. Different lifecycle (keys, not tokens). Unchanged.
- **`SecretVault`** — the DB-backed, per-tenant credential store fronted by the
  proxy's secret-route header injection. Also no plaintext read-back over its
  API. `SecretStore` is the **local, file/TEE-sealed** store for the operator's
  own bootstrap secrets (the ones that used to live in Railway env), sealed to a
  key the operator controls rather than a DB master password. The two compose:
  `SecretStore` can hold the master material that `SecretVault` is configured
  with, closing the "operator seeds everything from env" hole.
