# Deploying Steward on dstack (Intel TDX)

This guide packages Steward (API + proxy + vault) as a [dstack](https://github.com/Dstack-TEE/dstack)
Docker Compose app running inside an Intel TDX confidential VM, with remote
attestation wired to `@stwd/attestation` (see `docs/ATTESTATION.md` for the
trust model and the signed measurement registry).

dstack is one backend behind the vendor-neutral `AttestationProvider`
interface. Nothing in Steward hard-depends on dstack or Phala: the same
compose app runs on self-hosted TDX hardware, and a bare-VPS no-TEE profile
remains available via the standard `docker-compose.yml`.

## What the packaging provides

| File | Purpose |
| --- | --- |
| `deploy/dstack/docker-compose.dstack.yml` | The measured compose app: api, proxy, dstack-verifier sidecar, postgres, redis. All images digest-pinned. Secrets only via dstack sealed env. |
| `deploy/dstack/docker-compose.dstack.dev.yml` | LOCAL DEV ONLY override: noop-dev attestation, no TEE claims, loudly labeled. |
| `deploy/dstack/make-app-compose.ts` | Deterministically renders `app-compose.json` (dstack manifest_version 2) and prints its sha256 = dstack `compose_hash`. `--check` mode runs in CI. |
| `deploy/dstack/app-compose.json` | The committed manifest whose sha256 is the attested `compose_hash`. |
| `deploy/dstack/pin-measurement.ts` | Pins `imageDigest` (dstack OS image hash) + `configHash` (compose hash) into the signed measurement registry; signing stays offline, two-person rule. |
| `packages/api/src/services/attestation-boot-gate.ts` | Fail-closed boot gate: with `STEWARD_ATTESTATION_PROVIDER=dstack-tdx` the API refuses to serve unless its own quote verifies. |
| `scripts/test-compose-dstack.sh` | CI contract test: compose validity, fail-closed secret contract, no-noop production posture, digest pinning, manifest freshness. |

## Trust chain, end to end

```
Intel TDX hardware root
  └─ TDX quote (RTMRs)
      ├─ os_image_hash  → measurement.imageDigest   (dstack guest OS)
      └─ compose_hash   → measurement.configHash    (sha256 of app-compose.json)
            └─ app-compose.json embeds docker-compose.dstack.yml verbatim
                  └─ which pins ghcr.io/steward-fi/steward BY DIGEST and
                     hardcodes STEWARD_ATTESTATION_PROVIDER=dstack-tdx
```

Changing the Steward image, any env name, or any compose byte changes
`compose_hash`, which invalidates the pinned measurement and (when KMS-gated)
stops secret release until the new measurement is explicitly re-authorized and
re-pinned via a signed registry PR. "Operator silently swaps the image" is
therefore visible and blockable.

## Prerequisites

- **Hardware/host**, one of:
  - Self-hosted bare-metal TDX server running dstack (dstack-vmm + KMS +
    gateway; see [dstack deployment docs](https://github.com/Dstack-TEE/dstack/blob/master/docs/deployment.md)).
    Production posture requires KMS in a CVM and an auth server allowlisting
    measurements.
  - Phala Cloud (managed dstack CVMs). Convenience, not a dependency.
- dstack guest OS image (e.g. `dstack-0.5.x`); record the `digest.txt` OS image
  hash, you will pin it.
- `bun` locally for the manifest/pinning scripts.
- Registry access to `ghcr.io/steward-fi/steward` (public).

## Deploy steps

### 1. Choose the image and regenerate the manifest

`deploy/dstack/docker-compose.dstack.yml` pins the Steward image by digest.
To deploy a different release, update the digest (both `steward-api` and
`steward-proxy`, same image), then:

```bash
bun deploy/dstack/make-app-compose.ts
# → writes deploy/dstack/app-compose.json, prints compose_hash
```

CI (`scripts/test-compose-dstack.sh`) fails if the committed manifest is stale.

### 2. Pin the expected measurement (PR-gated, two-person rule)

```bash
bun deploy/dstack/pin-measurement.ts \
  --deployment phala-prod \
  --os-image-hash <hash from dstack guest image digest.txt> \
  --endpoint https://steward.example.com/quote \
  --status pending
```

This updates `docs/attestation/measurements.json` and clears `signatures[]`.
Release key holders independently reproduce the compose hash
(`bun deploy/dstack/make-app-compose.ts --check`), then sign the canonical
payload offline (ed25519 over `canonicalizeJson(payload)`, see
`packages/attestation/src/registry.ts`) and add their signature entries. Merge
via a PR containing only the measurement change + evidence. Flip `pending` →
`active` in the PR that carries verified deploy evidence.

### 3. Prepare sealed secrets (never plaintext, never in the repo)

Secrets enter the CVM ONLY through dstack's KMS-encrypted environment. The
allowed names are listed in `app-compose.json` `allowed_envs` (adding a name is
a measurement change). On the operator machine create an env file with the
required values:

```
POSTGRES_PASSWORD=...
STEWARD_MASTER_PASSWORD=...
STEWARD_JWT_SECRET=...
STEWARD_EXECUTION_AUTH_SECRET=v1:...
STEWARD_KDF_SALT=...
STEWARD_AUDIT_HMAC_KEY=...
STEWARD_PROXY_REQUEST_SIGNING_SECRET=...
# optional: DATABASE_URL, STEWARD_PLATFORM_KEYS, APP_URL, PASSKEY_*, ...
```

The dstack tooling (`vmm-cli.py deploy --env-file`, or the Phala Cloud UI/CLI
secret input) encrypts these to the KMS **before they leave your machine**;
the KMS releases them only to CVMs whose measurement is authorized. Delete the
local file after deploy. Do not commit it, do not put values in compose.

Rehearse first with dummy values; live credential cutover is
orchestrator-gated per the sovereign-custody plan.

### 4. Deploy the CVM

Self-hosted dstack:

```bash
# on the dstack host, using the committed manifest
python3 vmm-cli.py --url http://127.0.0.1:9080 deploy \
  --name steward \
  --compose deploy/dstack/app-compose.json \
  --env-file steward.env \
  --image dstack-0.5.x \
  --port tcp:0.0.0.0:3200:3200 \
  --port tcp:0.0.0.0:8080:8080 \
  --vcpu 4 --memory 8G --disk 40G
```

Phala Cloud: create an app from `deploy/dstack/docker-compose.dstack.yml`
(the platform wraps it into the same app-compose format), supply the secrets
through the encrypted env input, and confirm the reported `compose_hash`
matches `bun deploy/dstack/make-app-compose.ts --check` output before
authorizing.

Boot behavior: the API runs the attestation boot gate before serving.
`STEWARD_ATTESTATION_PROVIDER=dstack-tdx` is hardcoded in the measured
compose; if the guest agent socket or the in-CVM verifier cannot produce a
fully verified quote after the retry budget (default 20 × 3s), the process
exits non-zero and the container restarts, it never serves unattested. There
is no fallback to `noop-dev` on this path.

### 5. Verify (outside party — do not trust the server's own claims)

Anyone can verify a running deployment without trusting the operator:

```bash
# 1. Registry + quote + measurement check (the CI verifier):
STEWARD_ATTESTATION_ENDPOINT=https://steward.example.com/quote \
STEWARD_ATTESTATION_DEPLOYMENT=phala-prod \
STEWARD_DSTACK_VERIFIER_URL=http://localhost:8080 \
bun run attestation:check
```

Run your OWN verifier rather than the deployment's sidecar:

```bash
docker run --rm -p 8080:8080 dstacktee/dstack-verifier:0.5.11@sha256:06a20b777e59196c7f54b0cd02ffe567df6d05ae39a0b2fea9cb0642fb23c1fd
```

What this proves (see `docs/ATTESTATION.md` for limits):

1. `GET /quote?nonce=<random>` returns raw TDX evidence with your nonce bound
   into `report_data` (anti-replay).
2. Your verifier performs DCAP/collateral verification against Intel's root of
   trust and reports `os_image_hash` + `compose_hash`.
3. `verifyQuoteAgainstRegistry` compares those against the signed, PR-gated
   measurement registry in this repo, whose signatures you check against the
   published release keys.
4. Reproduce `compose_hash` yourself from source:
   `git checkout <release> && bun deploy/dstack/make-app-compose.ts --check`.

If any step fails, do not send the deployment secrets or traffic.

## Local development (no TEE)

```bash
docker compose \
  -f deploy/dstack/docker-compose.dstack.yml \
  -f deploy/dstack/docker-compose.dstack.dev.yml \
  up -d
```

This is loudly labeled in the override file: `noop-dev` provider,
`verified:false` semantics unless explicitly allowed, refuses explicit allow
under `NODE_ENV=production`, and the production manifest never includes the
override. `/quote` responses clearly report `provider: "noop-dev"` so any
measurement-pinning client rejects them.

## Rollback

Measurements make rollback explicit:

1. Keep the previous deployment's registry entry `active` until the new one is
   verified (use `pending` for the new entry during rollout).
2. To roll back the app: redeploy the previous `app-compose.json` (previous
   image digest). Its measurement is still in the registry, so clients and the
   KMS still accept it. No secret rotation needed if the compromise was
   operational rather than key-level.
3. To retire a bad build: set its registry entry `status: "retired"` in a
   signed PR. Clients pinning the registry stop trusting it at next check; the
   KMS allowlist should be updated to match so it can no longer receive
   secrets.
4. Emergency: revoke at the KMS/auth-server first (stops secret release
   immediately, even before the registry PR merges), then reconcile the
   registry.

Break-glass rule from the custody plan: secrets are re-onboarded, never
extracted. If a CVM is suspected compromised, rotate the affected credentials
at their providers and re-onboard; do not attempt recovery of sealed material.

## CI

- `scripts/test-compose-dstack.sh` runs in the `e2e-integration` job on every
  PR: compose validity, fail-closed secret interpolation, dstack-tdx-only
  production posture, digest pinning, manifest freshness, no secret-value
  leakage into committed files.
- `packages/api/src/__tests__/attestation-boot-gate.test.ts` proves the boot
  gate fails closed when the verifier is unreachable or quotes do not verify,
  and that there is no noop fallback.
- `bun run attestation:check` is the third-party verification entrypoint used
  against live deployments (needs a reachable endpoint, so it is a deploy-time
  step, not a PR gate).
