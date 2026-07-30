# Steward Attestation

Steward's attestation layer is vendor-neutral by design. dstack/Intel TDX is the first implemented backend, but callers depend on `AttestationProvider`, not on Phala or dstack-specific APIs.

## What a quote proves

A verified quote proves that the reported runtime measurement came from a supported hardware attestation root and that the measured boot/runtime state matched the evidence checked by the provider verifier.

For the `dstack-tdx` backend, Steward uses dstack Guest Agent evidence from `/var/run/dstack.sock`:

- `/GetQuote` returns `quote`, `event_log`, `report_data`, `vm_config`, and versioned `attestation`.
- `/Info` returns app/runtime fields including `os_image_hash`, `compose_hash`, `mr_aggregated`, and `vm_config`.
- Client-side verification delegates Intel DCAP/event-log/OS-image checks to the dstack verifier service `/verify` and only marks `verified: true` when verifier output reports quote, event log, OS image binding, TEE variant, and nonce checks as valid.

Normalized Steward measurement:

- `measurement.imageDigest`: dstack `app_info.os_image_hash` (the attested dstack OS image hash). Application container images must be pinned by digest in compose; the compose hash below is what binds those pins.
- `measurement.configHash`: dstack `app_info.compose_hash`.

## What a quote does not prove

A quote does **not** prove that the application is bug-free, that policy is correct, that the endpoint is the intended DNS name, or that secrets were never mishandled before being onboarded. It also does not replace TLS endpoint authentication. Production deployments should prefer RA-TLS or another binding between the verified quote and the serving endpoint, then check the measurement registry.

If `STEWARD_DSTACK_VERIFIER_URL` is not configured, `dstack-tdx` may generate evidence but returns `verified: false`. There is no vacuous-green path.

## Backend matrix

- `dstack-tdx`: implemented. Quote generation uses dstack Guest Agent `/GetQuote` and `/Info`; verification uses dstack verifier `/verify`. Full Intel PCS/DCAP collateral handling lives in the verifier service, not in Steward's TypeScript process.
- `noop-dev`: implemented for local development. It returns `verified: false` unless `STEWARD_ATTESTATION_NOOP_ALLOW=true`, and that explicit allow is rejected when `NODE_ENV=production`.
- `aws-nitro`: interface seam only. No implementation in this lane.
- `amd-sev-snp`: interface seam only. No implementation in this lane.

## `/quote` endpoint

`GET /quote?nonce=<challenge>` returns the normalized `AttestationQuote` from the configured provider.

Environment:

- `STEWARD_ATTESTATION_PROVIDER=dstack-tdx|noop-dev` (default: `noop-dev`)
- `DSTACK_SOCKET_PATH=/var/run/dstack.sock` (optional dstack override)
- `STEWARD_DSTACK_VERIFIER_URL=http://verifier:8080` (required for real dstack verification)
- `STEWARD_ATTESTATION_NOOP_ALLOW=true` (local development only)

## Measurement registry

The registry lives at `docs/attestation/measurements.json` and has this shape:

```json
{
  "payload": {
    "schemaVersion": 1,
    "registryId": "steward-prod",
    "updatedAt": "2026-07-30T00:00:00.000Z",
    "deployments": {
      "phala-prod": {
        "provider": "dstack-tdx",
        "measurement": {
          "imageDigest": "<verified os_image_hash>",
          "configHash": "<verified compose_hash>"
        },
        "endpoint": "https://steward.example.com",
        "status": "active"
      }
    }
  },
  "signatures": [
    {
      "keyId": "release-key-1",
      "algorithm": "ed25519",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----...",
      "signatureBase64": "..."
    }
  ]
}
```

Registry signatures are over canonical JSON of `payload`. CI can require more than one valid signature with `STEWARD_REGISTRY_REQUIRED_SIGNATURES=2` and should pin trusted release keys with `STEWARD_REGISTRY_TRUSTED_KEY_IDS=release-key-1,release-key-2` plus public-key fingerprints in `STEWARD_REGISTRY_TRUSTED_KEY_SHA256=...`; this is the intended two-person-rule for production measurement changes. Any production measurement update must be an explicit PR that reviewers can compare against build/deploy evidence.

## CI check

Run:

```bash
STEWARD_ATTESTATION_ENDPOINT=https://steward.example.com/quote \
STEWARD_ATTESTATION_DEPLOYMENT=phala-prod \
STEWARD_DSTACK_VERIFIER_URL=http://dstack-verifier:8080 \
STEWARD_REGISTRY_REQUIRED_SIGNATURES=2 \
STEWARD_REGISTRY_TRUSTED_KEY_IDS=release-key-1,release-key-2 \
STEWARD_REGISTRY_TRUSTED_KEY_SHA256=<sha256-public-key-pem>,<sha256-public-key-pem> \
bun run scripts/check-attestation.ts
```

The script fetches `/quote`, verifies the dstack evidence with the configured verifier, validates the registry signatures, and fails if the served measurement differs from the registry.

For the full dstack deployment packaging (compose app, sealed-secret env contract, app-compose manifest, boot gate, rollback), see `docs/DSTACK-DEPLOY.md`.

## Self-host measurement registration

1. Deploy Steward with images pinned by digest in your dstack compose file.
2. Fetch `/quote?nonce=<random>` from the running instance.
3. Verify it with a dstack verifier service.
4. Copy the verified `measurement.imageDigest` and `measurement.configHash` into a new deployment entry.
5. Sign the registry payload with your release key(s).
6. Open a PR containing only the measurement update plus verifier transcript/evidence.
