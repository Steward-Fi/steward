# Steward dstack packaging

Run Steward (API + proxy + vault) inside an Intel TDX confidential VM via
[dstack](https://github.com/Dstack-TEE/dstack), with fail-closed attestation
wired to `@stwd/attestation`.

Full guide: [`docs/DSTACK-DEPLOY.md`](../../docs/DSTACK-DEPLOY.md).
Trust model + measurement registry: [`docs/ATTESTATION.md`](../../docs/ATTESTATION.md).

- `docker-compose.dstack.yml` — the measured production compose app. Digest-pinned
  images, secrets only via dstack sealed env, `STEWARD_ATTESTATION_PROVIDER=dstack-tdx`
  hardcoded.
- `docker-compose.dstack.dev.yml` — LOCAL DEV ONLY override (noop-dev, no TEE claims).
- `make-app-compose.ts` — renders `app-compose.json` deterministically; its sha256 is
  the attested `compose_hash`. `--check` runs in CI.
- `app-compose.json` — committed dstack manifest (manifest_version 2).
- `pin-measurement.ts` — pins expected measurements into the signed registry
  (`docs/attestation/measurements.json`); signing is offline, two-person rule.

CI contract test: `scripts/test-compose-dstack.sh`.
