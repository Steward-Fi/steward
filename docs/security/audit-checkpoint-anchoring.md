# Third-party audit-checkpoint anchoring

Steward can optionally send the SHA-256 digest of each canonical Ed25519 audit
checkpoint payload to an RFC 3161 timestamp authority (TSA). A verified token
shows that the checkpoint existed no later than the TSA's signed time. This
narrows the window in which an operator could rewrite pre-anchor history and
produce a new checkpoint.

Anchoring is not tamper-proof or operator-proof. It does not prove that the
export is complete, protect events created after the anchor, prevent TSA and
operator collusion, or replace the auditor's out-of-band trust in Steward's
Ed25519 signing-key fingerprint and the TSA certificate authority.

## Configuration

No setting means `off`: Steward constructs no sink, makes no network request,
and returns the existing v1 bundle shape without an `anchor` field.

```bash
STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE=best-effort # off | best-effort | required
STEWARD_AUDIT_CHECKPOINT_ANCHOR_PROVIDER=rfc3161
STEWARD_AUDIT_RFC3161_URL=https://tsa.example.com/timestamp
STEWARD_AUDIT_RFC3161_TIMEOUT_MS=10000
```

- `best-effort` logs a TSA failure and returns the ordinary signed bundle
  without an anchor proof.
- `required` returns HTTP 503 and does not emit an evidence bundle when the TSA
  is missing, rejects the request, times out, or returns a malformed response.
- production TSA URLs must use HTTPS, may not embed credentials, do not follow
  redirects, and responses are capped at 1 MiB.

The reference sink sends a DER RFC 3161 `TimeStampReq` with a SHA-256
`MessageImprint` and `certReq=true`. The bundle contains the opaque DER
`TimeStampResp`, the checkpoint digest, and non-secret algorithm/provider
metadata. It never contains TSA credentials.

Self-hosted API compositions can implement `AuditCheckpointAnchorSink` and
register a named provider with `registerAuditCheckpointAnchorSink` before
serving evidence routes. Selecting an unregistered provider fails closed.

## Offline verification

Trust the TSA only through CA material obtained independently from the bundle:

```bash
node scripts/verify-evidence-bundle.mjs bundle.json \
  --expected-key-fingerprint "$STEWARD_EXPECTED_AUDIT_KEY_FP" \
  --tsa-ca auditor-trusted-tsa-ca.pem \
  --require-anchor
```

The verifier reconstructs the exact checkpoint digest, invokes OpenSSL's RFC
3161 verifier entirely offline, validates the timestamp token's certificate
chain and message imprint, and reports the TSA time as the "existed no later
than" bound. An intermediate chain can be supplied with `--tsa-untrusted`.

To enforce a compliance cutoff:

```bash
node scripts/verify-evidence-bundle.mjs bundle.json \
  --tsa-ca auditor-trusted-tsa-ca.pem \
  --require-anchor \
  --anchored-before 2026-12-31T23:59:59Z
```

Without `--tsa-ca`, an included token is reported as present but untrusted. The
bundle-carried token and any bundle-carried identity are never treated as their
own trust root.
