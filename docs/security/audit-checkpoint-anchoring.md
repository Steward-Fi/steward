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
STEWARD_AUDIT_RFC3161_CA_FILE=/etc/steward/tsa-ca.pem
STEWARD_AUDIT_RFC3161_UNTRUSTED_FILE=/etc/steward/tsa-intermediates.pem # optional
STEWARD_AUDIT_RFC3161_POLICY_OID=1.2.3.4.1 # optional exact policy
STEWARD_AUDIT_RFC3161_MAX_AGE_SECONDS=300
STEWARD_AUDIT_RFC3161_MAX_FUTURE_SKEW_SECONDS=300
STEWARD_AUDIT_RFC3161_TIMEOUT_MS=10000
```

- `best-effort` logs a TSA failure and returns the ordinary signed bundle
  without an anchor proof.
- `required` returns HTTP 503 and does not emit an evidence bundle when the TSA
  is missing, rejects the request, times out, returns a malformed response,
  fails cryptographic verification, or the verified proof cannot be persisted.
- production TSA URLs must use HTTPS, may not embed credentials, do not follow
  redirects, and responses are capped at 1 MiB.

The reference sink sends a DER RFC 3161 `TimeStampReq` with a SHA-256
`MessageImprint`, a new unpredictable 128-bit nonce, and `certReq=true`. Before
accepting the response, Steward invokes OpenSSL's RFC 3161 verifier against the
original query and operator-supplied CA. That verifies the CMS `SignedData`,
signed `TSTInfo`, imprint, nonce, timestamping EKU, signature, and certificate
path at the signed `genTime` (so a legitimately expired TSA signing certificate
does not invalidate older evidence). Steward also enforces the signed policy OID
when configured and checks `genTime` freshness using the TSA's signed accuracy
interval. The complete uncertainty interval must fit the configured acquisition
window; an imprecise timestamp cannot pass merely because its interval overlaps
the window.

The bundle contains the DER `TimeStampResp`, checkpoint digest, nonce, policy,
time/accuracy, verification time, and acquisition trust-anchor fingerprint. The
same proof is stored append-only beside the exact signed checkpoint. It never
contains TSA credentials or a trust root. `best-effort` may still return an
anchored bundle if later database persistence fails; `required` may not.

Anchoring occurs when an audit bundle or governed evidence case produces a
checkpoint. Steward does not claim a periodic anchor cadence: operators who
need hourly/daily bounds must schedule those evidence exports externally and
monitor for successful persisted proofs.

Self-hosted API compositions can implement `AuditCheckpointAnchorSink` and
register a named provider with `registerAuditCheckpointAnchorSink` before
serving evidence routes. Selecting an unregistered provider fails closed.

## Offline verification

Trust the TSA only through CA material obtained independently from the bundle:

```bash
node scripts/verify-evidence-bundle.mjs bundle.json \
  --expected-key-fingerprint "$STEWARD_EXPECTED_AUDIT_KEY_FP" \
  --tsa-ca auditor-trusted-tsa-ca.pem \
  --tsa-policy 1.2.3.4.1 \
  --require-anchor
```

The verifier reconstructs the exact checkpoint digest, invokes OpenSSL's RFC
3161 verifier entirely offline, validates the CMS/TSTInfo signature, timestamping
certificate path, message imprint, persisted nonce/policy/time metadata, and
reports `genTime + accuracy` as the conservative "existed no later than" bound.
An intermediate chain can be supplied with `--tsa-untrusted`.

Verification is deliberately offline and does not fetch CRLs or OCSP responses.
For long-term validation, auditors must retain the independently obtained CA and
intermediate set applicable at `genTime`, plus any time-applicable revocation
evidence required by their policy. The persisted CA fingerprint and TSA policy
identify the acquisition trust policy; they are not themselves revocation proof.

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
