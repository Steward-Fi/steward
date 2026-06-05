# Privy Parity Red-Team Slice

Date: 2026-06-04

Scope: recently added Privy-parity surfaces in the local Steward tree: financial adapter routes, plaintext private-key export gate, P-256 authorization keys and nested quorums, ERC20 transfer wallet actions, and generated OpenAPI exposure.

## Findings

### Fixed: P-256 quorum counted low-permission leaf signers

Severity: High

The P-256 request-signature middleware enforced the required permission on single signers and on the root quorum, but each presented leaf signer counted toward nested quorum threshold as long as its signature verified. That diverged from the HMAC signer authorization path, which requires every signer credential to hold the requested permission.

Exploit shape:

1. A root quorum has `sign_message` permission and threshold `2`.
2. The quorum contains one signer with `sign_message` and one active P-256 signer without `sign_message`.
3. Both sign the canonical request.
4. Before the fix, the middleware counted both verified signatures and accepted the request.

Fix:

- `packages/api/src/middleware/authorization-signature.ts` now marks a P-256 quorum credential as unsatisfied when the signer lacks the route-required permission.
- Nested child quorums also fail closed when their own permission set does not include the route-required permission.
- `packages/api/src/__tests__/authorization-keys.test.ts` adds a regression proving a low-permission P-256 leaf cannot satisfy the quorum threshold.

### Reviewed: adapter money paths

No direct exploit confirmed in this slice.

Observed controls:

- Fund-moving adapter build routes resolve the acting agent through tenant ownership checks.
- Swap, earn deposit/withdraw, and bridge build routes assert returned artifacts are unsigned before applying the policy/spend gate and before returning the intent.
- Adapter user/session resources bind user sessions to their own user ID and require tenant-level callers to name a tenant member.
- Exchange embed sessions require an exact tenant app-client return URL allowlist match.
- Custodial mock signing fails closed and does not fabricate signatures.

Residual risk: quoted `estimatedUsd` is caller supplied for adapter build spend checks. The current fallback is conservative when omitted, but real adapters should compute or attest notional server-side from the quote rather than trust caller estimates.

### Reviewed: plaintext key export gate

No direct exploit confirmed in this slice.

Observed controls:

- Private-key export requires both break-glass env flags, tenant-level owner/admin session, recent MFA, tenant ownership of the agent, audit before export, no-store response headers, and a production-only plaintext response acknowledgement gate.

Residual risk: plaintext export remains catastrophic under API-process compromise or production env misconfiguration. The safer parity path is encrypted export or an external signer/HSM boundary.

### Reviewed: ERC20 transfer wallet actions

No direct exploit confirmed in this slice.

Observed controls:

- ERC20 action signing rewrites the transaction target to the token contract, native value to zero, and calldata to `transfer(address,uint256)`.
- Execution requires a constrained `contract-allowlist` selector policy with recipient and maxAmount constraints.
- Status polling does not return stored signed transactions.

Residual risk: token spend accounting and settlement status are still less complete than native transfer accounting. Add confirmed token transfer indexing before relying on daily token spend limits for settled lifecycle views.

### Reviewed: OpenAPI exposure

No direct exploit confirmed in this slice.

Observed controls:

- Generated OpenAPI exposes adapter routes as unsigned-intent builders, documents P-256 signer registration, includes key-quorum resources, and marks transfer action status/error parity.
- HMAC `credentialSecret` and transfer `signedTx` appear in response schemas only where the runtime intentionally returns one-time signer secrets or immediate signed-only action responses.

Residual risk: the OpenAPI contract does not yet inventory every route's request-expiry, idempotency, MFA, and authorization-signature requirements. That is a documentation/client-generation hardening gap, not a runtime bypass found in this pass.

### Fixed: Solana parser treated decoded non-transfer side effects as policy-safe

Severity: High

The serialized Solana transaction parser decoded several System Program and SPL Token / Token-2022 instructions, but `fullyParsed` previously meant only "decoded." That left side-effect instructions such as SPL `Approve`, `CloseAccount`, mint/burn, and System `CreateAccount` eligible to flow into the sign-solana policy route as zero-value or incomplete-envelope actions. Address Lookup Table account references were already designed to fail closed when unresolved; this pass added explicit regression coverage for that ambiguity too.

Exploit shape:

1. Caller submits a serialized Solana transaction containing a decoded SPL delegate approval or close-account instruction.
2. Caller supplies benign `to`/`value` hints, or no meaningful transfer hints.
3. The parser derives no transfer spend while still reporting the transaction as fully parsed.
4. The API's existing `derived.fullyParsed` gate does not reject, so policy evaluation can reason over an incomplete action envelope.

Fix:

- `packages/vault/src/solana-instructions.ts` now marks decoded but unsupported side-effect instructions as `unparsed: true` with a specific fail-closed reason. The existing sign-solana API gate rejects these by default unless the explicit audited blind-signing opt-in is enabled.
- `packages/vault/src/__tests__/solana-instructions.test.ts` adds coverage for SPL approve/delegate, SPL close-account, System create-account lamport funding, and v0 Address Lookup Table account references.

## Targeted Tests

Run:

```bash
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/authorization-keys.test.ts
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/adapters-policy-gate.test.ts packages/api/src/__tests__/key-export-plaintext-gate.test.ts packages/api/src/__tests__/wallet-actions.test.ts packages/api/src/__tests__/openapi-contract.test.ts
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/vault/src/__tests__/solana-instructions.test.ts packages/vault/src/__tests__/solana-offline-broadcast.test.ts
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/sign-solana-policy-derivation.test.ts
```

## Unresolved Risks

- P-256 authorization-key route coverage is still concentrated on vault/request-signature paths; extend the same authorization model across every controlled Privy-parity resource before calling parity complete.
- Adapter production providers must be reviewed individually for signed artifact leakage, return URL behavior, quote manipulation, and provider-side session ownership.
- Plaintext key export should remain a break-glass path only; external signer isolation is the meaningful long-term control.
- OpenAPI should eventually publish route-level hardening annotations so generated clients cannot omit required idempotency, timestamp, MFA, or request-signature controls.
