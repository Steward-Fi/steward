# @stwd/sdk Changelog

## Unreleased

### Added
- Add shared magic-link + six-digit companion-code login helpers: `verifyEmailSignInCode()` and status-only `pollEmailSignInStatus()`. `signInWithEmail()` now returns opaque polling credentials.
- `BridgeHandoff` type and `BridgeBuildResult = AdapterUnsignedIntent | BridgeHandoff` union. `buildBridgeIntent()` now returns either an unsigned transaction intent or a non-signable external handoff (for providers like wxmr.io that require an interactive wallet and expose no safe transaction-building API). Bridge quote/session types gain optional `direction`, `executionMode`, `handoffUrl`, `feeScope`, `notices`, and `recipientSensitive` metadata. Additive and backward compatible.
- Add typed provider-action lifecycle states and complete provider-case evidence contracts.

### Docs
- Point example `baseUrl` values at a self-hosted instance (`http://localhost:3200`) instead of a hosted `api.steward.fi` URL. Steward is self-host-first today; there is no shared hosted API. JSDoc/README/test-fixture only, no runtime or API change (the SDK `baseUrl` remains a required field with no default).

## 0.10.1

- chainId threaded through SIWE/SIWS sign-in (signInWithSIWE/signInWithSolana accept the connected chain).
- Security audit hardening release.

- Expands Hyperliquid trade asset types to include NEAR, HYPE, ZEC, XMR.
- Expands Hyperliquid trade asset types to include BNB, SOL, AVAX, ARB, and OP.
- Documents the optional per-selector `maxNativeValueWei` contract policy field used by governed EVM swap preparation.

## 0.10.0

BREAKING-CHANGES:
- Adds the Sprint 4 trade API surface under `StewardClient.tradeSessions` and `StewardClient.trade.hyperliquid`.
- Consumers that pin exact SDK versions should upgrade to `0.10.0` before using trade session or Hyperliquid order helpers.
