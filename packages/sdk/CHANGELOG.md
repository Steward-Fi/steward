# @stwd/sdk Changelog

## Unreleased

### Security (BREAKING)
- `StewardClient`, `StewardAuth`, and `AgentClient` constructors now REJECT a plaintext non-loopback `baseUrl` (fail closed, SEC-048). These clients transmit platform keys, app secrets, bearer tokens, and HMAC-signed credentials, which must never travel cleartext off-loopback — the CLI has always enforced this. `http://localhost`/`127.0.0.1`/`[::1]` stay allowed for local development; operators on trusted private networks can opt out with the new `allowInsecureBaseUrl: true` config (warns loudly at construction). Previously-working insecure configs must pass the flag or switch to HTTPS.
- `/accounts` and `/global-wallet` mutations are now HMAC-signed when `requestSigningSecret` is configured, aligning the request-signing prefix list with all eight other SDKs (SEC-049). Servers that enforce signatures on these routes previously saw unsigned mutations from this SDK.

### Added
- `StewardAuthConfig.authProxyUrl`: optional same-origin auth proxy prefix (e.g. `/api/auth`) that keeps the long-lived refresh token in an HttpOnly, SameSite=Strict cookie instead of JS-readable storage (SEC-018). When set, sign-in deposits the refresh token with the proxy (failing closed if the deposit cannot be completed), and refresh / revoke / tenant-switch calls go through the proxy — only the short-lived access token is kept in `storage`. Unset keeps the previous behavior unchanged.
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
