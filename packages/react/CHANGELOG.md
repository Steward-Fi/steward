# Changelog

All notable changes to `@stwd/react` are documented here.

## Unreleased

### Fixed
- `StewardLogin` no longer emits the `webauthn` autocomplete token on the email input, so browser passkey conditional-mediation autofill cannot hijack a brand-new-email signup. Explicit passkey button flow is unchanged.

### Changed
- Approval confirmations now keep failed mutations actionable while preventing a delayed result from closing or contaminating a newer confirmation.
- Approval hooks now use stable cursor pagination and pass their agent scope to the server, avoiding offset shifts and client-only filtering of tenant-wide queue pages.
- Route approval, transaction-history, and spend-stat requests through the credentialed `StewardClient`; remove unauthenticated raw-fetch paths and derive pagination and spend aggregates from authenticated history (SEC-195).

### Added
- `StewardAuthConfig.authProxyUrl` on `StewardProvider`: forwarded to the SDK so the long-lived refresh token can be held by a same-origin HttpOnly-cookie proxy instead of JS-readable storage (SEC-018). Optional; previous behavior is unchanged when unset.

### Docs
- Point example `baseUrl` values in JSDoc (`StewardProvider`, `StewardLogin`) and the README at a self-hosted instance (`http://localhost:3200`) instead of a hosted `api.steward.fi` URL. Steward is self-host-first today; there is no shared hosted API. Docs/comment only, no source behavior change.

### Tests
- Added test coverage for utilities (format, theme, walletPanelRegistry), context hooks (useAuth, useSteward), data hooks (useWallet, useTransactions, useApprovals, usePolicies, useSpend), and SSR branch coverage for the component surface (auth guard, user button, tenant picker, spend dashboard, approval queue, wallet overview, policy controls, email/OAuth callbacks, passkey enrollment). Suite goes from 56 to 195 passing. No source changes.
- Mount linked-account interaction coverage through the real Steward and auth contexts so its test doubles cannot leak into OAuth callback suites; test-harness only, with no runtime behavior change.
- State the StewardLogin hook-order regression as a current invariant instead of change-history narration. Test comment only; no runtime or API change.

## 0.9.1

- Security audit hardening release.
- StewardLogin scrubs the magic-link token and email from the URL via history.replaceState after capture, so credentials no longer land in browser history or the Referer header.
