# @stwd/eliza-plugin Changelog

## Unreleased

### Security
- Normalize trailing API URL slashes with a linear scan before applying the existing HTTPS, credential, and redirect guards, avoiding regex backtracking on attacker-sized configuration values.
- Proxy request-signing coverage now verifies the fail-closed default and the explicit development-mode opt-in under an isolated, fully restored environment.
- submit-trade now applies the shared `assertSecureApiUrl` guard to `STEWARD_API_URL`, so a non-localhost plaintext `http://` URL can no longer send the agent JWT in cleartext (SEC-095). Loopback http stays allowed for local dev.
- Proxy request HMAC signing is now mandatory whenever a signing secret is configured, regardless of `NODE_ENV` or the enforcement flag — a provisioned secret can never silently downgrade to unsigned proxy calls (SEC-171).

### Changed
- Fail closed on non-JSON provider-action arguments, sanitize lifecycle failures, and keep concurrent polling results bound to their original action IDs.
- Reject nested password, passphrase, auth, client-secret-value, and cookie-header fields through the shared credential-key classifier before provider submission.

### Docs
- Make the opt-in live integration suite (`STEWARD_LIVE_TESTS=1`) target env-configurable (`STEWARD_URL` / `STEWARD_API_KEY` / `STEWARD_TENANT_ID`) with self-host defaults (`http://localhost:3200`, `my-app`) instead of a hardcoded hosted `api.steward.fi` URL and production tenant/key. Steward is self-host-first today; there is no shared hosted API. Test-fixture only, no runtime change.

## 0.4.4

- Bundle Steward shared runtime helpers into the published package so consumers do not depend on
  workspace-only package references.
- Restrict the npm artifact to the compiled distribution and package changelog.
- Apply bounded diagnostics to runtime rejection paths and extend the telemetry guard to Promise
  rejection callbacks.

## 0.4.1

- Security audit hardening release.
- assertSecureApiUrl rejects plaintext http:// origins for non-localhost hosts.
