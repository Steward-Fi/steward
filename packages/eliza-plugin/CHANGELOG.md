# @stwd/eliza-plugin Changelog

## Unreleased

### Changed
- Fail closed on non-JSON provider-action arguments, sanitize lifecycle failures, and keep concurrent polling results bound to their original action IDs.

### Docs
- Make the opt-in live integration suite (`STEWARD_LIVE_TESTS=1`) target env-configurable (`STEWARD_URL` / `STEWARD_API_KEY` / `STEWARD_TENANT_ID`) with self-host defaults (`http://localhost:3200`, `my-app`) instead of a hardcoded hosted `api.steward.fi` URL and production tenant/key. Steward is self-host-first today; there is no shared hosted API. Test-fixture only, no runtime change.

## 0.4.1

- Security audit hardening release.
- assertSecureApiUrl rejects plaintext http:// origins for non-localhost hosts.
