# @stwd/eliza-plugin Changelog

## Unreleased

### Security
- Every action now checks WHO is asking, not just whether Steward is connected. Each action declares a risk class (read, reversible-write, spend, admin) and a minimum sender role in `STEWARD_ACTION_POLICIES`. The sender is the platform-verified `message.entityId`. Message text, display names, and metadata are never used. Owners come from `STEWARD_OWNER_ENTITY_IDS` (or `character.settings.steward.ownerEntityIds`), falling back to elizaOS core `checkSenderRole` when available. Unknown senders can only chat. Spend actions (transfer, sign, trade, provider action, governed API call) run only for the owner in a DM. Owners in a group, and everyone else, get a clear denial and nothing reaches Steward. The check runs in both `validate` and `handler`, and fails closed if Steward, role lookup, or room lookup is unavailable, or the room type is unknown. `API` rooms count as DMs only with `STEWARD_API_ROOMS_ARE_DM=true`. Agent-initiated spend needs `STEWARD_ALLOW_AUTONOMOUS_SPEND=true` and an autonomous room.
- Disable the plugin when its API URL, authentication, or agent identity is missing; default agent auto-registration to off and require an explicit tenant-scoped API key when it is enabled.
- Proxy request-signing coverage now verifies the fail-closed default and the explicit development-mode opt-in under an isolated, fully restored environment.
- submit-trade now applies the shared `assertSecureApiUrl` guard to `STEWARD_API_URL`, so a non-localhost plaintext `http://` URL can no longer send the agent JWT in cleartext (SEC-095). Loopback http stays allowed for local dev.
- Proxy request HMAC signing is now mandatory whenever a signing secret is configured, regardless of `NODE_ENV` or the enforcement flag — a provisioned secret can never silently downgrade to unsigned proxy calls (SEC-171).

### Changed
- `approvalRequired` evaluator now implements the elizaOS core 2.0.x evaluator contract (`schema`, `shouldRun`, `prompt`, `processors`) and keeps the legacy `validate` / `handler` shape for older alpha cores. Dev dependency on `@elizaos/core` moves to `2.0.3-beta.7` so the package typechecks against the current core.
- Remove the inert `fallbackLocal` option and misleading local-signing message. Steward connection failures now leave managed wallet operations explicitly unavailable.
- Fail closed on non-JSON provider-action arguments, sanitize lifecycle failures, and keep concurrent polling results bound to their original action IDs.
- Reject nested password, passphrase, auth, client-secret-value, and cookie-header fields through the shared credential-key classifier before provider submission.
- Refresh action descriptions and source comments to describe the current leverage-policy, native-transfer, plugin-composition, and trust contracts without changing execution behavior.

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
