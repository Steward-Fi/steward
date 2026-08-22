# Auth security claim inventory

This inventory replaces `auth-audit-hardening.test.ts`. That suite read route
and migration text, so it could pass without executing any boundary. Runtime
claims below are owned by mounted tests; immutable database fences are owned by
database migration/schema tests.

| Retired claim | Executed owner |
| --- | --- |
| Production test-token posture | `auth-test-account.test.ts`, `auth-test-inbox.test.ts` |
| Logout revokes access and refresh credentials | `auth-refresh-reuse.test.ts` |
| Refresh reuse revokes minted access credentials | `auth-refresh-reuse.test.ts` |
| Refresh rotation versus user-wide revoke | `auth-refresh-revocation-race.test.ts` |
| Blocking authorization audit before mutation | `audit-events-filters.test.ts`, `audit-bundle-signing-gate.test.ts` |
| Login and MFA audit before session mint | `auth-mfa-sms.test.ts`, `auth-passkey-mfa-mounted.test.ts` |
| Audit-route owner/admin RBAC and bounded ranges | `audit-events-filters.test.ts`, `audit-bundle-signing-gate.test.ts` |
| Phone login OTP tenant-purpose binding | `auth-mfa-sms.test.ts`, `auth-whatsapp.test.ts` |
| Direct-route tenant login-method policy | `auth-abuse-controls.test.ts`, `auth-passkey-enumeration.test.ts`, `tenant-sso-domains.test.ts` |
| OAuth redirect safety and atomic state/code consume | `auth-nonce-binding.test.ts`, `auth-oauth-callback-browser.test.ts`, `auth-oauth-nonce-exchange.test.ts` |
| Recent stronger authentication before factor addition | `auth-mfa-sms.test.ts`, `auth-passkey-enumeration.test.ts` |
| Stable passkey registration/verification failures | `auth-passkey-enumeration.test.ts`, `auth-passkey-mfa-mounted.test.ts`, `auth-email-route-lifecycle.test.ts` |
| Tenant access before OAuth token or authenticator persistence | `auth-oauth-callback-browser.test.ts`, `auth-oidc-jwt.test.ts`, `auth-passkey-mfa-mounted.test.ts` |
| OAuth provider-account insert-conflict ownership | `user-linked-accounts.test.ts`, `auth-oauth-callback-browser.test.ts` |
| Test-account, OIDC email, passkey enumeration, and SMS enrollment hardening | `auth-test-account.test.ts`, `auth-oidc-jwt.test.ts`, `auth-passkey-enumeration.test.ts`, `auth-mfa-sms.test.ts` |
| One user row per wallet identity | `auth-wallets.test.ts`, `packages/db/src/__tests__/auth-identity-uniqueness-migration.test.ts` |
| Tenant-disabled methods on direct auth routes | `auth-abuse-controls.test.ts`, `auth-test-account.test.ts`, `auth-email-route-lifecycle.test.ts` |

No row in this file is an executable assertion. It is only a routing index so
future changes must update the mounted owner instead of adding a source scan.
