# Auth security claim inventory

This inventory replaces `auth-audit-hardening.test.ts`. That suite read route
and migration text, so it could pass without executing any boundary. Runtime
claims below are owned by mounted tests; immutable database fences are owned by
database migration/schema tests.

| Retired claim | Executed owner |
| --- | --- |
| Test-account production posture and sanitized failures | `auth-test-account.test.ts`, `auth-test-inbox.test.ts` |
| Logout, refresh reuse, and refresh/revoke fencing | `auth-refresh-reuse.test.ts`, `auth-refresh-revocation-race.test.ts` |
| Login/MFA audit-before-session behavior | `auth-mfa-sms.test.ts`, `auth-passkey-mfa-mounted.test.ts`, `audit-events-filters.test.ts` |
| Audit route RBAC and bounded time ranges | `audit-events-filters.test.ts`, `audit-bundle-signing-gate.test.ts` |
| Tenant login-method and SSO policy enforcement | `auth-abuse-controls.test.ts`, `auth-passkey-enumeration.test.ts`, `tenant-sso-domains.test.ts` |
| OAuth redirect, callback state, nonce, PKCE, and one-time exchange | `auth-nonce-binding.test.ts`, `auth-oauth-callback-browser.test.ts`, `auth-oauth-nonce-exchange.test.ts`, `auth-oidc-jwt.test.ts` |
| MFA challenge, recovery-code, SMS, TOTP, and passkey clone fences | `auth-mfa-sms.test.ts`, `auth-passkey-mfa-mounted.test.ts` |
| Email companion code, status polling, OTP grants, and passkey grant lifecycle | `auth-email-route-lifecycle.test.ts`, `auth-email-delivery-failclosed.test.ts`, `auth-email-otp-signup.test.ts` |
| Passkey enumeration, redaction, ownership, and counter handling | `auth-passkey-enumeration.test.ts`, `auth-passkey-mfa-mounted.test.ts` |
| OAuth/OIDC provider-account ownership and verified-email policy | `auth-oidc-jwt.test.ts`, `auth-oauth-callback-browser.test.ts`, `user-linked-accounts.test.ts` |
| Phone/SMS purpose binding | `auth-mfa-sms.test.ts`, `auth-whatsapp.test.ts` |
| Wallet nonce binding, replay, and wallet identity behavior | `auth-nonce-binding.test.ts`, `auth-wallets.test.ts` |
| Authenticator and wallet identity uniqueness | `packages/db/src/__tests__/auth-identity-uniqueness-migration.test.ts` |

No row in this file is an executable assertion. It is only a routing index so
future changes must update the mounted owner instead of adding a source scan.
