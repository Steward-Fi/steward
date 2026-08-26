# Tenant Email Config

Steward supports per-tenant magic link email settings in addition to the global fallback env vars:

- `RESEND_API_KEY`
- `EMAIL_FROM`

If a tenant has no `tenant_configs.email_config`, auth continues using the global env-based Resend configuration exactly as before.

## Stored Shape

`tenant_configs.email_config` stores:

```json
{
  "provider": "resend",
  "apiKeyEncrypted": "...",
  "from": "Tenant <login@example.com>",
  "replyTo": "support@example.com",
  "brandName": "Acme",
  "templateId": "acme",
  "subjectOverride": "Sign in",
  "magicLinkBaseUrl": "https://app.acme.example",
  "magicLinkCallbackPath": "/auth/callback/email",
  "templates": {
    "magicLink": { "subject": "...", "text": "...", "html": "..." },
    "otp": { "subject": "...", "text": "...", "html": "..." }
  }
}
```

The plaintext Resend API key is encrypted server-side with Steward's existing `KeyStore` / `STEWARD_MASTER_PASSWORD` flow before it is persisted.

## Platform API

Routes require `X-Steward-Platform-Key`.

### Set or update config

```bash
curl -X PATCH "$API_BASE/platform/tenants/acme/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{
    "apiKey": "re_xxxxxxxxx",
    "from": "Acme <login@acme.example>",
    "replyTo": "support@acme.example",
    "templateId": "acme",
    "subjectOverride": "Sign in to Acme"
  }'
```

### Read config

```bash
curl "$API_BASE/platform/tenants/acme/email-config" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY"
```

Response omits `apiKeyEncrypted` and returns `hasApiKey` instead.

### Clear config

```bash
curl -X DELETE "$API_BASE/platform/tenants/acme/email-config" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY"
```

## Template-only branding (no per-tenant Resend key)

A tenant can keep the platform's global Resend provider and only override the
email branding. `brandName` customizes both built-in magic-link and OTP
templates without requiring raw HTML. PATCH with no `apiKey` (and no `from`):

```bash
curl -X PATCH "$API_BASE/platform/tenants/acme/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{ "brandName": "Acme" }'
```

Branding fields are merged over any existing config, so a template-only PATCH
never clobbers `magicLinkBaseUrl` or stored provider credentials. `from`
without `apiKey` is rejected (provider config is all-or-nothing).

`brandName` is a single-line display string of at most 100 characters. It
defaults to `Steward` when unset. Use `subjectOverride` only when the subject
must differ from the built-in `Sign in to <brand name>` copy.

## Hosted callback routing

When a tenant's application owns the browser callback, configure both its
public origin and the root-relative route that the application actually
serves. These fields can be patched together with `brandName` and merge over
any existing provider credentials:

```bash
curl -X PATCH "$API_BASE/platform/tenants/acme/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{
    "brandName": "Acme",
    "magicLinkBaseUrl": "https://app.acme.example",
    "magicLinkCallbackPath": "/auth/callback/email"
  }'
```

Without `magicLinkBaseUrl`, links use Steward's global `APP_URL`. When a base
URL is set without a callback path, the path defaults to
`/auth/email/verify`. Always verify that a generated link lands on the tenant
application before promoting the configuration.

Hosted deployments can also set a durable environment fallback for shared
email delivery:

```bash
EMAIL_BRAND_NAME=Acme
EMAIL_MAGIC_LINK_BASE_URL=https://app.acme.example
EMAIL_MAGIC_LINK_CALLBACK_PATH=/auth/callback/email
```

These values are used when tenant email config is absent or temporarily
unavailable. A tenant's explicit `brandName` and `magicLinkBaseUrl` still take
precedence. Keep the email link origin separate from `APP_URL` when `APP_URL`
must identify the Steward API for OAuth callbacks. The email base must be a
credential-free HTTP(S) origin, and the callback must be root-relative.

## Custom raw templates (deployer-supplied branded markup)

For fully branded auth emails, a hosted Steward instance can store raw
templates as tenant CONFIG instead of shipping branded markup in this repo.
Each template is `{ subject, text, html }` with `{{placeholder}}`
substitution:

- magic link: `{{magicLink}}`, `{{email}}`, `{{tenantName}}`, `{{expiresInMinutes}}`
- OTP: `{{code}}`, `{{email}}`, `{{brandName}}`, `{{expiresInMinutes}}`

Substituted values are HTML-escaped in the `html` body; the template markup
itself is trusted platform-admin config. Unknown placeholders are left as-is
so typos surface in rendered output. When set, `templates` takes precedence
over `templateId` resolution for that email type.

```bash
curl -X PATCH "$API_BASE/platform/tenants/acme/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{
    "templates": {
      "magicLink": {
        "subject": "Sign in to Acme",
        "text": "Sign in: {{magicLink}} (expires in {{expiresInMinutes}} minutes)",
        "html": "<a href=\"{{magicLink}}\">Sign in to Acme</a>"
      },
      "otp": {
        "subject": "{{code}} is your Acme sign-in code",
        "text": "Your code: {{code}}",
        "html": "<b>{{code}}</b> is your Acme sign-in code"
      }
    }
  }'
```

Pass `"templates": null` to clear stored templates (falls back to
`templateId` / default).

## Template IDs

Each template ID covers the full auth email set: magic-link sign-in AND the
6-digit OTP sign-in-code email.

- `default`: built-in Steward template (dark, amber CTA)

Tenant-specific branded templates should live in the deployer's Steward
instance or extension layer, not in the OSS repository.

Unknown template IDs also fall back to the default template.

## Runtime behavior

- `POST /auth/email/send` resolves the tenant from `X-Steward-Tenant`, then `body.tenantId`, then the existing default fallback behavior.
- `POST /auth/email/verify` and `GET /auth/callback/email` use the matching tenant-scoped token store configuration when verifying tokens.
- Updating or deleting tenant email config invalidates the in-process auth cache for that tenant.
