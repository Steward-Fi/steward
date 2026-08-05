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
  "templateId": "acme",
  "subjectOverride": "Sign in",
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
email branding. PATCH with no `apiKey` (and no `from`):

```bash
curl -X PATCH "$API_BASE/platform/tenants/acme/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{ "templateId": "acme" }'
```

Branding fields are merged over any existing config, so a template-only PATCH
never clobbers `magicLinkBaseUrl` or stored provider credentials. `from`
without `apiKey` is rejected (provider config is all-or-nothing).

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
