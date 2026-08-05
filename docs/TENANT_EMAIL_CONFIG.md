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
  "templateId": "elizacloud",
  "subjectOverride": "Sign in"
}
```

The plaintext Resend API key is encrypted server-side with Steward's existing `KeyStore` / `STEWARD_MASTER_PASSWORD` flow before it is persisted.

## Platform API

Routes require `X-Steward-Platform-Key`.

### Set or update config

```bash
curl -X PATCH "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{
    "apiKey": "re_xxxxxxxxx",
    "from": "Eliza Cloud <login@elizacloud.ai>",
    "replyTo": "support@elizacloud.ai",
    "templateId": "elizacloud",
    "subjectOverride": "Sign in to Eliza Cloud"
  }'
```

### Read config

```bash
curl "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY"
```

Response omits `apiKeyEncrypted` and returns `hasApiKey` instead.

### Clear config

```bash
curl -X DELETE "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY"
```

## Template-only branding (no per-tenant Resend key)

A tenant can keep the platform's global Resend provider and only override the
email branding. PATCH with no `apiKey` (and no `from`):

```bash
curl -X PATCH "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{ "templateId": "elizacloud" }'
```

Branding fields are merged over any existing config, so a template-only PATCH
never clobbers `magicLinkBaseUrl` or stored provider credentials. `from`
without `apiKey` is rejected (provider config is all-or-nothing).

## Template IDs

Each template ID covers the full auth email set: magic-link sign-in AND the
6-digit OTP sign-in-code email.

- `default`: built-in Steward template (dark, amber CTA)
- `elizacloud`: Eliza Cloud brand — black field, `#141414` card, orange
  `#FF6B00` pill CTA, hosted eliza mark from `app.elizacloud.ai/brand/`,
  matching the product's transactional emails

Unknown template IDs also fall back to the default template.

## Runtime behavior

- `POST /auth/email/send` resolves the tenant from `X-Steward-Tenant`, then `body.tenantId`, then the existing default fallback behavior.
- `POST /auth/email/verify` and `GET /auth/callback/email` use the matching tenant-scoped token store configuration when verifying tokens.
- Updating or deleting tenant email config invalidates the in-process auth cache for that tenant.
