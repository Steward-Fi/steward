import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const source = readFileSync(join(import.meta.dir, "..", "routes", "tenants.ts"), "utf8");

describe("legacy tenant webhook deprecation", () => {
  it("rejects new legacy values and never creates an undisclosed signing secret", () => {
    expect(source).toContain("LEGACY_WEBHOOK_DEPRECATION_ERROR");
    expect(source).toContain("POST /webhooks instead (the secret is returned once)");
    expect(source.match(/LEGACY_WEBHOOK_DEPRECATION_ERROR }, 410/g)).toHaveLength(2);
    expect(source).not.toContain("upsertLegacyTenantWebhook");
    expect(source).not.toContain("generateWebhookSecret");
    expect(source).not.toContain('description: "legacy:tenant-webhook"');
  });

  it("does not present or preserve a historical inert URL as active", () => {
    expect(source).toContain("data: getTenantPayload(tenant)");
    expect(source).not.toContain("webhookUrl: body.webhookUrl");
    expect(source).not.toContain("defaultPolicies: body.defaultPolicies");
  });
});
