import { describe, expect, it, mock } from "bun:test";

import { EmailAuth } from "../email";
import type { EmailProvider } from "../email-provider";

describe("EmailAuth.sendMagicLink", () => {
  it("calls the template renderer with the agreed magic-link payload", async () => {
    const sent = mock(async () => undefined);
    const templateRenderer = mock(() => ({
      subject: "subject",
      text: "text",
      html: "<p>html</p>",
    }));
    const provider: EmailProvider = { send: sent };
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider,
      templateId: "customer-template",
      tokenTtlMs: 10 * 60 * 1000,
      templateRenderer,
    });

    await auth.sendMagicLink("user@example.com");

    expect(templateRenderer).toHaveBeenCalledTimes(1);
    const [templateId, data] = templateRenderer.mock.calls[0]!;
    expect(templateId).toBe("customer-template");
    expect(data).toMatchObject({
      email: "user@example.com",
      expiresInMinutes: 10,
      tenantName: undefined,
    });
    expect(data.magicLink).toContain("https://steward.fi/auth/callback/email?");
    expect(data.magicLink).toContain("email=user%40example.com");

    expect(sent).toHaveBeenCalledTimes(1);

    auth.destroy();
  });

  it("binds the tenant into the magic link for non-default tenants (and omits it otherwise)", async () => {
    const sent = mock(async () => undefined);
    const templateRenderer = mock(() => ({
      subject: "subject",
      text: "text",
      html: "<p>html</p>",
    }));
    const provider: EmailProvider = { send: sent };
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider,
      templateId: "customer-template",
      tokenTtlMs: 10 * 60 * 1000,
      templateRenderer,
    });

    // Non-default tenant: the emailed link must carry ?tenantId so
    // GET /auth/callback/email resolves the SAME tenant the token was minted
    // for (otherwise the verify guard fires tenant_mismatch and the exchange
    // code is stored under the wrong tenant).
    await auth.sendMagicLink("user@example.com", { tenantId: "customer" });
    const [, withTenant] = templateRenderer.mock.calls[0]!;
    expect(withTenant.magicLink).toContain("tenantId=customer");

    // No tenant context: byte-for-byte back-compat — no tenantId param at all.
    await auth.sendMagicLink("user@example.com");
    const [, withoutTenant] = templateRenderer.mock.calls[1]!;
    expect(withoutTenant.magicLink).not.toContain("tenantId");

    auth.destroy();
  });

  it("sends tenant invitation emails with a one-time accept link", async () => {
    const sent = mock(async () => undefined);
    const provider: EmailProvider = { send: sent };
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider,
    });

    await auth.sendTenantInvitation("user@example.com", {
      tenantId: "tenant-1",
      tenantName: "Tenant One",
      token: "a".repeat(64),
      expiresAt: new Date("2026-06-01T12:00:00.000Z"),
    });

    expect(sent).toHaveBeenCalledTimes(1);
    const [to, subject, text, html] = sent.mock.calls[0]!;
    expect(to).toBe("user@example.com");
    expect(subject).toBe("You're invited to Tenant One on Steward");
    expect(text).toContain("https://steward.fi/accept-invitation?");
    expect(text).toContain("tenantId=tenant-1");
    expect(text).toContain(`token=${"a".repeat(64)}`);
    expect(html).toContain("Accept invitation");

    auth.destroy();
  });
});

describe("EmailAuth.sendOtp", () => {
  it("routes OTP emails through the per-tenant otp template renderer", async () => {
    const sent = mock(async () => undefined);
    const otpTemplateRenderer = mock(() => ({
      subject: "otp subject",
      text: "otp text",
      html: "<p>otp html</p>",
    }));
    const provider: EmailProvider = { send: sent };
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider,
      templateId: "customer-template",
      tokenTtlMs: 10 * 60 * 1000,
      otpTemplateRenderer,
    });

    await auth.sendOtp("user@example.com", {
      tenantId: "customer",
      tenantName: "Customer App",
    });

    expect(otpTemplateRenderer).toHaveBeenCalledTimes(1);
    const [templateId, data] = otpTemplateRenderer.mock.calls[0]!;
    expect(templateId).toBe("customer-template");
    expect(data).toMatchObject({
      email: "user@example.com",
      brandName: "Customer App",
      expiresInMinutes: 10,
    });
    expect(data.code).toMatch(/^\d{6}$/);

    expect(sent).toHaveBeenCalledTimes(1);
    const [to, subject, text, html] = sent.mock.calls[0]!;
    expect(to).toBe("user@example.com");
    expect(subject).toBe("otp subject");
    expect(text).toBe("otp text");
    expect(html).toBe("<p>otp html</p>");

    auth.destroy();
  });

  it("renders the Steward default OTP email when no template is configured", async () => {
    const sent = mock(async () => undefined);
    const provider: EmailProvider = { send: sent };
    const auth = new EmailAuth({
      from: "login@steward.fi",
      baseUrl: "https://steward.fi",
      provider,
      tokenTtlMs: 10 * 60 * 1000,
    });

    await auth.sendOtp("user@example.com", { tenantName: "Acme" });

    const [, subject, text, html] = sent.mock.calls[0]!;
    expect(subject).toMatch(/^\d{6} is your Acme sign-in code$/);
    expect(text).toContain("Your Acme sign-in code is:");
    expect(html).toContain("Acme sign-in code");
    expect(html).toContain("#0b0a09");

    auth.destroy();
  });
});
