import { describe, expect, it } from "bun:test";

import { renderDefaultOtpTemplate, renderDefaultTemplate } from "../email-templates/default";
import {
  renderElizaCloudOtpTemplate,
  renderElizaCloudTemplate,
} from "../email-templates/elizacloud";
import { renderOtpTemplate, renderTemplate } from "../email-templates/index";

const MAGIC_LINK_DATA = {
  email: "user@example.com",
  magicLink: "https://steward.fi/auth/callback/email?token=test",
  expiresInMinutes: 10,
};

const ELIZA_MAGIC_LINK_DATA = {
  ...MAGIC_LINK_DATA,
  magicLink: "https://api.elizacloud.ai/auth/callback/email?token=test",
};

const OTP_DATA = {
  email: "user@example.com",
  code: "123456",
  brandName: "Steward",
  expiresInMinutes: 10,
};

describe("renderTemplate", () => {
  it("falls back to the default template for unknown template ids", () => {
    expect(renderTemplate("unknown-template", MAGIC_LINK_DATA)).toEqual(
      renderDefaultTemplate(MAGIC_LINK_DATA),
    );
  });

  it("resolves the elizacloud template", () => {
    expect(renderTemplate("elizacloud", MAGIC_LINK_DATA)).toEqual(
      renderElizaCloudTemplate(MAGIC_LINK_DATA),
    );
  });
});

describe("renderOtpTemplate", () => {
  it("falls back to the default OTP template for unknown/absent template ids", () => {
    expect(renderOtpTemplate(undefined, OTP_DATA)).toEqual(renderDefaultOtpTemplate(OTP_DATA));
    expect(renderOtpTemplate("unknown-template", OTP_DATA)).toEqual(
      renderDefaultOtpTemplate(OTP_DATA),
    );
  });

  it("resolves the elizacloud OTP template", () => {
    expect(renderOtpTemplate("elizacloud", OTP_DATA)).toEqual(
      renderElizaCloudOtpTemplate(OTP_DATA),
    );
  });
});

describe("default OTP template", () => {
  it("keeps the pre-extraction Steward subject/copy and escapes the brand", () => {
    const rendered = renderDefaultOtpTemplate({
      ...OTP_DATA,
      brandName: '<b>"Evil"</b>',
    });
    expect(rendered.subject).toBe('123456 is your <b>"Evil"</b> sign-in code');
    expect(rendered.html).toContain("&lt;b&gt;&quot;Evil&quot;&lt;/b&gt; sign-in code");
    expect(rendered.html).not.toContain('<b>"Evil"</b>');
    expect(rendered.html).toContain("123456");
    expect(rendered.text).toContain("It expires in 10 minutes.");
  });
});

describe("elizacloud templates", () => {
  it("magic-link email is Eliza-branded, dark, and email-client safe", () => {
    const rendered = renderElizaCloudTemplate(ELIZA_MAGIC_LINK_DATA);
    expect(rendered.subject).toBe("Sign in to Eliza Cloud");
    // Brand fidelity: black field, product card + CTA colors, hosted mark.
    expect(rendered.html).toContain("#000000");
    expect(rendered.html).toContain("#141414");
    expect(rendered.html).toContain("#ff6b00");
    expect(rendered.html).toContain("app.elizacloud.ai/brand/favicons");
    // No Steward branding leaks into the tenant email.
    expect(rendered.html.toLowerCase()).not.toContain("steward");
    expect(rendered.text.toLowerCase()).not.toContain("steward");
    // Email-client safety: no third-party stylesheets or script.
    expect(rendered.html).not.toContain("<link");
    expect(rendered.html).not.toContain("<script");
    expect(rendered.html).toContain('name="color-scheme" content="dark"');
    expect(rendered.html).toContain(ELIZA_MAGIC_LINK_DATA.magicLink);
    expect(rendered.text).toContain(ELIZA_MAGIC_LINK_DATA.magicLink);
  });

  it("OTP email is Eliza-branded and escapes the code", () => {
    const rendered = renderElizaCloudOtpTemplate({
      ...OTP_DATA,
      code: "654321",
    });
    expect(rendered.subject).toBe("654321 is your Eliza Cloud sign-in code");
    expect(rendered.html).toContain("654321");
    expect(rendered.html).toContain("app.elizacloud.ai/brand/favicons");
    expect(rendered.html.toLowerCase()).not.toContain("steward");
    expect(rendered.text.toLowerCase()).not.toContain("steward");
    expect(rendered.html).not.toContain("<script");
  });
});
