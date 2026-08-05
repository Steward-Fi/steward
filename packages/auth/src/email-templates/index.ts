import {
  type MagicLinkTemplateData,
  type OtpTemplateData,
  type RenderedMagicLinkTemplate,
  renderDefaultOtpTemplate,
  renderDefaultTemplate,
} from "./default";
import { renderElizaCloudOtpTemplate, renderElizaCloudTemplate } from "./elizacloud";

export type {
  MagicLinkTemplateData,
  OtpTemplateData,
  RenderedMagicLinkTemplate,
} from "./default";

export function renderTemplate(
  templateId: string | undefined,
  data: MagicLinkTemplateData,
): RenderedMagicLinkTemplate {
  if (templateId === "elizacloud") {
    return renderElizaCloudTemplate(data);
  }

  return renderDefaultTemplate(data);
}

/**
 * Per-tenant OTP (sign-in code) template resolution. Mirrors
 * `renderTemplate`: unknown/absent templateIds fall back to the
 * Steward-branded default so existing tenants are unaffected.
 */
export function renderOtpTemplate(
  templateId: string | undefined,
  data: OtpTemplateData,
): RenderedMagicLinkTemplate {
  if (templateId === "elizacloud") {
    return renderElizaCloudOtpTemplate(data);
  }

  return renderDefaultOtpTemplate(data);
}
