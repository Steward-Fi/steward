import { randomBytes } from "node:crypto";

import { hashSha256Hex } from "./crypto";
import type { EmailProvider } from "./email-provider";
import { ConsoleProvider } from "./email-provider";
import {
  renderTemplate as defaultTemplateRenderer,
  type MagicLinkTemplateData,
  type RenderedMagicLinkTemplate,
} from "./email-templates";
import { TokenStore } from "./token-store";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface EmailAuthConfig {
  /** Sender address, e.g. "login@steward.fi" */
  from: string;
  /** Base URL for building the callback link, e.g. "https://steward.fi" */
  baseUrl: string;
  /**
   * Pluggable email provider.
   * Defaults to ConsoleProvider so nothing breaks without API credentials.
   */
  provider?: EmailProvider;
  /** Token TTL in milliseconds. Default: 10 minutes. */
  tokenTtlMs?: number;
  /** Path that receives the magic-link callback. Default: "/auth/callback/email" */
  callbackPath?: string;
  /**
   * Optional external TokenStore to use for magic-link tokens.
   * Defaults to a fresh TokenStore backed by in-memory storage.
   * Pass a store configured with a Redis or Postgres backend for
   * restart-safe / multi-instance deployments.
   */
  tokenStore?: TokenStore;
  /** Override the magic-link template renderer. */
  templateRenderer?: (
    templateId: string | undefined,
    data: MagicLinkTemplateData,
  ) => RenderedMagicLinkTemplate;
  /** Template ID to render for outgoing magic-link emails. */
  templateId?: string;
  /** Override the rendered subject line. */
  subjectOverride?: string;
  /** Optional reply-to address to pass through to the provider. */
  replyTo?: string;
}

export interface TenantInvitationEmailContext {
  tenantId: string;
  token: string;
  expiresAt: Date;
  acceptPath?: string;
  tenantName?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TOKEN_BYTES = 32;
const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 min
const DEFAULT_CALLBACK = "/auth/callback/email";
const OTP_DIGITS = 6;

function generateToken(): string {
  // URL-safe hex token (64 chars from 32 bytes)
  return randomBytes(TOKEN_BYTES).toString("hex");
}

function generateOtpCode(): string {
  // Crypto-random 6-digit code with rejection sampling to avoid modulo bias.
  const max = 10 ** OTP_DIGITS;
  // 2^32 / 10^6 -> keep draws below the largest multiple of max to stay uniform.
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  for (;;) {
    const bytes = randomBytes(4);
    const draw =
      ((bytes[0] << 24) >>> 0) + ((bytes[1] << 16) >>> 0) + ((bytes[2] << 8) >>> 0) + bytes[3];
    if (draw < limit) {
      return String(draw % max).padStart(OTP_DIGITS, "0");
    }
  }
}

function hashToken(token: string): string {
  return hashSha256Hex(token);
}

function buildMagicLink(
  baseUrl: string,
  callbackPath: string,
  token: string,
  email: string,
  tenantId?: string,
): string {
  const url = new URL(callbackPath, baseUrl);
  url.searchParams.set("token", token);
  url.searchParams.set("email", email);
  // Carry the tenant so GET /auth/callback/email resolves the SAME tenant the
  // token was minted for (mirrors buildInvitationLink). Without it the callback
  // falls back to the default tenant, the verify tenant guard fires
  // tenant_mismatch, and the issued exchange-code is stored with the wrong
  // tenant -> the SPA's /oauth/exchange then 401s code_tenant_mismatch.
  if (tenantId) url.searchParams.set("tenantId", tenantId);
  return url.toString();
}

function buildInvitationLink(
  baseUrl: string,
  acceptPath: string,
  token: string,
  tenantId: string,
  email: string,
): string {
  const url = new URL(acceptPath, baseUrl);
  url.searchParams.set("tenantId", tenantId);
  url.searchParams.set("token", token);
  url.searchParams.set("email", email);
  return url.toString();
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

type MagicLinkPayload = {
  email: string;
  tenantId?: string;
};

function otpStoreKey(email: string, tenantId: string | undefined, code: string): string {
  // Hash binds the code to {email, tenant} so a code minted for one address
  // or tenant can never verify for another.
  return hashSha256Hex(`email-otp:${tenantId ?? ""}:${email}:${code}`);
}

function encodeMagicLinkPayload(payload: MagicLinkPayload): string {
  return JSON.stringify(payload);
}

function decodeMagicLinkPayload(value: string): MagicLinkPayload {
  try {
    const parsed = JSON.parse(value) as MagicLinkPayload;
    if (typeof parsed.email === "string") return parsed;
  } catch {
    // Backward-compatible legacy tokens stored the email as the raw value.
  }
  return { email: value };
}

// ---------------------------------------------------------------------------
// EmailAuth
// ---------------------------------------------------------------------------

export class EmailAuth {
  private provider: EmailProvider;
  private tokenStore: TokenStore;
  private baseUrl: string;
  private callbackPath: string;
  private tokenTtlMs: number;
  private from: string;
  private replyTo?: string;
  private templateId?: string;
  private subjectOverride?: string;
  private templateRenderer: (
    templateId: string | undefined,
    data: MagicLinkTemplateData,
  ) => RenderedMagicLinkTemplate;

  constructor(config: EmailAuthConfig) {
    this.from = config.from;
    this.baseUrl = config.baseUrl.replace(/\/$/, ""); // strip trailing slash
    this.callbackPath = config.callbackPath ?? DEFAULT_CALLBACK;
    this.tokenTtlMs = config.tokenTtlMs ?? DEFAULT_TTL_MS;
    this.provider = config.provider ?? new ConsoleProvider();
    this.tokenStore = config.tokenStore ?? new TokenStore();
    this.replyTo = config.replyTo;
    this.templateId = config.templateId;
    this.subjectOverride = config.subjectOverride;
    this.templateRenderer = config.templateRenderer ?? defaultTemplateRenderer;
  }

  /**
   * Generate a magic link token, persist its hash, and send the email.
   * Returns the token hash (for verification lookup) and the expiry date.
   */
  async sendMagicLink(
    email: string,
    context: { tenantId?: string } = {},
  ): Promise<{ tokenHash: string; expiresAt: Date }> {
    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);

    this.tokenStore.store(
      tokenHash,
      encodeMagicLinkPayload({ email, tenantId: context.tenantId }),
      this.tokenTtlMs,
    );

    // Build and send the email
    const magicLink = buildMagicLink(
      this.baseUrl,
      this.callbackPath,
      token,
      email,
      context.tenantId,
    );
    const rendered = this.templateRenderer(this.templateId, {
      magicLink,
      email,
      expiresInMinutes: Math.floor(this.tokenTtlMs / (60 * 1000)),
      tenantName: undefined,
    });
    const subject = this.subjectOverride || rendered.subject;
    const body = rendered.text;
    const html = rendered.html;

    await this.provider.send(email, subject, body, html, { replyTo: this.replyTo });

    return { tokenHash, expiresAt };
  }

  /**
   * Generate a 6-digit one-time code, persist its hash, and email it.
   * Privy-style email verification: the code proves address ownership and
   * is exchanged for a short-lived verified-email grant by the API layer.
   */
  async sendOtp(
    email: string,
    context: { tenantId?: string; tenantName?: string } = {},
  ): Promise<{ expiresAt: Date }> {
    const code = generateOtpCode();
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);

    this.tokenStore.store(
      otpStoreKey(email, context.tenantId, code),
      encodeMagicLinkPayload({ email, tenantId: context.tenantId }),
      this.tokenTtlMs,
    );

    const minutes = Math.floor(this.tokenTtlMs / (60 * 1000));
    const brand = context.tenantName || "Steward";
    const subject = `${code} is your ${brand} sign-in code`;
    const text = [
      `Your ${brand} sign-in code is: ${code}`,
      "",
      `It expires in ${minutes} minutes. If you didn't request this, ignore this email.`,
    ].join("\n");
    const escapedBrand = escapeHtml(brand);
    const escapedCode = escapeHtml(code);
    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#0b0a09;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0b0a09;min-height:100vh;">
    <tr><td align="center" style="padding:60px 24px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:420px;">
        <tr><td style="background-color:#141210;border:1px solid #2a2722;padding:40px 32px;">
          <div style="font-size:18px;font-weight:700;color:#e8e5e0;padding-bottom:8px;">${escapedBrand} sign-in code</div>
          <div style="font-size:13px;color:#9c9788;line-height:1.5;padding-bottom:24px;">Enter this code to verify your email. It expires in ${minutes} minutes.</div>
          <div style="text-align:center;padding-bottom:24px;">
            <span style="display:inline-block;background-color:#0b0a09;border:1px solid #2a2722;color:#e8e5e0;font-size:32px;font-weight:700;letter-spacing:0.35em;padding:16px 24px 16px 32px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;">${escapedCode}</span>
          </div>
          <div style="border-top:1px solid #2a2722;padding-top:20px;font-size:11px;color:#9c9788;line-height:1.5;">If you didn't request this code, you can safely ignore this email.</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

    await this.provider.send(email, subject, text, html, { replyTo: this.replyTo });

    return { expiresAt };
  }

  /**
   * Verify a 6-digit code for {email, tenantId}. One-time use: the code is
   * consumed on success. Returns false for unknown/expired/mismatched codes.
   */
  async verifyOtp(email: string, code: string, tenantId?: string): Promise<boolean> {
    if (!/^\d{6}$/.test(code)) return false;
    const stored = await this.tokenStore.consume(otpStoreKey(email, tenantId, code));
    if (!stored) return false;
    const payload = decodeMagicLinkPayload(stored);
    return payload.email === email && (payload.tenantId ?? undefined) === (tenantId ?? undefined);
  }

  async sendTenantInvitation(email: string, context: TenantInvitationEmailContext): Promise<void> {
    const acceptLink = buildInvitationLink(
      this.baseUrl,
      context.acceptPath ?? "/accept-invitation",
      context.token,
      context.tenantId,
      email,
    );
    const expiresAt = context.expiresAt.toISOString();
    const tenantLabel = context.tenantName || context.tenantId;
    const subject = `You're invited to ${tenantLabel} on Steward`;
    const text = [
      `You've been invited to join ${tenantLabel} on Steward.`,
      "",
      "Open this link to accept the invitation:",
      "",
      acceptLink,
      "",
      `This invitation expires at ${expiresAt}.`,
      "If you were not expecting this invitation, you can ignore this email.",
      "",
      "— Steward",
    ].join("\n");
    const escapedTenant = escapeHtml(tenantLabel);
    const escapedLink = escapeHtml(acceptLink);
    const escapedExpiresAt = escapeHtml(expiresAt);
    const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#0b0a09;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0b0a09;min-height:100vh;">
    <tr><td align="center" style="padding:60px 24px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:420px;">
        <tr><td style="background-color:#141210;border:1px solid #2a2722;padding:40px 32px;">
          <div style="font-size:22px;font-weight:700;color:#e8e5e0;padding-bottom:8px;">Join ${escapedTenant}</div>
          <div style="font-size:14px;color:#9c9788;line-height:1.5;padding-bottom:32px;">You've been invited to Steward. This invitation expires at ${escapedExpiresAt}.</div>
          <div style="text-align:center;padding-bottom:32px;">
            <a href="${escapedLink}" target="_blank" style="display:inline-block;background-color:#c4873a;color:#0b0a09;font-size:14px;font-weight:600;text-decoration:none;padding:12px 32px;">Accept invitation</a>
          </div>
          <div style="border-top:1px solid #2a2722;padding-top:24px;font-size:11px;color:#9c9788;word-break:break-all;line-height:1.5;">${escapedLink}</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

    await this.provider.send(email, subject, text, html, { replyTo: this.replyTo });
  }

  /**
   * Verify a raw token received from the callback URL.
   * One-time use: deletes the token after successful verification.
   */
  async verifyMagicLink(
    token: string,
  ): Promise<{ email: string; tenantId?: string; valid: boolean }> {
    const tokenHash = hashToken(token);
    const stored = await this.tokenStore.consume(tokenHash);

    if (!stored) {
      return { email: "", valid: false };
    }

    const payload = decodeMagicLinkPayload(stored);
    return { email: payload.email, tenantId: payload.tenantId, valid: true };
  }

  /**
   * Clean up background timers.  Call in tests after each suite.
   */
  destroy(): void {
    this.tokenStore.destroy();
  }
}
