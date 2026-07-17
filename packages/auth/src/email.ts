import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { hashSha256Hex } from "./crypto";
import type { EmailProvider } from "./email-provider";
import { ConsoleProvider } from "./email-provider";
import {
  renderOtpTemplate as defaultOtpTemplateRenderer,
  renderTemplate as defaultTemplateRenderer,
  type MagicLinkTemplateData,
  type OtpTemplateData,
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
  /** Override the OTP (sign-in code) template renderer. */
  otpTemplateRenderer?: (
    templateId: string | undefined,
    data: OtpTemplateData,
  ) => RenderedMagicLinkTemplate;
  /** Template ID to render for outgoing magic-link emails. */
  templateId?: string;
  /** Override the rendered subject line. */
  subjectOverride?: string;
  /** Optional reply-to address to pass through to the provider. */
  replyTo?: string;
  /** Server secret used for keyed email login code and polling verifiers. */
  codeVerifierSecret?: string;
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
const EMAIL_LOGIN_PURPOSE = "email-login";
const MAX_EMAIL_LOGIN_CODE_ATTEMPTS = 5;

function generateToken(): string {
  // URL-safe hex token (64 chars from 32 bytes)
  return randomBytes(TOKEN_BYTES).toString("hex");
}

function generateOpaqueId(): string {
  return randomBytes(32).toString("hex");
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

function keyedHash(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("hex");
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

type EmailLoginPendingChallenge = {
  status: "pending";
  challengeId: string;
  emailHash: string;
  tenantId?: string;
  purpose: typeof EMAIL_LOGIN_PURPOSE;
  codeVerifier: string;
  pollSecretHash: string;
  expiresAt: string;
};

type EmailLoginStatusRecord = {
  status: "pending" | "consumed" | "locked";
  challengeId: string;
  pollSecretHash: string;
  expiresAt: string;
};

export type EmailLoginVerifyResult =
  | { valid: true; email: string; tenantId?: string; challengeId: string }
  | { valid: false; email: ""; reason?: "invalid" | "locked" };

export type EmailLoginChallengeStatus =
  | { status: "pending"; expiresAt: string }
  | { status: "consumed" | "locked" | "expired" | "invalid" };

function otpStoreKey(email: string, tenantId: string | undefined, code: string): string {
  // Hash binds the code to {email, tenant} so a code minted for one address
  // or tenant can never verify for another.
  return hashSha256Hex(`email-otp:${tenantId ?? ""}:${email}:${code}`);
}

function emailLoginBinding(email: string, tenantId: string | undefined): string {
  return `${tenantId ?? ""}:${email}:${EMAIL_LOGIN_PURPOSE}`;
}

function emailLoginTargetKey(email: string, tenantId: string | undefined): string {
  return `email-login:active:${hashSha256Hex(emailLoginBinding(email, tenantId))}`;
}

function emailLoginPendingKey(challengeId: string): string {
  return `email-login:pending:${challengeId}`;
}

function emailLoginStatusKey(challengeId: string): string {
  return `email-login:status:${challengeId}`;
}

function emailLoginLinkAliasKey(tokenHash: string): string {
  return `email-login:link:${tokenHash}`;
}

function emailLoginCodeAliasKey(codeVerifier: string): string {
  return `email-login:code:${codeVerifier}`;
}

function emailLoginFailureKey(challengeId: string, slot: number): string {
  return `email-login:failure:${challengeId}:${slot}`;
}

function parsePendingChallenge(value: string | null): EmailLoginPendingChallenge | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<EmailLoginPendingChallenge>;
    if (
      parsed.status === "pending" &&
      typeof parsed.challengeId === "string" &&
      typeof parsed.emailHash === "string" &&
      parsed.purpose === EMAIL_LOGIN_PURPOSE &&
      typeof parsed.codeVerifier === "string" &&
      typeof parsed.pollSecretHash === "string" &&
      typeof parsed.expiresAt === "string"
    ) {
      return parsed as EmailLoginPendingChallenge;
    }
  } catch {
    return null;
  }
  return null;
}

function parseStatusRecord(value: string | null): EmailLoginStatusRecord | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<EmailLoginStatusRecord>;
    if (
      typeof parsed.challengeId === "string" &&
      typeof parsed.pollSecretHash === "string" &&
      typeof parsed.expiresAt === "string" &&
      (parsed.status === "pending" || parsed.status === "consumed" || parsed.status === "locked")
    ) {
      return parsed as EmailLoginStatusRecord;
    }
  } catch {
    return null;
  }
  return null;
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
  private codeVerifierSecret: string;
  private templateRenderer: (
    templateId: string | undefined,
    data: MagicLinkTemplateData,
  ) => RenderedMagicLinkTemplate;
  private otpTemplateRenderer: (
    templateId: string | undefined,
    data: OtpTemplateData,
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
    const configuredCodeSecret = config.codeVerifierSecret || process.env.STEWARD_EMAIL_CODE_SECRET;
    if (!configuredCodeSecret && process.env.NODE_ENV === "production") {
      throw new Error("STEWARD_EMAIL_CODE_SECRET is required in production");
    }
    this.codeVerifierSecret = configuredCodeSecret || "steward-development-email-login-secret";
    this.templateRenderer = config.templateRenderer ?? defaultTemplateRenderer;
    this.otpTemplateRenderer = config.otpTemplateRenderer ?? defaultOtpTemplateRenderer;
  }

  private emailHash(email: string, tenantId: string | undefined): string {
    return keyedHash(this.codeVerifierSecret, emailLoginBinding(email, tenantId));
  }

  private codeVerifier(email: string, tenantId: string | undefined, code: string): string {
    return keyedHash(this.codeVerifierSecret, `${emailLoginBinding(email, tenantId)}:${code}`);
  }

  private pollSecretHash(challengeId: string, pollSecret: string): string {
    return keyedHash(this.codeVerifierSecret, `${challengeId}:${pollSecret}:poll`);
  }

  private pollSecretMatches(challengeId: string, pollSecret: string, expected: string): boolean {
    const actual = Buffer.from(this.pollSecretHash(challengeId, pollSecret), "hex");
    const stored = Buffer.from(expected, "hex");
    return actual.length === stored.length && timingSafeEqual(actual, stored);
  }

  private async markEmailLoginConsumed(challengeId: string): Promise<void> {
    const current = parseStatusRecord(
      await this.tokenStore.verify(emailLoginStatusKey(challengeId)),
    );
    if (!current || current.status !== "pending") return;
    const ttlMs = Math.max(1, new Date(current.expiresAt).getTime() - Date.now());
    await this.tokenStore.store(
      emailLoginStatusKey(challengeId),
      JSON.stringify({ ...current, status: "consumed" } satisfies EmailLoginStatusRecord),
      ttlMs,
    );
  }

  /**
   * Generate a magic link token, persist its hash, and send the email.
   * Returns the token hash (for verification lookup) and the expiry date.
   */
  async sendMagicLink(
    email: string,
    context: { tenantId?: string } = {},
  ): Promise<{ tokenHash: string; expiresAt: Date; challengeId: string; pollSecret: string }> {
    email = email.toLowerCase().trim();
    const token = generateToken();
    const tokenHash = hashToken(token);
    const code = generateOtpCode();
    const challengeId = generateOpaqueId();
    const pollSecret = generateOpaqueId();
    const ttlMs = Math.min(this.tokenTtlMs, DEFAULT_TTL_MS);
    const expiresAt = new Date(Date.now() + ttlMs);
    const targetKey = emailLoginTargetKey(email, context.tenantId);
    const priorChallengeId = await this.tokenStore.verify(targetKey);
    if (priorChallengeId) {
      await this.tokenStore.consume(emailLoginPendingKey(priorChallengeId));
      const priorStatus = parseStatusRecord(
        await this.tokenStore.verify(emailLoginStatusKey(priorChallengeId)),
      );
      await this.tokenStore.store(
        emailLoginStatusKey(priorChallengeId),
        JSON.stringify({
          status: "consumed",
          challengeId: priorChallengeId,
          pollSecretHash: priorStatus?.pollSecretHash ?? "",
          expiresAt: new Date().toISOString(),
        }),
        1_000,
      );
    }

    const codeVerifier = this.codeVerifier(email, context.tenantId, code);
    const pending: EmailLoginPendingChallenge = {
      status: "pending",
      challengeId,
      emailHash: this.emailHash(email, context.tenantId),
      tenantId: context.tenantId,
      purpose: EMAIL_LOGIN_PURPOSE,
      codeVerifier,
      pollSecretHash: this.pollSecretHash(challengeId, pollSecret),
      expiresAt: expiresAt.toISOString(),
    };
    const status: EmailLoginStatusRecord = {
      status: "pending",
      challengeId,
      pollSecretHash: pending.pollSecretHash,
      expiresAt: pending.expiresAt,
    };

    await this.tokenStore.store(emailLoginPendingKey(challengeId), JSON.stringify(pending), ttlMs);
    await this.tokenStore.store(emailLoginStatusKey(challengeId), JSON.stringify(status), ttlMs);
    await this.tokenStore.store(emailLoginLinkAliasKey(tokenHash), challengeId, ttlMs);
    await this.tokenStore.store(emailLoginCodeAliasKey(codeVerifier), challengeId, ttlMs);
    await this.tokenStore.store(targetKey, challengeId, ttlMs);

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
      code,
      expiresInMinutes: Math.floor(ttlMs / (60 * 1000)),
      tenantName: undefined,
    });
    const subject = this.subjectOverride || rendered.subject;
    const body = rendered.text;
    const html = rendered.html;

    await this.provider.send(email, subject, body, html, { replyTo: this.replyTo });

    return { tokenHash, expiresAt, challengeId, pollSecret };
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

    await this.tokenStore.store(
      otpStoreKey(email, context.tenantId, code),
      encodeMagicLinkPayload({ email, tenantId: context.tenantId }),
      this.tokenTtlMs,
    );

    const minutes = Math.floor(this.tokenTtlMs / (60 * 1000));
    const brand = context.tenantName || "Steward";
    const rendered = this.otpTemplateRenderer(this.templateId, {
      email,
      code,
      brandName: brand,
      expiresInMinutes: minutes,
    });

    await this.provider.send(email, rendered.subject, rendered.text, rendered.html, {
      replyTo: this.replyTo,
    });

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
    email?: string,
    tenantId?: string,
  ): Promise<EmailLoginVerifyResult> {
    const tokenHash = hashToken(token);
    const challengeId = await this.tokenStore.consume(emailLoginLinkAliasKey(tokenHash));

    if (!challengeId) {
      const legacy = await this.tokenStore.consume(tokenHash);
      if (!legacy) return { email: "", valid: false };
      const payload = decodeMagicLinkPayload(legacy);
      return { email: payload.email, tenantId: payload.tenantId, valid: true, challengeId: "" };
    }
    const stored = await this.tokenStore.consume(emailLoginPendingKey(challengeId));
    const payload = parsePendingChallenge(stored);
    if (!payload) {
      return { email: "", valid: false };
    }

    const normalizedEmail = email?.toLowerCase().trim();
    const resolvedTenantId = tenantId ?? payload.tenantId;
    if (
      !normalizedEmail ||
      (payload.tenantId ?? undefined) !== (resolvedTenantId ?? undefined) ||
      payload.emailHash !== this.emailHash(normalizedEmail, resolvedTenantId)
    ) {
      return { email: "", valid: false };
    }
    await this.tokenStore.delete(emailLoginTargetKey(normalizedEmail, resolvedTenantId));
    await this.tokenStore.delete(emailLoginCodeAliasKey(payload.codeVerifier));
    await this.markEmailLoginConsumed(challengeId);
    return { email: normalizedEmail, tenantId: payload.tenantId, valid: true, challengeId };
  }

  async verifyEmailLoginCode(
    email: string,
    code: string,
    tenantId?: string,
  ): Promise<EmailLoginVerifyResult> {
    email = email.toLowerCase().trim();
    if (!/^\d{6}$/.test(code)) {
      const reason = await this.recordEmailLoginCodeFailure(email, tenantId);
      return { email: "", valid: false, reason: reason === "locked" ? "locked" : "invalid" };
    }
    const verifier = this.codeVerifier(email, tenantId, code);
    const challengeId = await this.tokenStore.consume(emailLoginCodeAliasKey(verifier));
    if (!challengeId) {
      const reason = await this.recordEmailLoginCodeFailure(email, tenantId);
      return { email: "", valid: false, reason: reason === "locked" ? "locked" : "invalid" };
    }
    const stored = await this.tokenStore.consume(emailLoginPendingKey(challengeId));
    const payload = parsePendingChallenge(stored);
    if (
      !payload ||
      (payload.tenantId ?? undefined) !== (tenantId ?? undefined) ||
      payload.emailHash !== this.emailHash(email, tenantId)
    ) {
      return { email: "", valid: false };
    }
    await this.tokenStore.delete(emailLoginTargetKey(email, tenantId));
    await this.markEmailLoginConsumed(challengeId);
    return { email, tenantId: payload.tenantId, valid: true, challengeId };
  }

  async recordEmailLoginCodeFailure(
    email: string,
    tenantId?: string,
  ): Promise<"failed" | "locked"> {
    const challengeId = await this.tokenStore.verify(emailLoginTargetKey(email, tenantId));
    if (!challengeId) return "failed";
    const pending = parsePendingChallenge(
      await this.tokenStore.verify(emailLoginPendingKey(challengeId)),
    );
    if (!pending) {
      const status = parseStatusRecord(
        await this.tokenStore.verify(emailLoginStatusKey(challengeId)),
      );
      return status?.status === "locked" ? "locked" : "failed";
    }
    const ttlMs = Math.max(1, new Date(pending.expiresAt).getTime() - Date.now());
    for (let i = 1; i <= MAX_EMAIL_LOGIN_CODE_ATTEMPTS; i++) {
      const reserved = await this.tokenStore.setIfNotExists(
        emailLoginFailureKey(challengeId, i),
        "1",
        ttlMs,
      );
      if (reserved) {
        if (i === MAX_EMAIL_LOGIN_CODE_ATTEMPTS) {
          await this.tokenStore.consume(emailLoginPendingKey(challengeId));
          await this.tokenStore.delete(emailLoginCodeAliasKey(pending.codeVerifier));
          await this.tokenStore.store(
            emailLoginStatusKey(challengeId),
            JSON.stringify({
              status: "locked",
              challengeId,
              pollSecretHash: pending.pollSecretHash,
              expiresAt: pending.expiresAt,
            } satisfies EmailLoginStatusRecord),
            ttlMs,
          );
          return "locked";
        }
        return "failed";
      }
    }
    return "locked";
  }

  async getEmailLoginStatus(
    challengeId: string,
    pollSecret: string,
  ): Promise<EmailLoginChallengeStatus> {
    const current = parseStatusRecord(
      await this.tokenStore.verify(emailLoginStatusKey(challengeId)),
    );
    if (!current) return { status: "expired" };
    if (!this.pollSecretMatches(challengeId, pollSecret, current.pollSecretHash)) {
      return { status: "invalid" };
    }
    return current.status === "pending"
      ? { status: "pending", expiresAt: current.expiresAt }
      : { status: current.status };
  }

  /**
   * Clean up background timers.  Call in tests after each suite.
   */
  destroy(): void {
    this.tokenStore.destroy();
  }
}
