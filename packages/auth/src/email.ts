import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { redactedThrownDiagnostics } from "@stwd/shared";

import { hashSha256Hex } from "./crypto";
import type { EmailDeliveryReceipt, EmailProvider } from "./email-provider";
import {
  ConsoleProvider,
  EmailDeliveryError,
  EmailDeliveryNotConfiguredError,
} from "./email-provider";
import {
  renderOtpTemplate as defaultOtpTemplateRenderer,
  renderTemplate as defaultTemplateRenderer,
  type MagicLinkTemplateData,
  type OtpTemplateData,
  type RenderedMagicLinkTemplate,
} from "./email-templates";
import { isDevSecretAllowed } from "./jwt";
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
  private deliveryNotConfigured: boolean;
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
    // Fail closed (elizaOS/eliza#18452): in production the ConsoleProvider —
    // whether the silent default when no provider is configured, or passed
    // explicitly — must never back login sends. Sends throw a typed
    // EmailDeliveryNotConfiguredError BEFORE any challenge state is stored,
    // so the API maps it to 503 instead of returning a false ok:true for a
    // challenge nobody can ever receive. Verification of previously issued
    // challenges is unaffected.
    this.deliveryNotConfigured =
      process.env.NODE_ENV === "production" && this.provider instanceof ConsoleProvider;
    this.tokenStore = config.tokenStore ?? new TokenStore();
    this.replyTo = config.replyTo;
    this.templateId = config.templateId;
    this.subjectOverride = config.subjectOverride;
    const configuredCodeSecret =
      config.codeVerifierSecret?.trim() || process.env.STEWARD_EMAIL_CODE_SECRET?.trim() || "";
    if (!configuredCodeSecret) {
      // Tests intentionally use an isolated deterministic fallback. Every
      // runnable non-test environment must explicitly opt in to that fallback,
      // matching the repository-wide dev-secret policy.
      if (process.env.NODE_ENV !== "test" && !isDevSecretAllowed()) {
        throw new Error(
          "STEWARD_EMAIL_CODE_SECRET is required. For local development only, set STEWARD_ALLOW_DEV_SECRETS=true to use the insecure dev secret.",
        );
      }
    } else if (process.env.NODE_ENV === "production" && configuredCodeSecret.length < 32) {
      throw new Error("STEWARD_EMAIL_CODE_SECRET must be at least 32 characters in production");
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

  private assertDeliveryConfigured(): void {
    if (this.deliveryNotConfigured) {
      throw new EmailDeliveryNotConfiguredError();
    }
  }

  /**
   * Dispatch through the provider and require an acceptance receipt.
   * Fail closed: on provider throw/rejection OR a missing receipt, run
   * `invalidate` (best-effort) so any just-minted challenge state is no
   * longer redeemable, then surface a typed EmailDeliveryError. Only the
   * error NAME is logged — never the recipient, subject, token, code, or
   * raw provider error text.
   */
  private async sendOrInvalidate(
    message: { to: string; subject: string; text: string; html?: string },
    invalidate: () => Promise<void>,
  ): Promise<EmailDeliveryReceipt> {
    let receipt: EmailDeliveryReceipt | undefined;
    try {
      receipt = await this.provider.send(message.to, message.subject, message.text, message.html, {
        replyTo: this.replyTo,
      });
    } catch (err) {
      console.error("[steward:auth] email provider rejected send", redactedThrownDiagnostics(err));
      await invalidate().catch(() => {});
      throw new EmailDeliveryError();
    }
    if (!receipt || typeof receipt.provider !== "string" || receipt.provider.length === 0) {
      console.error("[steward:auth] email provider returned no acceptance receipt");
      await invalidate().catch(() => {});
      throw new EmailDeliveryError("Email provider returned no acceptance receipt");
    }
    return receipt;
  }

  /**
   * Remove every record of a pending email-login challenge so neither the
   * magic link nor the companion code can ever redeem it. Aliases go first
   * (they are the redemption entry points); all deletes are idempotent.
   */
  private async invalidateEmailLoginChallenge(params: {
    challengeId: string;
    tokenHash: string;
    codeVerifier: string;
    email: string;
    tenantId?: string;
  }): Promise<void> {
    await this.tokenStore.delete(emailLoginLinkAliasKey(params.tokenHash));
    await this.tokenStore.delete(emailLoginCodeAliasKey(params.codeVerifier));
    await this.tokenStore.delete(emailLoginPendingKey(params.challengeId));
    await this.tokenStore.delete(emailLoginStatusKey(params.challengeId));
    await this.tokenStore.delete(emailLoginTargetKey(params.email, params.tenantId));
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
    this.assertDeliveryConfigured();
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

    // Fail closed: success only after the provider ACCEPTED the message. On
    // rejection or a missing receipt the just-minted challenge is invalidated
    // so a false ok:true can never leave a live, undeliverable challenge.
    await this.sendOrInvalidate({ to: email, subject, text: body, html }, () =>
      this.invalidateEmailLoginChallenge({
        challengeId,
        tokenHash,
        codeVerifier,
        email,
        tenantId: context.tenantId,
      }),
    );

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
    this.assertDeliveryConfigured();
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

    // Fail closed: delete the just-stored code if the provider did not accept
    // the message, so an unsendable code is never left redeemable.
    await this.sendOrInvalidate(
      { to: email, subject: rendered.subject, text: rendered.text, html: rendered.html },
      () => this.tokenStore.delete(otpStoreKey(email, context.tenantId, code)),
    );

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
    this.assertDeliveryConfigured();
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

    // The invitation token's persistence is owned by the caller (it is stored
    // hashed in tenant_invitations before this call); surface a typed error so
    // callers report emailSent=false instead of a false green. Nothing here is
    // invalidated because EmailAuth does not own that record.
    await this.sendOrInvalidate({ to: email, subject, text, html }, async () => {});
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

  /**
   * Record a failed code attempt against the pending challenge; locks the
   * challenge after MAX_EMAIL_LOGIN_CODE_ATTEMPTS failures.
   *
   * Accepted trade-off (SEC-136): the attempt counter is keyed by email, so
   * anyone who knows a victim's address can burn the attempts and force the
   * victim to re-request a code. That is inherent to any attempt limiter —
   * the alternative (no limiter) leaves the 6-digit code brute-forceable.
   * Impact is availability-only (re-request); no code is ever confirmed or
   * consumed by failed attempts.
   */
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
