import { createHash, randomBytes } from "node:crypto";

import type { EmailProvider } from "./email-provider";
import { ConsoleProvider } from "./email-provider";
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TOKEN_BYTES = 32;
const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 min
const DEFAULT_CALLBACK = "/auth/callback/email";

function generateToken(): string {
  // URL-safe hex token (64 chars from 32 bytes)
  return randomBytes(TOKEN_BYTES).toString("hex");
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function buildMagicLink(baseUrl: string, callbackPath: string, token: string, email: string): string {
  const url = new URL(callbackPath, baseUrl);
  url.searchParams.set("token", token);
  url.searchParams.set("email", email);
  return url.toString();
}

function buildEmailBody(link: string): string {
  return [
    "Click the link below to sign in:",
    "",
    link,
    "",
    "This link expires in 10 minutes.",
    "If you didn't request this, you can safely ignore this email.",
    "",
    "— Steward",
  ].join("\n");
}

function buildEmailHtml(link: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#0b0a09;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0b0a09;min-height:100vh;">
    <tr><td align="center" style="padding:60px 24px;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:420px;">

        <!-- Logo -->
        <tr><td align="center" style="padding-bottom:40px;">
          <table cellpadding="0" cellspacing="0"><tr>
            <td style="font-size:20px;font-weight:700;color:#e8e5e0;letter-spacing:-0.02em;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
              ✦&nbsp;&nbsp;steward
            </td>
          </tr></table>
        </td></tr>

        <!-- Card -->
        <tr><td style="background-color:#141210;border:1px solid #2a2722;padding:40px 32px;">

          <!-- Heading -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="font-size:22px;font-weight:700;color:#e8e5e0;letter-spacing:-0.02em;padding-bottom:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
              Sign in to Steward
            </td></tr>
            <tr><td style="font-size:14px;color:#6b6560;line-height:1.5;padding-bottom:32px;">
              Click the button below to securely sign in. This link expires in 10 minutes.
            </td></tr>
          </table>

          <!-- Button -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td align="center" style="padding-bottom:32px;">
              <a href="${link}" target="_blank" style="display:inline-block;background-color:#c4873a;color:#0b0a09;font-size:14px;font-weight:600;text-decoration:none;padding:12px 32px;letter-spacing:0.01em;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
                Sign in
              </a>
            </td></tr>
          </table>

          <!-- Divider -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="border-top:1px solid #2a2722;padding-top:24px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr><td style="font-size:11px;color:#6b6560;line-height:1.6;">
                  Or copy this link into your browser:
                </td></tr>
                <tr><td style="font-size:11px;color:#9c9788;word-break:break-all;line-height:1.5;padding-top:6px;">
                  ${link}
                </td></tr>
              </table>
            </td></tr>
          </table>

        </td></tr>

        <!-- Footer -->
        <tr><td style="padding-top:24px;text-align:center;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="font-size:11px;color:#6b6560;line-height:1.6;">
              If you didn't request this email, you can safely ignore it.
            </td></tr>
            <tr><td style="font-size:11px;color:#4a4540;padding-top:12px;">
              steward.fi — agent wallet infrastructure
            </td></tr>
          </table>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
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

  constructor(config: EmailAuthConfig) {
    this.from = config.from;
    this.baseUrl = config.baseUrl.replace(/\/$/, ""); // strip trailing slash
    this.callbackPath = config.callbackPath ?? DEFAULT_CALLBACK;
    this.tokenTtlMs = config.tokenTtlMs ?? DEFAULT_TTL_MS;
    this.provider = config.provider ?? new ConsoleProvider();
    this.tokenStore = config.tokenStore ?? new TokenStore();
  }

  /**
   * Generate a magic link token, persist its hash, and send the email.
   * Returns the token hash (for verification lookup) and the expiry date.
   */
  async sendMagicLink(email: string): Promise<{ tokenHash: string; expiresAt: Date }> {
    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);

    // Persist hash → email with TTL
    this.tokenStore.store(tokenHash, email, this.tokenTtlMs);

    // Build and send the email
    const link = buildMagicLink(this.baseUrl, this.callbackPath, token, email);
    const subject = "Sign in to Steward";
    const body = buildEmailBody(link);
    const html = buildEmailHtml(link);

    await this.provider.send(email, subject, body, html);

    return { tokenHash, expiresAt };
  }

  /**
   * Verify a raw token received from the callback URL.
   * One-time use: deletes the token after successful verification.
   */
  async verifyMagicLink(token: string): Promise<{ email: string; valid: boolean }> {
    const tokenHash = hashToken(token);
    const email = await this.tokenStore.verify(tokenHash);

    if (!email) {
      return { email: "", valid: false };
    }

    // Consume the token (one-time use)
    this.tokenStore.delete(tokenHash);

    return { email, valid: true };
  }

  /**
   * Clean up background timers.  Call in tests after each suite.
   */
  destroy(): void {
    this.tokenStore.destroy();
  }
}
