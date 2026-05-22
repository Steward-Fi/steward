/**
 * PhoneAuth — SMS OTP login.
 *
 * 6-digit numeric code, persisted as hash-of-(phone||code) so a leaked code
 * cannot be replayed against a different phone number. One-time consume,
 * 5-minute TTL by default.
 *
 * Caller responsibilities at the API layer:
 *  - Rate-limit /sendOtp per phone number and per IP.
 *  - Track failed verifyOtp attempts and lock out after N (e.g. 5).
 */

import { randomInt } from "node:crypto";

import { hashSha256Hex } from "./crypto";
import { ConsoleSmsProvider, type SmsProvider } from "./sms-provider";
import { TokenStore } from "./token-store";

export interface PhoneAuthConfig {
  provider?: SmsProvider;
  /** OTP TTL in milliseconds. Default: 5 minutes. */
  tokenTtlMs?: number;
  tokenStore?: TokenStore;
  bodyTemplate?: string;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_BODY = "Your code is {code}. Expires in 5 minutes. Do not share it.";
const E164 = /^\+[1-9]\d{6,14}$/;

function generateCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, "0");
}

function codeStorageKey(phone: string, code: string): string {
  return hashSha256Hex(`${phone}:${code}`);
}

export function isValidE164(phone: unknown): phone is string {
  return typeof phone === "string" && E164.test(phone);
}

export class PhoneAuth {
  private provider: SmsProvider;
  private tokenStore: TokenStore;
  private tokenTtlMs: number;
  private bodyTemplate: string;

  constructor(config: PhoneAuthConfig = {}) {
    this.provider = config.provider ?? new ConsoleSmsProvider();
    this.tokenStore = config.tokenStore ?? new TokenStore();
    this.tokenTtlMs = config.tokenTtlMs ?? DEFAULT_TTL_MS;
    this.bodyTemplate = config.bodyTemplate ?? DEFAULT_BODY;
  }

  async sendOtp(phone: string): Promise<{ expiresAt: Date }> {
    if (!isValidE164(phone)) {
      throw new Error("phone must be E.164 (e.g. +14155551234)");
    }
    const code = generateCode();
    const key = codeStorageKey(phone, code);
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);
    this.tokenStore.store(key, phone, this.tokenTtlMs);
    await this.provider.send(phone, this.bodyTemplate.replace("{code}", code));
    return { expiresAt };
  }

  async verifyOtp(phone: string, code: string): Promise<{ valid: boolean; phone?: string }> {
    if (!isValidE164(phone) || !/^\d{6}$/.test(code)) {
      return { valid: false };
    }
    const key = codeStorageKey(phone, code);
    const stored = await this.tokenStore.verify(key);
    if (!stored || stored !== phone) {
      return { valid: false };
    }
    this.tokenStore.delete(key);
    return { valid: true, phone };
  }

  destroy(): void {
    this.tokenStore.destroy();
  }
}
