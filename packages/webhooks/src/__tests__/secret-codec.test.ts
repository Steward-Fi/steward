import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { decryptWebhookSecret, encryptWebhookSecret } from "../secret-codec";

/**
 * SEC-102: the hardcoded dev key must require BOTH an explicit opt-in flag AND
 * an explicit development NODE_ENV — an unset NODE_ENV must never fall through
 * to a publicly-known key.
 */
describe("webhook secret-codec dev-key gate (SEC-102)", () => {
  const ENV_KEYS = [
    "NODE_ENV",
    "STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_ALLOW_DEV_SECRETS",
    "STEWARD_ALLOW_DEV_SECRET",
  ] as const;
  let snapshot: Record<string, string | undefined>;

  beforeEach(() => {
    snapshot = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
    for (const key of ENV_KEYS) delete process.env[key];
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (snapshot[key] === undefined) delete process.env[key];
      else process.env[key] = snapshot[key];
    }
  });

  it("refuses the dev key when NODE_ENV is unset, even with the opt-in flag", () => {
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    expect(() => encryptWebhookSecret("tenant-secret")).toThrow(
      /NODE_ENV is not an explicit development value/,
    );
  });

  it("refuses the dev key for a non-development NODE_ENV, even with the opt-in flag", () => {
    process.env.NODE_ENV = "staging";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    expect(() => encryptWebhookSecret("tenant-secret")).toThrow(
      /NODE_ENV is not an explicit development value/,
    );
  });

  it("still refuses in production with the dedicated message", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    expect(() => encryptWebhookSecret("tenant-secret")).toThrow(
      /STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY or STEWARD_MASTER_PASSWORD is required/,
    );
  });

  it("still requires the opt-in flag in an explicit development environment", () => {
    process.env.NODE_ENV = "development";
    expect(() => encryptWebhookSecret("tenant-secret")).toThrow(/STEWARD_ALLOW_DEV_SECRETS=true/);
  });

  it("round-trips with the dev key only when explicitly opted into a development environment", () => {
    process.env.NODE_ENV = "development";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const encrypted = encryptWebhookSecret("tenant-secret");
    expect(decryptWebhookSecret(encrypted)).toBe("tenant-secret");
  });

  it("round-trips with the dev key under NODE_ENV=test (bun test default)", () => {
    process.env.NODE_ENV = "test";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const encrypted = encryptWebhookSecret("tenant-secret");
    expect(decryptWebhookSecret(encrypted)).toBe("tenant-secret");
  });

  it("prefers a configured master password regardless of NODE_ENV", () => {
    process.env.STEWARD_MASTER_PASSWORD = "a-real-master-password-for-tests";
    const encrypted = encryptWebhookSecret("tenant-secret");
    expect(decryptWebhookSecret(encrypted)).toBe("tenant-secret");
  });
});
