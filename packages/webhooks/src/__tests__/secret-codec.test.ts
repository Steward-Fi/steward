import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import {
  decryptWebhookSecret,
  encryptWebhookSecret,
  resolveWebhookSecretAuthority,
} from "../secret-codec";

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
    "STEWARD_KDF_SALT",
    "STEWARD_WEBHOOK_SECRET_KDF_SALT",
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

  it("does not mistake an invalid configured salt for the internal dev default", () => {
    process.env.STEWARD_MASTER_PASSWORD = "a-real-master-password-for-tests";
    process.env.STEWARD_WEBHOOK_SECRET_KDF_SALT = "steward-webhook-secret-v1";
    expect(() => encryptWebhookSecret("tenant-secret")).toThrow(/even-length hexadecimal string/);
  });

  it("rejects a configured salt with a valid hex prefix and invalid suffix", () => {
    process.env.STEWARD_MASTER_PASSWORD = "a-real-master-password-for-tests";
    process.env.STEWARD_WEBHOOK_SECRET_KDF_SALT = `${"ab".repeat(16)}zz`;
    expect(() => encryptWebhookSecret("tenant-secret")).toThrow(/even-length hexadecimal string/);
  });

  it("never accepts a whitespace-only Worker webhook encryption root", () => {
    expect(() =>
      withRuntimeEnvironment(
        {
          STEWARD_RUNTIME: "workers",
          NODE_ENV: "production",
          STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY: "   ",
          STEWARD_WEBHOOK_SECRET_KDF_SALT: "ab".repeat(16),
        },
        () => encryptWebhookSecret("tenant-secret"),
      ),
    ).toThrow(/STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY or STEWARD_MASTER_PASSWORD is required/);
  });

  it("keeps sequential Worker webhook roots separate across key and KDF rotations", () => {
    const authorityA = {
      NODE_ENV: "production",
      STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY: "webhook-authority-a",
      STEWARD_WEBHOOK_SECRET_KDF_SALT: "a1".repeat(16),
    };
    const authorityB = {
      NODE_ENV: "production",
      STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY: "webhook-authority-b",
      STEWARD_WEBHOOK_SECRET_KDF_SALT: "b2".repeat(16),
    };
    const encryptedA = withRuntimeEnvironment(authorityA, () => encryptWebhookSecret("secret-a"));
    const encryptedB = withRuntimeEnvironment(authorityB, () => encryptWebhookSecret("secret-b"));

    expect(
      withRuntimeEnvironment(authorityA, () => "fingerprint" in resolveWebhookSecretAuthority()),
    ).toBe(false);

    expect(withRuntimeEnvironment(authorityA, () => decryptWebhookSecret(encryptedA))).toBe(
      "secret-a",
    );
    expect(withRuntimeEnvironment(authorityB, () => decryptWebhookSecret(encryptedB))).toBe(
      "secret-b",
    );
    expect(() =>
      withRuntimeEnvironment(authorityB, () => decryptWebhookSecret(encryptedA)),
    ).toThrow();
    expect(() =>
      withRuntimeEnvironment(authorityA, () => decryptWebhookSecret(encryptedB)),
    ).toThrow();
  });

  it("does not inherit a stale webhook root when the current Worker binding is absent", () => {
    process.env.STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY = "stale-isolate-webhook-root";
    process.env.STEWARD_WEBHOOK_SECRET_KDF_SALT = "cc".repeat(16);
    expect(() =>
      withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
        encryptWebhookSecret("must-fail-closed"),
      ),
    ).toThrow(/STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY or STEWARD_MASTER_PASSWORD is required/);
  });

  it("classifies a blank Worker NODE_ENV as production", () => {
    expect(() =>
      withRuntimeEnvironment(
        {
          STEWARD_RUNTIME: "workers",
          NODE_ENV: "   ",
          STEWARD_ALLOW_DEV_SECRETS: "true",
        },
        () => encryptWebhookSecret("must-not-use-dev-root"),
      ),
    ).toThrow(/STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY or STEWARD_MASTER_PASSWORD is required/);
  });

  it("preserves webhook authority when A suspends, B runs, then A resumes", async () => {
    const authorityA = {
      NODE_ENV: "production",
      STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY: "webhook-overlap-a",
      STEWARD_WEBHOOK_SECRET_KDF_SALT: "d4".repeat(16),
    };
    const authorityB = {
      NODE_ENV: "production",
      STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY: "webhook-overlap-b",
      STEWARD_WEBHOOK_SECRET_KDF_SALT: "e5".repeat(16),
    };
    let releaseA: (() => void) | undefined;
    let signalAStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      signalAStarted = resolve;
    });
    const resume = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    const requestA = withRuntimeEnvironment(authorityA, async () => {
      signalAStarted?.();
      await resume;
      return encryptWebhookSecret("overlap-secret-a");
    });
    await started;
    const encryptedB = withRuntimeEnvironment(authorityB, () =>
      encryptWebhookSecret("overlap-secret-b"),
    );
    releaseA?.();
    const encryptedA = await requestA;

    expect(withRuntimeEnvironment(authorityA, () => decryptWebhookSecret(encryptedA))).toBe(
      "overlap-secret-a",
    );
    expect(withRuntimeEnvironment(authorityB, () => decryptWebhookSecret(encryptedB))).toBe(
      "overlap-secret-b",
    );
    expect(() =>
      withRuntimeEnvironment(authorityB, () => decryptWebhookSecret(encryptedA)),
    ).toThrow();
  });
});
