import { afterEach, describe, expect, it } from "bun:test";
import { createSignerCredentialHash, verifySignerCredential } from "../services/signer-credentials";

// SEC-073: the signer-credential pepper must never silently degrade to "".
// Production fails closed; outside production the pepperless path requires the
// explicit STEWARD_ALLOW_DEV_SECRETS opt-in. test-preload.ts sets a real test
// pepper, so the happy path below exercises the production-shaped code path.

const PEPPER_ENV = "STEWARD_SIGNER_CREDENTIAL_PEPPER";
const DEV_SECRETS_ENV = "STEWARD_ALLOW_DEV_SECRETS";

describe("signer credential pepper posture (SEC-073)", () => {
  const savedPepper = process.env[PEPPER_ENV];
  const savedDevSecrets = process.env[DEV_SECRETS_ENV];

  afterEach(() => {
    if (savedPepper === undefined) delete process.env[PEPPER_ENV];
    else process.env[PEPPER_ENV] = savedPepper;
    if (savedDevSecrets === undefined) delete process.env[DEV_SECRETS_ENV];
    else process.env[DEV_SECRETS_ENV] = savedDevSecrets;
  });

  it("hashes and verifies with the configured pepper", async () => {
    const hash = await createSignerCredentialHash("stwd_signer_sec073_happy_path");
    expect(hash.startsWith("stwd_scrypt_v1$")).toBe(true);
    expect(await verifySignerCredential("stwd_signer_sec073_happy_path", hash)).toBe(true);
    expect(await verifySignerCredential("stwd_signer_sec073_wrong_secret", hash)).toBe(false);
  });

  it("throws when the pepper is unset without the dev opt-in", async () => {
    delete process.env[PEPPER_ENV];
    delete process.env[DEV_SECRETS_ENV];
    await expect(createSignerCredentialHash("stwd_signer_sec073_no_pepper")).rejects.toThrow(
      /STEWARD_SIGNER_CREDENTIAL_PEPPER is required/,
    );
  });

  it("rejects configured peppers that are too short or only whitespace", async () => {
    for (const weak of ["short", " ".repeat(64)]) {
      process.env[PEPPER_ENV] = weak;
      await expect(createSignerCredentialHash("stwd_signer_sec073_weak")).rejects.toThrow(
        /at least 32 characters of entropy/,
      );
    }
  });

  it("permits the pepperless path only with the explicit dev opt-in", async () => {
    delete process.env[PEPPER_ENV];
    process.env[DEV_SECRETS_ENV] = "true";
    const hash = await createSignerCredentialHash("stwd_signer_sec073_dev_opt_in");
    expect(await verifySignerCredential("stwd_signer_sec073_dev_opt_in", hash)).toBe(true);
  });

  it("peppered hashes do not verify against the pepperless dev path", async () => {
    const hash = await createSignerCredentialHash("stwd_signer_sec073_cross_check");
    delete process.env[PEPPER_ENV];
    process.env[DEV_SECRETS_ENV] = "true";
    expect(await verifySignerCredential("stwd_signer_sec073_cross_check", hash)).toBe(false);
  });
});
