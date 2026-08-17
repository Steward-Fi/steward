import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { scryptSync } from "node:crypto";

import { getJwtSecret, signAccessToken, verifyToken } from "../jwt";

const ENV_KEYS = [
  "STEWARD_JWT_SECRET",
  "STEWARD_SESSION_SECRET",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_DB_MODE",
  "STEWARD_EMBEDDED",
  "STEWARD_EMBEDDED_MODE",
  "DATABASE_URL",
  "STEWARD_ALLOW_DEV_SECRETS",
  "NODE_ENV",
] as const;

describe("getJwtSecret embedded-mode master password fallback (SEC-013)", () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const key of ENV_KEYS) {
      saved[key] = process.env[key];
      delete process.env[key];
    }
    process.env.STEWARD_DB_MODE = "pglite";
    process.env.STEWARD_MASTER_PASSWORD = "embedded-master-password-for-tests";
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    }
  });

  it("never uses the raw master password as the JWT secret", () => {
    const secret = getJwtSecret({ warn: null });
    expect(secret).not.toBe(process.env.STEWARD_MASTER_PASSWORD);
    expect(secret.length).toBeGreaterThanOrEqual(32);
  });

  it("derives the JWT secret via domain-separated scrypt", () => {
    const expected = (
      scryptSync("embedded-master-password-for-tests", "steward-kdf:jwt-signing:v1", 32) as Buffer
    ).toString("hex");
    expect(getJwtSecret({ warn: null })).toBe(expected);
  });

  it("signs and verifies tokens with the derived secret", async () => {
    const token = await signAccessToken({
      address: "0x0000000000000000000000000000000000000000",
      tenantId: "default",
    });
    const payload = await verifyToken(token);
    expect(payload.tenantId).toBe("default");
  });

  it("prefers an explicit STEWARD_JWT_SECRET over the derivation", () => {
    process.env.STEWARD_JWT_SECRET = "explicit-jwt-secret-with-32-characters!!";
    expect(getJwtSecret({ warn: null })).toBe("explicit-jwt-secret-with-32-characters!!");
  });
});
