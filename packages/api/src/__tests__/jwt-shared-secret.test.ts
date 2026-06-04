import { afterEach, describe, expect, it } from "bun:test";
import { ACCESS_TOKEN_EXPIRY, signAccessToken, signAgentToken, verifyToken } from "@stwd/auth";
import { decodeJwt } from "jose";

const ORIGINAL_ENV = {
  STEWARD_JWT_SECRET: process.env.STEWARD_JWT_SECRET,
  STEWARD_SESSION_SECRET: process.env.STEWARD_SESSION_SECRET,
  STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD,
  NODE_ENV: process.env.NODE_ENV,
  STEWARD_DB_MODE: process.env.STEWARD_DB_MODE,
  DATABASE_URL: process.env.DATABASE_URL,
};

afterEach(() => {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

describe("shared JWT signing and verification", () => {
  it("verifies an API-minted agent token with the canonical STEWARD_JWT_SECRET", async () => {
    process.env.STEWARD_JWT_SECRET = "shared-jwt-secret-for-api-and-proxy-tests";
    delete process.env.STEWARD_SESSION_SECRET;
    delete process.env.STEWARD_MASTER_PASSWORD;

    const token = await signAgentToken({ agentId: "agent-1", tenantId: "tenant-1" }, "1h");
    const payload = await verifyToken(token);

    expect(payload.agentId).toBe("agent-1");
    expect(payload.tenantId).toBe("tenant-1");
    expect(payload.scope).toBe("agent");
  });

  it("uses deprecated STEWARD_SESSION_SECRET only as a backwards-compatible fallback", async () => {
    delete process.env.STEWARD_JWT_SECRET;
    process.env.STEWARD_SESSION_SECRET = "legacy-session-secret-for-migration-tests";
    delete process.env.STEWARD_MASTER_PASSWORD;

    const token = await signAccessToken({
      address: "0x0000000000000000000000000000000000000000",
      tenantId: "tenant-1",
    });
    const payload = await verifyToken(token);

    expect(payload.address).toBe("0x0000000000000000000000000000000000000000");
    expect(payload.tenantId).toBe("tenant-1");
  });

  it("mints user access tokens with the shared short-lived TTL", async () => {
    process.env.STEWARD_JWT_SECRET = "short-lived-access-token-secret-for-tests";
    delete process.env.STEWARD_SESSION_SECRET;
    delete process.env.STEWARD_MASTER_PASSWORD;

    expect(ACCESS_TOKEN_EXPIRY).toBe("15m");
    const token = await signAccessToken({
      address: "0x0000000000000000000000000000000000000000",
      tenantId: "tenant-1",
    });
    const payload = decodeJwt(token);

    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.exp).toBe("number");
    expect(Number(payload.exp) - Number(payload.iat)).toBe(900);
  });
});
