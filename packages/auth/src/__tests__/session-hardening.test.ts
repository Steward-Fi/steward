import { describe, expect, it } from "bun:test";
import { decodeJwt, jwtVerify } from "jose";

import { signAgentToken, validateAgentTokenExpiryEnv } from "../jwt";
import { SessionManager } from "../session";

describe("validateAgentTokenExpiryEnv (SEC-134)", () => {
  it("accepts valid durations", () => {
    for (const value of ["30d", "15m", "12h", "1y", "45 minutes", "2 weeks"]) {
      expect(() => validateAgentTokenExpiryEnv(value)).not.toThrow();
    }
  });

  it("rejects malformed durations", () => {
    for (const value of ["", "nope", "30", "-5d", "30d ago", "1x"]) {
      expect(() => validateAgentTokenExpiryEnv(value)).toThrow(/AGENT_TOKEN_EXPIRY/);
    }
  });

  it("rejects durations beyond the one-year bound", () => {
    for (const value of ["2y", "400d", "53 weeks"]) {
      expect(() => validateAgentTokenExpiryEnv(value)).toThrow(/one-year maximum/);
    }
  });

  it("reads the agent expiry after module import so hydrated Worker bindings are current", async () => {
    const previousSecret = process.env.STEWARD_JWT_SECRET;
    const previousExpiry = process.env.AGENT_TOKEN_EXPIRY;
    process.env.STEWARD_JWT_SECRET = "worker-expiry-test-secret-at-least-32-characters";
    process.env.AGENT_TOKEN_EXPIRY = "2h";
    try {
      const payload = decodeJwt(
        await signAgentToken({ agentId: "agent-a", tenantId: "tenant-a", scope: "agent" }),
      );
      expect((payload.exp ?? 0) - (payload.iat ?? 0)).toBe(2 * 60 * 60);
    } finally {
      if (previousSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = previousSecret;
      if (previousExpiry === undefined) delete process.env.AGENT_TOKEN_EXPIRY;
      else process.env.AGENT_TOKEN_EXPIRY = previousExpiry;
    }
  });
});

describe("SessionManager.createSession claim precedence (SEC-134)", () => {
  const secret = "test-session-hardening-secret-at-least-32-chars";

  it("never lets extra claims override userId or pre-select a jti", async () => {
    const sessions = new SessionManager({ secret, expiresIn: "1h" });
    const token = await sessions.createSession("authenticated-user", {
      userId: "attacker-user",
      jti: "attacker-chosen-jti",
      role: "admin",
    });
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
      issuer: "steward",
    });
    expect(payload.userId).toBe("authenticated-user");
    expect(payload.jti).not.toBe("attacker-chosen-jti");
    expect(typeof payload.jti).toBe("string");
    expect(payload.role).toBe("admin");
  });
});
