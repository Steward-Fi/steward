import { describe, expect, it } from "bun:test";
import { jwtVerify } from "jose";
import { revocationStore, SessionManager, TokenRevokedError } from "../index";

const secret = "test-session-revocation-secret-at-least-32-chars";

describe("session revocation", () => {
  it("rejects a revoked JTI during verify", async () => {
    const sessions = new SessionManager({ secret, expiresIn: "1h" });
    const token = await sessions.createSession("user-revoked-jti");

    await sessions.invalidateSession(token);

    await expect(sessions.verifySession(token)).rejects.toBeInstanceOf(TokenRevokedError);
  });

  it("revokes agent tokens issued before the revocation line only", async () => {
    const sessions = new SessionManager({ secret, expiresIn: "1h" });
    const oldToken = await sessions.createSession("agent-user", {
      scope: "agent",
      agentId: "agent-revoke-test",
    });
    const { payload: oldPayload } = await jwtVerify(oldToken, new TextEncoder().encode(secret), {
      issuer: "steward",
    });

    await revocationStore.revokeAgentTokens(
      "agent-revoke-test",
      Number(oldPayload.iat) + 1,
      Date.now() + 60_000,
    );

    await expect(sessions.verifySession(oldToken)).rejects.toBeInstanceOf(TokenRevokedError);

    const newToken = await sessions.createSession("agent-user", {
      scope: "agent",
      agentId: "agent-revoke-test",
    });
    const { payload: newPayload } = await jwtVerify(newToken, new TextEncoder().encode(secret), {
      issuer: "steward",
    });
    await revocationStore.revokeAgentTokens(
      "agent-revoke-test-after",
      Number(newPayload.iat) - 1,
      Date.now() + 60_000,
    );

    const validAgentToken = await sessions.createSession("agent-user", {
      scope: "agent",
      agentId: "agent-revoke-test-after",
    });
    expect(await sessions.verifySession(validAgentToken)).toMatchObject({
      agentId: "agent-revoke-test-after",
    });
  });

  it("revokes agent tokens issued in the same second as the revocation line", async () => {
    const sessions = new SessionManager({ secret, expiresIn: "1h" });
    const token = await sessions.createSession("agent-user", {
      scope: "agent",
      agentId: "agent-revoke-same-second",
    });
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
      issuer: "steward",
    });

    await revocationStore.revokeAgentTokens(
      "agent-revoke-same-second",
      Number(payload.iat),
      Date.now() + 60_000,
    );

    await expect(sessions.verifySession(token)).rejects.toBeInstanceOf(TokenRevokedError);
  });

  it("revokes user tokens issued before the user revocation line", async () => {
    const sessions = new SessionManager({ secret, expiresIn: "1h" });
    const token = await sessions.createSession("user-revoke-line");
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
      issuer: "steward",
    });

    await revocationStore.revokeUserTokens(
      "user-revoke-line",
      Number(payload.iat),
      Date.now() + 60_000,
    );

    await expect(sessions.verifySession(token)).rejects.toBeInstanceOf(TokenRevokedError);
  });

  it("keeps user revocation lines monotonic when an older line is written later", async () => {
    await revocationStore.revokeUserTokens("user-monotonic-line", 200, Date.now() + 60_000);
    await revocationStore.revokeUserTokens("user-monotonic-line", 100, Date.now() + 60_000);

    await expect(revocationStore.getUserRevokedBefore("user-monotonic-line")).resolves.toBe(200);
  });

  it("keeps agent revocation lines monotonic when an older line is written later", async () => {
    await revocationStore.revokeAgentTokens("agent-monotonic-line", 200, Date.now() + 60_000);
    await revocationStore.revokeAgentTokens("agent-monotonic-line", 100, Date.now() + 60_000);

    await expect(revocationStore.getAgentRevokedBefore("agent-monotonic-line")).resolves.toBe(200);
  });

  it("fails closed in production when no shared revocation backend is configured", async () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousRedisUrl = process.env.REDIS_URL;
    process.env.NODE_ENV = "production";
    delete process.env.REDIS_URL;

    try {
      await expect(revocationStore.isRevoked("missing-shared-store")).rejects.toThrow(
        "Shared token revocation store unavailable",
      );
      await expect(revocationStore.revokeUserTokens("missing-shared-store-user")).rejects.toThrow(
        "Shared token revocation store unavailable",
      );
      await expect(
        revocationStore.getAgentRevokedBefore("missing-shared-store-agent"),
      ).rejects.toThrow("Shared token revocation store unavailable");
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previousNodeEnv;
      }
      if (previousRedisUrl === undefined) {
        delete process.env.REDIS_URL;
      } else {
        process.env.REDIS_URL = previousRedisUrl;
      }
    }
  });
});
