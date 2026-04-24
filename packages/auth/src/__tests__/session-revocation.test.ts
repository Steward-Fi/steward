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
    const { payload: oldPayload } = await jwtVerify(
      oldToken,
      new TextEncoder().encode(secret),
      { issuer: "steward" },
    );

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
    const { payload: newPayload } = await jwtVerify(
      newToken,
      new TextEncoder().encode(secret),
      { issuer: "steward" },
    );
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
});
