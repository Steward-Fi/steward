import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("refresh token reuse detection", () => {
  it("records consumed refresh tokens and revokes tenant session tokens on reuse", () => {
    expect(authSource).toContain("refresh:used:");
    expect(authSource).toContain('status: "reused"');
    expect(authSource).toContain("auth.refresh.reuse_detected");
    expect(authSource).toContain("Refresh token reuse detected");
  });

  it("serializes refresh rotation under token and user-session advisory locks", () => {
    const rotationStart = authSource.indexOf("async function rotateRefreshTokenForUserSession");
    expect(rotationStart).toBeGreaterThanOrEqual(0);
    const rotationBody = authSource.slice(
      rotationStart,
      authSource.indexOf("/** Build the standard dual-token auth response.", rotationStart),
    );
    expect(rotationBody).toContain("const [refreshCandidate]");
    expect(rotationBody).toContain("refresh_token_${tokenHash}");
    expect(rotationBody).toContain("pg_advisory_xact_lock");
    expect(rotationBody).toContain("user_session_${refreshCandidate.userId}");
    const userLock = rotationBody.indexOf("user_session_${refreshCandidate.userId}");
    const validDelete = rotationBody.indexOf(".delete(refreshTokens)", userLock);
    expect(userLock).toBeLessThan(validDelete);
    expect(rotationBody.indexOf("revocationStore.getUserRevokedBefore")).toBeGreaterThan(
      rotationBody.indexOf(".insert(refreshTokens)"),
    );
  });
});
