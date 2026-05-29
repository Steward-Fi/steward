import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("auth refresh revocation race hardening", () => {
  it("serializes user-wide refresh revocation with refresh rotation", () => {
    expect(routeSource).toContain('import { lockUserSession } from "../services/session-lock"');
    expect(routeSource).toContain("async function revokeUserRefreshSessions");
    expect(routeSource).toContain("refreshTokenIssuedAtSeconds(record)");

    const rotateStart = routeSource.indexOf("async function rotateRefreshTokenForUserSession");
    expect(rotateStart).toBeGreaterThanOrEqual(0);
    const rotateRoute = routeSource.slice(rotateStart, routeSource.indexOf("/** Build", rotateStart));
    expect(rotateRoute).toContain("await lockUserSession(tx, refreshCandidate.userId)");
    expect(rotateRoute).toContain("revokedBefore >= refreshTokenIssuedAtSeconds(record)");
    expect(rotateRoute).not.toContain("revokedBefore >= refreshStartedAt");

    for (const marker of ['action: "mfa.enable.authorized"', 'action: "mfa.disable.authorized"']) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const tail = routeSource.slice(start, start + 2_000);
      expect(tail).toContain("revokeUserRefreshSessions(session.payload.userId)");
    }

    const revokeAllStart = routeSource.indexOf('auth.delete("/sessions"');
    expect(revokeAllStart).toBeGreaterThanOrEqual(0);
    const revokeAll = routeSource.slice(
      revokeAllStart,
      routeSource.indexOf('auth.post("/refresh"', revokeAllStart),
    );
    expect(revokeAll).toContain("revokeUserRefreshSessions(payload.userId)");
  });
});
