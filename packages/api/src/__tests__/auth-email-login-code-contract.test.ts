import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../routes/auth.ts", import.meta.url), "utf8");

function routeSlice(startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("email login companion-code API contract", () => {
  it("applies the same tenant login and SSO gates before consuming the code", () => {
    const route = routeSlice('auth.post("/email/code/verify"', 'auth.post("/email/status"');
    const verify = route.indexOf("verifyEmailLoginCode");

    expect(route.indexOf("requireTenantLoginMethodAllowed")).toBeLessThan(verify);
    expect(route.indexOf("requireNonSsoEmailLoginAllowed")).toBeLessThan(verify);
    expect(route.indexOf('"email-code-verify-target"')).toBeLessThan(verify);
    expect(route.indexOf("completeEmailAuth")).toBeGreaterThan(verify);
    expect(route).toContain("authExchangeJson(c, authResult.response)");
    expect(route).toContain('result.reason === "locked"');
  });

  it("requires both opaque polling credentials and rate limits status polling", () => {
    const route = routeSlice('auth.post("/email/status"', "// ── Email OTP");

    expect(route).toContain('"email-status"');
    expect(route).toContain("body?.challengeId");
    expect(route).toContain("body?.pollSecret");
    expect(route).toContain("getEmailLoginStatus(body.challengeId, body.pollSecret)");
    expect(route).not.toContain("authExchangeJson");
  });

  it("preserves passkey-registration OTP as a grant-only flow", () => {
    const otp = routeSlice('auth.post("/email/otp/send"', "// ── Guest");

    expect(otp).toContain("sendOtp(email");
    expect(otp).toContain("verifyOtp(email, code");
    expect(otp).toContain("issueEmailGrant(email, resolvedTenantId)");
    expect(otp).not.toContain("verifyEmailLoginCode");
    expect(otp).not.toContain("completeEmailAuth(c, email");
  });
});
