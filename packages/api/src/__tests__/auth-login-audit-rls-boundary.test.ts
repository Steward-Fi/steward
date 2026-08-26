import { describe, expect, test } from "bun:test";

const source = await Bun.file(new URL("../routes/auth.ts", import.meta.url)).text();

function sourceBetween(startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + 1);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("auth login audit RLS boundary", () => {
  test("binds every auth.login audit to the verified user tenant", () => {
    const auditHelper = sourceBetween(
      "async function writeAuthLoginAudit(",
      "async function findOrCreateWalletTenant(",
    );
    expect(auditHelper).toContain("withVerifiedAuthTenant(tenantId, userId");
    expect(auditHelper).toContain('action: "auth.login"');
  });

  test("routes shared OAuth/session finalization through the guarded audit helper", () => {
    const responseBuilder = sourceBetween(
      "async function buildAuthOrMfaResponse(",
      "function authExchangeJson(",
    );
    expect(responseBuilder).toContain("await writeAuthLoginAudit(c, tenantId, userId, claims)");
    expect(responseBuilder).not.toContain("await writeAuditEvent(");
  });
});
