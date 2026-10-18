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
  test("keeps auth.login authority exclusively inside the verified-tenant helper", () => {
    const auditHelper = sourceBetween(
      "async function writeAuthLoginAudit(",
      "async function findOrCreateWalletTenant(",
    );
    expect(auditHelper).toContain("withVerifiedAuthTenant(tenantId, userId");
    expect(auditHelper).toContain('action: "auth.login"');

    const sourceWithoutHelper = source.replace(auditHelper, "");
    expect(sourceWithoutHelper).not.toContain('action: "auth.login"');
  });

  test("routes shared OAuth/session finalization through the guarded audit helper", () => {
    const responseBuilder = sourceBetween(
      "async function buildAuthOrMfaResponse(",
      "function authExchangeJson(",
    );
    expect(responseBuilder).toContain("await writeAuthLoginAudit(c, tenantId, userId, claims)");
    expect(responseBuilder).not.toContain("await writeAuditEvent(");
  });

  test("routes the dedicated SIWE finalization audit through the guarded helper", () => {
    const siweRoute = sourceBetween(
      'auth.post("/verify", async (c) => {',
      'auth.post("/verify/solana"',
    );
    expect(siweRoute).toContain(
      "await writeAuthLoginAudit(\n    c,\n    effectiveTenantId,\n    user.id,",
    );
    expect(siweRoute).toContain('{ address, walletChain: "ethereum" }');
    expect(siweRoute).not.toContain("await writeAuditEvent({");
  });
});
