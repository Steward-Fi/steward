import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");

function expectAdminMfaBeforeRouteMutation(routeMarker: string, beforeMarker: string) {
  const routeStart = vaultSource.indexOf(routeMarker);
  expect(routeStart).toBeGreaterThanOrEqual(0);
  const nextRoute = vaultSource.indexOf("vaultRoutes.", routeStart + routeMarker.length);
  const routeBody = vaultSource.slice(routeStart, nextRoute === -1 ? undefined : nextRoute);
  const gate = vaultSource.indexOf(
    "!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)",
    routeStart,
  );
  const before = vaultSource.indexOf(beforeMarker, routeStart);
  expect(gate).toBeGreaterThan(routeStart);
  expect(before).toBeGreaterThan(routeStart);
  expect(gate).toBeLessThan(before);
  expect(routeBody).toContain("!hasTenantAdminSession(c) || !hasRecentSessionMfa(c)");
}

describe("vault unsafe signing hardening", () => {
  it("requires owner/admin recent MFA for unsafe off-chain and account-abstraction signing", () => {
    expectAdminMfaBeforeRouteMutation(
      'vaultRoutes.post("/:agentId/sign-message"',
      "vault.signMessage",
    );
    expectAdminMfaBeforeRouteMutation(
      'vaultRoutes.post("/:agentId/sign-user-operation"',
      "parseUserOperation(body.userOperation)",
    );
    expectAdminMfaBeforeRouteMutation(
      'vaultRoutes.post("/:agentId/sign-raw-hash"',
      'requireSignerPermission(c, tenantId, agentId, "sign_raw_hash")',
    );
    expectAdminMfaBeforeRouteMutation(
      'vaultRoutes.post("/:agentId/sign-authorization"',
      'requireSignerPermission(\n    c,\n    tenantId,\n    agentId,\n    "sign_authorization"',
    );
  });

  it("does not let sign wildcard grant wallet actions", () => {
    const permissionStart = vaultSource.indexOf("function signerHasPermission");
    expect(permissionStart).toBeGreaterThanOrEqual(0);
    const permissionBody = vaultSource.slice(
      permissionStart,
      vaultSource.indexOf("function timingSafeEqualHex", permissionStart),
    );
    expect(permissionBody).toContain('required.startsWith("sign_")');
    expect(permissionBody).toContain('"wallet_action_transfer"');
    expect(permissionBody).toContain('"transfer"');
    expect(permissionBody).not.toContain(
      'permissions.includes("sign:*") ||\n    permissions.includes(required)',
    );
  });

  it("applies tenant MFA policy to delegated signer automation and key import/export freshness", () => {
    expect(vaultSource).toContain("readTenantMfaPolicy");
    expect(vaultSource).toContain("tenantMfaMaxAgeMs");
    expect(vaultSource).toContain("tenantMfaRequiredFor");
    expect(vaultSource).toContain("hasRecentTenantSessionMfa");
    expect(vaultSource).toContain('tenantMfaRequiredFor(mfaPolicy, "vaultSigning")');
    expect(vaultSource).toContain("mfaPolicy.allowKeyQuorumAutomation === false");
    expect(vaultSource).toContain("mfaPolicy.allowDelegatedSignerAutomation === false");
    expect(vaultSource).toContain("Tenant MFA policy disables key quorum automation");
    expect(vaultSource).toContain("Tenant MFA policy disables delegated signer automation");
    const importStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/import"');
    const exportStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/export"');
    expect(
      vaultSource.indexOf('hasRecentTenantSessionMfa(c, tenantId, "keyImport")', importStart),
    ).toBeGreaterThan(importStart);
    expect(
      vaultSource.indexOf('hasRecentTenantSessionMfa(c, tenantId, "keyExport")', exportStart),
    ).toBeGreaterThan(exportStart);
  });

  it("does not replay pending typed wallet actions as normal transactions", () => {
    const approvalStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"');
    expect(approvalStart).toBeGreaterThanOrEqual(0);
    const disabledCheck = vaultSource.indexOf(
      'transaction.actionType === "send_calls"',
      approvalStart,
    );
    const userOpDisabledCheck = vaultSource.indexOf(
      'transaction.actionType === "user_operation"',
      approvalStart,
    );
    const signTransaction = vaultSource.indexOf("vault.signTransaction", approvalStart);
    expect(disabledCheck).toBeGreaterThan(approvalStart);
    expect(userOpDisabledCheck).toBeGreaterThan(disabledCheck);
    expect(signTransaction).toBeGreaterThan(disabledCheck);
  });

  it("requires private key import to target an existing tenant agent", () => {
    const importStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/import"');
    expect(importStart).toBeGreaterThanOrEqual(0);
    const ensureAgent = vaultSource.indexOf("ensureAgentForTenant(tenantId, agentId)", importStart);
    const importCall = vaultSource.indexOf("vault.importKey", importStart);
    expect(ensureAgent).toBeGreaterThan(importStart);
    expect(importCall).toBeGreaterThan(ensureAgent);
  });

  it("marks tenant-admin private key export responses as non-cacheable", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/export"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf("\n});", routeStart);
    const routeBody = vaultSource.slice(routeStart, routeEnd);
    const exportCall = routeBody.indexOf("vault.exportPrivateKey");
    const cacheControl = routeBody.indexOf('"Cache-Control"', exportCall);
    const response = routeBody.indexOf("return c.json", cacheControl);

    expect(exportCall).toBeGreaterThanOrEqual(0);
    expect(cacheControl).toBeGreaterThan(exportCall);
    expect(response).toBeGreaterThan(cacheControl);
    expect(routeBody).toContain('"no-store, max-age=0"');
    expect(routeBody).toContain('"Pragma", "no-cache"');
    expect(routeBody).toContain('"Expires", "0"');
  });

  it("guards direct native transaction signing against contract-recipient gas burn", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf(
      'vaultRoutes.post("/:agentId/actions/transfer/quote"',
      routeStart,
    );
    const routeBody = vaultSource.slice(routeStart, routeEnd);
    const guard = routeBody.indexOf("nativeTransferGasAccountingGuard");
    const policyEvaluation = routeBody.indexOf("policyEngine.evaluate");
    const signCall = routeBody.indexOf("vault.signTransaction(signRequest");

    expect(guard).toBeGreaterThanOrEqual(0);
    expect(policyEvaluation).toBeGreaterThan(guard);
    expect(signCall).toBeGreaterThan(guard);
    expect(vaultSource).toContain("Native transfers cannot set gasLimit");
  });

  it("does not mark direct transfers failed after signing or broadcast succeeds", () => {
    const routeStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = vaultSource.indexOf(
      'vaultRoutes.get("/:agentId/actions/:actionId"',
      routeStart,
    );
    const routeBody = vaultSource.slice(routeStart, routeEnd);
    const signCall = routeBody.indexOf("vault.signTransaction(signRequest");
    const completedResult = routeBody.indexOf("completedResult = result", signCall);
    const catchStart = routeBody.indexOf("} catch (e: unknown)", completedResult);
    const guard = routeBody.indexOf("if (completedResult && completedStatus)", catchStart);
    const failedInsert = routeBody.indexOf('status: "failed"', catchStart);

    expect(completedResult).toBeGreaterThan(signCall);
    expect(guard).toBeGreaterThan(catchStart);
    expect(failedInsert).toBeGreaterThan(guard);
    expect(routeBody.slice(guard, failedInsert)).toContain("ok: true");
    expect(routeBody.slice(guard, failedInsert)).toContain("transferActionResponse");
  });
});
