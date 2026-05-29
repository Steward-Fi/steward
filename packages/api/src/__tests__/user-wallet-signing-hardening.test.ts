import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const userSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");

describe("user wallet signing hardening", () => {
  it("requires replay protection for broadcast wallet signing", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/sign-message"', routeStart);
    const routeBody = userSource.slice(routeStart, routeEnd);
    expect(routeBody).toContain("const shouldBroadcast = body.broadcast !== false");
    expect(routeBody).toContain('c.req.header("Idempotency-Key")');
    expect(routeBody).toContain("Broadcast signing requires an Idempotency-Key header");
    expect(routeBody).toContain('status: shouldBroadcast ? "broadcast" : "signed"');
  });

  it("validates value is a non-negative uint256 before user wallet signing", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/sign-message"', routeStart);
    const routeBody = userSource.slice(routeStart, routeEnd);
    const valueGuard = routeBody.indexOf("isUint256DecimalString(body.value)");
    const signRequest = routeBody.indexOf("const signRequest");

    expect(valueGuard).toBeGreaterThanOrEqual(0);
    expect(signRequest).toBeGreaterThan(valueGuard);
    expect(routeBody).toContain("non-negative uint256 wei amount");
    // Validator must reject negative/garbage (only digits accepted, bounded to uint256).
    expect(userSource).toContain('!/^\\d+$/.test(value)');
  });

  it("rejects caller-controlled gas limits before user wallet signing", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/sign-message"', routeStart);
    const routeBody = userSource.slice(routeStart, routeEnd);
    const gasLimitGuard = routeBody.indexOf('gasLimit !== undefined');
    const signRequest = routeBody.indexOf("const signRequest");

    expect(gasLimitGuard).toBeGreaterThanOrEqual(0);
    expect(signRequest).toBeGreaterThan(gasLimitGuard);
    expect(routeBody).toContain("gas spend is not policy-accounted");
  });

  it("fails closed for contract-recipient native transfers before user wallet signing", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/sign-message"', routeStart);
    const routeBody = userSource.slice(routeStart, routeEnd);
    const codeLookup = routeBody.indexOf('method: "eth_getCode"');
    const contractRecipientGuard = routeBody.indexOf("native transfers to contract recipients");
    const signRequest = routeBody.indexOf("const signRequest");

    expect(codeLookup).toBeGreaterThanOrEqual(0);
    expect(contractRecipientGuard).toBeGreaterThan(codeLookup);
    expect(signRequest).toBeGreaterThan(contractRecipientGuard);
    expect(routeBody).toContain("recipient contract code is verified");
  });

  it("does not report completed user wallet broadcasts as failed if bookkeeping throws", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/sign"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/sign-message"', routeStart);
    const routeBody = userSource.slice(routeStart, routeEnd);
    const completedDeclaration = routeBody.indexOf("let completedResult");
    const signCall = routeBody.indexOf("vault.signTransaction(signRequest");
    const completedAssignment = routeBody.indexOf("completedResult = { txId, txHash }", signCall);
    const completedAudit = routeBody.indexOf('action: "user.wallet.sign"', completedAssignment);
    const catchHandler = routeBody.indexOf("if (completedResult)", completedAudit);
    const failureAudit = routeBody.indexOf('action: "user.wallet.sign.failed"', catchHandler);

    expect(completedDeclaration).toBeGreaterThanOrEqual(0);
    expect(signCall).toBeGreaterThan(completedDeclaration);
    expect(completedAssignment).toBeGreaterThan(signCall);
    expect(completedAudit).toBeGreaterThan(completedAssignment);
    expect(catchHandler).toBeGreaterThan(completedAudit);
    expect(failureAudit).toBeGreaterThan(catchHandler);
    expect(routeBody.slice(catchHandler, failureAudit)).toContain("ok: true");
    expect(routeBody.slice(catchHandler, failureAudit)).toContain("data: completedResult");
  });

  it("writes an authorization audit before unsafe user message signing", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/sign-message"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/export"', routeStart);
    const routeBody = userSource.slice(routeStart, routeEnd);
    const authorizedAudit = routeBody.indexOf('action: "user.wallet.sign_message.authorized"');
    const signCall = routeBody.indexOf("vault.signMessage");
    const completedAudit = routeBody.indexOf(
      'action: "user.wallet.sign_message"',
      authorizedAudit + 1,
    );
    expect(authorizedAudit).toBeGreaterThanOrEqual(0);
    expect(signCall).toBeGreaterThan(authorizedAudit);
    expect(completedAudit).toBeGreaterThan(signCall);
    expect(routeBody).toContain("unsafeCompatibilityMode: true");
  });
});
