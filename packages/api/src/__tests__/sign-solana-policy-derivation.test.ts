import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Structural / wiring tests for the sign-solana route.
 *
 * The spoof-resistance security property is exercised end-to-end against real
 * serialized transactions in packages/vault (solana-instructions.test.ts). These
 * tests assert the ROUTE actually wires the parser in as the authoritative policy
 * source, in the correct order, and that all fail-closed gates and auth checks are
 * preserved. A regression that, say, re-trusts caller-supplied `to`/`value` or
 * removes the unparsed fail-closed gate would surface here without needing a full
 * authenticated DB harness.
 */
const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");

function routeSlice(): string {
  const start = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-solana"');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = vaultSource.indexOf('vaultRoutes.post("/:agentId/rpc"', start);
  expect(end).toBeGreaterThan(start);
  return vaultSource.slice(start, end);
}

describe("sign-solana — parser-derived policy wiring", () => {
  it("imports the byte-level parser and helpers from @stwd/vault", () => {
    expect(vaultSource).toContain("parseSolanaTransaction");
    expect(vaultSource).toContain("deriveSolanaPolicyFields");
    expect(vaultSource).toContain("detectSolanaPolicyConflicts");
  });

  it("no longer has the blanket disable function", () => {
    expect(vaultSource).not.toContain("function solanaTransactionSigningDisabled");
  });

  it("enforces the agent-access auth gate before parsing", () => {
    const route = routeSlice();
    const authGate = route.indexOf("requireAgentAccess(c)");
    const parse = route.indexOf("parseSolanaTransaction(body.transaction)");
    expect(authGate).toBeGreaterThanOrEqual(0);
    expect(parse).toBeGreaterThan(authGate);
  });

  it("treats caller 'to'/'value' as advisory and derives authoritative values from bytes", () => {
    const route = routeSlice();
    // The authoritative recipient/value must come from the parser, not the body.
    expect(route).toContain("const toAddress = derived.to ??");
    expect(route).toContain("const txValue = derived.value;");
    // A comment documents that caller fields are advisory only.
    expect(route).toContain("ADVISORY ONLY");
  });

  it("rejects when caller fields conflict with the parsed transaction (spoof guard)", () => {
    const route = routeSlice();
    const conflictCheck = route.indexOf("detectSolanaPolicyConflicts(derived");
    const rejectSpoof = route.indexOf("rejected_spoofed_fields");
    const conflictReturn = route.indexOf("conflict with the serialized transaction");
    expect(conflictCheck).toBeGreaterThanOrEqual(0);
    expect(rejectSpoof).toBeGreaterThan(conflictCheck);
    expect(conflictReturn).toBeGreaterThan(conflictCheck);
    // The spoof rejection must happen BEFORE the transaction is signed.
    const signCall = route.indexOf("vault.signSolanaTransaction(");
    expect(conflictCheck).toBeLessThan(signCall);
  });

  it("fails closed on any unparsed instruction unless the blind-sign flag is set", () => {
    const route = routeSlice();
    const fullyParsedGate = route.indexOf("if (!derived.fullyParsed)");
    const failClosedMsg = route.indexOf("fail-closed");
    expect(fullyParsedGate).toBeGreaterThanOrEqual(0);
    expect(failClosedMsg).toBeGreaterThan(fullyParsedGate);
    // The fully-parsed gate is itself guarded by the blind-sign flag.
    const gateBlock = route.slice(fullyParsedGate, fullyParsedGate + 1400);
    expect(gateBlock).toContain("ALLOW_UNSAFE_SOLANA_BLIND_SIGNING");
    expect(gateBlock).toContain("signSolanaBlind(c, {");
    // Fail-closed gate precedes signing.
    expect(fullyParsedGate).toBeLessThan(route.indexOf("vault.signSolanaTransaction("));
  });

  it("fails closed when the payload cannot be deserialized at all", () => {
    const route = routeSlice();
    expect(route).toContain("could not be decoded for policy evaluation and was rejected");
    // The catch around parseSolanaTransaction must gate on the blind flag too.
    const tryParse = route.indexOf("try {\n    const summary = parseSolanaTransaction");
    expect(tryParse).toBeGreaterThanOrEqual(0);
  });

  it("defines the blind-sign flag default-off, mirroring other unsafe flags", () => {
    expect(vaultSource).toContain(
      'const allowUnsafeSolanaBlindSigning = (): boolean =>\n  process.env.STEWARD_ALLOW_UNSAFE_SOLANA_BLIND_SIGNING === "true"',
    );
  });

  it("only passes the legacy single-transfer envelope for a single native SOL transfer", () => {
    const route = routeSlice();
    const guard = route.indexOf("const isSingleNativeTransfer =");
    const envelopeSpread = route.indexOf(
      "isSingleNativeTransfer ? { expectedTo: toAddress, expectedValue: txValue } : {}",
    );
    expect(guard).toBeGreaterThanOrEqual(0);
    expect(envelopeSpread).toBeGreaterThan(guard);
    expect(route).toContain('instructionType === "system:Transfer"');
  });

  it("preserves the existing policy-evaluation, rate-limit, audit, and webhook gates", () => {
    const route = routeSlice();
    expect(route).toContain("await enforceRateLimit(agentId, policySet)");
    expect(route).toContain("await policyEngine.evaluate(policySet, {");
    expect(route).toContain('action: "vault.sign.solana"');
    expect(route).toContain('dispatchWebhook(tenantId, agentId, "tx_signed"');
    // Authoritative parser output is recorded in the success audit.
    expect(route).toContain("derivedFromTransaction: true");
  });

  it("records the spend using the authoritative parsed value", () => {
    const route = routeSlice();
    const evalCall = route.indexOf("await policyEngine.evaluate(policySet");
    const recordSpend = route.indexOf("recordVaultSpend(agentId, tenantId, txValue, chainId)");
    expect(evalCall).toBeGreaterThanOrEqual(0);
    expect(recordSpend).toBeGreaterThan(evalCall);
  });

  it("requires idempotency for broadcast requests before signing", () => {
    const route = routeSlice();
    const idempotencyGate = route.indexOf("Broadcast Solana signing requests");
    const signCall = route.indexOf("vault.signSolanaTransaction(");
    expect(idempotencyGate).toBeGreaterThanOrEqual(0);
    expect(idempotencyGate).toBeLessThan(signCall);
  });

  it("does not report broadcasted transactions as failed after bookkeeping errors", () => {
    const route = routeSlice();
    const completedMarker = route.indexOf("completedResult = { txId, ...result }");
    const retryFence = route.indexOf("returning completed result to prevent duplicate retry");
    const failedWebhook = route.indexOf(
      'dispatchWebhook(tenantId, agentId, "tx_failed"',
      retryFence,
    );
    expect(completedMarker).toBeGreaterThanOrEqual(0);
    expect(retryFence).toBeGreaterThan(completedMarker);
    expect(failedWebhook).toBeGreaterThan(retryFence);
  });
});

describe("sign-solana — blind signing fallback", () => {
  it("has a dedicated blind-signing helper that re-applies policy on caller fields", () => {
    expect(vaultSource).toContain("async function signSolanaBlind(");
    const start = vaultSource.indexOf("async function signSolanaBlind(");
    const end = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-solana"', start);
    const helper = vaultSource.slice(start, end);
    expect(helper).toContain("await policyEngine.evaluate(policySet");
    expect(helper).toContain("await enforceRateLimit(agentId, policySet)");
    // Blind path is audited distinctly so it is reviewable.
    expect(helper).toContain('action: "vault.sign.solana.blind"');
    expect(helper).toContain("blindSigned: true");
  });

  it("applies the same broadcast idempotency and post-broadcast retry fence", () => {
    const start = vaultSource.indexOf("async function signSolanaBlind(");
    const end = vaultSource.indexOf('vaultRoutes.post("/:agentId/sign-solana"', start);
    const helper = vaultSource.slice(start, end);
    expect(helper).toContain("Broadcast Solana signing requests");
    expect(helper).toContain("completedResult = { txId, ...result }");
    expect(helper).toContain("returning completed result to prevent duplicate retry");
  });
});
