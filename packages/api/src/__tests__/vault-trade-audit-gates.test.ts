/**
 * STRUCTURAL BACKSTOP (source-order assertions) for the residual audit/ordering
 * invariants whose high-value behavior is NOT yet behaviorally executable in
 * this package.
 *
 * Most of what this file used to grep for is now driven for REAL elsewhere —
 * the substring checks were deleted, not weakened:
 *   - step-up / fail-closed gates on approve/reject/lifecycle/replace/
 *     sign-message/sign-user-operation/sign-authorization → vault-approval-gates
 *     .test.ts + vault-signing-gates.test.ts
 *   - audit-before-irreversible-sign on the two primary signing paths
 *     (/sign and approve) via fault injection → vault-native-transfer-guard
 *     .test.ts + vault-approval-gates.test.ts
 *   - direct-broadcast idempotency (428) and approval-time policy revalidation
 *     → vault-native-transfer-guard.test.ts + vault-approval-gates.test.ts
 *   - lifecycle-pending-approval block → vault-approval-gates.test.ts
 *   - trade session create/get/revoke MFA gates + human-actor attribution +
 *     authorized-before-create ordering → trade-session-gates.test.ts
 *   - Solana offline signing withholds the broadcast, and the offline return is a
 *     fully-signed transfer → @stwd/vault solana-offline-broadcast.test.ts
 *   - the deep Hyperliquid venue-submit path fences spend + idempotency on
 *     venue-rejection (releaseSpend + canceled audit, no submitted) and unknown-
 *     status (502, spend retained), and sequences submit-authorization before the
 *     submitted audit (signOrder before submitOrder) → trade-venue-submit-fence
 *     .test.ts
 *
 * What remains here is ONLY source-order coverage for invariants that cannot be
 * proven in-process without machinery that does not belong in this package:
 *   - the disabled-by-default signing routes (message / user-operation /
 *     authorization) write their authorization audit before the signer call —
 *     reachable behaviorally only behind a break-glass env opt-in AND real key
 *     material, so the ordering is asserted structurally;
 *   - the secondary transfer + lifecycle routes order authorization-audit before
 *     their mutation (a lower-value second instance of the pattern already
 *     proven behaviorally on /sign + approve);
 *   - the legacy manual-approval broadcast-intent plumbing — including that the
 *     Solana approve branch threads the caller's broadcast flag into
 *     vault.signSolanaTransaction rather than force-broadcasting (the offline
 *     gate itself is now behavioral, see above) — and the first-class replace
 *     route's audit/webhook wiring.
 *
 * A source-order assertion proves the lines are in the safe order TODAY; it does
 * not execute the guard. Where it was feasible to execute, the behavior now is —
 * in the files listed above.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const vaultSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");

describe("vault audit-ordering structural backstops", () => {
  it("orders authorization-audit before the irreversible action on secondary/disabled signing routes", () => {
    // Secondary signing/lifecycle routes (the audit-before-sign pattern itself is
    // proven behaviorally on /sign + approve; these are the lower-value siblings).
    const transferRouteStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"');
    const transferRouteEnd = vaultSource.indexOf("vaultRoutes.", transferRouteStart + 1);
    const transferRoute = vaultSource.slice(transferRouteStart, transferRouteEnd);
    expect(transferRoute).toContain("requireSignerPermission");
    expect(transferRoute).toContain('"wallet_action_transfer"');
    expect(transferRoute.indexOf('action: "wallet_action.transfer.authorized"')).toBeLessThan(
      transferRoute.indexOf("vault.signTransaction(signRequest"),
    );
    expect(vaultSource.indexOf('action: "transaction.lifecycle.authorized"')).toBeLessThan(
      vaultSource.indexOf(
        ".update(transactions)",
        vaultSource.indexOf("transactions/:txId/lifecycle"),
      ),
    );

    // Disabled-by-default arbitrary/AA signing routes: reachable only behind a
    // break-glass env opt-in + real key material, so the order is asserted here.
    expect(vaultSource.indexOf('action: "vault.message.sign.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signMessage"),
    );
    expect(vaultSource.indexOf('action: "vault.sign.user_operation.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signUserOperation"),
    );
    expect(vaultSource.indexOf('action: "vault.sign.authorization.authorized"')).toBeLessThan(
      vaultSource.indexOf("vault.signAuthorization"),
    );
  });

  it("preserves legacy sign broadcast intent through manual approval", () => {
    const pendingInsert = vaultSource.indexOf('status: "pending"');
    expect(pendingInsert).toBeGreaterThanOrEqual(0);
    expect(vaultSource.indexOf("transactionActionPayload", pendingInsert)).toBeGreaterThan(
      pendingInsert,
    );

    const approvalStart = vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"');
    expect(approvalStart).toBeGreaterThanOrEqual(0);
    const approvalRoute = vaultSource.slice(
      approvalStart,
      vaultSource.indexOf('vaultRoutes.post("/:agentId/reject/:txId"', approvalStart),
    );
    expect(approvalRoute).toContain("getTransactionActionPayload");
    expect(approvalRoute).toContain("transactionPayload.broadcast");
    expect(approvalRoute).toContain("const shouldBroadcast");
    expect(approvalRoute).toContain("signedTx: shouldBroadcast ? undefined : txHash");
    // The Solana approve branch threads the caller's broadcast intent into
    // vault.signSolanaTransaction rather than force-broadcasting an offline sign.
    // (signSolanaTransaction's own offline-vs-broadcast gate is proven behaviorally
    // in @stwd/vault's solana-offline-broadcast.test.ts.)
    expect(approvalRoute).toContain("broadcast: shouldBroadcast");
    expect(approvalRoute).not.toContain("broadcast: true");
  });

  it("exposes a guarded first-class transaction replacement route", () => {
    const replaceStart = vaultSource.indexOf(
      'vaultRoutes.post("/:agentId/transactions/:txId/replace"',
    );
    expect(replaceStart).toBeGreaterThanOrEqual(0);
    const nextRoute = vaultSource.indexOf("vaultRoutes.", replaceStart + 1);
    const replaceRoute = vaultSource.slice(
      replaceStart,
      nextRoute > replaceStart ? nextRoute : undefined,
    );
    expect(replaceRoute).toContain("replacementTxHash is required");
    expect(replaceRoute).toContain("Pending approval must be resolved before replacement");
    expect(replaceRoute).toContain('action: "transaction.replace.authorized"');
    expect(replaceRoute).toContain('action: "transaction.replaced"');
    expect(replaceRoute).toContain("dispatchTransactionLifecycleWebhook");
    expect(replaceRoute).toContain('"transaction.replaced"');
  });
});
