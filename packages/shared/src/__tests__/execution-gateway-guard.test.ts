import { describe, expect, test } from "bun:test";
import { LEGACY_EVM_SIGN_CALL_SITES, SECURITY_SURFACE_OPERATIONS } from "../security-surface.js";

const read = async (path: string) => Bun.file(new URL(path, import.meta.url)).text();

/**
 * CI guard for the PR4 execution gateway.
 *
 * The migrated primary EVM `/vault/:agentId/sign` route and its compatible
 * approval replay must never reach the raw `Vault.signTransaction` signer
 * without going through GovernedVault authorization. Because the vault route
 * file legitimately contains a Solana raw fallback (primary sign) and a
 * transfer raw fallback (approval replay), a naive "ban raw sign" static rule is
 * brittle. Instead we assert the invariant guards that make those fallbacks
 * unreachable for primary-EVM/approval flows are present, and that the security
 * surface honestly scopes the gateway claim.
 */
describe("execution gateway guard", () => {
  test("primary EVM sign + approval replay raw fallbacks are invariant-guarded", async () => {
    const source = await read("../../../api/src/routes/vault.ts");

    // Primary sign path: the raw fallback must be gated by an isEvmSignRequest
    // invariant guard that throws, so an EVM request can never reach raw signing.
    expect(source).toContain(
      "invariant: primary EVM sign reached raw signer without gateway authorization",
    );
    // Approval replay: the raw fallback must be gated by an isRawEvmSigningCandidate
    // invariant guard that throws for any primary-EVM candidate.
    expect(source).toContain(
      "invariant: primary EVM approval reached raw signer without gateway authorization",
    );

    // The approval replay must fail closed (never raw-sign) when the stored
    // digest or policy-revision binding is absent/malformed.
    expect(source).toContain("isRawEvmSigningCandidate");
    expect(source).toContain("missing_stored_execution_payload_digest");
    expect(source).toContain("missing_stored_execution_policy_revision_hash");
    expect(source).toContain("missing_or_malformed_transaction_action_payload");
  });

  test("every raw signTransaction call site in the vault route is accounted for", async () => {
    const source = await read("../../../api/src/routes/vault.ts");
    const rawCalls = [...source.matchAll(/\bvault\.signTransaction\(/g)];
    // Exactly three raw call sites are expected:
    //  1. primary-sign Solana-only fallback (invariant-guarded)
    //  2. transfer action EVM sign (separate non-migrated surface)
    //  3. approval replay TRANSFER fallback (invariant-guarded)
    // If a new raw call site is added, this test fails until it is classified
    // (either gateway-migrated or added to LEGACY_EVM_SIGN_CALL_SITES).
    expect(rawCalls.length).toBe(3);
  });

  test("gateway claim is honestly scoped in the security surface", () => {
    const evmSign = SECURITY_SURFACE_OPERATIONS.find(
      (operation) => operation.id === "wallet.evm_transaction.sign",
    );
    expect(evmSign).toBeDefined();
    if (!evmSign) return;

    const migratedPaths = evmSign.routes
      .filter((route) => route.gatewayMigrated === true)
      .map((route) => route.path)
      .sort();
    // Only the primary sign + approval replay are gateway-migrated.
    expect(migratedPaths).toEqual(["/:agentId/approve/:txId", "/:agentId/sign"]);

    // Everything else in the operation is explicitly NOT gateway-migrated.
    const notMigrated = evmSign.routes.filter((route) => route.gatewayMigrated !== true);
    expect(notMigrated.length).toBeGreaterThan(0);
  });

  test("legacy EVM sign call sites are enumerated in the other route files", async () => {
    const files = [...new Set(LEGACY_EVM_SIGN_CALL_SITES.map((site) => site.file))];
    for (const file of files) {
      if (file === "packages/api/src/routes/vault.ts") continue;
      const source = await read(`../../../${file.replace("packages/", "")}`);
      expect(source).toContain("signTransaction");
    }
    // The non-vault legacy files each have at least one enumerated call site.
    for (const file of [
      "packages/api/src/routes/intents.ts",
      "packages/api/src/routes/user.ts",
      "packages/api/src/routes/global-wallet.ts",
    ]) {
      expect(LEGACY_EVM_SIGN_CALL_SITES.some((site) => site.file === file)).toBe(true);
    }
  });
});
