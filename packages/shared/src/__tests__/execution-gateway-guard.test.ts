import { describe, expect, test } from "bun:test";
import {
  LEGACY_EVM_SIGN_CALL_SITES,
  RAW_EVM_SIGN_EXPECTED_COUNTS,
  RAW_EVM_SIGN_INVENTORY,
  SECURITY_SURFACE_OPERATIONS,
} from "../security-surface.js";

const read = async (path: string) => Bun.file(new URL(path, import.meta.url)).text();

/**
 * CI guard for the execution gateway.
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

  test("vault route raw signTransaction count matches the shared inventory", async () => {
    const source = await read("../../../api/src/routes/vault.ts");
    const rawCalls = [...source.matchAll(/\b(?:vault|getVault\(\))\.signTransaction\(/g)];
    // Derived from RAW_EVM_SIGN_INVENTORY (single source of truth), NOT a magic
    // number. The full repository-wide one-for-one scan lives in packages/api
    // (execution-gateway-inventory.test.ts) to avoid crossing package rootDirs;
    // this is the in-package consistency check for the vault route file.
    expect(rawCalls.length).toBe(RAW_EVM_SIGN_EXPECTED_COUNTS["packages/api/src/routes/vault.ts"]);
  });

  test("raw-sign inventory is internally consistent and reconciles with the legacy list", () => {
    // Per-file expected counts are derived from the inventory and must not drift.
    const recomputed = RAW_EVM_SIGN_INVENTORY.reduce<Record<string, number>>((acc, site) => {
      acc[site.file] = (acc[site.file] ?? 0) + 1;
      return acc;
    }, {});
    expect(RAW_EVM_SIGN_EXPECTED_COUNTS).toEqual(recomputed);

    // LEGACY_EVM_SIGN_CALL_SITES and RAW_EVM_SIGN_INVENTORY are two lenses on the
    // same raw-sign surface:
    //  - LEGACY enumerates non-primary EVM sign SURFACES with route-local policy
    //    only, including the vault.ts transfer + approval-
    //    transfer branches.
    //  - The inventory classifies each raw call by REACHABILITY: the two vault.ts
    //    primary/approval fallbacks are "migrated-invariant-guarded" (an
    //    invariant throws before them) even though the transfer surfaces they sit
    //    beside are legacy.
    // Reconcile at the file level: every file that appears in LEGACY must appear
    // in the inventory, and the inventory must be a superset (it also carries the
    // guarded primary-sign fallback that LEGACY does not list).
    const legacyFiles = new Set(LEGACY_EVM_SIGN_CALL_SITES.map((s) => s.file));
    const inventoryFiles = new Set(RAW_EVM_SIGN_INVENTORY.map((s) => s.file));
    for (const file of legacyFiles) {
      expect(inventoryFiles.has(file), `${file} must be in the raw-sign inventory`).toBe(true);
    }

    // The non-vault legacy files are pure legacy surfaces, so their inventory
    // rows must all be classified "legacy" and one-for-one with LEGACY.
    for (const file of inventoryFiles) {
      if (file === "packages/api/src/routes/vault.ts") continue;
      const invForFile = RAW_EVM_SIGN_INVENTORY.filter((s) => s.file === file);
      const legacyForFile = LEGACY_EVM_SIGN_CALL_SITES.filter((s) => s.file === file);
      expect(
        invForFile.every((s) => s.classification === "legacy"),
        `${file} raw calls must all be legacy-classified`,
      ).toBe(true);
      expect(
        invForFile.length,
        `${file} inventory count must equal its legacy call-site count`,
      ).toBe(legacyForFile.length);
    }
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
