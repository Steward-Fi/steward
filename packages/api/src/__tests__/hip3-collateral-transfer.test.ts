import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const operatorRecoverySource = readFileSync(
  join(apiRoot, "routes", "operator-recovery.ts"),
  "utf8",
);
const appSource = readFileSync(join(apiRoot, "app.ts"), "utf8");

describe("HIP-3 collateral transfer route hardening", () => {
  test("mounts /:venue/transfer behind the operator recovery auth path", () => {
    expect(operatorRecoverySource).toContain('operatorRecoveryRoutes.post("/:venue/transfer"');
    expect(appSource).toContain('path.endsWith("/transfer")');
  });

  test("requires a platform key and rejects tenant/admin operator auth for transfers", () => {
    const route = operatorRecoverySource.slice(
      operatorRecoverySource.indexOf('operatorRecoveryRoutes.post("/:venue/transfer"'),
      operatorRecoverySource.indexOf("// ── POST /v1/trade/:venue/close-all"),
    );
    expect(route).toContain('c.get("authType") !== "platform"');
    expect(route).toContain("Platform key required for collateral transfer");
  });

  test("audits requested, failed, and submitted transfer events", () => {
    expect(operatorRecoverySource).toContain('"trade.recovery.transfer.requested"');
    expect(operatorRecoverySource).toContain('"trade.recovery.transfer.failed"');
    expect(operatorRecoverySource).toContain('"trade.recovery.transfer.submitted"');
  });

  test("uses the vault-backed adapter sendAsset path and documents the builder-dex exit story", () => {
    expect(operatorRecoverySource).toContain("adapter.signSendAsset");
    expect(operatorRecoverySource).toContain("adapter.submitSendAsset");
    expect(operatorRecoverySource).toContain('sourceDex "xyz" → destinationDex ""');
    expect(operatorRecoverySource).toContain("existing core-only withdraw route");
  });
});
