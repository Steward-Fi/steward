import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const userSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");

describe("pregenerated wallet claim audit order", () => {
  it("writes authorization audit before decrypting pregenerated wallet keys", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/claim-pregenerated"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/recovery/setup"', routeStart);
    expect(routeEnd).toBeGreaterThan(routeStart);
    const route = userSource.slice(routeStart, routeEnd);

    const authorized = route.indexOf('action: "user.wallet.pregenerated_claim.authorized"');
    const exportPrivateKey = route.indexOf("vault.exportPrivateKey(");

    expect(authorized).toBeGreaterThanOrEqual(0);
    expect(exportPrivateKey).toBeGreaterThanOrEqual(0);
    expect(authorized).toBeLessThan(exportPrivateKey);
  });

  it("atomically consumes the claim token before decrypting pregenerated wallet keys", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/claim-pregenerated"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/recovery/setup"', routeStart);
    expect(routeEnd).toBeGreaterThan(routeStart);
    const route = userSource.slice(routeStart, routeEnd);

    const casClaim = route.indexOf("eq(agents.platformId, claimablePlatformId)");
    const claimedReturning = route.indexOf(".returning({ id: agents.id })", casClaim);
    const exportPrivateKey = route.indexOf("vault.exportPrivateKey(");

    expect(casClaim).toBeGreaterThanOrEqual(0);
    expect(claimedReturning).toBeGreaterThan(casClaim);
    expect(exportPrivateKey).toBeGreaterThanOrEqual(0);
    expect(claimedReturning).toBeLessThan(exportPrivateKey);
  });
});
