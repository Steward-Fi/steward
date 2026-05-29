import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routesDir = join(import.meta.dir, "..", "routes");
const authSource = readFileSync(join(routesDir, "auth.ts"), "utf8");
const userSource = readFileSync(join(routesDir, "user.ts"), "utf8");
const dbSchemaSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "db", "src", "schema.ts"),
  "utf8",
);

describe("wallet tenant preclaim hardening", () => {
  it("reserves wallet-auth tenant namespaces from self-serve tenant creation", () => {
    const reservedStart = userSource.indexOf("function isReservedTenantId");
    expect(reservedStart).toBeGreaterThanOrEqual(0);
    expect(userSource.indexOf('normalized.startsWith("eth:")', reservedStart)).toBeGreaterThan(
      reservedStart,
    );
    expect(userSource.indexOf('normalized.startsWith("t-")', reservedStart)).toBeGreaterThan(
      reservedStart,
    );
    expect(userSource.indexOf('normalized.startsWith("solana:")', reservedStart)).toBeGreaterThan(
      reservedStart,
    );
  });

  it("derives EVM wallet tenant ids from the full address", () => {
    const helperStart = authSource.indexOf("function ethereumWalletTenantId");
    expect(helperStart).toBeGreaterThanOrEqual(0);
    const verifyStart = authSource.indexOf('auth.post("/verify"', helperStart);
    expect(
      authSource.indexOf("return `eth:${address.toLowerCase()}`", helperStart),
    ).toBeGreaterThan(helperStart);
    expect(authSource.indexOf("ethereumWalletTenantId(address)", verifyStart)).toBeGreaterThan(
      verifyStart,
    );
    expect(authSource).not.toContain("tenantId: `t-${address.slice(2, 10)}`");
  });

  it("does not trust an id-conflicting wallet tenant unless ownerAddress matches", () => {
    const helperStart = authSource.indexOf("async function findOrCreateWalletTenant");
    expect(helperStart).toBeGreaterThanOrEqual(0);
    const conflictStart = authSource.indexOf("const [conflictingTenant]", helperStart);
    expect(
      authSource.indexOf("eq(tenants.ownerAddress, opts.ownerAddress)", helperStart),
    ).toBeLessThan(conflictStart);
    expect(conflictStart).toBeGreaterThan(helperStart);
    expect(
      authSource.indexOf(
        "Wallet tenant id is already reserved for a different owner",
        conflictStart,
      ),
    ).toBeGreaterThan(conflictStart);
    expect(authSource.indexOf("return { tenant: retryTenant", helperStart)).toBe(-1);
  });

  it("declares ownerAddress uniqueness for wallet tenant ownership", () => {
    expect(dbSchemaSource).toContain('uniqueIndex("tenants_owner_address_unique")');
    expect(dbSchemaSource).toContain("is not null");
  });
});
