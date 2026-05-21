// Sprint 4 Phase 1 Day 3: tests for the default Sol policy seeder.

import { afterAll, beforeEach, describe, expect, test } from "bun:test";

import { agents, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

import { seedSolDefaultPolicy } from "../sol-default-policy";

const openClients: Array<{ close: () => Promise<void> }> = [];

async function freshDb(): Promise<void> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });
  await getDb().insert(tenants).values({
    id: "test-tenant",
    name: "Test",
    apiKeyHash: "h",
  });
  await getDb().insert(agents).values({
    id: "sol",
    tenantId: "test-tenant",
    name: "Sol",
    walletAddress: "0x0000000000000000000000000000000000000001",
  });
}

describe("seedSolDefaultPolicy", () => {
  beforeEach(async () => {
    await freshDb();
  });

  afterAll(async () => {
    // Close every PGLite client we opened so Bun's process exits cleanly
    // under CI (exit code 99 otherwise on dangling async handles).
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
  });

  test("creates spending-limit, venue-allowlist, and leverage-cap policies", async () => {
    const result = await seedSolDefaultPolicy({ agentId: "sol" });

    expect(result.agentId).toBe("sol");
    expect(result.created.length).toBe(3);
    expect(result.preserved.length).toBe(0);

    const rows = await getDb().select().from(policies).where(eq(policies.agentId, "sol"));
    const types = rows.map((r) => r.type).sort();
    expect(types).toEqual(["leverage-cap", "spending-limit", "venue-allowlist"]);
  });

  test("default config matches the Phase 1 spec", async () => {
    await seedSolDefaultPolicy({ agentId: "sol" });

    const rows = await getDb().select().from(policies).where(eq(policies.agentId, "sol"));
    const byType = new Map(rows.map((r) => [r.type, r.config]));

    expect(byType.get("spending-limit")).toEqual({ maxPerDayUsd: 100 });
    expect(byType.get("venue-allowlist")).toEqual({ allowedVenues: ["hyperliquid"] });
    expect(byType.get("leverage-cap")).toEqual({ maxLeverage: 2 });
  });

  test("preserveExisting=true is idempotent (default)", async () => {
    await seedSolDefaultPolicy({ agentId: "sol" });
    const second = await seedSolDefaultPolicy({ agentId: "sol" });

    expect(second.created.length).toBe(0);
    expect(second.preserved.length).toBe(3);

    const rows = await getDb().select().from(policies).where(eq(policies.agentId, "sol"));
    expect(rows.length).toBe(3);
  });

  test("preserveExisting=false re-seeds (replaces existing rows)", async () => {
    await seedSolDefaultPolicy({ agentId: "sol" });
    const second = await seedSolDefaultPolicy({ agentId: "sol", preserveExisting: false });

    expect(second.created.length).toBe(3);
    expect(second.preserved.length).toBe(0);

    const rows = await getDb().select().from(policies).where(eq(policies.agentId, "sol"));
    expect(rows.length).toBe(3);
  });

  test("respects custom overrides", async () => {
    const result = await seedSolDefaultPolicy({
      agentId: "sol",
      dailyUsd: 500,
      allowedVenues: ["hyperliquid", "polymarket"],
      maxLeverage: 5,
    });

    expect(result.created.length).toBe(3);

    const rows = await getDb().select().from(policies).where(eq(policies.agentId, "sol"));
    const byType = new Map(rows.map((r) => [r.type, r.config]));

    expect(byType.get("spending-limit")).toEqual({ maxPerDayUsd: 500 });
    expect(byType.get("venue-allowlist")).toEqual({
      allowedVenues: ["hyperliquid", "polymarket"],
    });
    expect(byType.get("leverage-cap")).toEqual({ maxLeverage: 5 });
  });

  test("refuses to seed when the agent row is missing (clear error)", async () => {
    await expect(seedSolDefaultPolicy({ agentId: "ghost" })).rejects.toThrow(
      /agent ghost not found/,
    );
  });
});
