import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import type { StewardReleaseReadinessInspection } from "@stwd/db/steward-release-readiness";
import { PgDialect } from "drizzle-orm/pg-core";

import {
  assertStewardOwnedPluginMigrationReadiness,
  createStewardReleaseReadinessProbe,
  ordinaryDrizzleMigrationReadinessQuery,
  resolveStewardMigrationReadinessConfig,
} from "../services/steward-release-readiness";

function readyInspection(schema: "public" | "steward"): StewardReleaseReadinessInspection {
  return {
    status: "ready",
    schema,
    core: {
      status: "already_applied",
      schema,
      bundleHash: "a".repeat(64),
      verifiedExisting: ["0083_provider_approval_quorum"],
      preflight: null,
    },
    authSchema: {
      status: "ready",
      schema,
      expectedCount: 2,
      appliedCount: 2,
      forwardCount: 0,
      expectedTip: "0001_passkey_rp_provenance_0114",
      rpProvenance: true,
    },
  };
}

describe("Steward production migration readiness configuration", () => {
  it("defaults ordinary installations to the Drizzle contract", () => {
    expect(resolveStewardMigrationReadinessConfig({})).toEqual({ mode: "drizzle" });
  });

  it("does not let SKIP_MIGRATIONS alone satisfy production readiness", () => {
    expect(() =>
      resolveStewardMigrationReadinessConfig({
        NODE_ENV: "production",
        SKIP_MIGRATIONS: "1",
      }),
    ).toThrow(/requires an explicit STEWARD_MIGRATION_READINESS_MODE/);
    expect(
      resolveStewardMigrationReadinessConfig({
        NODE_ENV: "production",
        SKIP_MIGRATIONS: "1",
        STEWARD_MIGRATION_READINESS_MODE: "drizzle",
      }),
    ).toEqual({ mode: "drizzle" });
  });

  it("requires an allowlisted explicit schema for Steward-owned readiness", () => {
    expect(
      resolveStewardMigrationReadinessConfig({
        STEWARD_MIGRATION_READINESS_MODE: "steward-owned",
        STEWARD_CORE_REPAIR_EXPECTED_SCHEMA: "steward",
      }),
    ).toEqual({ mode: "steward-owned", expectedSchema: "steward" });

    expect(() =>
      resolveStewardMigrationReadinessConfig({
        STEWARD_MIGRATION_READINESS_MODE: "steward-owned",
      }),
    ).toThrow(/EXPECTED_SCHEMA is required/);
    expect(() =>
      resolveStewardMigrationReadinessConfig({
        STEWARD_MIGRATION_READINESS_MODE: "auto",
        STEWARD_CORE_REPAIR_EXPECTED_SCHEMA: "steward",
      }),
    ).toThrow(/must be drizzle or steward-owned/);
  });
});

describe("Steward-owned plugin migration readiness", () => {
  const stewardOwned = {
    mode: "steward-owned" as const,
    expectedSchema: "steward" as const,
  };

  it("preserves ordinary Drizzle behavior for schema-owning plugins", () => {
    expect(() =>
      assertStewardOwnedPluginMigrationReadiness({ mode: "drizzle" }, new Set(["capabilities"])),
    ).not.toThrow();
  });

  it("allows steward-owned mode when all enabled plugins are schema-less", () => {
    expect(() =>
      assertStewardOwnedPluginMigrationReadiness(stewardOwned, new Set(["trading", "wxmr"])),
    ).not.toThrow();
  });

  it("fails closed with a clear diagnostic for an unreviewed schema owner", () => {
    expect(() =>
      assertStewardOwnedPluginMigrationReadiness(
        stewardOwned,
        new Set(["trading", "capabilities"]),
      ),
    ).toThrow(
      /no reviewed migration\/readiness contract.*schema-owning plugin\(s\): capabilities/i,
    );
  });

  it("runs the guard before app composition and the listener", () => {
    const indexSource = readFileSync(new URL("../index.ts", import.meta.url), "utf8");
    const guardCall = indexSource.indexOf(
      "assertStewardOwnedPluginMigrationReadiness(migrationReadinessConfig, enabledPlugins);",
    );
    expect(guardCall).toBeGreaterThan(-1);
    expect(guardCall).toBeLessThan(indexSource.indexOf("await composeApp()"));
    expect(guardCall).toBeLessThan(indexSource.indexOf("Bun.serve(serverOptions)"));
  });
});

describe("ordinary Drizzle migration readiness query", () => {
  it("orders the consumed outer ledger rows by migration id", () => {
    const query = new PgDialect().sqlToQuery(ordinaryDrizzleMigrationReadinessQuery());
    expect(query.sql).toMatch(
      /LEFT JOIN LATERAL \([\s\S]+\) AS migrations ON TRUE\s+ORDER BY migrations\.id ASC\s*$/,
    );
  });
});

describe("Steward production migration readiness probe", () => {
  it("deduplicates concurrent checks and caches only inside its bounded TTL", async () => {
    let now = 1_000;
    let calls = 0;
    let releaseFirst: (() => void) | undefined;
    const firstBlocked = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const probe = createStewardReleaseReadinessProbe({
      expectedSchema: "steward",
      ttlMs: 1_000,
      now: () => now,
      inspect: async () => {
        calls += 1;
        if (calls === 1) await firstBlocked;
        return readyInspection("steward");
      },
    });

    const first = probe();
    const concurrent = probe();
    expect(calls).toBe(1);
    releaseFirst?.();
    await expect(Promise.all([first, concurrent])).resolves.toHaveLength(2);

    now = 1_999;
    await probe();
    expect(calls).toBe(1);
    now = 2_000;
    await probe();
    expect(calls).toBe(2);
  });

  it("briefly caches a failed inspection to bound hostile probe load, then recovers", async () => {
    let now = 1_000;
    let calls = 0;
    const probe = createStewardReleaseReadinessProbe({
      expectedSchema: "steward",
      ttlMs: 1_000,
      failureTtlMs: 1_000,
      now: () => now,
      inspect: async () => {
        calls += 1;
        if (calls === 1) throw new Error("catalog mismatch");
        return readyInspection("steward");
      },
    });

    await expect(probe()).rejects.toThrow("catalog mismatch");
    await expect(probe()).rejects.toThrow("catalog mismatch");
    expect(calls).toBe(1);
    now = 2_000;
    await expect(probe()).resolves.toMatchObject({ status: "ready", schema: "steward" });
    expect(calls).toBe(2);
  });
});
