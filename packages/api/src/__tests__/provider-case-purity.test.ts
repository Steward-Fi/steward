/**
 * evidence static purity + determinism (spec §9.2 acceptance gate).
 *
 *  - The case assemblers are PURE READS: provider-case.ts contains no
 *    INSERT/UPDATE/DELETE against audit_events (or any mutating write). The only
 *    exported assemblers are getProviderCase / getProviderCaseEvidence.
 *  - Deterministic manifest: two assemblies of the same committed case produce
 *    byte-identical manifests modulo the advisory `assembledAt` field.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { getProviderCase } from "../services/provider-case";
import { createAllowedCase, F, seedCaseFixture, wipeCase } from "./provider-case-fixture";

const SERVICE_SRC = join(import.meta.dir, "..", "services", "provider-case.ts");

describe("evidence case assembler purity + determinism", () => {
  test("provider-case.ts contains no mutating write to audit_events (pure read)", () => {
    const src = readFileSync(SERVICE_SRC, "utf8");
    // No INSERT/UPDATE/DELETE against audit_events anywhere in the assembler.
    expect(/insert\s+into\s+audit_events/i.test(src)).toBe(false);
    expect(/update\s+audit_events/i.test(src)).toBe(false);
    expect(/delete\s+from\s+audit_events/i.test(src)).toBe(false);
    // No Drizzle mutation builders on the audit tables / bindings from here.
    expect(/\.insert\(/.test(src)).toBe(false);
    expect(/\.update\(/.test(src)).toBe(false);
    expect(/\.delete\(/.test(src)).toBe(false);
    // The ONLY public assemblers.
    expect(src.includes("export async function getProviderCase")).toBe(true);
    expect(src.includes("export async function getProviderCaseEvidence")).toBe(true);
  });

  describe("determinism (PGLite)", () => {
    beforeAll(async () => {
      process.env.STEWARD_PGLITE_MEMORY = "true";
      process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
      const { db, client } = await createPGLiteDb("memory://");
      setPGLiteOverride(db, async () => client.close());
    });
    afterAll(async () => {
      await closeDb();
      delete process.env.STEWARD_PGLITE_MEMORY;
    });
    beforeEach(async () => {
      await wipeCase();
      await seedCaseFixture();
    });

    test("two assemblies of the same case are byte-identical modulo assembledAt", async () => {
      const intentId = await createAllowedCase();
      const a = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE]);
      const b = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE]);
      expect(a).not.toBeNull();
      expect(b).not.toBeNull();
      const norm = (m: object) => JSON.stringify({ ...m, assembledAt: "X" });
      expect(norm(a!.manifest)).toBe(norm(b!.manifest));
    });
  });
});
