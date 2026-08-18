/**
 * Provider-case determinism (spec §9.2 acceptance gate).
 *
 *  - Deterministic manifest: two assemblies of the same committed case produce
 *    byte-identical manifests modulo the advisory `assembledAt` field.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { getProviderCase } from "../services/provider-case";
import { createAllowedCase, F, seedCaseFixture, wipeCase } from "./provider-case-fixture";

describe("case assembler purity + determinism", () => {
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
