/**
 * No-read-back property of the SecretVault custody plane (sovereign-custody
 * Pillar A / A2, converged from PR #245's sibling age store onto the EXISTING
 * plane).
 *
 * Bidirectional proof:
 *   - EXERCISE WORKS: `exerciseSecret` decrypts, hands the plaintext to a
 *     caller closure, and returns the closure's RESULT — never the secret.
 *   - GET IS IMPOSSIBLE: every metadata surface (getSecret / getSecretById /
 *     listSecrets) is proven value-free, and the prototype surface pin below
 *     means a future `getSecretValue`-style method cannot appear without
 *     failing this suite with a classification instruction.
 *   - FAIL-CLOSED AUDIT: the `beforeUse` chokepoint runs BEFORE decryption;
 *     if it throws (e.g. a failed audit append), the secret is never
 *     decrypted and the closure never runs.
 *
 * The repo-wide caller inventory for the remaining direct-decrypt callers
 * lives in secret-no-read-back-inventory.test.ts.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "../secret-vault";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "no-read-back-master-password";
const vault = new SecretVault(MASTER_PASSWORD);

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
});

async function ensureTenant(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
}

describe("SecretVault no-read-back: exercise works", () => {
  it("hands the plaintext to the closure and returns the closure result only", async () => {
    const tenantId = `tenant-nrb-exercise-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    const secretValue = "dummy-bot-token-abc123";
    const secret = await vault.createSecret(tenantId, "discord-bot-token", secretValue);

    let seenInsideClosure: string | undefined;
    const result = await vault.exerciseSecret(tenantId, secret.id, (plaintext) => {
      seenInsideClosure = plaintext;
      // The closure returns a RESULT (here: a derived length), not the secret.
      return { used: true, length: plaintext.length };
    });

    expect(seenInsideClosure).toBe(secretValue);
    expect(result).toEqual({ used: true, length: secretValue.length });
    // The result object carries no secret material.
    expect(JSON.stringify(result)).not.toContain(secretValue);
  });

  it("supports async closures (broker-a-call shape)", async () => {
    const tenantId = `tenant-nrb-async-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    const secret = await vault.createSecret(tenantId, "api-key", "sk-dummy-async");

    const status = await vault.exerciseSecret(tenantId, secret.id, async (plaintext) => {
      expect(plaintext).toBe("sk-dummy-async");
      return 200;
    });
    expect(status).toBe(200);
  });
});

describe("SecretVault no-read-back: fail-closed audit chokepoint", () => {
  it("a throwing beforeUse prevents decryption: the closure never runs", async () => {
    const tenantId = `tenant-nrb-audit-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    const secret = await vault.createSecret(tenantId, "webhook-secret", "whsec-dummy");

    let closureRan = false;
    await expect(
      vault.exerciseSecret(
        tenantId,
        secret.id,
        () => {
          closureRan = true;
          return null;
        },
        {
          beforeUse: () => {
            throw new Error("audit append failed");
          },
        },
      ),
    ).rejects.toThrow("audit append failed");
    expect(closureRan).toBe(false);
  });

  it("beforeUse is not invoked for a missing secret", async () => {
    const tenantId = `tenant-nrb-missing-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);

    let beforeUseRan = false;
    await expect(
      vault.exerciseSecret(tenantId, crypto.randomUUID(), () => null, {
        beforeUse: () => {
          beforeUseRan = true;
        },
      }),
    ).rejects.toThrow(/not found/);
    expect(beforeUseRan).toBe(false);
  });

  it("expired secrets cannot be exercised", async () => {
    const tenantId = `tenant-nrb-expired-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    const secret = await vault.createSecret(tenantId, "expiring", "short-lived-dummy", {
      expiresAt: new Date(Date.now() - 60_000),
    });

    let closureRan = false;
    await expect(
      vault.exerciseSecret(tenantId, secret.id, () => {
        closureRan = true;
        return null;
      }),
    ).rejects.toThrow(/expired/);
    expect(closureRan).toBe(false);
  });
});

describe("SecretVault no-read-back: get is impossible", () => {
  it("metadata surfaces never leak the value (or ciphertext material)", async () => {
    const tenantId = `tenant-nrb-meta-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    const secretValue = "sk-super-secret-value-xyz-789";
    const created = await vault.createSecret(tenantId, "openai", secretValue, {
      description: "test key",
    });

    const byName = await vault.getSecret(tenantId, "openai");
    const byId = await vault.getSecretById(tenantId, created.id);
    const listed = await vault.listSecrets(tenantId);

    for (const surface of [created, byName, byId, listed]) {
      const serialized = JSON.stringify(surface);
      expect(serialized).not.toContain(secretValue);
      expect(serialized).not.toContain("ciphertext");
      expect(serialized).not.toContain("authTag");
    }

    // The metadata shape is EXACTLY the value-free field set. A new field must
    // be added here deliberately (and must never be the plaintext).
    expect(Object.keys(byId ?? {}).sort()).toEqual([
      "createdAt",
      "description",
      "expiresAt",
      "id",
      "name",
      "rotatedAt",
      "tenantId",
      "updatedAt",
      "version",
    ]);
  });

  it("pins the full SecretVault method surface and its plaintext-capable subset", () => {
    // If this test fails because you added a method: classify it. If it can
    // return plaintext directly to a caller, DO NOT add it. Prefer exerciseSecret
    // / exerciseSecretRow (use-only closures). The direct-return decrypt methods
    // exist solely for the pinned proxy-injection / provider-refresh callers (see
    // the inventory test).
    const methods = Object.getOwnPropertyNames(SecretVault.prototype)
      .filter((name) => name !== "constructor")
      .sort();
    expect(methods).toEqual([
      "createRoute",
      "createRouteWithinTx",
      "createSecret",
      "createSecretWithinTx",
      "decryptSecret",
      "decryptSecretRow",
      "deleteRoute",
      "deleteSecret",
      "exerciseSecret",
      "exerciseSecretRow",
      "getRoute",
      "getSecret",
      "getSecretById",
      "listRoutes",
      "listSecrets",
      "migrateLegacyRootSecrets",
      "rotateSecret",
      "rotateSecretWithinTx",
      "toMetadata",
      "updateRoute",
      "updateRouteWithinTx",
    ]);

    // The plaintext-capable subset is exactly these two direct-return methods
    // plus the use-only exerciseSecret/exerciseSecretRow closures. Everything else
    // returns metadata/routes. (migrateLegacyRootSecrets handles plaintext
    // internally but returns row COUNTS only — like rotateSecret, it never
    // surfaces a value to its caller.)
    const plaintextCapable = [
      "decryptSecret",
      "decryptSecretRow",
      "exerciseSecret",
      "exerciseSecretRow",
    ];
    for (const name of plaintextCapable) {
      expect(methods).toContain(name);
    }
  });
});
