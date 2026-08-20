/**
 * SEC-164 regression test: forced re-encryption of pre-domain-separation
 * secret rows (legacy undomained root → domain-separated `secret-vault` root).
 *
 * Seeds REAL ciphertext through the production encrypt path (KeyStore with no
 * domain label, exactly what pre-separation SecretVault builds wrote), then
 * drives SecretVault.migrateLegacyRootSecrets against in-memory PGLite and
 * proves:
 *   - legacy rows (including SOFT-DELETED versions) are re-encrypted in place,
 *     preserving id/tenantId/name/version (the AAD context);
 *   - the walk is idempotent (rerun migrates zero rows);
 *   - corrupt rows are reported, never silently rewritten or dropped;
 *   - STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK=false makes the compat decrypt
 *     fallback fail closed, and migrated rows keep decrypting with it off.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { closeDb, eq, getDb, secrets, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { type EncryptedKey, KeyStore } from "../keystore";
import { SecretVault } from "../secret-vault";

// PGLite boots Postgres-in-WASM and replays the migration set in beforeAll.
setDefaultTimeout(120000);

const MASTER_PASSWORD = "legacy-root-migration-master-password";
const KDF_SALT = "cc".repeat(16); // 32 hex chars / 16 bytes
const TENANT_ID = "tenant-legacy-root";

let vault: SecretVault;
let openClient: { close: () => Promise<void> } | undefined;
let savedKdfSalt: string | undefined;
let savedFallback: string | undefined;

beforeAll(async () => {
  // KeyStore reads STEWARD_KDF_SALT at construction; pin it so every root in
  // this file (vault + assertion keystores) derives from the same salt.
  savedKdfSalt = process.env.STEWARD_KDF_SALT;
  savedFallback = process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK;
  process.env.STEWARD_KDF_SALT = KDF_SALT;
  delete process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK;
  process.env.STEWARD_PGLITE_MEMORY = "true";

  const { db, client } = await createPGLiteDb("memory://");
  openClient = client;
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  vault = new SecretVault(MASTER_PASSWORD);
  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Legacy Root Tenant", apiKeyHash: "legacy-root-hash" });
});

afterAll(async () => {
  await openClient?.close().catch(() => {});
  await closeDb().catch(() => {});
  if (savedKdfSalt === undefined) delete process.env.STEWARD_KDF_SALT;
  else process.env.STEWARD_KDF_SALT = savedKdfSalt;
  if (savedFallback === undefined) delete process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK;
  else process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK = savedFallback;
  delete process.env.STEWARD_PGLITE_MEMORY;
});

/** The undomained root pre-separation secrets were written under. */
const legacyRoot = () => new KeyStore(MASTER_PASSWORD);
/** The domain-separated root all new secrets are written under. */
const domainRoot = () => new KeyStore(MASTER_PASSWORD, undefined, "secret-vault");

function contextFor(row: { tenantId: string; name: string; version: number }) {
  return { tenantId: row.tenantId, name: row.name, version: row.version };
}

function rawEnc(row: {
  ciphertext: string;
  iv: string;
  authTag: string;
  salt: string;
}): EncryptedKey {
  return { ciphertext: row.ciphertext, iv: row.iv, tag: row.authTag, salt: row.salt };
}

function decryptsUnder(
  ks: KeyStore,
  enc: EncryptedKey,
  ctx: Parameters<KeyStore["decrypt"]>[1],
): boolean {
  try {
    ks.decrypt(enc, ctx);
    return true;
  } catch {
    return false;
  }
}

/** Insert a secret row encrypted under the LEGACY root, as pre-separation writes did. */
async function insertLegacySecret(name: string, value: string, opts?: { deleted?: boolean }) {
  const enc = legacyRoot().encrypt(value, { tenantId: TENANT_ID, name, version: 1 });
  const [row] = await getDb()
    .insert(secrets)
    .values({
      tenantId: TENANT_ID,
      name,
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      authTag: enc.tag,
      salt: enc.salt,
      version: 1,
      ...(opts?.deleted ? { deletedAt: new Date() } : {}),
    })
    .returning();
  return row;
}

async function freshRow(id: string) {
  const [row] = await getDb().select().from(secrets).where(eq(secrets.id, id));
  if (!row) throw new Error(`row ${id} vanished`);
  return row;
}

describe("SEC-164 legacy-root secret re-encryption", () => {
  let legacyActiveId: string;
  let legacyDeletedId: string;

  it("reads seeded legacy-root rows via the (default-enabled) fallback", async () => {
    await vault.createSecret(TENANT_ID, "domain-secret", "domain-value");
    const legacyActive = await insertLegacySecret("legacy-active", "legacy-value-a");
    const legacyDeleted = await insertLegacySecret("legacy-deleted", "legacy-value-d", {
      deleted: true,
    });
    legacyActiveId = legacyActive.id;
    legacyDeletedId = legacyDeleted.id;

    // Compat fallback (default on) keeps the pre-separation row readable.
    expect(await vault.decryptSecret(TENANT_ID, legacyActiveId)).toBe("legacy-value-a");
    // ...but it does NOT authenticate under the domain root.
    expect(decryptsUnder(domainRoot(), rawEnc(legacyActive), contextFor(legacyActive))).toBe(false);
  });

  it("dry-run classifies every row and writes nothing", async () => {
    const res = await vault.migrateLegacyRootSecrets({ dryRun: true });
    expect(res).toEqual({ scanned: 3, migrated: 2, alreadyDomainSeparated: 1, failed: [] });

    // Nothing was re-encrypted: the legacy rows are still legacy-only.
    const row = await freshRow(legacyActiveId);
    expect(decryptsUnder(domainRoot(), rawEnc(row), contextFor(row))).toBe(false);
    expect(decryptsUnder(legacyRoot(), rawEnc(row), contextFor(row))).toBe(true);
  });

  it("write mode re-encrypts legacy rows in place under the domain root (incl. soft-deleted)", async () => {
    const before = await freshRow(legacyDeletedId);
    const res = await vault.migrateLegacyRootSecrets();
    expect(res).toEqual({ scanned: 3, migrated: 2, alreadyDomainSeparated: 1, failed: [] });

    for (const [id, value] of [
      [legacyActiveId, "legacy-value-a"],
      [legacyDeletedId, "legacy-value-d"],
    ] as const) {
      const row = await freshRow(id);
      const enc = rawEnc(row);
      // Now authenticates under the DOMAIN root with the SAME AAD context...
      expect(decryptsUnder(domainRoot(), enc, contextFor(row))).toBe(true);
      // ...and no longer under the legacy root.
      expect(decryptsUnder(legacyRoot(), enc, contextFor(row))).toBe(false);
      // In place: identity + AAD-relevant fields untouched.
      expect(row.name).toBe(id === legacyActiveId ? "legacy-active" : "legacy-deleted");
      expect(row.version).toBe(1);
      expect(row.tenantId).toBe(TENANT_ID);
      // The plaintext survived the move exactly.
      expect(domainRoot().decrypt(enc, contextFor(row))).toBe(value);
    }

    // Soft-deleted ciphertext really was rewritten (not skipped).
    const after = await freshRow(legacyDeletedId);
    expect(after.ciphertext).not.toBe(before.ciphertext);

    // The production read path still returns the value (now via the primary root).
    expect(await vault.decryptSecret(TENANT_ID, legacyActiveId)).toBe("legacy-value-a");
  });

  it("is idempotent on rerun", async () => {
    const res = await vault.migrateLegacyRootSecrets();
    expect(res).toEqual({ scanned: 3, migrated: 0, alreadyDomainSeparated: 3, failed: [] });
  });

  it("does not overwrite a concurrent secret re-encryption from a stale classified row", async () => {
    const concurrent = await insertLegacySecret("legacy-concurrent", "stale-value");
    const context = contextFor(concurrent);
    const replacement = domainRoot().encrypt("concurrent-value", context);
    const realDb = getDb();
    const originalUpdate = realDb.update.bind(realDb);
    let injected = false;
    const migrationDb = new Proxy(realDb, {
      get(target, property, receiver) {
        if (property !== "update") return Reflect.get(target, property, receiver);
        return ((table: Parameters<typeof originalUpdate>[0]) => {
          const updateBuilder = originalUpdate(table);
          return {
            set(values: Parameters<typeof updateBuilder.set>[0]) {
              const setBuilder = updateBuilder.set(values);
              return {
                where(condition: Parameters<typeof setBuilder.where>[0]) {
                  const whereBuilder = setBuilder.where(condition);
                  return {
                    async returning(fields: Parameters<typeof whereBuilder.returning>[0]) {
                      if (!injected) {
                        injected = true;
                        // Deterministically emulate a password rotation after
                        // classification and immediately before our stale CAS.
                        await originalUpdate(secrets)
                          .set({
                            ciphertext: replacement.ciphertext,
                            iv: replacement.iv,
                            authTag: replacement.tag,
                            salt: replacement.salt,
                          })
                          .where(eq(secrets.id, concurrent.id));
                      }
                      return whereBuilder.returning(fields);
                    },
                  };
                },
              };
            },
          };
        }) as typeof realDb.update;
      },
    });

    try {
      const res = await vault.migrateLegacyRootSecrets({ db: migrationDb });
      expect(res.failed).toContain(concurrent.id);
      expect(res.migrated).toBe(0);
      const row = await freshRow(concurrent.id);
      expect(domainRoot().decrypt(rawEnc(row), context)).toBe("concurrent-value");
    } finally {
      await getDb().delete(secrets).where(eq(secrets.id, concurrent.id));
    }
  });

  it("fails closed with the fallback disabled, until the row is migrated", async () => {
    const late = await insertLegacySecret("legacy-late", "legacy-value-c");
    process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK = "false";
    try {
      // Fallback disabled: the legacy row is unreadable (fail closed).
      await expect(vault.decryptSecret(TENANT_ID, late.id)).rejects.toThrow();

      // The migration itself does not depend on the fallback gate...
      const res = await vault.migrateLegacyRootSecrets();
      expect(res).toEqual({ scanned: 4, migrated: 1, alreadyDomainSeparated: 3, failed: [] });
      // ...and the migrated row decrypts through the primary path with the flag still off.
      expect(await vault.decryptSecret(TENANT_ID, late.id)).toBe("legacy-value-c");
    } finally {
      delete process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK;
    }
  });

  it("defaults the legacy-root fallback off in production unless explicitly acknowledged", async () => {
    const late = await insertLegacySecret("legacy-production", "legacy-production-value");
    const priorNodeEnv = process.env.NODE_ENV;
    delete process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK;
    process.env.NODE_ENV = "production";
    try {
      await expect(vault.decryptSecret(TENANT_ID, late.id)).rejects.toThrow();
      process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK = "true";
      expect(await vault.decryptSecret(TENANT_ID, late.id)).toBe("legacy-production-value");
    } finally {
      delete process.env.STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK;
      if (priorNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = priorNodeEnv;
      await getDb().delete(secrets).where(eq(secrets.id, late.id));
    }
  });

  it("reports rows that authenticate under neither root and leaves them untouched", async () => {
    const [corrupt] = await getDb()
      .insert(secrets)
      .values({
        tenantId: TENANT_ID,
        name: "corrupt",
        ciphertext: "deadbeef",
        iv: "00".repeat(16),
        authTag: "00".repeat(16),
        salt: "00".repeat(16),
        version: 1,
      })
      .returning();
    try {
      const res = await vault.migrateLegacyRootSecrets();
      expect(res.failed).toEqual([corrupt.id]);
      expect(res.migrated).toBe(0);
      // Untouched, byte for byte.
      expect((await freshRow(corrupt.id)).ciphertext).toBe("deadbeef");
    } finally {
      await getDb().delete(secrets).where(eq(secrets.id, corrupt.id));
    }
  });
});
