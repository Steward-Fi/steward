import { afterAll, describe, expect, it } from "bun:test";
import { createDb, eq, tenantConfigs, tenants } from "@stwd/db";
import { buildRotationKeystores, rotateTable } from "../../../../scripts/rotate-master-password";
import type { EncryptedKey } from "../keystore";
import { KeyStore } from "../keystore";

const url = process.env.STEWARD_ROTATION_REAL_PG_URL;
const suite = url ? describe : describe.skip;
const OLD_PASSWORD = "real-pg-old-master-password-aaaaaaaa";
const OLD_SALT = "aa".repeat(16);
const NEW_PASSWORD = "real-pg-new-master-password-bbbbbbbb";
const NEW_SALT = "bb".repeat(16);
const tenantId = `rotation-real-pg-${process.pid}`;
const connection = url ? createDb(url) : null;

suite("master-password rotation real PostgreSQL transaction", () => {
  afterAll(async () => {
    if (!connection) return;
    await connection.db
      .delete(tenants)
      .where(eq(tenants.id, tenantId))
      .catch(() => {});
    await connection.client.end();
  });

  it("rolls back re-encryption after an injected mid-transaction failure", async () => {
    if (!connection) throw new Error("real PostgreSQL URL missing");
    const { db } = connection;
    await db.insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: tenantId });
    const oldEncrypted = new KeyStore(OLD_PASSWORD, OLD_SALT).encrypt("real-pg-plaintext");
    await db.insert(tenantConfigs).values({
      tenantId,
      emailConfig: {
        provider: "resend",
        from: "rotation-real-pg@example.com",
        apiKeyEncrypted: JSON.stringify(oldEncrypted),
      },
    });

    const roots = buildRotationKeystores(OLD_PASSWORD, OLD_SALT, NEW_PASSWORD, NEW_SALT);
    await expect(
      db.transaction(async (tx) => {
        const result = await rotateTable("tenant_email_configs", tx as never, roots, false);
        expect(result.failed).toEqual([]);
        throw new Error("injected real PostgreSQL failure");
      }),
    ).rejects.toThrow("injected real PostgreSQL failure");

    const [row] = await db.select().from(tenantConfigs).where(eq(tenantConfigs.tenantId, tenantId));
    const encrypted = JSON.parse(row.emailConfig?.apiKeyEncrypted ?? "") as EncryptedKey;
    expect(new KeyStore(OLD_PASSWORD, OLD_SALT).decrypt(encrypted)).toBe("real-pg-plaintext");
    expect(() => new KeyStore(NEW_PASSWORD, NEW_SALT).decrypt(encrypted)).toThrow();
  });
});
