import { afterAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
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
const scriptPath = fileURLToPath(
  new URL("../../../../scripts/rotate-master-password.ts", import.meta.url),
);

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

  // A completion audit event runs AFTER the transaction commits. If it fails
  // (e.g. STEWARD_AUDIT_HMAC_KEY absent), the ciphertext is already durable, so
  // the script must report COMPLETE (not ABORTED), exit non-1, exit promptly
  // (no hung audit pool), and leave the data rotated to the NEW root. Reporting
  // a committed rotation as aborted would invite a catastrophic backup restore.
  it("reports COMPLETE not ABORTED when the post-commit audit event fails, and exits cleanly", () => {
    if (!url) throw new Error("real PostgreSQL URL missing");
    const auditTenant = `${tenantId}-audit`;
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? "",
      DATABASE_URL: url,
      STEWARD_MASTER_PASSWORD: OLD_PASSWORD,
      STEWARD_KDF_SALT: OLD_SALT,
      STEWARD_MASTER_PASSWORD_NEW: NEW_PASSWORD,
      STEWARD_KDF_SALT_NEW: NEW_SALT,
      // NODE_ENV=production forces the audit key to be mandatory; leaving
      // STEWARD_AUDIT_HMAC_KEY unset makes the post-commit audit write throw.
      NODE_ENV: "production",
    };

    // Seed one rotatable row under the OLD root just before the run.
    const seedOld = new KeyStore(OLD_PASSWORD, OLD_SALT).encrypt("audit-path-plaintext");
    return (async () => {
      const { db } = connection ?? createDb(url);
      await db
        .insert(tenants)
        .values({ id: auditTenant, name: auditTenant, apiKeyHash: auditTenant });
      await db.insert(tenantConfigs).values({
        tenantId: auditTenant,
        emailConfig: {
          provider: "resend",
          from: "audit-path@example.com",
          apiKeyEncrypted: JSON.stringify(seedOld),
        },
      });

      const result = spawnSync("bun", ["run", scriptPath, "--confirm"], {
        env,
        encoding: "utf8",
        timeout: 60_000,
      });

      // Exited (not killed by the 60s timeout => no hung audit pool).
      expect(result.signal).toBeNull();
      const output = `${result.stdout}\n${result.stderr}`;
      expect(output).toContain("ROTATION COMPLETE");
      expect(output).toContain("do NOT restore the backup");
      expect(output).not.toContain("ROTATION ABORTED");
      // Distinct non-zero status for the missing audit record, never the plain
      // abort code 1.
      expect(result.status).not.toBe(1);
      expect(result.status).toBe(2);

      // The row is genuinely rotated to the NEW root despite the audit failure.
      const [after] = await db
        .select()
        .from(tenantConfigs)
        .where(eq(tenantConfigs.tenantId, auditTenant));
      const enc = JSON.parse(after.emailConfig?.apiKeyEncrypted ?? "") as EncryptedKey;
      expect(new KeyStore(NEW_PASSWORD, NEW_SALT).decrypt(enc)).toBe("audit-path-plaintext");
      expect(() => new KeyStore(OLD_PASSWORD, OLD_SALT).decrypt(enc)).toThrow();

      await db
        .delete(tenants)
        .where(eq(tenants.id, auditTenant))
        .catch(() => {});
    })();
  });
});
