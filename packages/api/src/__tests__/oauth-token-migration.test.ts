import { afterAll, describe, expect, test } from "bun:test";
import { accounts, encryptOAuthAccountPlaintextTokens, users } from "@stwd/db";
import { createPGLiteDb } from "@stwd/db/pglite";
import { KeyStore } from "@stwd/vault";
import { eq } from "drizzle-orm";

const MASTER_PASSWORD = "oauth-migration-test-master";

describe("OAuth account token encryption migration", () => {
  afterAll(() => {
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("encrypts seeded plaintext values left by the column rename", async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");

    try {
      const [user] = await db
        .insert(users)
        .values({ email: "migration-oauth@example.com", emailVerified: true })
        .returning();

      const [account] = await db
        .insert(accounts)
        .values({
          userId: user.id,
          provider: "github",
          providerAccountId: "github-user-1",
          accessTokenEncrypted: "legacy-access-token",
          refreshTokenEncrypted: "legacy-refresh-token",
        })
        .returning();

      const encryptedRows = await encryptOAuthAccountPlaintextTokens(
        db,
        new KeyStore(MASTER_PASSWORD),
      );
      expect(encryptedRows).toBe(1);

      const [updated] = await db.select().from(accounts).where(eq(accounts.id, account.id));
      expect(updated.accessTokenEncrypted).not.toBe("legacy-access-token");
      expect(updated.refreshTokenEncrypted).not.toBe("legacy-refresh-token");
      expect(updated.accessTokenIv).toMatch(/^[0-9a-f]{32}$/);
      expect(updated.accessTokenTag).toMatch(/^[0-9a-f]{32}$/);
      expect(updated.accessTokenSalt).toMatch(/^[0-9a-f]{32}$/);

      const keyStore = new KeyStore(MASTER_PASSWORD);
      expect(
        keyStore.decrypt({
          ciphertext: updated.accessTokenEncrypted!,
          iv: updated.accessTokenIv!,
          tag: updated.accessTokenTag!,
          salt: updated.accessTokenSalt!,
        }),
      ).toBe("legacy-access-token");
      expect(
        keyStore.decrypt({
          ciphertext: updated.refreshTokenEncrypted!,
          iv: updated.refreshTokenIv!,
          tag: updated.refreshTokenTag!,
          salt: updated.refreshTokenSalt!,
        }),
      ).toBe("legacy-refresh-token");

      const encryptedAgain = await encryptOAuthAccountPlaintextTokens(
        db,
        new KeyStore(MASTER_PASSWORD),
      );
      expect(encryptedAgain).toBe(0);
    } finally {
      await client.close();
    }
  });
});
