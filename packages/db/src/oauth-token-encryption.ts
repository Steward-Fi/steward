/**
 * OAuth account token encryption helper.
 *
 * Idempotent: rows that already have AES-GCM metadata (iv/tag/salt) are
 * skipped, so this is safe to run multiple times.
 *
 * Used by:
 * - `scripts/encrypt-oauth-account-tokens.ts` (operator one-shot CLI)
 * - `packages/db/src/__tests__/oauth-token-migration.test.ts` (regression test)
 */

import { KeyStore } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { accounts } from "./schema-auth";

type DbLike = {
  select: (...args: unknown[]) => {
    from: (table: typeof accounts) => Promise<(typeof accounts.$inferSelect)[]>;
  };
  update: (table: typeof accounts) => {
    set: (values: Partial<typeof accounts.$inferInsert>) => {
      where: (predicate: unknown) => Promise<unknown>;
    };
  };
};

export async function encryptOAuthAccountPlaintextTokens(
  db: DbLike,
  masterPassword: string,
): Promise<number> {
  if (!masterPassword) {
    throw new Error("STEWARD_MASTER_PASSWORD is required to encrypt OAuth provider tokens");
  }

  const keyStore = new KeyStore(masterPassword);
  // biome-ignore lint/suspicious/noExplicitAny: drizzle's typed select chain is hard to express here
  const rows = (await (db as any).select().from(accounts)) as (typeof accounts.$inferSelect)[];
  let encryptedCount = 0;

  for (const row of rows) {
    const updates: Partial<typeof accounts.$inferInsert> = {};

    if (
      row.accessTokenEncrypted &&
      !(row.accessTokenIv && row.accessTokenTag && row.accessTokenSalt)
    ) {
      const encrypted = keyStore.encrypt(row.accessTokenEncrypted);
      updates.accessTokenEncrypted = encrypted.ciphertext;
      updates.accessTokenIv = encrypted.iv;
      updates.accessTokenTag = encrypted.tag;
      updates.accessTokenSalt = encrypted.salt;
    }

    if (
      row.refreshTokenEncrypted &&
      !(row.refreshTokenIv && row.refreshTokenTag && row.refreshTokenSalt)
    ) {
      const encrypted = keyStore.encrypt(row.refreshTokenEncrypted);
      updates.refreshTokenEncrypted = encrypted.ciphertext;
      updates.refreshTokenIv = encrypted.iv;
      updates.refreshTokenTag = encrypted.tag;
      updates.refreshTokenSalt = encrypted.salt;
    }

    if (Object.keys(updates).length > 0) {
      await db.update(accounts).set(updates).where(eq(accounts.id, row.id));
      encryptedCount += 1;
    }
  }

  return encryptedCount;
}
