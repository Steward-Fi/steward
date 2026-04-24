#!/usr/bin/env bun
/**
 * One-time OAuth account token encryption backfill.
 *
 * Run immediately after drizzle migration 0019_oauth_account_token_encryption:
 *   STEWARD_MASTER_PASSWORD=... bun run scripts/encrypt-oauth-account-tokens.ts
 *
 * The SQL migration renames access_token/refresh_token to *_encrypted so no
 * tokens are dropped. This script encrypts any renamed plaintext values that do
 * not yet have AES-GCM metadata. It is idempotent: rows with iv/tag/salt are
 * skipped.
 */

import { accounts, createDb } from "@stwd/db";
import { KeyStore } from "@stwd/vault";
import { eq } from "drizzle-orm";

export async function encryptOAuthAccountPlaintextTokens(
  db: Pick<ReturnType<typeof createDb>["db"], "select" | "update">,
  masterPassword: string,
): Promise<number> {
  if (!masterPassword) {
    throw new Error("STEWARD_MASTER_PASSWORD is required to encrypt OAuth provider tokens");
  }

  const keyStore = new KeyStore(masterPassword);
  const rows = await db.select().from(accounts);
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

const isEntrypoint = process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  const { client, db } = createDb();
  try {
    const count = await encryptOAuthAccountPlaintextTokens(db, masterPassword ?? "");
    console.log(`[oauth-token-encryption] encrypted ${count} account row(s)`);
  } finally {
    await client.end();
  }
}
