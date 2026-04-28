#!/usr/bin/env bun
/**
 * One-time OAuth account token encryption backfill.
 *
 * Run immediately after drizzle migration 0021_oauth_account_token_encryption:
 *   STEWARD_MASTER_PASSWORD=... bun run scripts/encrypt-oauth-account-tokens.ts
 *
 * The SQL migration renames access_token/refresh_token to *_encrypted so no
 * tokens are dropped. This script encrypts any renamed plaintext values that do
 * not yet have AES-GCM metadata. It is idempotent: rows with iv/tag/salt are
 * skipped.
 */

import { createDb, encryptOAuthAccountPlaintextTokens } from "@stwd/db";
import { KeyStore } from "@stwd/vault";

const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
if (!masterPassword) {
  throw new Error("STEWARD_MASTER_PASSWORD is required to encrypt OAuth provider tokens");
}

const { client, db } = createDb();
const keyStore = new KeyStore(masterPassword);
try {
  const count = await encryptOAuthAccountPlaintextTokens(db, keyStore);
  console.log(`[oauth-token-encryption] encrypted ${count} account row(s)`);
} finally {
  await client.end();
}
