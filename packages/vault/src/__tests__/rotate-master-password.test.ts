/**
 * DB-backed master-password / KDF-salt rotation test.
 *
 * Seeds real ciphertext via the production encrypt paths (Vault.createAgent /
 * Vault.importKey / Vault.createWallet, SecretVault.createSecret / rotateSecret /
 * deleteSecret, and the OAuth-token encryptor's contextless KeyStore), then
 * drives the ACTUAL rotation functions from scripts/rotate-master-password.ts
 * against an in-memory PGLite database.
 *
 * It proves the properties the old test could never observe:
 *   - every row decrypts under the NEW keystore WITH the correct AAD context +
 *     KDF domain, and FAILS under the OLD keystore;
 *   - soft-deleted secret versions are rotated (not skipped);
 *   - a re-run is fully idempotent (every row already-rotated, zero re-encrypts).
 *
 * No DATABASE_URL required — PGLite runs Postgres in-process via WASM, exactly
 * like the other vault DB tests (venue-scoping, secret-vault-lifecycle).
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  accounts,
  agents,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  secrets as secretsTable,
  tenants,
  users,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, isNotNull } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  buildRotationKeystores,
  rotateAccounts,
  rotateEncryptedChainKeys,
  rotateEncryptedKeys,
  rotateSecrets,
  rotateTable,
} from "../../../../scripts/rotate-master-password";
import { type EncryptedKey, KeyStore } from "../keystore";
import { SecretVault } from "../secret-vault";
import { Vault } from "../vault";

// PGLite boots Postgres-in-WASM and replays the full migration set in beforeAll,
// which can take well over the default per-hook timeout on a cold run.
setDefaultTimeout(120000);

const OLD_PW = "old-master-password-aaaaaaaaaaaaaaaaaaaa";
const OLD_SALT = "aa".repeat(16); // 32 hex chars / 16 bytes
const NEW_PW = "new-master-password-bbbbbbbbbbbbbbbbbbbb";
const NEW_SALT = "bb".repeat(16);

const TENANT_ID = "tenant-rotate";
let openClient: { close: () => Promise<void> } | undefined;
let savedKdfSalt: string | undefined;

beforeAll(async () => {
  // Vault/SecretVault read STEWARD_KDF_SALT at construction. Pin it to OLD_SALT
  // so the seeded ciphertext is derived from the OLD root.
  savedKdfSalt = process.env.STEWARD_KDF_SALT;
  process.env.STEWARD_KDF_SALT = OLD_SALT;
  process.env.STEWARD_PGLITE_MEMORY = "true";

  const { db, client } = await createPGLiteDb("memory://");
  openClient = client;
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Rotate Tenant", apiKeyHash: "rotate-hash" });
});

afterAll(async () => {
  await openClient?.close().catch(() => {});
  if (savedKdfSalt === undefined) delete process.env.STEWARD_KDF_SALT;
  else process.env.STEWARD_KDF_SALT = savedKdfSalt;
  delete process.env.STEWARD_PGLITE_MEMORY;
});

/** New-keystore roots used both by the rotators and by our assertions. */
function newRoots() {
  return {
    signing: new KeyStore(NEW_PW, NEW_SALT),
    secretDomain: new KeyStore(NEW_PW, NEW_SALT, "secret-vault"),
    legacy: new KeyStore(NEW_PW, NEW_SALT),
  };
}
function oldRoots() {
  return {
    signing: new KeyStore(OLD_PW, OLD_SALT),
    secretDomain: new KeyStore(OLD_PW, OLD_SALT, "secret-vault"),
    legacy: new KeyStore(OLD_PW, OLD_SALT),
  };
}

function decryptsUnder(ks: KeyStore, enc: EncryptedKey, ctx?: Parameters<KeyStore["decrypt"]>[1]) {
  try {
    ks.decrypt(enc, ctx);
    return true;
  } catch {
    return false;
  }
}

describe("master-password rotation (DB-backed, real encrypt paths)", () => {
  it("rotates every wallet key, secret, and OAuth token to the NEW root with correct context/domain", async () => {
    const db = getDb();
    const vault = new Vault({ masterPassword: OLD_PW });
    const secretVault = new SecretVault(OLD_PW);

    // ── Seed wallet keys (encrypted_keys + encrypted_chain_keys) ──────────────
    // createAgent writes the legacy EVM row + evm/solana chain-key rows.
    await vault.createAgent(TENANT_ID, "agent-a", "Agent A");
    // A second agent via createAgent for more chain-key rows.
    await vault.createAgent(TENANT_ID, "agent-b", "Agent B");
    // A venue-scoped wallet (non-null venue in the AAD).
    await vault.createWallet({
      agentId: "agent-a",
      venue: "hyperliquid",
      chainType: "evm",
      purpose: "perp",
    });
    // importKey overwrites agent-b's legacy EVM row + null-venue chain key.
    const importedPk = generatePrivateKey();
    await vault.importKey(TENANT_ID, "agent-b", importedPk, "evm");

    // ── Seed secrets: active + rotated (soft-deletes prior) + fully deleted ───
    await secretVault.createSecret(TENANT_ID, "openai", "sk-openai-v1");
    await secretVault.rotateSecret(TENANT_ID, "openai", "sk-openai-v2"); // v1 soft-deleted
    const toDelete = await secretVault.createSecret(TENANT_ID, "anthropic", "sk-ant-v1");
    await secretVault.deleteSecret(TENANT_ID, toDelete.id); // soft-deleted

    // Confirm there is at least one soft-deleted secret row to exercise that path.
    const softDeleted = await db
      .select({ id: secretsTable.id })
      .from(secretsTable)
      .where(and(eq(secretsTable.tenantId, TENANT_ID), isNotNull(secretsTable.deletedAt)));
    expect(softDeleted.length).toBeGreaterThanOrEqual(2);

    // ── Seed an OAuth-token accounts row (contextless undomained KeyStore) ────
    const oauthKs = new KeyStore(OLD_PW); // matches encryptOAuthProviderTokens
    const accessPt = "oauth-access-token-value";
    const refreshPt = "oauth-refresh-token-value";
    const encAccess = oauthKs.encrypt(accessPt);
    const encRefresh = oauthKs.encrypt(refreshPt);
    const [userRow] = await db
      .insert(users)
      .values({ email: "rotate-user@example.com" })
      .returning({ id: users.id });
    await db.insert(accounts).values({
      userId: userRow.id,
      provider: "google",
      providerAccountId: "google-123",
      accessTokenEncrypted: encAccess.ciphertext,
      accessTokenIv: encAccess.iv,
      accessTokenTag: encAccess.tag,
      accessTokenSalt: encAccess.salt,
      refreshTokenEncrypted: encRefresh.ciphertext,
      refreshTokenIv: encRefresh.iv,
      refreshTokenTag: encRefresh.tag,
      refreshTokenSalt: encRefresh.salt,
    });

    // Capture pre-rotation ciphertext so we can prove the rows actually changed.
    const beforeChainKeys = await db
      .select()
      .from(encryptedChainKeys)
      .orderBy(encryptedChainKeys.id);
    expect(beforeChainKeys.length).toBeGreaterThan(0);

    // ── Run the ACTUAL rotation (dryRun=false) ────────────────────────────────
    const ks = buildRotationKeystores(OLD_PW, OLD_SALT, NEW_PW, NEW_SALT);
    const results = [];
    for (const table of [
      "encrypted_keys",
      "encrypted_chain_keys",
      "secrets",
      "accounts",
    ] as const) {
      results.push(await rotateTable(table, db, ks, false));
    }

    // No row failed to decrypt under OLD/NEW.
    for (const res of results) {
      expect(res.failed).toEqual([]);
      expect(res.rotated).toBeGreaterThan(0);
      expect(res.alreadyRotated).toBe(0);
    }

    const NEW = newRoots();
    const OLD = oldRoots();

    // ── Assert encrypted_chain_keys: NEW decrypts w/ correct ctx, OLD fails ───
    const afterChainKeys = await db
      .select({
        id: encryptedChainKeys.id,
        agentId: encryptedChainKeys.agentId,
        chainFamily: encryptedChainKeys.chainFamily,
        venue: encryptedChainKeys.venue,
        ciphertext: encryptedChainKeys.ciphertext,
        iv: encryptedChainKeys.iv,
        tag: encryptedChainKeys.tag,
        salt: encryptedChainKeys.salt,
        tenantId: agents.tenantId,
      })
      .from(encryptedChainKeys)
      .innerJoin(agents, eq(encryptedChainKeys.agentId, agents.id))
      .orderBy(encryptedChainKeys.id);

    expect(afterChainKeys.length).toBe(beforeChainKeys.length);
    for (const row of afterChainKeys) {
      const enc: EncryptedKey = {
        ciphertext: row.ciphertext,
        iv: row.iv,
        tag: row.tag,
        salt: row.salt,
      };
      const ctx = {
        tenantId: row.tenantId,
        agentId: row.agentId,
        chainFamily: row.chainFamily,
        venue: row.venue ?? null,
      };
      // NEW root + correct context authenticates.
      expect(decryptsUnder(NEW.signing, enc, ctx)).toBe(true);
      // OLD root no longer authenticates (ciphertext was re-rooted).
      expect(decryptsUnder(OLD.signing, enc, ctx)).toBe(false);
      // Wrong AAD (no context) also fails — proves binding survived rotation.
      expect(decryptsUnder(NEW.signing, enc, undefined)).toBe(false);
    }

    // ── Assert encrypted_keys legacy row ──────────────────────────────────────
    const afterLegacy = await db
      .select({
        agentId: encryptedKeys.agentId,
        ciphertext: encryptedKeys.ciphertext,
        iv: encryptedKeys.iv,
        tag: encryptedKeys.tag,
        salt: encryptedKeys.salt,
        tenantId: agents.tenantId,
        walletAddress: agents.walletAddress,
      })
      .from(encryptedKeys)
      .innerJoin(agents, eq(encryptedKeys.agentId, agents.id));
    expect(afterLegacy.length).toBe(2);
    for (const row of afterLegacy) {
      const enc: EncryptedKey = {
        ciphertext: row.ciphertext,
        iv: row.iv,
        tag: row.tag,
        salt: row.salt,
      };
      const family = row.walletAddress.startsWith("0x") ? "evm" : "solana";
      const ctx = {
        tenantId: row.tenantId,
        agentId: row.agentId,
        chainFamily: family,
        venue: null,
      };
      expect(decryptsUnder(NEW.signing, enc, ctx)).toBe(true);
      expect(decryptsUnder(OLD.signing, enc, ctx)).toBe(false);
    }
    // The imported EVM key must round-trip to its exact plaintext under NEW.
    const importedAgent = afterLegacy.find((r) => r.agentId === "agent-b");
    expect(importedAgent).toBeDefined();
    if (importedAgent) {
      const pt = NEW.signing.decrypt(
        {
          ciphertext: importedAgent.ciphertext,
          iv: importedAgent.iv,
          tag: importedAgent.tag,
          salt: importedAgent.salt,
        },
        {
          tenantId: importedAgent.tenantId,
          agentId: "agent-b",
          chainFamily: "evm",
          venue: null,
        },
      );
      expect(pt).toBe(importedPk);
      // The derived address is unchanged — proves the plaintext key is intact.
      expect(privateKeyToAccount(pt as `0x${string}`).address).toBe(
        privateKeyToAccount(importedPk).address,
      );
    }

    // ── Assert secrets (including soft-deleted) under the secret-vault domain ─
    const afterSecrets = await db
      .select()
      .from(secretsTable)
      .where(eq(secretsTable.tenantId, TENANT_ID));
    // 3 versions: openai v1 (deleted), openai v2 (active), anthropic v1 (deleted).
    expect(afterSecrets.length).toBe(3);
    for (const row of afterSecrets) {
      const enc: EncryptedKey = {
        ciphertext: row.ciphertext,
        iv: row.iv,
        tag: row.authTag,
        salt: row.salt,
      };
      const ctx = { tenantId: row.tenantId, name: row.name, version: row.version };
      // NEW domain root + correct context authenticates — even soft-deleted rows.
      expect(decryptsUnder(NEW.secretDomain, enc, ctx)).toBe(true);
      // OLD domain root fails.
      expect(decryptsUnder(OLD.secretDomain, enc, ctx)).toBe(false);
      // A NEW root WITHOUT the secret-vault domain must also fail (domain bound).
      expect(decryptsUnder(NEW.legacy, enc, ctx)).toBe(false);
    }
    // Plaintext fidelity for the active version.
    const openaiV2 = afterSecrets.find((r) => r.name === "openai" && r.version === 2);
    expect(openaiV2).toBeDefined();
    if (openaiV2) {
      const pt = NEW.secretDomain.decrypt(
        {
          ciphertext: openaiV2.ciphertext,
          iv: openaiV2.iv,
          tag: openaiV2.authTag,
          salt: openaiV2.salt,
        },
        { tenantId: openaiV2.tenantId, name: "openai", version: 2 },
      );
      expect(pt).toBe("sk-openai-v2");
    }

    // ── Assert accounts (OAuth tokens) ────────────────────────────────────────
    const [acct] = await db.select().from(accounts);
    expect(acct).toBeDefined();
    const encAccessAfter: EncryptedKey = {
      ciphertext: acct.accessTokenEncrypted as string,
      iv: acct.accessTokenIv as string,
      tag: acct.accessTokenTag as string,
      salt: acct.accessTokenSalt as string,
    };
    const encRefreshAfter: EncryptedKey = {
      ciphertext: acct.refreshTokenEncrypted as string,
      iv: acct.refreshTokenIv as string,
      tag: acct.refreshTokenTag as string,
      salt: acct.refreshTokenSalt as string,
    };
    expect(NEW.legacy.decrypt(encAccessAfter)).toBe(accessPt);
    expect(NEW.legacy.decrypt(encRefreshAfter)).toBe(refreshPt);
    expect(decryptsUnder(OLD.legacy, encAccessAfter, undefined)).toBe(false);
    expect(decryptsUnder(OLD.legacy, encRefreshAfter, undefined)).toBe(false);
  });

  it("is fully idempotent on a re-run (all rows already-rotated, zero re-encrypts)", async () => {
    const db = getDb();
    const ks = buildRotationKeystores(OLD_PW, OLD_SALT, NEW_PW, NEW_SALT);

    // Snapshot ciphertext before the second run.
    const before = await db
      .select({ id: encryptedChainKeys.id, ct: encryptedChainKeys.ciphertext })
      .from(encryptedChainKeys)
      .orderBy(encryptedChainKeys.id);

    const second = [
      await rotateEncryptedKeys(db, ks.signing, false),
      await rotateEncryptedChainKeys(db, ks.signing, false),
      await rotateSecrets(db, ks.secretDomain, ks.legacy, false),
      await rotateAccounts(db, ks.legacy, false),
    ];

    for (const res of second) {
      expect(res.rotated).toBe(0);
      expect(res.failed).toEqual([]);
      expect(res.alreadyRotated).toBeGreaterThan(0);
    }

    // Idempotent: ciphertext is byte-identical (no needless re-encryption that
    // would otherwise churn IV/salt on every run).
    const after = await db
      .select({ id: encryptedChainKeys.id, ct: encryptedChainKeys.ciphertext })
      .from(encryptedChainKeys)
      .orderBy(encryptedChainKeys.id);
    expect(after).toEqual(before);
  });

  it("dry-run verifies without mutating, and records undecryptable rows instead of throwing", async () => {
    const db = getDb();

    // Inject a deliberately corrupt encrypted_chain_keys row (garbage ciphertext)
    // under a fresh agent. It must be recorded as failed, not abort the table.
    const evmPk = generatePrivateKey();
    const addr = privateKeyToAccount(evmPk).address;
    await db.insert(agents).values({
      id: "agent-corrupt",
      tenantId: TENANT_ID,
      name: "Corrupt",
      walletAddress: addr,
    });
    await db.insert(encryptedChainKeys).values({
      agentId: "agent-corrupt",
      chainFamily: "evm",
      venue: null,
      ciphertext: "deadbeef",
      iv: "00".repeat(16),
      tag: "11".repeat(16),
      salt: "22".repeat(16),
    });

    const ks = buildRotationKeystores(OLD_PW, OLD_SALT, NEW_PW, NEW_SALT);

    // Snapshot a known-good (already NEW-rooted) row to prove dry-run is read-only.
    const [goodBefore] = await db
      .select()
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, "agent-a"))
      .limit(1);

    const res = await rotateEncryptedChainKeys(db, ks.signing, true);

    // The corrupt row is recorded; good rows are NOT counted as failed.
    expect(res.failed.length).toBe(1);
    expect(res.failed[0]).toContain("agent-corrupt");
    // Already-rotated good rows are detected even in dry-run.
    expect(res.alreadyRotated).toBeGreaterThan(0);

    // Dry-run wrote nothing.
    const [goodAfter] = await db
      .select()
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, "agent-a"))
      .limit(1);
    expect(goodAfter).toEqual(goodBefore);
  });
});
