// SEC-023/SEC-024 regression tests for Vault.importKey.
//
// SEC-023: importing a Solana key for a legacy (pre-multi-chain) agent used to
// delete the legacy encrypted_keys row — the sole store of the agent's EVM key —
// and insert a Solana-AAD row there, permanently bricking EVM signing.
//
// SEC-024: importKey used to upsert a server-managed key over a wallet row
// marked custody:"external", silently converting the wallet back to server
// custody while the metadata kept claiming external custody.

import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Keypair } from "@solana/web3.js";
import {
  agentWallets,
  and,
  encryptedChainKeys,
  encryptedKeys,
  eq,
  getDb,
  isNull,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { generatePrivateKey } from "viem/accounts";
import type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
} from "../external-key-custody";
import { Vault } from "../vault";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "test-vault-import-key";
const TENANT_ID = "import-tenant";

const openClients: Array<{ close: () => Promise<void> }> = [];

async function freshVault(provider?: ExternalKeyCustodyProvider): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Import Tenant",
    apiKeyHash: "import-hash",
  });

  return new Vault({ masterPassword: MASTER_PASSWORD, externalKeyCustodyProvider: provider });
}

function solanaKeyHex(): string {
  return Buffer.from(Keypair.generate().secretKey).toString("hex");
}

class RaceTestProvider implements ExternalKeyCustodyProvider {
  id = "race-test-provider";
  readonly contractVersion = 1 as const;
  registrationCalls = 0;

  async registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration> {
    this.registrationCalls += 1;
    return {
      custody: "external",
      tenantId: request.tenantId,
      agentId: request.agentId,
      chainFamily: request.chainFamily,
      address: request.address,
      handle: request.handle,
      venue: request.venue ?? null,
      purpose: request.purpose ?? null,
      metadata: request.metadata ?? {},
      registeredAt: new Date("2026-06-05T00:00:00.000Z"),
      exportablePrivateKey: false,
      signingAvailability: "not-supported",
    };
  }
}

describe("Vault.importKey custody hardening", () => {
  let vault: Vault;

  beforeEach(async () => {
    vault = await freshVault();
  });

  afterAll(async () => {
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
  });

  test("SEC-023: importing a Solana key preserves the legacy EVM encrypted_keys row", async () => {
    const agentId = "legacy-evm-agent";
    const evmKey = generatePrivateKey();
    await vault.importKey(TENANT_ID, agentId, evmKey, "evm");

    // Simulate a pre-multi-chain legacy agent: its EVM key lives ONLY in the
    // legacy encrypted_keys table (no encrypted_chain_keys / agent_wallets).
    await getDb()
      .delete(encryptedChainKeys)
      .where(
        and(eq(encryptedChainKeys.agentId, agentId), eq(encryptedChainKeys.chainFamily, "evm")),
      );
    await getDb()
      .delete(agentWallets)
      .where(and(eq(agentWallets.agentId, agentId), eq(agentWallets.chainFamily, "evm")));

    await vault.importKey(TENANT_ID, agentId, solanaKeyHex(), "solana");

    // The legacy row must survive untouched (exactly one row, still the EVM key).
    const legacyRows = await getDb()
      .select()
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, agentId));
    expect(legacyRows).toHaveLength(1);

    const keyStore = (
      vault as unknown as {
        keyStore: { decrypt: (row: unknown, ctx: unknown) => Promise<string> };
      }
    ).keyStore;
    const decrypted = await keyStore.decrypt(legacyRows[0], {
      tenantId: TENANT_ID,
      agentId,
      chainFamily: "evm",
      venue: null,
    });
    expect(decrypted.toLowerCase()).toBe(evmKey.toLowerCase());

    // The Solana key landed in the multi-wallet table as usual.
    const solRows = await getDb()
      .select()
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, "solana"),
          isNull(encryptedChainKeys.venue),
        ),
      );
    expect(solRows).toHaveLength(1);
  });

  test("SEC-024: importKey rejects wallets marked as external custody", async () => {
    const agentId = "external-custody-agent";
    await vault.createAgent(TENANT_ID, agentId, "External Custody Agent");
    await getDb()
      .update(agentWallets)
      .set({
        metadata: {
          custody: "external",
          externalKey: {
            providerId: "aws-kms",
            keyId: "arn:aws:kms:us-east-1:123:key/abc",
            registeredAt: new Date().toISOString(),
            exportablePrivateKey: false,
            signingAvailability: "sign-only",
          },
        },
      })
      .where(
        and(
          eq(agentWallets.agentId, agentId),
          eq(agentWallets.chainFamily, "evm"),
          isNull(agentWallets.venue),
        ),
      );

    const [before] = await getDb()
      .select({ ciphertext: encryptedChainKeys.ciphertext })
      .from(encryptedChainKeys)
      .where(
        and(eq(encryptedChainKeys.agentId, agentId), eq(encryptedChainKeys.chainFamily, "evm")),
      );

    await expect(vault.importKey(TENANT_ID, agentId, generatePrivateKey(), "evm")).rejects.toThrow(
      /external-custody/,
    );

    // The server-managed key material must be untouched by the rejected import.
    const [after] = await getDb()
      .select({ ciphertext: encryptedChainKeys.ciphertext })
      .from(encryptedChainKeys)
      .where(
        and(eq(encryptedChainKeys.agentId, agentId), eq(encryptedChainKeys.chainFamily, "evm")),
      );
    expect(after.ciphertext).toBe(before.ciphertext);
  });

  test("SEC-024: a Solana import is also rejected over an external-custody wallet", async () => {
    const agentId = "external-custody-sol-agent";
    await vault.createAgent(TENANT_ID, agentId, "External Sol Agent");
    await getDb()
      .update(agentWallets)
      .set({
        metadata: {
          custody: "external",
          externalKey: {
            providerId: "aws-kms",
            keyId: "arn:aws:kms:us-east-1:123:key/def",
            registeredAt: new Date().toISOString(),
            exportablePrivateKey: false,
            signingAvailability: "sign-only",
          },
        },
      })
      .where(
        and(
          eq(agentWallets.agentId, agentId),
          eq(agentWallets.chainFamily, "solana"),
          isNull(agentWallets.venue),
        ),
      );

    await expect(vault.importKey(TENANT_ID, agentId, solanaKeyHex(), "solana")).rejects.toThrow(
      /external-custody/,
    );
  });

  // Re-audit: the importKey / importExternalKeyHandle custody guards were
  // check-then-act with no DB-level serialization — two concurrent admin
  // custody ops for the same scope could interleave and BOTH commit, leaving
  // a server-managed key shadowing an external-custody wallet. The guards now
  // run inside a per-scope advisory-locked transaction, so exactly one
  // transition can commit and the loser fails closed.
  test("concurrent importKey and importExternalKeyHandle cannot both win a custody transition", async () => {
    vault = await freshVault(new RaceTestProvider());
    const agentId = "race-agent";
    await vault.createAgent(TENANT_ID, agentId, "Race Agent");
    // Bare agent: strip the server-managed rows createAgent provisioned so
    // both custody transitions start from an empty (evm, venue-less) scope.
    await getDb()
      .delete(encryptedChainKeys)
      .where(
        and(eq(encryptedChainKeys.agentId, agentId), eq(encryptedChainKeys.chainFamily, "evm")),
      );
    await getDb()
      .delete(agentWallets)
      .where(and(eq(agentWallets.agentId, agentId), eq(agentWallets.chainFamily, "evm")));

    const results = await Promise.allSettled([
      vault.importKey(TENANT_ID, agentId, generatePrivateKey(), "evm"),
      vault.importExternalKeyHandle({
        tenantId: TENANT_ID,
        agentId,
        chainFamily: "evm",
        address: "0x1111111111111111111111111111111111111111",
        handle: { providerId: "race-hsm", keyId: "key-1" },
      }),
    ]);

    // Exactly one custody transition may commit; the loser must fail closed.
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);

    // Final state must be consistent: never both a server-managed key AND an
    // external-custody wallet row in the same scope.
    const [chainKey] = await getDb()
      .select({ id: encryptedChainKeys.id })
      .from(encryptedChainKeys)
      .where(
        and(
          eq(encryptedChainKeys.agentId, agentId),
          eq(encryptedChainKeys.chainFamily, "evm"),
          isNull(encryptedChainKeys.venue),
        ),
      );
    const [wallet] = await getDb()
      .select({ metadata: agentWallets.metadata })
      .from(agentWallets)
      .where(
        and(
          eq(agentWallets.agentId, agentId),
          eq(agentWallets.chainFamily, "evm"),
          isNull(agentWallets.venue),
        ),
      );
    const walletIsExternal =
      wallet?.metadata != null &&
      typeof wallet.metadata === "object" &&
      (wallet.metadata as Record<string, unknown>).custody === "external";
    expect(chainKey != null && walletIsExternal).toBe(false);
  });

  test("rejects known local-custody conflicts before contacting the external provider", async () => {
    const provider = new RaceTestProvider();
    vault = await freshVault(provider);
    const agentId = "provider-precheck-agent";
    await vault.createAgent(TENANT_ID, agentId, "Provider Precheck Agent");
    // Exercise the multi-chain-key fast-fail specifically, not the older
    // legacy-key precheck. The local encrypted_chain_keys/wallet rows remain.
    await getDb().delete(encryptedKeys).where(eq(encryptedKeys.agentId, agentId));

    await expect(
      vault.importExternalKeyHandle({
        tenantId: TENANT_ID,
        agentId,
        chainFamily: "evm",
        address: "0x1111111111111111111111111111111111111111",
        handle: { providerId: "race-hsm", keyId: "must-not-be-disclosed" },
      }),
    ).rejects.toThrow(/server-managed/);
    expect(provider.registrationCalls).toBe(0);
  });

  test("rejects a legacy EVM key after a Solana import changes the primary wallet family", async () => {
    const provider = new RaceTestProvider();
    vault = await freshVault(provider);
    const agentId = "legacy-evm-after-solana-agent";

    await vault.importKey(TENANT_ID, agentId, generatePrivateKey(), "evm");
    // Reproduce a pre-multi-wallet EVM agent: only encrypted_keys retains its
    // EVM key. A later Solana import changes agents.walletAddress to Solana but
    // intentionally preserves that legacy EVM row (SEC-023).
    await getDb()
      .delete(encryptedChainKeys)
      .where(
        and(eq(encryptedChainKeys.agentId, agentId), eq(encryptedChainKeys.chainFamily, "evm")),
      );
    await getDb()
      .delete(agentWallets)
      .where(and(eq(agentWallets.agentId, agentId), eq(agentWallets.chainFamily, "evm")));
    await vault.importKey(TENANT_ID, agentId, solanaKeyHex(), "solana");

    await expect(
      vault.importExternalKeyHandle({
        tenantId: TENANT_ID,
        agentId,
        chainFamily: "evm",
        address: "0x1111111111111111111111111111111111111111",
        handle: { providerId: "race-hsm", keyId: "must-not-be-disclosed-after-solana" },
      }),
    ).rejects.toThrow(/legacy server-managed key/);
    expect(provider.registrationCalls).toBe(0);
  });

  // Structural guard (PGlite serializes transactions, so the lock itself is
  // exercised but cannot interleave here): both custody transitions must take
  // the advisory lock INSIDE their transaction, before any custody check or
  // write, and the provider call must stay outside the lock.
  test("custody transitions lock before their guards (source structure)", () => {
    const source = readFileSync(join(import.meta.dir, "..", "vault.ts"), "utf8");

    const importKeyBody = source.slice(
      source.indexOf("async importKey("),
      source.indexOf("async importExternalKeyHandle("),
    );
    const ikTx = importKeyBody.indexOf("await db.transaction(");
    const ikLock = importKeyBody.indexOf("pg_advisory_xact_lock");
    const ikGuard = importKeyBody.indexOf("isExternalKeyWalletMetadata(externalWallet.metadata)");
    expect(ikTx).toBeGreaterThanOrEqual(0);
    expect(ikLock).toBeGreaterThan(ikTx);
    expect(ikGuard).toBeGreaterThan(ikLock);
    expect(importKeyBody).toContain("custodyTransitionLockKey(tenantId, agentId, chainType, null)");
    expect(importKeyBody).toContain("hashtextextended");

    const importExternalBody = source.slice(
      source.indexOf("async importExternalKeyHandle("),
      source.indexOf("async registerExternalKeyHandle("),
    );
    const ieTx = importExternalBody.indexOf("await db.transaction(");
    const ieLock = importExternalBody.indexOf("pg_advisory_xact_lock");
    const ieGuard = importExternalBody.indexOf("over a server-managed signing key", ieLock);
    const ieWrite = importExternalBody.indexOf(".insert(agentWallets)");
    const ieProvider = importExternalBody.indexOf("registerKeyHandle(request)");
    expect(ieTx).toBeGreaterThanOrEqual(0);
    expect(ieLock).toBeGreaterThan(ieTx);
    expect(ieGuard).toBeGreaterThan(ieLock);
    expect(ieWrite).toBeGreaterThan(ieLock);
    expect(ieProvider).toBeGreaterThanOrEqual(0);
    expect(ieProvider).toBeLessThan(ieTx);
    expect(importExternalBody).toContain("hashtextextended");
  });
});
