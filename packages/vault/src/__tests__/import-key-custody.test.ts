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
import { Vault } from "../vault";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "test-vault-import-key";
const TENANT_ID = "import-tenant";

const openClients: Array<{ close: () => Promise<void> }> = [];

async function freshVault(): Promise<Vault> {
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

  return new Vault({ masterPassword: MASTER_PASSWORD });
}

function solanaKeyHex(): string {
  return Buffer.from(Keypair.generate().secretKey).toString("hex");
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
});
