import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { agents, encryptedChainKeys, encryptedKeys, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Vault } from "../vault";

const MASTER_PASSWORD = "test-vault-mnemonic-restore";
const TENANT_ID = "mnemonic-restore-tenant";
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

async function freshVault(): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Mnemonic Restore Tenant",
    apiKeyHash: "test-hash",
  });

  return new Vault({ masterPassword: MASTER_PASSWORD });
}

describe("Vault mnemonic restore", () => {
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

  test("creates a missing recoverable wallet from a mnemonic", async () => {
    const restored = await vault.restoreAgentFromMnemonic(
      TENANT_ID,
      "recoverable-agent",
      "Recoverable Agent",
      TEST_MNEMONIC,
      { walletType: "recoverable_user", platformId: "user:user-1" },
    );

    expect(restored.restoredExisting).toBe(false);
    expect(restored.walletAddress).toBe("0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    expect(restored.walletAddresses?.solana).toBeTruthy();
  });

  test("derives distinct deterministic identities for indexed recoverable wallets", async () => {
    const first = await vault.restoreAgentFromMnemonic(
      TENANT_ID,
      "recoverable-agent",
      "Recoverable Agent",
      TEST_MNEMONIC,
      { walletType: "recoverable_user", platformId: "user:user-1" },
    );
    const second = await vault.restoreAgentFromMnemonic(
      TENANT_ID,
      "recoverable-agent-1",
      "Recoverable Agent 1",
      TEST_MNEMONIC,
      {
        walletType: "recoverable_user",
        platformId: "user:user-1",
        evmIndex: 1,
        solanaAccount: 1,
      },
    );

    expect(first.walletAddress).toBe("0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    expect(second.walletAddress).not.toBe(first.walletAddress);
    expect(second.walletAddresses?.solana).toBeTruthy();
    expect(second.walletAddresses?.solana).not.toBe(first.walletAddresses?.solana);
  });

  test("re-encrypts keys for an existing recoverable wallet only when identity matches", async () => {
    await vault.createAgentFromMnemonic(
      TENANT_ID,
      "recoverable-agent",
      "Recoverable Agent",
      TEST_MNEMONIC,
      {
        walletType: "recoverable_user",
      },
    );
    await getDb().delete(encryptedKeys).where(eq(encryptedKeys.agentId, "recoverable-agent"));
    await getDb()
      .delete(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, "recoverable-agent"));

    const restored = await vault.restoreAgentFromMnemonic(
      TENANT_ID,
      "recoverable-agent",
      "Recoverable Agent",
      TEST_MNEMONIC,
      { walletType: "recoverable_user" },
    );

    expect(restored.restoredExisting).toBe(true);
    const [legacyKey] = await getDb()
      .select({ agentId: encryptedKeys.agentId })
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, "recoverable-agent"));
    expect(legacyKey?.agentId).toBe("recoverable-agent");
    const chainKeys = await getDb()
      .select({ chainFamily: encryptedChainKeys.chainFamily })
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, "recoverable-agent"));
    expect(chainKeys.map((row) => row.chainFamily).sort()).toEqual(["evm", "solana"]);
  });

  test("refuses an existing unrelated wallet instead of replacing it", async () => {
    const random = await vault.createAgent(TENANT_ID, "random-agent", "Random Agent");
    expect(random.walletAddress).not.toBe("0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

    await expect(
      vault.restoreAgentFromMnemonic(TENANT_ID, "random-agent", "Random Agent", TEST_MNEMONIC, {
        walletType: "recoverable_user",
      }),
    ).rejects.toThrow(/not mnemonic-recoverable/);
  });

  test("refuses mismatched mnemonic for a recoverable wallet", async () => {
    await vault.createAgentFromMnemonic(
      TENANT_ID,
      "recoverable-agent",
      "Recoverable Agent",
      TEST_MNEMONIC,
      {
        walletType: "recoverable_user",
      },
    );
    await getDb()
      .update(agents)
      .set({ walletAddress: "0x000000000000000000000000000000000000dEaD" })
      .where(eq(agents.id, "recoverable-agent"));

    await expect(
      vault.restoreAgentFromMnemonic(
        TENANT_ID,
        "recoverable-agent",
        "Recoverable Agent",
        TEST_MNEMONIC,
        { walletType: "recoverable_user" },
      ),
    ).rejects.toThrow(/does not match/);
  });
});
