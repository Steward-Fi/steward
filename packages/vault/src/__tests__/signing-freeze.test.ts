import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { getDb, tenants, vaultSigningFreezes } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { isVaultSigningFrozenError } from "../signing-freeze";
import { Vault } from "../vault";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "test-vault-signing-freeze";
const TENANT_ID = "freeze-tenant";
const AGENT_ID = "freeze-agent";
const openClients: Array<{ close: () => Promise<void> }> = [];

async function freshVault(): Promise<Vault> {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Freeze Tenant",
    apiKeyHash: "freeze-hash",
  });

  const vault = new Vault({ masterPassword: MASTER_PASSWORD });
  await vault.createAgent(TENANT_ID, AGENT_ID, "Freeze Agent");
  return vault;
}

describe("vault signing freeze", () => {
  let vault: Vault;

  beforeEach(async () => {
    vault = await freshVault();
  });

  afterAll(async () => {
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("agent freeze blocks signing before key decryption", async () => {
    await getDb().insert(vaultSigningFreezes).values({
      tenantId: TENANT_ID,
      scopeType: "agent",
      agentId: AGENT_ID,
      reason: "compromised agent",
      createdByType: "user",
      createdById: "admin",
    });

    let decryptCalls = 0;
    const keyStore = (vault as unknown as { keyStore: { decrypt: (...args: unknown[]) => string } })
      .keyStore;
    keyStore.decrypt = () => {
      decryptCalls += 1;
      throw new Error("decrypt should not run while frozen");
    };

    let thrown: unknown;
    try {
      await vault.signMessage(TENANT_ID, AGENT_ID, "blocked");
    } catch (error) {
      thrown = error;
    }

    expect(isVaultSigningFrozenError(thrown)).toBe(true);
    expect(decryptCalls).toBe(0);
  });
});
