import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { evmWalletNonces, getDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { allocateEvmNonce } from "../evm-nonce-manager";

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

async function resetDb(): Promise<void> {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });
}

describe("EVM nonce manager", () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterAll(async () => {
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("allocates distinct monotonic nonces for concurrent requests from one wallet", async () => {
    const walletAddress = "0x1111111111111111111111111111111111111111";
    const allocations = await Promise.all(
      Array.from({ length: 8 }, () =>
        allocateEvmNonce({
          walletAddress,
          chainId: 8453,
          getPendingNonce: async () => 7,
        }),
      ),
    );

    expect([...allocations].sort((a, b) => a - b)).toEqual([7, 8, 9, 10, 11, 12, 13, 14]);
    const [row] = await getDb().select().from(evmWalletNonces);
    expect(row.nextNonce).toBe(15);
  });

  test("advances from max(stored next nonce, pending RPC nonce)", async () => {
    const walletAddress = "0x2222222222222222222222222222222222222222";
    await getDb().insert(evmWalletNonces).values({
      walletAddress,
      chainId: 1,
      nextNonce: 3,
      updatedAt: new Date(),
    });

    const nonce = await allocateEvmNonce({
      walletAddress,
      chainId: 1,
      getPendingNonce: async () => 10,
    });

    expect(nonce).toBe(10);
    const [row] = await getDb().select().from(evmWalletNonces);
    expect(row.nextNonce).toBe(11);
  });
});
