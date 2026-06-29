import { afterAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { and, eq, evmWalletNonceInflight, evmWalletNonces, getDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { allocateEvmNonce, confirmEvmNonce, markEvmNonceDropped } from "../evm-nonce-manager";

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

  test("offline batch with no explicit nonce yields distinct incrementing nonces", async () => {
    const walletAddress = "0x3333333333333333333333333333333333333333";
    const nonces: number[] = [];
    for (let i = 0; i < 5; i++) {
      nonces.push(
        await allocateEvmNonce({
          walletAddress,
          chainId: 137,
          getPendingNonce: async () => 0,
        }),
      );
    }

    expect(nonces).toEqual([0, 1, 2, 3, 4]);
    const [row] = await getDb().select().from(evmWalletNonces);
    expect(row.nextNonce).toBe(5);
  });

  test("two different agentIds on the same wallet+chain do not collide (allocator ignores agentId)", async () => {
    const walletAddress = "0x4444444444444444444444444444444444444444";
    // The allocator API takes no agentId; both agents share the same
    // (wallet, chain) allocator and must receive distinct nonces.
    const agentAllocate = (_agentId: string) =>
      allocateEvmNonce({
        walletAddress,
        chainId: 8453,
        getPendingNonce: async () => 0,
      });

    const [a, b] = await Promise.all([agentAllocate("agent-one"), agentAllocate("agent-two")]);

    expect([a, b].sort((x, y) => x - y)).toEqual([0, 1]);
    const [row] = await getDb().select().from(evmWalletNonces);
    expect(row.nextNonce).toBe(2);
  });

  test("gap recovery reclaims a dropped nonce instead of leaving a hole", async () => {
    const walletAddress = "0x5555555555555555555555555555555555555555";
    const chainId = 8453;
    const alloc = () =>
      allocateEvmNonce({ walletAddress, chainId, getPendingNonce: async () => 5 });

    const n0 = await alloc(); // 5
    const n1 = await alloc(); // 6
    const n2 = await alloc(); // 7
    expect([n0, n1, n2]).toEqual([5, 6, 7]);

    // The middle tx fails -> its nonce becomes reclaimable.
    await markEvmNonceDropped({ walletAddress, chainId, nonce: 6 });

    // Next allocation must reuse 6 (>= pending), not advance to 8.
    const reclaimed = await alloc();
    expect(reclaimed).toBe(6);

    // Stored counter is untouched by a reclaim.
    const [counter] = await getDb().select().from(evmWalletNonces);
    expect(counter.nextNonce).toBe(8);

    // After the reclaim the only dropped row is gone; next allocation advances.
    const next = await alloc();
    expect(next).toBe(8);
  });

  test("a confirmed nonce is cleared and never reclaimed", async () => {
    const walletAddress = "0x6666666666666666666666666666666666666666";
    const chainId = 1;
    const alloc = () =>
      allocateEvmNonce({ walletAddress, chainId, getPendingNonce: async () => 0 });

    const n0 = await alloc(); // 0
    await alloc(); // 1
    expect(n0).toBe(0);

    // Confirm 0 (success) -> removed from in-flight, not reclaimable.
    await confirmEvmNonce({ walletAddress, chainId, nonce: 0 });
    const remaining = await getDb()
      .select()
      .from(evmWalletNonceInflight)
      .where(
        and(
          eq(evmWalletNonceInflight.walletAddress, walletAddress),
          eq(evmWalletNonceInflight.nonce, 0),
        ),
      );
    expect(remaining).toHaveLength(0);

    // Next allocation advances monotonically; the confirmed 0 is never reused.
    const next = await alloc();
    expect(next).toBe(2);
  });
});
