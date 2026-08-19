import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { eq, evmWalletNonceInflight, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { type Hex, keccak256 } from "viem";
import { ExternalBroadcastOutcomeUnknownError } from "../external-key-custody";
import { Vault } from "../vault";

setDefaultTimeout(30_000);

const TENANT_ID = "local-broadcast-tenant";
const AGENT_ID = "local-broadcast-agent";
const CHAIN_ID = 84532;
const openClients: Array<{ close: () => Promise<void> }> = [];

function jsonRpcResponse(id: number, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result });
}

describe("local EVM broadcast wiring", () => {
  afterAll(async () => {
    for (const client of openClients) await client.close().catch(() => {});
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("public Vault signing checkpoints before one raw broadcast and retains an ambiguous nonce", async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    openClients.push(client);
    setPGLiteOverride(db as never, async () => client.close());
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Local Broadcast Tenant",
      apiKeyHash: "local-broadcast-hash",
    });

    const vault = new Vault({ masterPassword: "local-broadcast-password" });
    const identity = await vault.createAgent(TENANT_ID, AGENT_ID, "Local Broadcast Agent");
    const originalFetch = globalThis.fetch;
    const rpcEvents: string[] = [];
    let rawBroadcasts = 0;

    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as {
        id: number;
        method: string;
        params?: unknown[];
      };
      rpcEvents.push(body.method);

      if (body.method === "eth_chainId") return jsonRpcResponse(body.id, "0x14a34");
      if (body.method === "eth_getTransactionCount") return jsonRpcResponse(body.id, "0x0");
      if (body.method === "eth_estimateGas") return jsonRpcResponse(body.id, "0x5208");
      if (body.method === "eth_gasPrice") return jsonRpcResponse(body.id, "0x3b9aca00");
      if (body.method === "eth_maxPriorityFeePerGas") {
        return jsonRpcResponse(body.id, "0x3b9aca00");
      }
      if (body.method === "eth_getBlockByNumber") {
        return jsonRpcResponse(body.id, {
          baseFeePerGas: "0x3b9aca00",
          difficulty: "0x0",
          extraData: "0x",
          gasLimit: "0x1c9c380",
          gasUsed: "0x0",
          hash: `0x${"11".repeat(32)}`,
          logsBloom: `0x${"00".repeat(256)}`,
          miner: `0x${"00".repeat(20)}`,
          mixHash: `0x${"22".repeat(32)}`,
          nonce: "0x0000000000000000",
          number: "0x1",
          parentHash: `0x${"33".repeat(32)}`,
          receiptsRoot: `0x${"44".repeat(32)}`,
          sha3Uncles: `0x${"55".repeat(32)}`,
          size: "0x1",
          stateRoot: `0x${"66".repeat(32)}`,
          timestamp: "0x1",
          totalDifficulty: "0x0",
          transactions: [],
          transactionsRoot: `0x${"77".repeat(32)}`,
          uncles: [],
        });
      }
      if (body.method === "eth_sendRawTransaction") {
        rawBroadcasts += 1;
        const [checkpoint] = await getDb()
          .select({ status: transactions.status, txHash: transactions.txHash })
          .from(transactions)
          .where(eq(transactions.agentId, AGENT_ID));
        const serialized = body.params?.[0] as Hex;
        expect(checkpoint).toEqual({
          status: "outcome_unknown",
          txHash: keccak256(serialized),
        });
        throw new Error("response lost after submit");
      }
      if (body.method === "eth_getTransactionByHash") return jsonRpcResponse(body.id, null);
      throw new Error(`Unexpected JSON-RPC method: ${body.method}`);
    }) as typeof fetch;

    try {
      const error = await vault
        .signTransaction({
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          to: `0x${"aa".repeat(20)}`,
          value: "1",
          chainId: CHAIN_ID,
          gasLimit: "21000",
        })
        .catch((cause) => cause);

      expect(error).toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
      expect(rawBroadcasts).toBe(1);
      expect(rpcEvents.filter((method) => method === "eth_sendRawTransaction")).toHaveLength(1);
      expect(rpcEvents).toContain("eth_getTransactionByHash");

      const [inflight] = await getDb()
        .select({ nonce: evmWalletNonceInflight.nonce, state: evmWalletNonceInflight.state })
        .from(evmWalletNonceInflight)
        .where(eq(evmWalletNonceInflight.walletAddress, identity.walletAddress.toLowerCase()));
      expect(inflight).toEqual({ nonce: 0, state: "allocated" });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
