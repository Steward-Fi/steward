import { describe, expect, test } from "bun:test";
import {
  type Address,
  decodeFunctionData,
  encodeAbiParameters,
  encodeEventTopics,
  type Hex,
} from "viem";
import { AGENTIC_COMMERCE_ABI, ERC20_ABI, ERC8183Client, EVALUATOR_ROUTER_ABI } from "../client";
import type { JobConfig, SignerAdapter } from "../types";

const AGENTIC_COMMERCE = "0x0000000000000000000000000000000000008183" as Address;
const EVALUATOR_ROUTER = "0x0000000000000000000000000000000000008184" as Address;
const OPTIMISTIC_POLICY = "0x0000000000000000000000000000000000008185" as Address;
const PAYMENT_TOKEN = "0x0000000000000000000000000000000000000006" as Address;
const PROVIDER = "0x0000000000000000000000000000000000000007" as Address;
const CLIENT = "0x0000000000000000000000000000000000000008" as Address;

const TX_HASH_1 = `0x${"1".repeat(64)}` as Hex;
const TX_HASH_2 = `0x${"2".repeat(64)}` as Hex;

describe("ERC8183Client", () => {
  test("createJob encodes calldata and decodes the JobCreated jobId", async () => {
    const sent: Array<{ to: Address; data: Hex }> = [];
    const client = makeClient({
      signer: {
        async sendTransaction(tx) {
          sent.push(tx);
          return TX_HASH_1;
        },
      },
      publicClient: {
        async waitForTransactionReceipt() {
          return { logs: [jobCreatedLog(42n)] };
        },
      },
    });

    const result = await client.createJob({
      provider: PROVIDER,
      expiredAt: 1_800_000_000n,
      description: "agent delivery",
    });

    expect(result).toEqual({ jobId: 42n, txHash: TX_HASH_1 });
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe(AGENTIC_COMMERCE);
    const decoded = decodeFunctionData({ abi: AGENTIC_COMMERCE_ABI, data: sent[0].data });
    expect(decoded.functionName).toBe("createJob");
    expect(decoded.args).toEqual([PROVIDER, EVALUATOR_ROUTER, 1_800_000_000n, "agent delivery"]);
  });

  test("fund approves the ERC-20 and then funds the job", async () => {
    const sent: Array<{ to: Address; data: Hex }> = [];
    const client = makeClient({
      signer: {
        async sendTransaction(tx) {
          sent.push(tx);
          return sent.length === 1 ? TX_HASH_1 : TX_HASH_2;
        },
      },
    });

    const result = await client.fund(42n, 1_000n);

    expect(result).toEqual({ approveTxHash: TX_HASH_1, fundTxHash: TX_HASH_2 });
    expect(sent).toHaveLength(2);
    expect(sent[0].to).toBe(PAYMENT_TOKEN);
    expect(decodeFunctionData({ abi: ERC20_ABI, data: sent[0].data })).toEqual({
      functionName: "approve",
      args: [AGENTIC_COMMERCE, 1_000n],
    });
    expect(sent[1].to).toBe(AGENTIC_COMMERCE);
    expect(decodeFunctionData({ abi: AGENTIC_COMMERCE_ABI, data: sent[1].data })).toEqual({
      functionName: "fund",
      args: [42n, 1_000n],
    });
  });

  test("settle encodes EvaluatorRouter settle calldata", async () => {
    const sent: Array<{ to: Address; data: Hex }> = [];
    const client = makeClient({
      signer: {
        async sendTransaction(tx) {
          sent.push(tx);
          return TX_HASH_1;
        },
      },
    });

    await client.settle(42n);

    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe(EVALUATOR_ROUTER);
    expect(decodeFunctionData({ abi: EVALUATOR_ROUTER_ABI, data: sent[0].data })).toEqual({
      functionName: "settle",
      args: [42n],
    });
  });

  test("claimRefund encodes AgenticCommerce claimRefund calldata", async () => {
    const sent: Array<{ to: Address; data: Hex }> = [];
    const client = makeClient({
      signer: {
        async sendTransaction(tx) {
          sent.push(tx);
          return TX_HASH_1;
        },
      },
    });

    await client.claimRefund(42n);

    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe(AGENTIC_COMMERCE);
    expect(decodeFunctionData({ abi: AGENTIC_COMMERCE_ABI, data: sent[0].data })).toEqual({
      functionName: "claimRefund",
      args: [42n],
    });
  });

  test("constructor rejects missing explicit deployment addresses", () => {
    expect(() => {
      new ERC8183Client({
        publicClient: {} as JobConfig["publicClient"],
        signer: mockSigner(),
        addresses: { agenticCommerce: AGENTIC_COMMERCE } as JobConfig["addresses"],
      });
    }).toThrow("missing evaluatorRouter, optimisticPolicy, paymentToken");
  });
});

function makeClient(overrides: {
  signer?: SignerAdapter;
  publicClient?: Record<string, unknown>;
}): ERC8183Client {
  return new ERC8183Client({
    publicClient: (overrides.publicClient ?? {
      async waitForTransactionReceipt() {
        return { logs: [] };
      },
    }) as JobConfig["publicClient"],
    signer: overrides.signer ?? mockSigner(),
    addresses: {
      agenticCommerce: AGENTIC_COMMERCE,
      evaluatorRouter: EVALUATOR_ROUTER,
      optimisticPolicy: OPTIMISTIC_POLICY,
      paymentToken: PAYMENT_TOKEN,
    },
  });
}

function mockSigner(): SignerAdapter {
  return {
    async sendTransaction() {
      return TX_HASH_1;
    },
  };
}

function jobCreatedLog(jobId: bigint): { data: Hex; topics: Hex[] } {
  const topics = encodeEventTopics({
    abi: AGENTIC_COMMERCE_ABI,
    eventName: "JobCreated",
    args: { jobId, client: CLIENT, provider: PROVIDER },
  });
  const data = encodeAbiParameters(
    [
      { name: "router", type: "address" },
      { name: "expiredAt", type: "uint64" },
      { name: "description", type: "string" },
    ],
    [EVALUATOR_ROUTER, 1_800_000_000n, "agent delivery"],
  );
  return { data, topics: topics.filter((topic): topic is Hex => typeof topic === "string") };
}
