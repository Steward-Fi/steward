import { expect, test } from "bun:test";
import type { StewardClient } from "@stwd/sdk";
import type { AgentTraderConfig } from "../config.js";
import { fetchAgentState } from "../state.js";

const TEST_CHAIN_ID = 31_337;
const RPC_URL = "https://rpc.example.test/";
const OPERATOR_ORACLE_URL = "https://operator.example.test/private-price";

test("agent state ignores an operator-controlled price-oracle URL at runtime", async () => {
  const originalFetch = globalThis.fetch;
  const originalRpcUrl = process.env[`RPC_URL_${TEST_CHAIN_ID}`];
  const originalOracleUrl = process.env.PRICE_ORACLE_URL;
  const requestedUrls: string[] = [];

  process.env[`RPC_URL_${TEST_CHAIN_ID}`] = RPC_URL;
  process.env.PRICE_ORACLE_URL = OPERATOR_ORACLE_URL;
  globalThis.fetch = (async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    requestedUrls.push(url);

    const request = JSON.parse(String(init?.body)) as { id: number; method: string };
    const result = request.method === "eth_getBalance" ? "0x2a" : `0x${"0".repeat(63)}7`;
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  const config: AgentTraderConfig = {
    agentId: "agent-oracle-boundary",
    tokenAddress: "0x1111111111111111111111111111111111111111",
    strategy: "manual",
    intervalSeconds: 60,
    enabled: true,
    chainId: TEST_CHAIN_ID,
    params: {},
  };
  const steward = {
    getHistory: async () => [],
  } as unknown as StewardClient;

  try {
    const state = await fetchAgentState(
      config,
      "0x2222222222222222222222222222222222222222",
      steward,
    );

    expect(requestedUrls.length).toBe(2);
    expect(requestedUrls).toEqual([RPC_URL, RPC_URL]);
    expect(requestedUrls).not.toContain(OPERATOR_ORACLE_URL);
    expect(state).toMatchObject({
      nativeBalance: 42n,
      tokenBalance: 7n,
      tokenPrice: 0n,
      priceConfidence: "none",
      treasuryValue: 42n,
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (originalRpcUrl === undefined) delete process.env[`RPC_URL_${TEST_CHAIN_ID}`];
    else process.env[`RPC_URL_${TEST_CHAIN_ID}`] = originalRpcUrl;
    if (originalOracleUrl === undefined) delete process.env.PRICE_ORACLE_URL;
    else process.env.PRICE_ORACLE_URL = originalOracleUrl;
  }
});
