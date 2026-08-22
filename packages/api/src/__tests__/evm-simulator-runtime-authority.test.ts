import { afterEach, describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { createEnvEvmSimulator, type EvmSimulationRequest } from "../services/evm-simulator";

const originalFetch = globalThis.fetch;
const request: EvmSimulationRequest = {
  chainId: 8453,
  from: "0x1111111111111111111111111111111111111111",
  to: "0x2222222222222222222222222222222222222222",
  value: "1",
  data: "0x12345678",
  intentHash: "simulator-runtime-authority",
};

function rpcResponse(method: string): Response {
  return Response.json({ jsonrpc: "2.0", id: 1, result: method === "eth_call" ? "0x" : "0x5208" });
}

describe("request-local EVM simulator authority", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("reuses one composed simulator across A -> B while removal fails closed", async () => {
    const simulator = createEnvEvmSimulator();
    const calls: string[] = [];
    globalThis.fetch = (async (input, init) => {
      calls.push(String(input));
      const method = JSON.parse(String(init?.body)).method as string;
      return rpcResponse(method);
    }) as typeof fetch;

    const resultA = await withRuntimeEnvironment(
      { STEWARD_EVM_RPC_URL_8453: "https://rpc-a.example" },
      () => simulator.simulate(request),
    );
    const resultB = await withRuntimeEnvironment(
      { STEWARD_EVM_RPC_URLS_JSON: '{"8453":"https://rpc-b.example"}' },
      () => simulator.simulate(request),
    );
    const removed = await withRuntimeEnvironment({}, () => simulator.simulate(request));

    expect(resultA).toEqual({ ok: true, gasEstimate: "0x5208" });
    expect(resultB).toEqual({ ok: true, gasEstimate: "0x5208" });
    expect(removed).toEqual({ ok: false, revertReason: "evm simulator rpc not configured" });
    expect(withRuntimeEnvironment({}, () => simulator.isConfigured?.(request.chainId))).toBe(false);
    expect(calls).toEqual([
      "https://rpc-a.example",
      "https://rpc-a.example",
      "https://rpc-b.example",
      "https://rpc-b.example",
    ]);
  });

  it("pins overlapping requests to their own immutable RPC binding", async () => {
    const simulator = createEnvEvmSimulator();
    const calls: Array<{ url: string; method: string }> = [];
    let releaseA!: () => void;
    let markAStarted!: () => void;
    const aStarted = new Promise<void>((resolve) => {
      markAStarted = resolve;
    });
    const aReleased = new Promise<void>((resolve) => {
      releaseA = resolve;
    });

    globalThis.fetch = (async (input, init) => {
      const url = String(input);
      const method = JSON.parse(String(init?.body)).method as string;
      calls.push({ url, method });
      if (url === "https://rpc-a.example" && method === "eth_call") {
        markAStarted();
        await aReleased;
      }
      return rpcResponse(method);
    }) as typeof fetch;

    const requestA = withRuntimeEnvironment(
      { STEWARD_EVM_RPC_URL_8453: "https://rpc-a.example" },
      () => simulator.simulate(request),
    );
    await aStarted;
    const resultB = await withRuntimeEnvironment(
      { STEWARD_EVM_RPC_URL_8453: "https://rpc-b.example" },
      () => simulator.simulate(request),
    );
    releaseA();
    const resultA = await requestA;

    expect(resultA).toEqual({ ok: true, gasEstimate: "0x5208" });
    expect(resultB).toEqual({ ok: true, gasEstimate: "0x5208" });
    expect(calls).toEqual([
      { url: "https://rpc-a.example", method: "eth_call" },
      { url: "https://rpc-b.example", method: "eth_call" },
      { url: "https://rpc-b.example", method: "eth_estimateGas" },
      { url: "https://rpc-a.example", method: "eth_estimateGas" },
    ]);
  });
});
