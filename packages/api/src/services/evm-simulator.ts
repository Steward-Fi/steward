import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

export interface EvmSimulationRequest {
  chainId: number;
  from: string;
  to: string;
  value: string;
  data: string;
  intentHash: string;
}

export interface EvmSimulationResult {
  ok: boolean;
  gasEstimate?: string;
  revertReason?: string;
}

export interface EvmSimulator {
  /** Request-local availability check for the requested chain. */
  isConfigured?(chainId: number): boolean;
  simulate(request: EvmSimulationRequest): Promise<EvmSimulationResult>;
}

function parseRpcUrls(raw: string | undefined): Record<string, string> {
  if (!raw?.trim()) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const urls: Record<string, string> = {};
    for (const [chainId, url] of Object.entries(parsed)) {
      if (/^\d+$/.test(chainId) && typeof url === "string" && /^https?:\/\//.test(url)) {
        urls[chainId] = url;
      }
    }
    return urls;
  } catch {
    return {};
  }
}

function rpcUrlForChain(chainId: number, env: Record<string, string | undefined>): string | null {
  const keyed = env[`STEWARD_EVM_RPC_URL_${chainId}`]?.trim();
  if (keyed && /^https?:\/\//.test(keyed)) return keyed;
  return parseRpcUrls(env.STEWARD_EVM_RPC_URLS_JSON)[String(chainId)] ?? null;
}

function runtimeRpcUrlForChain(chainId: number): string | null {
  const keyed = runtimeEnvironmentValue(`STEWARD_EVM_RPC_URL_${chainId}`)?.trim();
  if (keyed && /^https?:\/\//.test(keyed)) return keyed;
  return (
    parseRpcUrls(runtimeEnvironmentValue("STEWARD_EVM_RPC_URLS_JSON"))[String(chainId)] ?? null
  );
}

async function rpcCall(url: string, method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`rpc-http-${response.status}`);
  const body = (await response.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error) throw new Error(body.error.message ?? "rpc-error");
  return body.result;
}

function hexWei(decimal: string): `0x${string}` {
  return `0x${BigInt(decimal).toString(16)}`;
}

export class JsonRpcEvmSimulator implements EvmSimulator {
  private readonly env: Readonly<Record<string, string | undefined>>;

  constructor(env: Record<string, string | undefined> = process.env) {
    this.env = Object.freeze({ ...env });
  }

  isConfigured(chainId: number): boolean {
    return rpcUrlForChain(chainId, this.env) !== null;
  }

  async simulate(request: EvmSimulationRequest): Promise<EvmSimulationResult> {
    const url = rpcUrlForChain(request.chainId, this.env);
    if (!url) return { ok: false, revertReason: "evm simulator rpc not configured" };

    const tx = {
      from: request.from,
      to: request.to,
      value: hexWei(request.value),
      data: request.data,
    };

    try {
      await rpcCall(url, "eth_call", [tx, "latest"]);
      const gas = await rpcCall(url, "eth_estimateGas", [tx]);
      return { ok: true, gasEstimate: typeof gas === "string" ? gas : undefined };
    } catch (error) {
      return {
        ok: false,
        revertReason: error instanceof Error ? error.message : "evm simulation failed",
      };
    }
  }
}

class RuntimeEnvironmentEvmSimulator implements EvmSimulator {
  isConfigured(chainId: number): boolean {
    return runtimeRpcUrlForChain(chainId) !== null;
  }

  async simulate(request: EvmSimulationRequest): Promise<EvmSimulationResult> {
    // Resolve once, synchronously, from the immutable request environment. Both
    // RPC calls stay pinned to this URL even when another Worker request runs
    // concurrently with a different binding generation.
    const url = runtimeRpcUrlForChain(request.chainId);
    if (!url) return { ok: false, revertReason: "evm simulator rpc not configured" };

    const tx = {
      from: request.from,
      to: request.to,
      value: hexWei(request.value),
      data: request.data,
    };

    try {
      await rpcCall(url, "eth_call", [tx, "latest"]);
      const gas = await rpcCall(url, "eth_estimateGas", [tx]);
      return { ok: true, gasEstimate: typeof gas === "string" ? gas : undefined };
    } catch (error) {
      return {
        ok: false,
        revertReason: error instanceof Error ? error.message : "evm simulation failed",
      };
    }
  }
}

/**
 * Return a stable simulator facade whose authority is resolved per invocation.
 * The composed Worker app may cache this object across isolate requests; it
 * never caches or consults a prior request's RPC bindings.
 */
export function createEnvEvmSimulator(): EvmSimulator {
  return new RuntimeEnvironmentEvmSimulator();
}
