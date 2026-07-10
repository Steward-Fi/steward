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
  simulate(request: EvmSimulationRequest): Promise<EvmSimulationResult>;
}

export interface EvmTransactionReceipt {
  transactionHash?: string;
  status?: string;
  blockHash?: string | null;
  blockNumber?: string | null;
}

export interface EvmRpcClient {
  getPendingNonce(chainId: number, address: string): Promise<number>;
  getGasPrice(chainId: number): Promise<string>;
  sendRawTransaction(chainId: number, rawTransaction: string): Promise<string>;
  getTransactionReceipt(chainId: number, txHash: string): Promise<EvmTransactionReceipt | null>;
  getTransactionByHash(chainId: number, txHash: string): Promise<Record<string, unknown> | null>;
}

export function parseRpcUrls(raw: string | undefined): Record<string, string> {
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

export function rpcUrlForChain(
  chainId: number,
  env: Record<string, string | undefined>,
): string | null {
  const keyed = env[`STEWARD_EVM_RPC_URL_${chainId}`]?.trim();
  if (keyed && /^https?:\/\//.test(keyed)) return keyed;
  return parseRpcUrls(env.STEWARD_EVM_RPC_URLS_JSON)[String(chainId)] ?? null;
}

export class EvmJsonRpcError extends Error {
  constructor(
    message: string,
    readonly code?: number,
  ) {
    super(message);
    this.name = "EvmJsonRpcError";
  }
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
  if (body.error) throw new EvmJsonRpcError(body.error.message ?? "rpc-error");
  return body.result;
}

function hexWei(decimal: string): `0x${string}` {
  return `0x${BigInt(decimal).toString(16)}`;
}

export class JsonRpcEvmSimulator implements EvmSimulator {
  constructor(private readonly env: Record<string, string | undefined> = process.env) {}

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

export class JsonRpcEvmClient implements EvmRpcClient {
  constructor(private readonly env: Record<string, string | undefined> = process.env) {}

  private url(chainId: number): string {
    const url = rpcUrlForChain(chainId, this.env);
    if (!url) throw new Error(`evm rpc not configured for chain ${chainId}`);
    return url;
  }

  async getPendingNonce(chainId: number, address: string): Promise<number> {
    const result = await rpcCall(this.url(chainId), "eth_getTransactionCount", [
      address,
      "pending",
    ]);
    if (typeof result !== "string" || !/^0x[0-9a-fA-F]+$/.test(result)) {
      throw new Error("RPC returned an invalid pending nonce");
    }
    return Number(BigInt(result));
  }

  async getGasPrice(chainId: number): Promise<string> {
    const result = await rpcCall(this.url(chainId), "eth_gasPrice", []);
    if (typeof result !== "string" || !/^0x[0-9a-fA-F]+$/.test(result)) {
      throw new Error("RPC returned an invalid gas price");
    }
    return BigInt(result).toString();
  }

  async sendRawTransaction(chainId: number, rawTransaction: string): Promise<string> {
    const result = await rpcCall(this.url(chainId), "eth_sendRawTransaction", [rawTransaction]);
    if (typeof result !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(result)) {
      throw new Error("RPC returned an invalid transaction hash");
    }
    return result.toLowerCase();
  }

  async getTransactionReceipt(
    chainId: number,
    txHash: string,
  ): Promise<EvmTransactionReceipt | null> {
    const result = await rpcCall(this.url(chainId), "eth_getTransactionReceipt", [txHash]);
    if (result === null) return null;
    return result && typeof result === "object" ? (result as EvmTransactionReceipt) : null;
  }

  async getTransactionByHash(
    chainId: number,
    txHash: string,
  ): Promise<Record<string, unknown> | null> {
    const result = await rpcCall(this.url(chainId), "eth_getTransactionByHash", [txHash]);
    if (result === null) return null;
    return result && typeof result === "object" ? (result as Record<string, unknown>) : null;
  }
}

export function createEnvEvmSimulator(): EvmSimulator | null {
  const hasJson =
    Object.keys(parseRpcUrls(process.env.STEWARD_EVM_RPC_URLS_JSON)).length > 0 ||
    Object.keys(process.env).some((key) => /^STEWARD_EVM_RPC_URL_\d+$/.test(key));
  return hasJson ? new JsonRpcEvmSimulator() : null;
}

export function createEnvEvmRpcClient(): EvmRpcClient | null {
  const hasJson =
    Object.keys(parseRpcUrls(process.env.STEWARD_EVM_RPC_URLS_JSON)).length > 0 ||
    Object.keys(process.env).some((key) => /^STEWARD_EVM_RPC_URL_\d+$/.test(key));
  return hasJson ? new JsonRpcEvmClient() : null;
}
