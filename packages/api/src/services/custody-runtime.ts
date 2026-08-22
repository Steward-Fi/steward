import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

const DEFAULT_VAULT_RPC_ALLOWLIST = "eth_chainId,eth_blockNumber,eth_getBalance";

/** Resolve a chain default from the active request snapshot, falling back to Bun's env. */
export function resolveRuntimeChainId(fallback: number): number {
  if (!Number.isSafeInteger(fallback) || fallback <= 0) {
    throw new Error("CHAIN_ID fallback must be a positive safe integer");
  }
  const configured = runtimeEnvironmentValue("CHAIN_ID")?.trim();
  if (!configured) return fallback;
  if (!/^[1-9]\d*$/.test(configured)) {
    throw new Error("CHAIN_ID must be a canonical positive integer");
  }
  const chainId = Number(configured);
  if (!Number.isSafeInteger(chainId)) {
    throw new Error("CHAIN_ID must be a positive safe integer");
  }
  return chainId;
}

/** Check the RPC gate from the active request snapshot rather than isolate-global state. */
export function isRuntimeVaultRpcMethodAllowed(method: string): boolean {
  const configured =
    runtimeEnvironmentValue("STEWARD_VAULT_RPC_ALLOWLIST") ?? DEFAULT_VAULT_RPC_ALLOWLIST;
  return configured
    .split(",")
    .map((candidate) => candidate.trim())
    .filter(Boolean)
    .includes(method);
}

/** Resolve an arbitrary custody-adjacent binding from the active request snapshot. */
export function runtimeCustodyValue(name: string): string | undefined {
  return runtimeEnvironmentValue(name);
}
