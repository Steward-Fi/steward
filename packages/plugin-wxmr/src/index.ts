/** Opt-in wxmr.io bridge provider for Steward. */
import { AdapterNotConfiguredError } from "@stwd/adapters";
import type { StewardPlugin } from "@stwd/shared";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { WxmrBridgeAdapter } from "./wxmr-bridge";

export * from "./wxmr-bridge";

/**
 * Resolve the Solana RPC in priority order, treating a blank/whitespace value as
 * unset. Docker Compose passes `WXMR_SOLANA_RPC_URL: "${WXMR_SOLANA_RPC_URL:-}"`,
 * so an operator who configures only `SOLANA_RPC_URL` still receives an empty
 * string for the wxmr-specific var; a bare `??` would select that empty string
 * and silently drop the operator's RPC in favor of the public default.
 */
export function resolveRpcUrl(): string | undefined {
  for (const candidate of [
    runtimeEnvironmentValue("WXMR_SOLANA_RPC_URL"),
    runtimeEnvironmentValue("SOLANA_RPC_URL"),
  ]) {
    const trimmed = candidate?.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
}

// Session records contain no endpoint or credential authority. Keep them
// separate from request-owned provider instances so the existing create/get
// session API survives isolate reuse without retaining a prior binding set.
const sessions = new Map<
  string,
  { session: import("@stwd/adapters").BridgeSession; expiresAt: number }
>();

/** Build one request-owned provider from the current immutable authority. */
export function createWxmrBridgeAdapter(): WxmrBridgeAdapter {
  const rpcUrl = resolveRpcUrl();
  if (!rpcUrl) throw new AdapterNotConfiguredError("bridge");
  return new WxmrBridgeAdapter({ rpcUrl, sessions });
}

export const wxmrPlugin: StewardPlugin = {
  name: "wxmr",
  version: "0.1.0",
  adapters: [
    {
      category: "bridge",
      provider: "wxmr",
      createAdapter: createWxmrBridgeAdapter,
    },
  ],
};
