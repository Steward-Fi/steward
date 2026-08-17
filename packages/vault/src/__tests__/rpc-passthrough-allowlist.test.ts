import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import { Vault } from "../vault";

/**
 * SEC-082 regression: rpcPassthrough must enforce an ALLOWLIST of read-only
 * methods (not a blocklist). A blocklist misses variants (eth_signTypedData_v3,
 * Solana signMessage/signTransaction) and whole operator namespaces (admin_,
 * debug_) when an operator points rpcUrl at a node with unlocked accounts.
 */

const vault = new Vault({ masterPassword: "rpc-passthrough-allowlist-test" });

const originalFetch = globalThis.fetch;
const originalEnv = process.env.STEWARD_VAULT_RPC_ALLOWLIST;

let fetchCalls: Array<{ url: string; method: string }>;

function okRpcResponse(): Response {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  fetchCalls = [];
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    fetchCalls.push({ url: String(input), method: "POST" });
    return okRpcResponse();
  }) as typeof fetch;
  delete process.env.STEWARD_VAULT_RPC_ALLOWLIST;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalEnv === undefined) delete process.env.STEWARD_VAULT_RPC_ALLOWLIST;
  else process.env.STEWARD_VAULT_RPC_ALLOWLIST = originalEnv;
});

describe("rpcPassthrough allowlist (SEC-082)", () => {
  test("rejects signing/state-modifying methods without touching the network", async () => {
    const blocked = [
      // EVM signing + send (incl. the variants the old blocklist missed)
      "eth_sendTransaction",
      "eth_sendRawTransaction",
      "eth_sign",
      "eth_signTypedData",
      "eth_signTypedData_v3",
      "eth_signTypedData_v4",
      "personal_sign",
      // Unlocked-account disclosure / operator namespaces
      "eth_accounts",
      "admin_peers",
      "debug_traceTransaction",
      "miner_start",
      "txpool_content",
      // Solana signing/state-changing
      "sendTransaction",
      "signTransaction",
      "signMessage",
      "requestAirdrop",
    ];
    for (const method of blocked) {
      await expect(vault.rpcPassthrough({ method, chainId: 84532 })).rejects.toThrow(
        /not allowed via RPC passthrough/,
      );
    }
    expect(fetchCalls.length).toBe(0);
  });

  test("allows the default read-only inventory (EVM + Solana)", async () => {
    const evm = await vault.rpcPassthrough({ method: "eth_getCode", chainId: 84532 });
    expect(evm.result).toBe("0x1");
    const sol = await vault.rpcPassthrough({ method: "getLatestBlockhash", chainId: 101 });
    expect(sol.result).toBe("0x1");
    expect(fetchCalls.length).toBe(2);
  });

  test("STEWARD_VAULT_RPC_ALLOWLIST replaces the default inventory (fail closed)", async () => {
    process.env.STEWARD_VAULT_RPC_ALLOWLIST = "eth_getLogs";

    // Operator-listed method passes...
    const res = await vault.rpcPassthrough({ method: "eth_getLogs", chainId: 84532 });
    expect(res.result).toBe("0x1");
    // ...and default-inventory methods NOT in the override are denied, even
    // though the vault's own native-transfer guard needs eth_getCode.
    await expect(vault.rpcPassthrough({ method: "eth_getCode", chainId: 84532 })).rejects.toThrow(
      /not allowed via RPC passthrough/,
    );
    expect(fetchCalls.length).toBe(1);
  });

  test("trims and ignores empty entries in the env override", async () => {
    process.env.STEWARD_VAULT_RPC_ALLOWLIST = " eth_chainId ,, eth_blockNumber ";
    const res = await vault.rpcPassthrough({ method: "eth_chainId", chainId: 84532 });
    expect(res.result).toBe("0x1");
    await expect(vault.rpcPassthrough({ method: "eth_getCode", chainId: 84532 })).rejects.toThrow(
      /not allowed via RPC passthrough/,
    );
  });
});
