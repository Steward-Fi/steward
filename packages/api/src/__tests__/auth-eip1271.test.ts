/**
 * EIP-1271 (smart contract wallet) signature verification tests.
 *
 * These exercise the helper directly with a mocked PublicClient. The end-to-end
 * /auth/verify smart contract flow needs a deployed contract on a real chain
 * to be fully exercised; that's out of scope for unit tests. Domain rejection
 * and EOA regression are covered by auth-wallets.test.ts.
 */

import { describe, expect, it } from "bun:test";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { type PublicClientFactory, resolveRpcUrl, verifyEip1271 } from "../services/eip1271";

const SAFE_ADDRESS = "0x1111111111111111111111111111111111111111";
const SIGNATURE = "0xdeadbeef";
const EIP1271_MAGIC = "0x1626ba7e";
const EIP1271_INVALID = "0xffffffff";

function clientReturning(value: string): PublicClientFactory {
  return () => {
    return {
      readContract: async () => value,
    } as unknown as ReturnType<PublicClientFactory>;
  };
}

function clientThrowing(err: unknown): PublicClientFactory {
  return () => {
    return {
      readContract: async () => {
        throw err;
      },
    } as unknown as ReturnType<PublicClientFactory>;
  };
}

const SAMPLE_MESSAGE = [
  "steward.fi wants you to sign in with your Ethereum account:",
  SAFE_ADDRESS,
  "",
  "Sign in to Steward",
  "",
  "URI: https://steward.fi",
  "Version: 1",
  "Chain ID: 1",
  "Nonce: abcdefgh",
  "Issued At: 2026-05-02T00:00:00.000Z",
].join("\n");

describe("verifyEip1271", () => {
  it("accepts when contract returns the EIP-1271 magic value", async () => {
    const result = await verifyEip1271({
      address: SAFE_ADDRESS as `0x${string}`,
      message: SAMPLE_MESSAGE,
      signature: SIGNATURE,
      chainId: 1,
      clientFactory: clientReturning(EIP1271_MAGIC),
    });

    expect(result.ok).toBe(true);
  });

  it("rejects when contract returns a non-magic value", async () => {
    const result = await verifyEip1271({
      address: SAFE_ADDRESS as `0x${string}`,
      message: SAMPLE_MESSAGE,
      signature: SIGNATURE,
      chainId: 1,
      clientFactory: clientReturning(EIP1271_INVALID),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature_invalid");
  });

  it("returns no_rpc when no RPC is available for the chain", async () => {
    const result = await verifyEip1271({
      address: SAFE_ADDRESS as `0x${string}`,
      message: SAMPLE_MESSAGE,
      signature: SIGNATURE,
      chainId: 1,
      clientFactory: () => null,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("no_rpc");
  });

  it("returns contract_call_failed when readContract throws (e.g. address is an EOA)", async () => {
    const result = await verifyEip1271({
      address: SAFE_ADDRESS as `0x${string}`,
      message: SAMPLE_MESSAGE,
      signature: SIGNATURE,
      chainId: 1,
      clientFactory: clientThrowing(new Error("ContractFunctionExecutionError: ...")),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("contract_call_failed");
  });

  it("rejects malformed addresses without making an RPC call", async () => {
    let calls = 0;
    const factory: PublicClientFactory = () => {
      calls += 1;
      return null;
    };
    const result = await verifyEip1271({
      address: "0xnotanaddress" as `0x${string}`,
      message: SAMPLE_MESSAGE,
      signature: SIGNATURE,
      chainId: 1,
      clientFactory: factory,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature_invalid");
    expect(calls).toBe(0);
  });

  it("works with EOAs being misclassified as 1271 (graceful degrade); the regular SIWE EOA path is unaffected", async () => {
    // This is a sanity check: an EOA address in the helper should fall through
    // to contract_call_failed (no contract code at the address). Real EOA
    // SIWE flows do not enter this codepath because siwe.verify succeeds first.
    const account = privateKeyToAccount(generatePrivateKey());
    const result = await verifyEip1271({
      address: account.address,
      message: SAMPLE_MESSAGE,
      signature: SIGNATURE,
      chainId: 1,
      clientFactory: clientThrowing(new Error("returned no data")),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("contract_call_failed");
  });
});

describe("resolveRpcUrl", () => {
  it("returns env override when SIWE_RPC_<chainId> is set", () => {
    const previous = process.env.SIWE_RPC_1;
    process.env.SIWE_RPC_1 = "https://my-private-mainnet-rpc.example.com";
    try {
      expect(resolveRpcUrl(1)).toBe("https://my-private-mainnet-rpc.example.com");
    } finally {
      if (previous === undefined) delete process.env.SIWE_RPC_1;
      else process.env.SIWE_RPC_1 = previous;
    }
  });

  it("falls back to public RPC for known major chains", () => {
    // Mainnet, Base, BSC, Polygon, Optimism, Arbitrum all have fallbacks.
    expect(resolveRpcUrl(1)).toContain("publicnode.com");
    expect(resolveRpcUrl(8453)).toContain("publicnode.com");
    expect(resolveRpcUrl(56)).toContain("publicnode.com");
  });

  it("returns null for unknown chain IDs without overrides", () => {
    const previous = process.env.SIWE_RPC_99999;
    delete process.env.SIWE_RPC_99999;
    try {
      expect(resolveRpcUrl(99999)).toBeNull();
    } finally {
      if (previous !== undefined) process.env.SIWE_RPC_99999 = previous;
    }
  });

  it("ignores empty string env override and falls back to default", () => {
    const previous = process.env.SIWE_RPC_8453;
    process.env.SIWE_RPC_8453 = "   ";
    try {
      expect(resolveRpcUrl(8453)).toContain("publicnode.com");
    } finally {
      if (previous === undefined) delete process.env.SIWE_RPC_8453;
      else process.env.SIWE_RPC_8453 = previous;
    }
  });
});
