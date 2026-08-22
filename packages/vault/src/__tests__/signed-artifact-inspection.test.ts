import { afterEach, describe, expect, it, spyOn } from "bun:test";
import { Connection, NonceAccount, PublicKey } from "@solana/web3.js";
import { Vault } from "../vault";

const MASTER_PASSWORD = "signed-artifact-inspection-master-password";
const HASH = `0x${"ab".repeat(32)}`;
const SIGNER = "0x1234567890123456789012345678901234567890";
const SIGNATURE =
  "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
const NONCE_ACCOUNT = "6TcyBfPdBt1kjsvDZLzmBFnuMaLWiTaAt4RjUr9VA5YD";
const NONCE_AUTHORITY = "9xQeWvG816bUx9EPfM4WB3W4QytqNyVRixh3nKJx1U7";

describe("strict signed-artifact chain inspection", () => {
  afterEach(() => {
    spyOn(globalThis, "fetch").mockRestore();
  });

  it("retires EVM evidence only after exact receipt absence and finalized nonce consumption", async () => {
    const calls: string[] = [];
    spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body)) as { method: string };
      calls.push(request.method);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: request.method === "eth_getTransactionReceipt" ? null : "0x8",
        }),
      );
    });
    const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
    expect(
      await vault.inspectEvmSignedArtifact({
        artifactHash: HASH,
        signer: SIGNER,
        nonce: "7",
        chainId: 31337,
      }),
    ).toEqual({ result: "absent_nonce_consumed" });
    expect(calls).toEqual(["eth_getTransactionReceipt", "eth_getTransactionCount"]);
  });

  it("fails closed on malformed EVM RPC success shapes", async () => {
    spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { status: "0x1" } })),
    );
    const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
    await expect(
      vault.inspectEvmSignedArtifact({
        artifactHash: HASH,
        signer: SIGNER,
        nonce: "7",
        chainId: 31337,
      }),
    ).rejects.toThrow("Malformed EVM receipt response");
  });

  it("rejects malformed Solana status arrays rather than inferring absence", async () => {
    const status = spyOn(Connection.prototype, "getSignatureStatuses").mockResolvedValue({
      context: { slot: 1 },
      value: [],
    });
    const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
    await expect(
      vault.inspectSolanaSignedArtifact({
        signature: SIGNATURE,
        recentBlockhash: "11111111111111111111111111111111",
        blockhashKind: "recent",
        lastValidBlockHeight: 100,
      }),
    ).rejects.toThrow("Malformed Solana signature-status response");
    status.mockRestore();
  });

  it("rejects malformed Solana transaction errors rather than inferring failure", async () => {
    const status = spyOn(Connection.prototype, "getSignatureStatuses").mockResolvedValue({
      context: { slot: 1 },
      value: [
        {
          slot: 1,
          confirmations: null,
          err: 7 as never,
          confirmationStatus: "finalized",
        },
      ],
    });
    try {
      const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
      await expect(
        vault.inspectSolanaSignedArtifact({
          signature: SIGNATURE,
          recentBlockhash: "11111111111111111111111111111111",
          blockhashKind: "recent",
          lastValidBlockHeight: 100,
        }),
      ).rejects.toThrow("Malformed Solana signature status");
    } finally {
      status.mockRestore();
    }
  });

  it("requires both the recorded height boundary and exact blockhash invalidity", async () => {
    const status = spyOn(Connection.prototype, "getSignatureStatuses").mockResolvedValue({
      context: { slot: 1 },
      value: [null],
    });
    let blockhashValid = true;
    let validityCalls = 0;
    spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body)) as { method: string };
      if (request.method === "getBlockHeight") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: 101 }));
      }
      expect(request.method).toBe("isBlockhashValid");
      validityCalls += 1;
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { context: { slot: 2 }, value: blockhashValid },
        }),
      );
    });
    const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
    expect(
      await vault.inspectSolanaSignedArtifact({
        signature: SIGNATURE,
        recentBlockhash: "11111111111111111111111111111111",
        blockhashKind: "recent",
        lastValidBlockHeight: 100,
      }),
    ).toEqual({ result: "absent_live" });
    blockhashValid = false;
    expect(
      await vault.inspectSolanaSignedArtifact({
        signature: SIGNATURE,
        recentBlockhash: "11111111111111111111111111111111",
        blockhashKind: "recent",
        lastValidBlockHeight: 100,
      }),
    ).toEqual({ result: "absent_expired" });
    expect(validityCalls).toBe(2);
    status.mockRestore();
  });

  it("rejects blockhash-validity responses without a canonical context slot", async () => {
    const status = spyOn(Connection.prototype, "getSignatureStatuses").mockResolvedValue({
      context: { slot: 1 },
      value: [null],
    });
    spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body)) as { method: string };
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: request.method === "getBlockHeight" ? 101 : { context: {}, value: false },
        }),
      );
    });
    try {
      const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
      await expect(
        vault.inspectSolanaSignedArtifact({
          signature: SIGNATURE,
          recentBlockhash: "11111111111111111111111111111111",
          blockhashKind: "recent",
          lastValidBlockHeight: 100,
        }),
      ).rejects.toThrow("Malformed Solana blockhash-validity response");
    } finally {
      status.mockRestore();
    }
  });

  it("retires durable-nonce evidence only after the exact authorized account advances", async () => {
    const status = spyOn(Connection.prototype, "getSignatureStatuses").mockResolvedValue({
      context: { slot: 1 },
      value: [null],
    });
    const account = spyOn(Connection.prototype, "getAccountInfo").mockResolvedValue({
      data: Buffer.alloc(80),
      executable: false,
      lamports: 1,
      owner: new PublicKey("11111111111111111111111111111111"),
      rentEpoch: 0,
    });
    const parse = spyOn(NonceAccount, "fromAccountData").mockReturnValue({
      authorizedPubkey: new PublicKey(NONCE_AUTHORITY),
      feeCalculator: { lamportsPerSignature: 5000 },
      nonce: "advanced-nonce-value",
    });
    try {
      const vault = new Vault({ masterPassword: MASTER_PASSWORD, rpcUrl: "https://rpc.invalid" });
      expect(
        await vault.inspectSolanaSignedArtifact({
          signature: SIGNATURE,
          recentBlockhash: "11111111111111111111111111111111",
          blockhashKind: "durable_nonce",
          durableNonceAccount: NONCE_ACCOUNT,
          durableNonceAuthority: NONCE_AUTHORITY,
        }),
      ).toEqual({ result: "absent_expired" });
      parse.mockReturnValue({
        authorizedPubkey: new PublicKey(NONCE_AUTHORITY),
        feeCalculator: { lamportsPerSignature: 5000 },
        nonce: "11111111111111111111111111111111",
      });
      expect(
        await vault.inspectSolanaSignedArtifact({
          signature: SIGNATURE,
          recentBlockhash: "11111111111111111111111111111111",
          blockhashKind: "durable_nonce",
          durableNonceAccount: NONCE_ACCOUNT,
          durableNonceAuthority: NONCE_AUTHORITY,
        }),
      ).toEqual({ result: "absent_live" });
    } finally {
      status.mockRestore();
      account.mockRestore();
      parse.mockRestore();
    }
  });
});
