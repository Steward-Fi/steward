import { describe, expect, it } from "bun:test";
import type { ExecutionAuthorization, SignRequest } from "@stwd/shared";
import {
  executionClaimDigestForGovernedSolanaParsedSign,
  executionPayloadDigestForGovernedEvmSign,
  executionPayloadDigestForGovernedSolanaNativeSign,
  executionPayloadDigestForGovernedSolanaParsedSign,
  GovernedVault,
  GovernedVaultError,
} from "../governed-vault";
import { normalizedSolanaMessageDigest } from "../solana";
import type { SignTransactionOptions, Vault } from "../vault";

const request: SignRequest = {
  tenantId: "tenant-1",
  agentId: "agent-1",
  to: "0x1111111111111111111111111111111111111111",
  value: "1",
  chainId: 8453,
  broadcast: false,
};

const requestPayloadDigest = executionPayloadDigestForGovernedEvmSign(request);

const authorization: ExecutionAuthorization = {
  id: "auth-1",
  requestId: "tx-1",
  tenantId: "tenant-1",
  agentId: "agent-1",
  capability: "wallet.sign_transaction",
  payloadDigest: requestPayloadDigest,
  backend: "local-vault",
  nonce: "nonce-1",
  issuedAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  status: "active",
  signature: "sig-1",
};

describe("GovernedVault", () => {
  it("consumes the complete parsed Solana claim before entering the raw custody signer", async () => {
    const calls: string[] = [];
    const transaction = "opaque-parsed-solana-transaction";
    const parsedRequest = {
      tenantId: "tenant-1",
      agentId: "agent-1",
      transaction,
      chainId: 101,
      broadcast: false,
    } as const;
    const parsedEffects = {
      movesNativeSol: false,
      programIds: ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
      tokenTransfers: [{ mint: "mint-1", destination: "destination-1", amount: "7" }],
    };
    const messageDigest = normalizedSolanaMessageDigest(transaction);
    const policyRevisionHash = "policy-revision-1";
    const executionPayloadDigest = executionPayloadDigestForGovernedSolanaParsedSign(
      parsedRequest,
      { messageDigest, parsedEffects, policyRevisionHash },
    );
    const executionClaimDigest = executionClaimDigestForGovernedSolanaParsedSign({
      executionPayloadDigest,
      executionToken: "lease-token-1",
      txId: "tx-parsed-1",
    });
    const rawVault = {
      async signSolanaTransaction(rawRequest: Record<string, unknown>) {
        expect(rawRequest.allowBlindSign).toBeUndefined();
        expect(rawRequest.governedParsedSign).toBeDefined();
        calls.push("raw-sign");
        return { signature: "signed", broadcast: false, chainId: 101 };
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {});

    const result = await governed.signSolanaParsedTransactionAuthorized(parsedRequest, {
      txId: "tx-parsed-1",
      executionToken: "lease-token-1",
      executionClaimDigest,
      executionPayloadDigest,
      messageDigest,
      parsedEffects,
      policyRevisionHash,
      consumeExecutionClaim: async (expected) => {
        expect(expected).toEqual({
          tenantId: "tenant-1",
          agentId: "agent-1",
          txId: "tx-parsed-1",
          executionToken: "lease-token-1",
          executionClaimDigest,
          executionPayloadDigest,
          messageDigest,
          parsedEffects,
          policyRevisionHash,
          chainId: 101,
          broadcast: false,
        });
        calls.push("consume-claim");
      },
    });

    expect(result.signature).toBe("signed");
    expect(calls).toEqual(["consume-claim", "raw-sign"]);
  });

  it("never enters raw parsed Solana signing for stale, mutated, or replayed authority", async () => {
    let rawCalls = 0;
    const transaction = "opaque-parsed-solana-transaction";
    const parsedRequest = {
      tenantId: "tenant-1",
      agentId: "agent-1",
      transaction,
      chainId: 101,
      broadcast: true,
    } as const;
    const parsedEffects = {
      movesNativeSol: false,
      programIds: ["program-1"],
      tokenTransfers: [{ destination: "destination-1", amount: "7" }],
    };
    const messageDigest = normalizedSolanaMessageDigest(transaction);
    const executionPayloadDigest = executionPayloadDigestForGovernedSolanaParsedSign(
      parsedRequest,
      { messageDigest, parsedEffects, policyRevisionHash: "policy-1" },
    );
    const options = {
      txId: "tx-parsed-2",
      executionToken: "lease-token-2",
      executionClaimDigest: executionClaimDigestForGovernedSolanaParsedSign({
        executionPayloadDigest,
        executionToken: "lease-token-2",
        txId: "tx-parsed-2",
      }),
      executionPayloadDigest,
      messageDigest,
      parsedEffects,
      policyRevisionHash: "policy-1",
      consumeExecutionClaim: async () => {
        throw new Error("claim already consumed");
      },
    };
    const rawVault = {
      async signSolanaTransaction() {
        rawCalls += 1;
        return { signature: "never", broadcast: true, chainId: 101 };
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {});

    await expect(
      governed.signSolanaParsedTransactionAuthorized(parsedRequest, options),
    ).rejects.toThrow("claim already consumed");
    await expect(
      governed.signSolanaParsedTransactionAuthorized(
        { ...parsedRequest, transaction: "mutated-transaction" },
        options,
      ),
    ).rejects.toThrow("does not match");
    await expect(
      governed.signSolanaParsedTransactionAuthorized(parsedRequest, {
        ...options,
        parsedEffects: { ...parsedEffects, programIds: ["program-2"] },
      }),
    ).rejects.toThrow("does not match");
    await expect(
      governed.signSolanaParsedTransactionAuthorized(parsedRequest, {
        ...options,
        policyRevisionHash: "policy-2",
      }),
    ).rejects.toThrow("does not match");
    expect(rawCalls).toBe(0);
  });

  it("consumes a durable Solana claim immediately before native raw signing", async () => {
    const calls: string[] = [];
    const solanaRequest: SignRequest = {
      tenantId: "tenant-1",
      agentId: "agent-1",
      to: "7J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
      value: "1000000000",
      chainId: 101,
      broadcast: true,
    };
    const rawVault = {
      async signTransaction() {
        calls.push("raw-sign");
        return "solana-signature";
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {
      throw new Error("EVM callback must not be used");
    });
    const digest = executionPayloadDigestForGovernedSolanaNativeSign(solanaRequest);

    const result = await governed.signSolanaNativeTransferAuthorized(solanaRequest, {
      txId: "solana-tx-1",
      executionToken: "claim-token",
      executionClaimDigest: "claim-digest",
      executionPayloadDigest: digest,
      consumeExecutionClaim: async (expected) => {
        expect(expected).toMatchObject({
          txId: "solana-tx-1",
          executionToken: "claim-token",
          executionClaimDigest: "claim-digest",
          payloadDigest: digest,
        });
        calls.push("consume-claim");
      },
    });

    expect(result).toBe("solana-signature");
    expect(calls).toEqual(["consume-claim", "raw-sign"]);
  });

  it("never raw-signs Solana when the durable claim rejects or intent changes", async () => {
    let rawCalls = 0;
    const solanaRequest: SignRequest = {
      tenantId: "tenant-1",
      agentId: "agent-1",
      to: "7J9kqM5kV8Fh1Q3b6N2pR4tYwLcXzAaBbCcDdEeFfGg",
      value: "1",
      chainId: 101,
      broadcast: true,
    };
    const rawVault = {
      async signTransaction() {
        rawCalls += 1;
        return "never";
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {});
    const digest = executionPayloadDigestForGovernedSolanaNativeSign(solanaRequest);

    await expect(
      governed.signSolanaNativeTransferAuthorized(
        { ...solanaRequest, value: "2" },
        {
          txId: "solana-tx-2",
          executionToken: "claim-token",
          executionClaimDigest: "claim-digest",
          executionPayloadDigest: digest,
          consumeExecutionClaim: async () => {},
        },
      ),
    ).rejects.toThrow("does not match");
    await expect(
      governed.signSolanaNativeTransferAuthorized(solanaRequest, {
        txId: "solana-tx-2",
        executionToken: "claim-token",
        executionClaimDigest: "claim-digest",
        executionPayloadDigest: digest,
        consumeExecutionClaim: async () => {
          throw new Error("stale claim");
        },
      }),
    ).rejects.toThrow("stale claim");
    expect(rawCalls).toBe(0);
  });

  it("consumes execution authorization immediately before raw signTransaction", async () => {
    const calls: string[] = [];
    const rawVault = {
      async signTransaction(_request: SignRequest, _options: SignTransactionOptions) {
        calls.push("raw-sign");
        return "0xsigned";
      },
    } as Vault;
    const governed = new GovernedVault(rawVault, async (_authorization, expected) => {
      calls.push(`consume:${expected.payloadDigest}`);
    });

    const result = await governed.signTransactionAuthorized(request, {
      txId: "tx-1",
      executionAuthorization: authorization,
      executionPayloadDigest: authorization.payloadDigest,
    });

    expect(result).toBe("0xsigned");
    expect(calls).toEqual([`consume:${authorization.payloadDigest}`, "raw-sign"]);
  });

  it("fails closed when the supplied digest does not match the actual request", async () => {
    let rawCalled = false;
    const rawVault = {
      async signTransaction() {
        rawCalled = true;
        return "0xsigned";
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {
      throw new Error("consume must not be reached");
    });

    await expect(
      governed.signTransactionAuthorized(
        { ...request, value: "2" },
        {
          txId: "tx-mismatch",
          executionAuthorization: authorization,
          executionPayloadDigest: authorization.payloadDigest,
        },
      ),
    ).rejects.toThrow("does not match");
    expect(rawCalled).toBe(false);
  });

  it("fails closed before raw signing without authorization", async () => {
    let rawCalled = false;
    const rawVault = {
      async signTransaction() {
        rawCalled = true;
        return "0xsigned";
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {});

    await expect(
      governed.signTransactionAuthorized(request, {
        txId: "tx-missing",
        executionPayloadDigest: authorization.payloadDigest,
      }),
    ).rejects.toBeInstanceOf(GovernedVaultError);
    expect(rawCalled).toBe(false);
  });

  it("does not raw-sign when the consume callback rejects replay", async () => {
    let rawCalled = false;
    const rawVault = {
      async signTransaction() {
        rawCalled = true;
        return "0xsigned";
      },
    } as unknown as Vault;
    const governed = new GovernedVault(rawVault, async () => {
      throw new Error("nonce consumed");
    });

    await expect(
      governed.signTransactionAuthorized(request, {
        txId: "tx-replay",
        executionAuthorization: authorization,
        executionPayloadDigest: authorization.payloadDigest,
      }),
    ).rejects.toThrow("nonce consumed");
    expect(rawCalled).toBe(false);
  });

  it("threads expectedBackend=local-vault into the raw signer (TOCTOU backend binding)", async () => {
    // The governed path is only ever consumed against backend "local-vault"
    // (see the consume callback's expected.backend). It must bind the raw
    // signer to that same backend so the vault layer can re-resolve and fail
    // closed if the wallet flipped to third-party custody between resolution and
    // signing. This asserts the option is forwarded verbatim.
    let observedOptions: SignTransactionOptions | undefined;
    const rawVault = {
      async signTransaction(_request: SignRequest, options: SignTransactionOptions) {
        observedOptions = options;
        return "0xsigned";
      },
    } as Vault;
    const governed = new GovernedVault(rawVault, async () => {});

    await governed.signTransactionAuthorized(request, {
      txId: "tx-bound",
      executionAuthorization: authorization,
      executionPayloadDigest: authorization.payloadDigest,
    });

    expect(observedOptions?.expectedBackend).toBe("local-vault");
    // The gateway-only fields are stripped before reaching the raw signer.
    expect(
      (observedOptions as { executionAuthorization?: unknown }).executionAuthorization,
    ).toBeUndefined();
    expect(
      (observedOptions as { executionPayloadDigest?: unknown }).executionPayloadDigest,
    ).toBeUndefined();
  });

  it("digest binds normalized intent via the shared canonicalizer (safe-integer validated)", () => {
    // Field-order independence proves the shared canonicalizer is used.
    const a = executionPayloadDigestForGovernedEvmSign({
      chainId: 8453,
      agentId: "agent-1",
      tenantId: "tenant-1",
      to: "0x1111111111111111111111111111111111111111",
      value: "1",
      nonce: 5,
      broadcast: false,
    });
    const b = executionPayloadDigestForGovernedEvmSign({
      to: "0x1111111111111111111111111111111111111111",
      value: "1",
      broadcast: false,
      nonce: 5,
      tenantId: "tenant-1",
      agentId: "agent-1",
      chainId: 8453,
    });
    expect(a).toBe(b);

    // Malformed numeric caller fields are rejected before digesting.
    expect(() => executionPayloadDigestForGovernedEvmSign({ ...request, nonce: -1 })).toThrow();
    expect(() => executionPayloadDigestForGovernedEvmSign({ ...request, chainId: -1 })).toThrow();
  });
});
