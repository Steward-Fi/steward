import { describe, expect, it } from "bun:test";
import type { ExecutionAuthorization, SignRequest } from "@stwd/shared";
import {
  executionPayloadDigestForGovernedEvmSign,
  GovernedVault,
  GovernedVaultError,
} from "../governed-vault";
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
