import { describe, expect, test } from "bun:test";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { recoverAuthorizationAddress } from "viem/experimental";
import {
  assembleEip7702Transaction,
  buildEip7702BroadcastRequest,
  EIP7702_DELEGATION_PREFIX,
  parseEip7702DelegatedImplementation,
  parseEip7702Transaction,
  readEip7702Delegation,
  serializeEip7702Transaction,
  toEip7702SignedAuthorization,
} from "../eip7702-auth";

/**
 * Pure-crypto test for EIP-7702 authorization signing. Exercises viem's
 * `account.signAuthorization()` directly so the test does not require a DB
 * fixture, and pins the signature → address recovery so any future viem
 * upgrade that breaks the EIP-7702 round-trip surfaces here.
 */
describe("EIP-7702 authorization signing", () => {
  test("a signed authorization recovers to the signer address", async () => {
    const pk = generatePrivateKey();
    const account = privateKeyToAccount(pk);
    const params = {
      contractAddress: "0xCAfe000000000000000000000000000000000000" as const,
      chainId: 1,
      nonce: 0,
    };
    const signed = await account.signAuthorization(params);
    const recovered = await recoverAuthorizationAddress({ authorization: signed });
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    expect(signed.r).toMatch(/^0x[0-9a-f]{64}$/);
    expect(signed.s).toMatch(/^0x[0-9a-f]{64}$/);
    expect([0, 1]).toContain(signed.yParity);
  });

  test("chainId=0 ('any chain') is accepted by the signer", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const signed = await account.signAuthorization({
      contractAddress: "0x1111111111111111111111111111111111111111",
      chainId: 0,
      nonce: 7,
    });
    expect(signed.chainId).toBe(0);
    expect(signed.nonce).toBe(7);
  });

  test("two signers over the same params produce different signatures", async () => {
    const a = privateKeyToAccount(generatePrivateKey());
    const b = privateKeyToAccount(generatePrivateKey());
    const params = {
      contractAddress: "0x2222222222222222222222222222222222222222" as const,
      chainId: 8453,
      nonce: 3,
    };
    const sa = await a.signAuthorization(params);
    const sb = await b.signAuthorization(params);
    expect(sa.r === sb.r && sa.s === sb.s).toBe(false);
    const ra = await recoverAuthorizationAddress({ authorization: sa });
    const rb = await recoverAuthorizationAddress({ authorization: sb });
    expect(ra).not.toBe(rb);
  });

  test("nonce changes the signature for the same signer", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const base = {
      contractAddress: "0x3333333333333333333333333333333333333333" as const,
      chainId: 1,
    };
    const s0 = await account.signAuthorization({ ...base, nonce: 0 });
    const s1 = await account.signAuthorization({ ...base, nonce: 1 });
    expect(s0.r === s1.r && s0.s === s1.s).toBe(false);
  });

  test("assembles and parses an EIP-7702 type-4 transaction with an authorization list", async () => {
    const delegateSigner = privateKeyToAccount(generatePrivateKey());
    const txSigner = privateKeyToAccount(generatePrivateKey());
    const authorization = await delegateSigner.signAuthorization({
      contractAddress: "0x4444444444444444444444444444444444444444",
      chainId: 8453,
      nonce: 5,
    });
    const stewardAuthorization = {
      contractAddress: authorization.address,
      chainId: authorization.chainId,
      nonce: authorization.nonce,
      r: authorization.r,
      s: authorization.s,
      yParity: authorization.yParity,
    };

    const transaction = assembleEip7702Transaction({
      chainId: 8453,
      nonce: 9,
      to: "0x5555555555555555555555555555555555555555",
      value: "123",
      data: "0xabcdef",
      gas: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      authorizationList: [stewardAuthorization],
    });
    expect(transaction.type).toBe("eip7702");
    expect(transaction.authorizationList).toEqual([
      toEip7702SignedAuthorization(stewardAuthorization),
    ]);

    const unsignedRaw = serializeEip7702Transaction({
      chainId: 8453,
      nonce: 9,
      to: "0x5555555555555555555555555555555555555555",
      value: "123",
      data: "0xabcdef",
      gas: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      authorizationList: [stewardAuthorization],
    });
    expect(unsignedRaw.startsWith("0x04")).toBe(true);

    const signedRaw = await txSigner.signTransaction(transaction);
    expect(signedRaw.startsWith("0x04")).toBe(true);

    const parsed = parseEip7702Transaction(signedRaw);
    expect(parsed).toMatchObject({
      type: "eip7702",
      chainId: 8453,
      nonce: 9,
      to: "0x5555555555555555555555555555555555555555",
      value: 123n,
      data: "0xabcdef",
      gas: 100000n,
      maxFeePerGas: 2000000000n,
      maxPriorityFeePerGas: 1000000000n,
      authorizationList: [
        {
          address: authorization.address,
          contractAddress: authorization.address,
          chainId: 8453,
          nonce: 5,
          r: authorization.r,
          s: authorization.s,
          yParity: authorization.yParity,
        },
      ],
    });

    const broadcast = buildEip7702BroadcastRequest(8453, signedRaw);
    expect(broadcast).toEqual({
      chainId: 8453,
      rawTransaction: signedRaw,
      rpcRequest: {
        method: "eth_sendRawTransaction",
        params: [signedRaw],
        chainId: 8453,
      },
    });
  });

  test("rejects unsafe or malformed type-4 assembly and broadcast inputs", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const authorization = await account.signAuthorization({
      contractAddress: "0x6666666666666666666666666666666666666666",
      chainId: 1,
      nonce: 0,
    });
    const stewardAuthorization = {
      contractAddress: authorization.address,
      chainId: authorization.chainId,
      nonce: authorization.nonce,
      r: authorization.r,
      s: authorization.s,
      yParity: authorization.yParity,
    };

    expect(() => assembleEip7702Transaction({ chainId: 1, authorizationList: [] })).toThrow(
      "authorizationList must contain at least one signed authorization",
    );
    expect(() =>
      assembleEip7702Transaction({
        chainId: 1,
        data: "not-hex",
        authorizationList: [stewardAuthorization],
      }),
    ).toThrow("data must be hex");
    expect(() =>
      assembleEip7702Transaction({
        chainId: 1,
        authorizationList: [{ ...stewardAuthorization, r: "0x1234" }],
      }),
    ).toThrow("authorization r must be 32-byte hex");
    expect(() => parseEip7702Transaction("0x02deadbeef")).toThrow(
      "rawTransaction must be an EIP-7702 type-4 transaction",
    );

    const signedRaw = await account.signTransaction(
      assembleEip7702Transaction({
        chainId: 1,
        nonce: 0,
        to: "0x7777777777777777777777777777777777777777",
        gas: 21000n,
        maxFeePerGas: 2n,
        maxPriorityFeePerGas: 1n,
        authorizationList: [stewardAuthorization],
      }),
    );
    expect(() => buildEip7702BroadcastRequest(8453, signedRaw)).toThrow(
      "rawTransaction chainId does not match broadcast chainId",
    );
  });
});

describe("EIP-7702 delegated implementation detection", () => {
  test("extracts the implementation address from exact delegation designator code", () => {
    const implementationAddress = "0x1234567890123456789012345678901234567890";
    const code = `${EIP7702_DELEGATION_PREFIX}${implementationAddress.slice(2)}`;

    expect(parseEip7702DelegatedImplementation(code)).toBe(implementationAddress);
  });

  test("treats empty or normal contract bytecode as not delegated", () => {
    expect(parseEip7702DelegatedImplementation("0x")).toBeNull();
    expect(parseEip7702DelegatedImplementation("0x6080604052348015600f57600080fd5b")).toBeNull();
  });

  test("rejects malformed code and malformed delegation designators", () => {
    expect(() => parseEip7702DelegatedImplementation("not-hex")).toThrow(
      "eth_getCode returned invalid hex code",
    );
    expect(() => parseEip7702DelegatedImplementation(`${EIP7702_DELEGATION_PREFIX}1234`)).toThrow(
      "eth_getCode returned malformed EIP-7702 delegation code",
    );
  });

  test("reads latest account code through a caller-supplied eth_getCode adapter", async () => {
    const walletAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const implementationAddress = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const calls: Array<[string, "latest"]> = [];
    const status = await readEip7702Delegation({
      walletAddress,
      chainId: 8453,
      getCode: async (address, blockTag) => {
        calls.push([address, blockTag]);
        return `${EIP7702_DELEGATION_PREFIX}${implementationAddress.slice(2)}`;
      },
    });

    expect(calls).toEqual([[walletAddress, "latest"]]);
    expect(status).toEqual({
      walletAddress,
      chainId: 8453,
      delegated: true,
      implementationAddress,
      code: `${EIP7702_DELEGATION_PREFIX}${implementationAddress.slice(2)}`,
    });
  });
});
