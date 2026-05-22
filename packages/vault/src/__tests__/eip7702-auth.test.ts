import { describe, expect, test } from "bun:test";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { recoverAuthorizationAddress } from "viem/experimental";

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
});
