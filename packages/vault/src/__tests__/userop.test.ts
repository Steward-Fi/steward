import { describe, expect, test } from "bun:test";
import { recoverMessageAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  ENTRY_POINT_V07,
  getUserOperationDigest,
  getUserOperationHash,
  packUints,
  packUserOperation,
  type UnpackedUserOperationFields,
} from "../userop";

const sampleOp: UnpackedUserOperationFields = {
  sender: "0x1111111111111111111111111111111111111111",
  nonce: 0n,
  initCode: "0x",
  callData: "0xdeadbeef",
  verificationGasLimit: 100000n,
  callGasLimit: 200000n,
  preVerificationGas: 21000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  maxFeePerGas: 2_000_000_000n,
  paymasterAndData: "0x",
};

describe("ERC-4337 userOp hashing", () => {
  test("packUints rejects values > uint128", () => {
    expect(() => packUints(1n << 128n, 0n)).toThrow();
    expect(() => packUints(0n, -1n)).toThrow();
  });

  test("packUints encodes high/low into a bytes32", () => {
    expect(packUints(0x1234n, 0x5678n)).toBe(
      "0x0000000000000000000000000000123400000000000000000000000000005678",
    );
  });

  test("getUserOperationHash is deterministic and chain-bound", () => {
    const packed = packUserOperation(sampleOp);
    const h1 = getUserOperationHash(packed, ENTRY_POINT_V07, 1);
    const h2 = getUserOperationHash(packed, ENTRY_POINT_V07, 1);
    const h3 = getUserOperationHash(packed, ENTRY_POINT_V07, 8453);
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h1).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("EOA signature over personal-sign digest recovers to the signer", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const packed = packUserOperation({ ...sampleOp, sender: account.address });
    const hash = getUserOperationHash(packed, ENTRY_POINT_V07, 1);
    const sig = await account.signMessage({ message: { raw: hash } });
    const digest = getUserOperationDigest(packed, ENTRY_POINT_V07, 1);
    const recovered = await recoverMessageAddress({ message: { raw: hash }, signature: sig });
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    expect(digest).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test("any mutated field changes the hash", () => {
    const baseHash = getUserOperationHash(packUserOperation(sampleOp), ENTRY_POINT_V07, 1);
    const mutated = packUserOperation({ ...sampleOp, nonce: 1n });
    expect(getUserOperationHash(mutated, ENTRY_POINT_V07, 1)).not.toBe(baseHash);
    const otherEntry = "0x0000000000000000000000000000000000000001" as const;
    expect(getUserOperationHash(packUserOperation(sampleOp), otherEntry, 1)).not.toBe(baseHash);
  });
});
