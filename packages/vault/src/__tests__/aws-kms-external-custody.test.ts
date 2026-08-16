import { describe, expect, test } from "bun:test";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  getAddress,
  type Hex,
  parseTransaction,
  recoverTransactionAddress,
  type TransactionSerializableLegacy,
  toHex,
} from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  type AwsKmsEvmRpc,
  AwsKmsExternalKeyCustodyProvider,
  type AwsKmsSigningClientLike,
  decodeAwsKmsEcdsaSignature,
} from "../aws-kms-external-custody";
import type {
  ExternalKeyHandleImportRequest,
  ExternalKeySignTransactionRequest,
} from "../external-key-custody";
import { runExternalKeyCustodyV1Conformance } from "../external-key-custody-conformance";

const CURVE_ORDER = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

function hexBytes(value: string): Uint8Array {
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  return Uint8Array.from({ length: clean.length / 2 }, (_, index) =>
    Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16),
  );
}

function concatBytes(...values: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function spkiForPrivateKey(privateKey: Uint8Array): Uint8Array {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  // SubjectPublicKeyInfo(ecPublicKey, secp256k1, uncompressed point).
  return concatBytes(hexBytes("3056301006072a8648ce3d020106052b8104000a034200"), publicKey);
}

function addressForPrivateKey(privateKey: Uint8Array) {
  return getAddress(publicKeyToAddress(toHex(secp256k1.getPublicKey(privateKey, false))));
}

type SignatureMode = "normal" | "high-s" | "malformed";

class MockKms implements AwsKmsSigningClientLike {
  readonly commands: Array<{ commandName: string; input: Record<string, unknown> }> = [];

  constructor(
    private readonly privateKey: Uint8Array,
    private readonly signatureMode: SignatureMode = "normal",
    private readonly keySpec = "ECC_SECG_P256K1",
  ) {}

  async send(command: unknown): Promise<unknown> {
    const parsed = command as { commandName: string; input: Record<string, unknown> };
    this.commands.push(parsed);
    if (parsed.commandName === "GetPublicKeyCommand") {
      return {
        KeyId: "arn:aws:kms:us-east-1:111122223333:key/test",
        PublicKey: spkiForPrivateKey(this.privateKey),
        KeySpec: this.keySpec,
        KeyUsage: "SIGN_VERIFY",
        SigningAlgorithms: ["ECDSA_SHA_256"],
      };
    }
    if (parsed.commandName === "SignCommand") {
      const digest = parsed.input.Message as Uint8Array;
      if (this.signatureMode === "malformed") {
        return { Signature: new Uint8Array([0x30, 0x01, 0x00]) };
      }
      const signature = secp256k1.sign(digest, this.privateKey, { lowS: true });
      const encoded =
        this.signatureMode === "high-s"
          ? new secp256k1.Signature(signature.r, CURVE_ORDER - signature.s).toBytes("der")
          : signature.toBytes("der");
      return { Signature: encoded, SigningAlgorithm: "ECDSA_SHA_256" };
    }
    throw new Error(`unexpected mock command ${parsed.commandName}`);
  }
}

class MockRpc implements AwsKmsEvmRpc {
  readonly broadcasts: Hex[] = [];
  transaction: TransactionSerializableLegacy = {
    type: "legacy",
    chainId: 8453,
    nonce: 7,
    gas: 21_000n,
    gasPrice: 1_000_000_000n,
    to: "0x2222222222222222222222222222222222222222",
    value: 123n,
    data: "0x",
  };

  async prepareTransaction(): Promise<TransactionSerializableLegacy> {
    return this.transaction;
  }

  async broadcast(serializedTransaction: Hex): Promise<Hex> {
    this.broadcasts.push(serializedTransaction);
    return "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  }
}

function registrationRequest(
  privateKey: Uint8Array,
  overrides: Partial<ExternalKeyHandleImportRequest> = {},
): ExternalKeyHandleImportRequest {
  return {
    tenantId: "tenant-1",
    agentId: "agent-1",
    chainFamily: "evm",
    address: addressForPrivateKey(privateKey),
    handle: { providerId: "aws-kms", keyId: "alias/steward-agent-1", region: "us-east-1" },
    venue: "aws-primary",
    purpose: "evm-signing",
    metadata: { owner: "security" },
    ...overrides,
  };
}

function signRequest(
  privateKey: Uint8Array,
  overrides: Partial<ExternalKeySignTransactionRequest> = {},
): ExternalKeySignTransactionRequest {
  return {
    tenantId: "tenant-1",
    agentId: "agent-1",
    chainFamily: "evm",
    address: addressForPrivateKey(privateKey),
    handle: { providerId: "aws-kms", keyId: "alias/steward-agent-1", region: "us-east-1" },
    chainId: 8453,
    to: "0x2222222222222222222222222222222222222222",
    value: "123",
    data: "0x",
    gasLimit: "21000",
    nonce: 7,
    broadcast: false,
    rpcUrl: "https://rpc.example.test",
    ...overrides,
  };
}

function providerFor(kms: MockKms, rpc: MockRpc): AwsKmsExternalKeyCustodyProvider {
  return new AwsKmsExternalKeyCustodyProvider({
    client: kms,
    region: "us-east-1",
    rpcFactory: () => rpc,
  });
}

describe("AWS KMS asymmetric external custody", () => {
  test("passes the reusable external custody v1 conformance contract", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const result = await runExternalKeyCustodyV1Conformance({
      createProvider: () => providerFor(new MockKms(privateKey), new MockRpc()),
      validRegistrationRequest: registrationRequest(privateKey),
    });
    expect(result).toEqual({
      contractVersion: 1,
      providerId: "external-custody:aws-kms",
      signingAvailability: "provider-signing",
    });
  });

  test("registers only an address-bound secp256k1 SIGN_VERIFY handle", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const kms = new MockKms(privateKey);
    const registration = await providerFor(kms, new MockRpc()).registerKeyHandle(
      registrationRequest(privateKey),
    );

    expect(registration).toMatchObject({
      custody: "external",
      chainFamily: "evm",
      address: addressForPrivateKey(privateKey),
      exportablePrivateKey: false,
      signingAvailability: "provider-signing",
      handle: { providerId: "aws-kms", keyId: "alias/steward-agent-1" },
    });
    const serializedRegistration = JSON.stringify(registration).toLowerCase();
    expect(serializedRegistration).not.toContain("secretkey");
    expect(serializedRegistration).not.toContain("mnemonic");
    expect(serializedRegistration).not.toContain("ciphertext");
    expect(kms.commands[0]).toEqual({
      commandName: "GetPublicKeyCommand",
      input: { KeyId: "alias/steward-agent-1" },
    });
  });

  test("rejects an address mismatch and unsupported AWS key modes", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    await expect(
      providerFor(new MockKms(privateKey), new MockRpc()).registerKeyHandle(
        registrationRequest(privateKey, {
          address: "0x1111111111111111111111111111111111111111",
        }),
      ),
    ).rejects.toThrow("does not match");

    await expect(
      providerFor(
        new MockKms(privateKey, "normal", "ECC_NIST_P256"),
        new MockRpc(),
      ).registerKeyHandle(registrationRequest(privateKey)),
    ).rejects.toThrow("ECC_SECG_P256K1");

    await expect(
      providerFor(new MockKms(privateKey), new MockRpc()).registerKeyHandle(
        registrationRequest(privateKey, { chainFamily: "solana" }),
      ),
    ).rejects.toThrow("EVM key handles only");

    await expect(
      new AwsKmsExternalKeyCustodyProvider({
        client: new MockKms(privateKey),
        region: "us-west-2",
        rpcFactory: () => new MockRpc(),
      }).registerKeyHandle(registrationRequest(privateKey)),
    ).rejects.toThrow("handle region must match");
  });

  test("signs a prepared legacy transaction digest and recovers the registered address", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const kms = new MockKms(privateKey);
    const result = await providerFor(kms, new MockRpc()).signTransaction(signRequest(privateKey));

    expect(result.broadcast).toBe(false);
    const raw = result.result as Hex;
    expect(await recoverTransactionAddress({ serializedTransaction: raw })).toBe(
      addressForPrivateKey(privateKey),
    );
    const parsed = parseTransaction(raw);
    expect(parsed.chainId).toBe(8453);
    expect(parsed.to).toBe("0x2222222222222222222222222222222222222222");
    expect(parsed.value).toBe(123n);
    expect(parsed.s && BigInt(parsed.s)).toBeLessThanOrEqual(CURVE_ORDER / 2n);

    const signCommand = kms.commands.find((command) => command.commandName === "SignCommand");
    expect(signCommand?.input).toMatchObject({
      KeyId: "alias/steward-agent-1",
      MessageType: "DIGEST",
      SigningAlgorithm: "ECDSA_SHA_256",
    });
    expect(signCommand?.input.Message).toBeInstanceOf(Uint8Array);
    expect((signCommand?.input.Message as Uint8Array).length).toBe(32);
  });

  test("normalizes high-s KMS output before serialization", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const result = await providerFor(
      new MockKms(privateKey, "high-s"),
      new MockRpc(),
    ).signTransaction(signRequest(privateKey));
    const parsed = parseTransaction(result.result as Hex);
    expect(parsed.s && BigInt(parsed.s)).toBeLessThanOrEqual(CURVE_ORDER / 2n);
    expect(await recoverTransactionAddress({ serializedTransaction: result.result as Hex })).toBe(
      addressForPrivateKey(privateKey),
    );
  });

  test("rejects malformed or wrong-key signatures before broadcast", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const malformedRpc = new MockRpc();
    await expect(
      providerFor(new MockKms(privateKey, "malformed"), malformedRpc).signTransaction(
        signRequest(privateKey, { broadcast: true }),
      ),
    ).rejects.toThrow("malformed ECDSA signature");
    expect(malformedRpc.broadcasts).toHaveLength(0);

    const otherKey = secp256k1.utils.randomPrivateKey();
    const wrongKeyRpc = new MockRpc();
    // GetPublicKey must still describe the registered key, while Sign is made to
    // return a signature from another key.
    const kms = new MockKms(privateKey);
    const originalSend = kms.send.bind(kms);
    kms.send = async (command: unknown) => {
      const parsed = command as { commandName: string; input: { Message: Uint8Array } };
      if (parsed.commandName === "SignCommand") {
        return { Signature: secp256k1.sign(parsed.input.Message, otherKey).toBytes("der") };
      }
      return originalSend(command);
    };
    await expect(
      providerFor(kms, wrongKeyRpc).signTransaction(signRequest(privateKey, { broadcast: true })),
    ).rejects.toThrow("does not recover");
    expect(wrongKeyRpc.broadcasts).toHaveLength(0);
  });

  test("rebinds semantic transaction fields before requesting a signature", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const kms = new MockKms(privateKey);
    const rpc = new MockRpc();
    rpc.transaction = { ...rpc.transaction, value: 124n };
    await expect(providerFor(kms, rpc).signTransaction(signRequest(privateKey))).rejects.toThrow(
      "wrong value",
    );
    expect(kms.commands.some((command) => command.commandName === "SignCommand")).toBe(false);

    rpc.transaction = { ...new MockRpc().transaction, nonce: 8 };
    await expect(providerFor(kms, rpc).signTransaction(signRequest(privateKey))).rejects.toThrow(
      "wrong nonce",
    );
    expect(kms.commands.some((command) => command.commandName === "SignCommand")).toBe(false);

    rpc.transaction = { ...new MockRpc().transaction, gas: 21_001n };
    await expect(providerFor(kms, rpc).signTransaction(signRequest(privateKey))).rejects.toThrow(
      "wrong gas limit",
    );
    expect(kms.commands.some((command) => command.commandName === "SignCommand")).toBe(false);
  });

  test("broadcasts only the address-verified serialized transaction", async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const rpc = new MockRpc();
    const result = await providerFor(new MockKms(privateKey), rpc).signTransaction(
      signRequest(privateKey, { broadcast: true }),
    );
    expect(result).toEqual({
      result: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      broadcast: true,
    });
    expect(rpc.broadcasts).toHaveLength(1);
    expect(await recoverTransactionAddress({ serializedTransaction: rpc.broadcasts[0] })).toBe(
      addressForPrivateKey(privateKey),
    );
  });

  test("strict DER parser rejects ambiguity, trailing bytes, zero and out-of-range scalars", () => {
    for (const malformed of [
      hexBytes("300102"),
      hexBytes("300602010102010100"),
      hexBytes("3006020100020101"),
      hexBytes("300702020001020101"),
      hexBytes("3006020180020101"),
    ]) {
      expect(() => decodeAwsKmsEcdsaSignature(malformed)).toThrow();
    }
  });
});
