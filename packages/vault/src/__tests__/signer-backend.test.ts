import { describe, expect, test } from "bun:test";

import { assertNoRawKeyExport, type SignerBackend, type ThresholdKeyRef } from "../signer-backend";

// A toy in-memory SignerBackend that exercises the interface SHAPE only. It is
// NOT a real threshold implementation (the real one is the FROST sidecar in
// @stwd/signer-frost). It proves: (1) the interface can be implemented without a
// raw-key path, (2) below-threshold signing rejects, (3) the runtime guard
// catches a backend that lies about canReturnRawKey.
function makeToyBackend(): SignerBackend & { availableShares: number } {
  const state = { availableShares: 2 };
  const ref: ThresholdKeyRef = {
    backend: "toy@2of3",
    groupId: "toy-group",
    publicKey: "0x" + "02".padEnd(66, "0"),
    scheme: "frost-secp256k1",
    threshold: 2,
    participants: 3,
  };
  return {
    id: "toy@2of3",
    availableShares: state.availableShares,
    capabilities: { canReturnRawKey: false, supportsReshare: false },
    async generate() {
      return ref;
    },
    async sign(r, message) {
      if (this.availableShares < r.threshold) {
        throw new Error(`below threshold: have ${this.availableShares}, need ${r.threshold}`);
      }
      // Deterministic toy "signature": not real crypto, just shape.
      const sig = new Uint8Array(64);
      sig.set(message.slice(0, Math.min(message.length, 64)));
      return { signature: sig };
    },
    async verify(_r, _message, signature) {
      return signature.length === 64;
    },
  };
}

describe("SignerBackend interface", () => {
  test("a backend can be implemented with no raw-key export path", () => {
    const backend = makeToyBackend();
    // TypeScript: `capabilities.canReturnRawKey` is the literal `false`.
    const cap: false = backend.capabilities.canReturnRawKey;
    expect(cap).toBe(false);
    // There is no `export`/`decrypt`/`getPrivateKey` method on the interface.
    expect((backend as Record<string, unknown>).decrypt).toBeUndefined();
    expect((backend as Record<string, unknown>).exportPrivateKey).toBeUndefined();
  });

  test("generate returns a ThresholdKeyRef with no private material", async () => {
    const backend = makeToyBackend();
    const ref = await backend.generate({
      scheme: "frost-secp256k1",
      threshold: 2,
      participants: 3,
    });
    expect(ref.threshold).toBe(2);
    expect(ref.participants).toBe(3);
    expect(ref.publicKey).toStartWith("0x");
    // The ref object must not carry anything private.
    expect(JSON.stringify(ref)).not.toContain("private");
  });

  test("sign succeeds at threshold and rejects below threshold", async () => {
    const backend = makeToyBackend();
    const ref = await backend.generate({
      scheme: "frost-secp256k1",
      threshold: 2,
      participants: 3,
    });
    const msg = new Uint8Array(32).fill(7);

    backend.availableShares = 2;
    const sig = await backend.sign(ref, msg);
    expect(sig.signature.length).toBe(64);

    backend.availableShares = 1;
    await expect(backend.sign(ref, msg)).rejects.toThrow(/below threshold/);
  });

  test("assertNoRawKeyExport passes an honest backend", () => {
    const backend = makeToyBackend();
    expect(() => assertNoRawKeyExport(backend)).not.toThrow();
  });

  test("assertNoRawKeyExport rejects a backend that lies about canReturnRawKey", () => {
    const liar = makeToyBackend() as unknown as SignerBackend;
    // Force a dishonest capability via cast (simulating an `any`-typed backend).
    (liar.capabilities as unknown as { canReturnRawKey: boolean }).canReturnRawKey = true;
    expect(() => assertNoRawKeyExport(liar)).toThrow(/never expose raw key export/);
  });
});
