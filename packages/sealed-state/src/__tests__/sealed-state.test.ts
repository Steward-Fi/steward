import { describe, expect, test } from "bun:test";
import { DevMeasurementKeyProvider, SealedState } from "..";

const m1 = { imageDigest: "image-a", configHash: "compose-a" };
const m2 = { imageDigest: "image-a", configHash: "compose-b" };
const store = new SealedState(new DevMeasurementKeyProvider("development-secret-only", "test"));

describe("sealed state", () => {
  test("round trips only under the same measurement", async () => {
    const envelope = await store.seal(new TextEncoder().encode("agent memory"), m1);
    expect(new TextDecoder().decode(await store.unseal(envelope, m1))).toBe("agent memory");
    await expect(store.unseal(envelope, m2)).rejects.toThrow(/measurement mismatch/);
  });

  test("property: every distinct simulated measurement fails closed", async () => {
    for (let index = 0; index < 64; index += 1) {
      const source = { imageDigest: `image-${index}`, configHash: `config-${index}` };
      const other = { ...source, configHash: `config-other-${index}` };
      const envelope = await store.seal(crypto.getRandomValues(new Uint8Array(32)), source);
      await expect(store.unseal(envelope, other)).rejects.toThrow(/measurement mismatch/);
    }
  });

  test("corrupt ciphertext and authenticated metadata fail closed", async () => {
    const envelope = await store.seal(new TextEncoder().encode("private state"), m1);
    const corrupt = { ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -2)}AA` };
    await expect(store.unseal(corrupt, m1)).rejects.toThrow(/authentication failed/);
    await expect(store.unseal({ ...envelope, purpose: "other" }, m1)).rejects.toThrow(
      /authentication failed/,
    );
  });

  test("dev provider cannot be enabled in production", () => {
    expect(() => new DevMeasurementKeyProvider("development-secret-only", "production")).toThrow(
      /forbidden/,
    );
  });
});
