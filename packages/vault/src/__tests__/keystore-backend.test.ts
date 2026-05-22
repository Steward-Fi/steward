import { describe, expect, test } from "bun:test";

import { KeyStore } from "../keystore";
import { backendFromKeyStore, type KeystoreBackend } from "../keystore-backend";

// Per-record randomness still requires NODE_ENV != production to skip the
// hard salt requirement. We set it explicitly here.
const env = process.env.NODE_ENV;
process.env.NODE_ENV = "test";

describe("KeystoreBackend interface", () => {
  test("backendFromKeyStore round-trips a private key", async () => {
    const ks = new KeyStore("backend-test-password");
    const backend: KeystoreBackend = backendFromKeyStore(ks);
    const pk = "0x" + "a".repeat(64);
    const encrypted = await backend.encrypt(pk);
    const decrypted = await backend.decrypt(encrypted);
    expect(decrypted).toBe(pk);
    expect(backend.id).toBe("aes-256-gcm@scrypt");
  });

  test("two encryptions of the same plaintext produce different ciphertext (IV freshness)", async () => {
    const backend = backendFromKeyStore(new KeyStore("iv-freshness-password"));
    const pk = "0xdeadbeef";
    const a = await backend.encrypt(pk);
    const b = await backend.encrypt(pk);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(await backend.decrypt(a)).toBe(pk);
    expect(await backend.decrypt(b)).toBe(pk);
  });

  test("a custom backend implementation satisfies the interface contract", async () => {
    // Identity backend — toy implementation that exercises the interface
    // shape without depending on KeyStore. Useful as the shape proof for
    // future MPC/HSM/TEE backends.
    const fake: KeystoreBackend = {
      id: "identity-noop",
      async encrypt(pk) {
        return { ciphertext: pk, iv: "00", tag: "00", salt: "00" };
      },
      async decrypt(e) {
        return e.ciphertext;
      },
    };
    const pk = "0x" + "1".repeat(64);
    const enc = await fake.encrypt(pk);
    expect(await fake.decrypt(enc)).toBe(pk);
  });

  test("context fields are accepted but optional", async () => {
    const backend: KeystoreBackend = {
      id: "context-noop",
      async encrypt(pk, ctx) {
        return {
          ciphertext: pk,
          iv: "00",
          tag: "00",
          salt: ctx?.agentId ?? "",
        };
      },
      async decrypt(e) {
        return e.ciphertext;
      },
    };
    const out = await backend.encrypt("k", { tenantId: "t", agentId: "a", venue: null });
    expect(out.salt).toBe("a");
    const out2 = await backend.encrypt("k");
    expect(out2.salt).toBe("");
  });
});

if (env !== undefined) process.env.NODE_ENV = env;
else delete process.env.NODE_ENV;
