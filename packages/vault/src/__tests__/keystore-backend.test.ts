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

  test("production NEVER takes the no-AAD legacy fallback, even with the env flag set", () => {
    const previousEnv = process.env.NODE_ENV;
    const previousFallback = process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK;
    try {
      process.env.NODE_ENV = "production";
      delete process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK;

      const ks = new KeyStore(
        "legacy-context-binding-test",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
      );
      const legacyCiphertext = ks.encrypt("0x" + "2".repeat(64));

      expect(() =>
        ks.decrypt(legacyCiphertext, {
          tenantId: "tenant-b",
          agentId: "agent-b",
          chainFamily: "evm",
          venue: null,
        }),
      ).toThrow();

      // Hardened: the env flag MUST NOT enable the no-AAD path in production.
      process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK = "true";
      expect(() =>
        ks.decrypt(legacyCiphertext, {
          tenantId: "tenant-b",
          agentId: "agent-b",
          chainFamily: "evm",
          venue: null,
        }),
      ).toThrow();
    } finally {
      if (previousEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousEnv;
      if (previousFallback === undefined) {
        delete process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK;
      } else {
        process.env.STEWARD_ALLOW_LEGACY_KEYSTORE_DECRYPT_FALLBACK = previousFallback;
      }
    }
  });
});

if (env !== undefined) process.env.NODE_ENV = env;
else delete process.env.NODE_ENV;
