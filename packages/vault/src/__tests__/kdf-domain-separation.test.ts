import { describe, expect, test } from "bun:test";

import { KeyStore } from "../keystore";

// Explicit salt → deterministic derivation independent of env. The three roots
// are constructed once (scrypt is intentionally expensive) and reused across tests.
const SALT = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MASTER = "shared-master-password-for-both-vaults";

const signingRoot = new KeyStore(MASTER, SALT); // legacy/undomain root used by the signing Vault
const secretRoot = new KeyStore(MASTER, SALT, "secret-vault");
const altDomainRoot = new KeyStore(MASTER, SALT, "signing-vault");

// scrypt makes each op ~10ms; give these crypto tests headroom over the 5s default.
const TIMEOUT = 30_000;

describe("KDF domain separation (#11)", () => {
  test(
    "secret-vault and signing-vault roots are cryptographically distinct",
    () => {
      // A ciphertext from one root MUST NOT decrypt under the other (auth-tag
      // failure) — proving the two roots are independent keys.
      const value = `0x${"a".repeat(64)}`;
      const signingCt = signingRoot.encrypt(value);
      expect(() => secretRoot.decrypt(signingCt)).toThrow();

      const secretCt = secretRoot.encrypt(value);
      expect(() => signingRoot.decrypt(secretCt)).toThrow();

      // Each root still round-trips its own ciphertext.
      expect(signingRoot.decrypt(signingCt)).toBe(value);
      expect(secretRoot.decrypt(secretCt)).toBe(value);
    },
    TIMEOUT,
  );

  test(
    "distinct domain labels yield distinct roots",
    () => {
      const ct = secretRoot.encrypt("hello");
      expect(() => altDomainRoot.decrypt(ct)).toThrow();
      expect(secretRoot.decrypt(ct)).toBe("hello");
    },
    TIMEOUT,
  );

  test(
    "legacy (undomain) ciphertext is still decryptable by the legacy root — backward compat",
    () => {
      // Simulates a row written before domain separation existed.
      const ct = signingRoot.encrypt("pre-migration-secret");
      const legacy2 = new KeyStore(MASTER, SALT); // same derivation as signingRoot
      expect(legacy2.decrypt(ct)).toBe("pre-migration-secret");
    },
    TIMEOUT,
  );

  test(
    "SecretVault two-root strategy: legacy ciphertext via fallback, new writes under domain root",
    () => {
      const legacyCt = signingRoot.encrypt("old-api-key");
      const decryptWithFallback = (ct: ReturnType<KeyStore["encrypt"]>) => {
        try {
          return secretRoot.decrypt(ct);
        } catch {
          return signingRoot.decrypt(ct);
        }
      };
      expect(decryptWithFallback(legacyCt)).toBe("old-api-key");

      const newCt = secretRoot.encrypt("new-api-key");
      expect(decryptWithFallback(newCt)).toBe("new-api-key");
    },
    TIMEOUT,
  );
});
