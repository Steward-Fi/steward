import { describe, expect, it } from "bun:test";
import { KeyStore } from "../keystore";

const SKIP = !process.env.DATABASE_URL;
const d = SKIP ? describe.skip : describe;

// Pure round-trip rotation test: simulates the per-row transformation the
// CLI applies — decrypt with OLD KeyStore, re-encrypt with NEW KeyStore,
// then decrypt with NEW. No DB required at the call-site level, but gated
// on DATABASE_URL to match the project convention for rotation tooling.
d("master password rotation round-trip", () => {
  const OLD_PW = "old-password-aaaaaaaaaaaaaaaaaaaa";
  const OLD_SALT = "aa".repeat(16);
  const NEW_PW = "new-password-bbbbbbbbbbbbbbbbbbbb";
  const NEW_SALT = "bb".repeat(16);

  const oldKs = new KeyStore(OLD_PW, OLD_SALT);
  const newKs = new KeyStore(NEW_PW, NEW_SALT);

  it("re-encrypts a dataset and preserves every plaintext", () => {
    const dataset = [
      "0xprivatekey1deadbeef",
      "sk-api-key-with-various-chars/+=",
      JSON.stringify({ a: 1, b: [2, 3], c: "x" }),
      "",
      "uéunicodeé",
    ];

    const oldRows = dataset.map((pt) => ({ pt, enc: oldKs.encrypt(pt) }));

    // Rotate: decrypt with OLD, re-encrypt with NEW.
    const newRows = oldRows.map((r) => {
      const decrypted = oldKs.decrypt(r.enc);
      const reEncrypted = newKs.encrypt(decrypted);
      return { pt: r.pt, enc: reEncrypted };
    });

    // Every new row must decrypt with NEW back to the original plaintext.
    for (const r of newRows) {
      expect(newKs.decrypt(r.enc)).toBe(r.pt);
    }
  });

  it("NEW-encrypted rows cannot be decrypted with the OLD keystore", () => {
    const pt = "secret-value";
    const newRow = newKs.encrypt(pt);
    expect(() => oldKs.decrypt(newRow)).toThrow();
  });

  it("OLD-encrypted rows cannot be decrypted with the NEW keystore (sanity)", () => {
    const pt = "secret-value";
    const oldRow = oldKs.encrypt(pt);
    expect(() => newKs.decrypt(oldRow)).toThrow();
  });
});
