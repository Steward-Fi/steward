import { describe, expect, test } from "bun:test";
import { containsSensitiveCredentialKey, isSensitiveCredentialKey } from "../sensitive-keys";

describe("sensitive credential keys", () => {
  test("recognizes normalized exact and suffix credential fields", () => {
    for (const key of [
      "password",
      "database_password",
      "passphrase",
      "wallet-passphrase",
      "auth",
      "clientSecretValue",
      "oauth_client_secret_value",
      "cookieHeader",
      "session_cookie_header",
      "accessToken",
      "api_key",
      "privateKey",
    ]) {
      expect(isSensitiveCredentialKey(key), key).toBe(true);
    }

    for (const key of ["author", "authenticationMode", "cookiePolicy", "tokenCount", "key"]) {
      expect(isSensitiveCredentialKey(key), key).toBe(false);
    }
  });

  test("finds credential fields through nested records and arrays", () => {
    expect(
      containsSensitiveCredentialKey({ public: [{ nested: { clientSecretValue: "hidden" } }] }),
    ).toBe(true);
    expect(containsSensitiveCredentialKey({ public: { labels: ["safe"] } })).toBe(false);
  });

  test("fails closed without invoking accessors", () => {
    let invoked = false;
    const input = Object.defineProperty({}, "password", {
      enumerable: true,
      get() {
        invoked = true;
        return "hidden";
      },
    });
    expect(containsSensitiveCredentialKey(input)).toBe(true);
    expect(invoked).toBe(false);
  });
});
