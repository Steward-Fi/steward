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
      "basicAuth",
      "oauth",
      "authorizationHeader",
      "access_token_value",
      "apiKeyValue",
      "passwordValue",
      "clientSecretValue",
      "oauth_client_secret_value",
      "cookieHeader",
      "session_cookie_header",
      "accessToken",
      "api_key",
      "privateKey",
      "privateKeyPem",
      "privateKeyPemValue",
      "private_key_pems",
      "aws_access_key_id",
      "awsAccessKey",
      "access_key_value",
      "secretAccessKey",
      "secretKeyHeader",
      "session_id",
      "clientCertificate",
      "signing_key",
      "walletMnemonic",
      "seed_phrase",
      "recoveryPhrase",
      "serviceJwt",
      "pat",
      "bearer",
      "accessTokenValue",
      "credential_value",
      "authorizationHeaderValue",
      "credential_headers",
      "apiKeys",
      "private_key_headers",
      "sessionCookieHeaderValues",
    ]) {
      expect(isSensitiveCredentialKey(key), key).toBe(true);
    }

    for (const key of [
      "author",
      "authenticationMode",
      "cookiePolicy",
      "tokenAddress",
      "tokenCount",
      "passwordless",
      "secretSanta",
      "key",
      "publicKey",
      "publicKeyPem",
      "certificatePem",
      "accessKeyCount",
      "headers",
      "publicValues",
      "status",
    ]) {
      expect(isSensitiveCredentialKey(key), key).toBe(false);
    }
  });

  test("finds credential fields through nested records and arrays", () => {
    expect(
      containsSensitiveCredentialKey({ public: [{ nested: { clientSecretValue: "hidden" } }] }),
    ).toBe(true);
    expect(containsSensitiveCredentialKey({ public: { labels: ["safe"] } })).toBe(false);
  });

  test("finds private-key armor under innocuous fields without rejecting public armor", () => {
    for (const value of [
      "-----BEGIN PRIVATE KEY-----\nsecret",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nsecret",
      "-----BEGIN RSA PRIVATE KEY-----\nsecret",
      "-----BEGIN EC PRIVATE KEY-----\nsecret",
      "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret",
    ]) {
      expect(containsSensitiveCredentialKey({ data: value }), value).toBe(true);
    }

    expect(containsSensitiveCredentialKey({ data: "-----BEGIN PUBLIC KEY-----\npublic" })).toBe(
      false,
    );
    expect(containsSensitiveCredentialKey({ data: "-----BEGIN CERTIFICATE-----\npublic" })).toBe(
      false,
    );
  });

  test("fails closed without invoking accessors", () => {
    let invoked = false;
    const nested = Object.defineProperty({}, "public", {
      enumerable: true,
      get() {
        invoked = true;
        return "hidden";
      },
    });
    expect(containsSensitiveCredentialKey({ nested })).toBe(true);
    expect(invoked).toBe(false);
  });

  test("fails closed on cycles and excessive depth but permits repeated references", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(containsSensitiveCredentialKey(cyclic)).toBe(true);

    let deep: Record<string, unknown> = {};
    for (let i = 0; i < 22; i++) deep = { nested: deep };
    expect(containsSensitiveCredentialKey(deep)).toBe(true);

    const shared = { public: "safe" };
    expect(containsSensitiveCredentialKey({ left: shared, right: shared })).toBe(false);
  });
});
