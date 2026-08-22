import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import {
  _getPasskeyAuthForTests,
  assertAuthStoresAreSafe,
  authCallbackBaseUrl,
  getAllowedSiweDomains,
  getConfiguredOidcClientSecret,
  parseOAuthRedirectAllowlistEnv,
  resolvePasskeyRuntimeAuthority,
} from "../routes/auth";

describe("auth Worker runtime authority", () => {
  it("isolates passkey configuration and cached authenticators across overlapping bindings", async () => {
    const authorityA = {
      PASSKEY_RP_ID: "a.example",
      PASSKEY_RP_NAME: "Tenant A",
      PASSKEY_ORIGIN: "https://a.example",
      PASSKEY_ALLOWED_ORIGINS: "https://a.example,https://www.a.example",
    };
    const authorityB = {
      PASSKEY_RP_ID: "b.example",
      PASSKEY_RP_NAME: "Tenant B",
      PASSKEY_ORIGIN: "https://b.example",
      PASSKEY_ALLOWED_ORIGINS: "https://b.example",
    };
    let releaseA!: () => void;
    const holdA = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    let startedA!: () => void;
    const didStartA = new Promise<void>((resolve) => {
      startedA = resolve;
    });

    const pendingA = withRuntimeEnvironment(authorityA, async () => {
      const first = _getPasskeyAuthForTests(authorityA.PASSKEY_ORIGIN);
      startedA();
      await holdA;
      return {
        authority: resolvePasskeyRuntimeAuthority(),
        first,
        second: _getPasskeyAuthForTests(authorityA.PASSKEY_ORIGIN),
      };
    });
    await didStartA;
    const observedB = await withRuntimeEnvironment(authorityB, async () => {
      await Promise.resolve();
      return {
        authority: resolvePasskeyRuntimeAuthority(),
        auth: _getPasskeyAuthForTests(authorityB.PASSKEY_ORIGIN),
      };
    });
    releaseA();
    const observedA = await pendingA;

    expect(observedA.authority).toEqual({
      defaultRpID: "a.example",
      defaultOrigin: "https://a.example",
      rpName: "Tenant A",
      allowedOrigins: ["https://a.example", "https://www.a.example"],
    });
    expect(observedB.authority).toEqual({
      defaultRpID: "b.example",
      defaultOrigin: "https://b.example",
      rpName: "Tenant B",
      allowedOrigins: ["https://b.example"],
    });
    expect(observedA.first).toBe(observedA.second);
    expect(observedA.first).not.toBe(observedB.auth);
    expect(withRuntimeEnvironment({}, resolvePasskeyRuntimeAuthority)).toEqual({
      defaultRpID: "steward.fi",
      defaultOrigin: "https://steward.fi",
      rpName: "Steward",
      allowedOrigins: ["https://steward.fi"],
    });
  });

  it("isolates SIWE domains, OAuth redirects, and dynamic provider secrets", async () => {
    const dynamicSecretName = "STEWARD_TENANT_OIDC_SECRET_RUNTIME_AUTHORITY";
    const read = async () => {
      await Promise.resolve();
      return {
        siwe: getAllowedSiweDomains(),
        redirects: parseOAuthRedirectAllowlistEnv(),
        secret: getConfiguredOidcClientSecret(dynamicSecretName),
      };
    };
    const [a, b, missing] = await Promise.all([
      withRuntimeEnvironment(
        {
          SIWE_ALLOWED_DOMAINS: "a.example,www.a.example",
          STEWARD_OAUTH_ALLOWED_REDIRECTS: "https://a.example/callback",
          [dynamicSecretName]: "secret-a",
        },
        read,
      ),
      withRuntimeEnvironment(
        {
          APP_URL: "https://b.example/app",
          STEWARD_OAUTH_REDIRECT_ALLOWLIST: "https://b.example/callback",
          [dynamicSecretName]: "secret-b",
        },
        read,
      ),
      withRuntimeEnvironment({}, read),
    ]);

    expect(a).toEqual({
      siwe: ["a.example", "www.a.example"],
      redirects: ["https://a.example/callback"],
      secret: "secret-a",
    });
    expect(b).toEqual({
      siwe: ["b.example"],
      redirects: ["https://b.example/callback"],
      secret: "secret-b",
    });
    expect(missing).toEqual({ siwe: ["steward.fi"], redirects: [], secret: undefined });
  });

  it("fails closed for missing production callback and durable-store authority", () => {
    const context = {
      req: { header: (name: string) => (name === "host" ? "hostile.example" : undefined) },
    };
    expect(() =>
      withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
        authCallbackBaseUrl(context as never),
      ),
    ).toThrow("APP_URL is required");
    expect(
      withRuntimeEnvironment({ NODE_ENV: "development" }, () =>
        authCallbackBaseUrl(context as never),
      ),
    ).toBe("https://hostile.example");

    const memoryStores = {
      challenge: "memory",
      token: "memory",
      siweNonce: "memory",
      mfa: "memory",
      importSession: "memory",
    } as const;
    expect(() =>
      withRuntimeEnvironment({ STEWARD_RUNTIME: "workers" }, () =>
        assertAuthStoresAreSafe(memoryStores),
      ),
    ).toThrow("Durable auth storage is required");
    expect(() =>
      withRuntimeEnvironment(
        { STEWARD_RUNTIME: "workers", STEWARD_ALLOW_MEMORY_AUTH_STORES: "true" },
        () => assertAuthStoresAreSafe(memoryStores),
      ),
    ).not.toThrow();
    expect(() =>
      withRuntimeEnvironment({}, () => assertAuthStoresAreSafe(memoryStores)),
    ).not.toThrow();
  });
});
