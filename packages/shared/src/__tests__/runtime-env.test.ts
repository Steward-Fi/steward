import { describe, expect, test } from "bun:test";
import {
  runtimeEnvironmentSnapshot,
  runtimeEnvironmentValue,
  withRuntimeEnvironment,
} from "../runtime-env";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("request-local runtime environment", () => {
  test("keeps overlapping Worker binding snapshots isolated", async () => {
    const firstEntered = deferred();
    const releaseFirst = deferred();

    const first = withRuntimeEnvironment(
      {
        NODE_ENV: "test",
        STEWARD_OIDC_JWKS_MAX_AGE_MS: "60000",
        STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH: "false",
      },
      async () => {
        firstEntered.resolve();
        await releaseFirst.promise;
        return {
          age: runtimeEnvironmentValue("STEWARD_OIDC_JWKS_MAX_AGE_MS"),
          override: runtimeEnvironmentValue("STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH"),
        };
      },
    );

    await firstEntered.promise;
    const second = await withRuntimeEnvironment(
      {
        NODE_ENV: "test",
        STEWARD_OIDC_JWKS_MAX_AGE_MS: "120000",
        STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH: "true",
      },
      async () => ({
        age: runtimeEnvironmentValue("STEWARD_OIDC_JWKS_MAX_AGE_MS"),
        override: runtimeEnvironmentValue("STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH"),
      }),
    );
    releaseFirst.resolve();

    expect(second).toEqual({ age: "120000", override: "true" });
    expect(await first).toEqual({ age: "60000", override: "false" });
  });

  test("isolates fetch and scheduled security authorities across awaits", async () => {
    const fetchEntered = deferred();
    const releaseFetch = deferred();
    const authorityNames = [
      "STEWARD_REQUEST_SIGNING_SECRET",
      "STEWARD_TRUSTED_PROXY_HOPS",
      "STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL",
      "STEWARD_CUSTOM_OAUTH_PROVIDERS",
      "PASSKEY_ALLOWED_ORIGINS",
      "SIWE_ALLOWED_DOMAINS",
      "RESEND_API_KEY",
      "REDIS_URL",
      "STEWARD_IDEMPOTENCY_TTL_MS",
      "STEWARD_GOOGLE_LIFECYCLE_SWEEPER",
    ] as const;
    const bindings = (generation: "fetch-a" | "scheduled-b") =>
      Object.fromEntries(authorityNames.map((name) => [name, `${generation}:${name}`]));
    const readAuthority = () =>
      Object.fromEntries(authorityNames.map((name) => [name, runtimeEnvironmentValue(name)]));

    const fetchWork = withRuntimeEnvironment(bindings("fetch-a"), async () => {
      fetchEntered.resolve();
      await releaseFetch.promise;
      return readAuthority();
    });
    await fetchEntered.promise;
    const scheduled = await withRuntimeEnvironment(bindings("scheduled-b"), async () => {
      await Promise.resolve();
      return readAuthority();
    });
    releaseFetch.resolve();

    expect(await fetchWork).toEqual(bindings("fetch-a"));
    expect(scheduled).toEqual(bindings("scheduled-b"));
  });

  test("observes sequential binding rotations and fails closed on missing values", () => {
    const read = () => ({
      signingSecret: runtimeEnvironmentValue("STEWARD_REQUEST_SIGNING_SECRET"),
      providerCredential: runtimeEnvironmentValue("RESEND_API_KEY"),
      redisUrl: runtimeEnvironmentValue("REDIS_URL"),
      snapshotKeys: Object.keys(runtimeEnvironmentSnapshot()).sort(),
    });

    expect(
      withRuntimeEnvironment(
        { STEWARD_REQUEST_SIGNING_SECRET: "a", RESEND_API_KEY: "a", REDIS_URL: "a" },
        read,
      ),
    ).toEqual({
      signingSecret: "a",
      providerCredential: "a",
      redisUrl: "a",
      snapshotKeys: ["REDIS_URL", "RESEND_API_KEY", "STEWARD_REQUEST_SIGNING_SECRET"],
    });
    expect(
      withRuntimeEnvironment(
        { STEWARD_REQUEST_SIGNING_SECRET: "b", RESEND_API_KEY: "b", REDIS_URL: "b" },
        read,
      ),
    ).toEqual({
      signingSecret: "b",
      providerCredential: "b",
      redisUrl: "b",
      snapshotKeys: ["REDIS_URL", "RESEND_API_KEY", "STEWARD_REQUEST_SIGNING_SECRET"],
    });
    expect(withRuntimeEnvironment({}, read)).toEqual({
      signingSecret: undefined,
      providerCredential: undefined,
      redisUrl: undefined,
      snapshotKeys: [],
    });
  });
});
