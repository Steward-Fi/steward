import { describe, expect, test } from "bun:test";
import { runtimeEnvironmentValue, withRuntimeEnvironment } from "../runtime-env";

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
});
