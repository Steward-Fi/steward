import { describe, expect, test } from "bun:test";
import {
  runtimeEnvironmentIdentity,
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
        const identity = runtimeEnvironmentIdentity();
        firstEntered.resolve();
        await releaseFirst.promise;
        return {
          identity,
          resumedIdentity: runtimeEnvironmentIdentity(),
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
        identity: runtimeEnvironmentIdentity(),
        age: runtimeEnvironmentValue("STEWARD_OIDC_JWKS_MAX_AGE_MS"),
        override: runtimeEnvironmentValue("STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH"),
      }),
    );
    releaseFirst.resolve();

    const resumedFirst = await first;
    expect(second.age).toBe("120000");
    expect(second.override).toBe("true");
    expect(resumedFirst.age).toBe("60000");
    expect(resumedFirst.override).toBe("false");
    expect(resumedFirst.resumedIdentity).toBe(resumedFirst.identity);
    expect(second.identity).not.toBe(resumedFirst.identity);
    expect(Object.keys(second.identity as object)).toEqual([]);
    expect(runtimeEnvironmentIdentity()).toBeUndefined();
  });
});
