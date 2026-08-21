import { describe, expect, test } from "bun:test";
import {
  runtimeEnvironmentValue,
  tradingRateLimitRedisRequired,
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
  test("requires Redis readiness for unacknowledged production trading", async () => {
    expect(
      await withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
        tradingRateLimitRedisRequired(true),
      ),
    ).toBe(true);
    expect(
      await withRuntimeEnvironment(
        {
          NODE_ENV: "production",
          STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS: "true",
        },
        () => tradingRateLimitRedisRequired(true),
      ),
    ).toBe(false);
    expect(
      await withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
        tradingRateLimitRedisRequired(false),
      ),
    ).toBe(false);

    for (const environment of [
      {},
      { NODE_ENV: "staging" },
      { NODE_ENV: "prodution" },
      { NODE_ENV: "development", STEWARD_RUNTIME: "workers" },
    ]) {
      expect(
        await withRuntimeEnvironment(environment, () => tradingRateLimitRedisRequired(true)),
      ).toBe(true);
    }
    for (const nodeEnvironment of ["development", "test"]) {
      expect(
        await withRuntimeEnvironment({ NODE_ENV: nodeEnvironment }, () =>
          tradingRateLimitRedisRequired(true),
        ),
      ).toBe(false);
    }
  });

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
