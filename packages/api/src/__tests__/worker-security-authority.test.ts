import { afterEach, describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { resolveJwksUrl } from "../middleware/agent-jwt";
import { isHstsEnabled } from "../middleware/security-headers";

const originalEnvironment = {
  ELIZA_CLOUD_JWKS_URL: process.env.ELIZA_CLOUD_JWKS_URL,
  STEWARD_HSTS_DISABLED: process.env.STEWARD_HSTS_DISABLED,
};

afterEach(() => {
  for (const [name, value] of Object.entries(originalEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe("Worker request-local security authority", () => {
  it("keeps overlapping agent JWKS authorities isolated from the process mirror", async () => {
    process.env.ELIZA_CLOUD_JWKS_URL = "https://ambient.invalid/jwks";
    let releaseFirst!: () => void;
    let firstReady!: () => void;
    const ready = new Promise<void>((resolve) => {
      firstReady = resolve;
    });
    const barrier = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const first = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        ELIZA_CLOUD_JWKS_URL: "https://first.invalid/jwks",
      },
      async () => {
        firstReady();
        await barrier;
        return resolveJwksUrl();
      },
    );
    await ready;
    const second = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        ELIZA_CLOUD_JWKS_URL: "https://second.invalid/jwks",
      },
      () => resolveJwksUrl(),
    );
    releaseFirst();

    await expect(first).resolves.toBe("https://first.invalid/jwks");
    expect(second).toBe("https://second.invalid/jwks");
  });

  it("never enables the development JWKS trust anchor on Workers", () => {
    expect(() =>
      withRuntimeEnvironment(
        {
          STEWARD_RUNTIME: "workers",
          NODE_ENV: "development",
          STEWARD_ALLOW_DEFAULT_ELIZA_JWKS: "true",
        },
        () => resolveJwksUrl(),
      ),
    ).toThrow("jwks-url-required");
  });

  it("binds HSTS posture to each Worker request snapshot", () => {
    process.env.STEWARD_HSTS_DISABLED = "true";
    expect(withRuntimeEnvironment({ STEWARD_HSTS_DISABLED: "false" }, isHstsEnabled)).toBe(true);
    expect(withRuntimeEnvironment({ STEWARD_HSTS_DISABLED: "true" }, isHstsEnabled)).toBe(false);
  });
});
