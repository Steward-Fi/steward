import { afterEach, describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import { resolveJwksUrl } from "../middleware/agent-jwt";
import {
  authorizationSignature,
  createAuthorizationSignature,
} from "../middleware/authorization-signature";
import { requestExpiry } from "../middleware/request-expiry";
import { isHstsEnabled } from "../middleware/security-headers";
import { apiKeyAdminMutationsEnabled } from "../routes/agents";
import { getPhoneAuth, isUnsafeUnboundOAuthProviderCodeExchangeAllowed } from "../routes/auth";

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

  it("does not let a weak invocation poison cached freshness middleware", async () => {
    const app = new Hono();
    const reachedWeakRoute = Promise.withResolvers<void>();
    const releaseWeakRoute = Promise.withResolvers<void>();
    app.use("*", requestExpiry());
    app.post("/vault/sign", async (c) => {
      reachedWeakRoute.resolve();
      await releaseWeakRoute.promise;
      return c.text("ok");
    });

    const weak = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "development",
        STEWARD_REQUIRE_REQUEST_EXPIRY: "false",
      },
      () => app.request("/vault/sign", { method: "POST" }),
    );
    await reachedWeakRoute.promise;
    const strong = await withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_REQUIRE_REQUEST_EXPIRY: "true",
      },
      () => app.request("/vault/sign", { method: "POST" }),
    );
    releaseWeakRoute.resolve();

    expect(strong.status).toBe(400);
    expect(await strong.json()).toEqual({ ok: false, error: "Request expiry header required" });
    expect((await weak).status).toBe(200);
  });

  it("does not let a weak invocation poison cached signature middleware or signing roots", async () => {
    const app = new Hono<{ Variables: { requestSignatureVerified?: boolean } }>();
    const reachedWeakRoute = Promise.withResolvers<void>();
    const releaseWeakRoute = Promise.withResolvers<void>();
    app.use("*", authorizationSignature());
    app.post("/vault/sign", async (c) => {
      if (!c.get("requestSignatureVerified")) {
        reachedWeakRoute.resolve();
        await releaseWeakRoute.promise;
      }
      return c.json({ verified: Boolean(c.get("requestSignatureVerified")) });
    });

    const weak = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "development",
        STEWARD_REQUIRE_AUTH_SIGNATURE: "false",
        STEWARD_REQUEST_SIGNING_SECRET: "weak-generation-signing-root",
      },
      () => app.request("/vault/sign", { method: "POST" }),
    );
    await reachedWeakRoute.promise;

    const timestamp = String(Math.floor(Date.now() / 1000));
    const idempotencyKey = "worker-generation-idempotency";
    const strongSecret = "strong-generation-signing-root";
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://worker.test/vault/sign",
        timestamp,
        idempotencyKey,
      },
      strongSecret,
    );
    const strong = await withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_REQUIRE_AUTH_SIGNATURE: "true",
        STEWARD_REQUEST_SIGNING_SECRET: strongSecret,
      },
      () =>
        app.request("https://worker.test/vault/sign", {
          method: "POST",
          headers: {
            "X-Steward-Request-Timestamp": timestamp,
            "Idempotency-Key": idempotencyKey,
            "X-Steward-Signature": signature,
          },
        }),
    );
    const unsignedStrong = await withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_REQUIRE_AUTH_SIGNATURE: "true",
      },
      () => app.request("/vault/sign", { method: "POST" }),
    );
    releaseWeakRoute.resolve();

    expect(strong.status).toBe(200);
    expect(await strong.json()).toEqual({ verified: true });
    expect(unsignedStrong.status).toBe(401);
    expect((await weak).status).toBe(200);
  });

  it("keeps root-equivalent route gates isolated across hostile overlap", async () => {
    let releaseWeak!: () => void;
    let weakReady!: () => void;
    const ready = new Promise<void>((resolve) => {
      weakReady = resolve;
    });
    const barrier = new Promise<void>((resolve) => {
      releaseWeak = resolve;
    });
    const weak = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE: "true",
        STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS: "true",
      },
      async () => {
        weakReady();
        await barrier;
        return {
          oauth: isUnsafeUnboundOAuthProviderCodeExchangeAllowed(),
          apiKeyAdmin: apiKeyAdminMutationsEnabled(),
        };
      },
    );
    await ready;
    const strong = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE: "false",
        STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS: "false",
      },
      () => ({
        oauth: isUnsafeUnboundOAuthProviderCodeExchangeAllowed(),
        apiKeyAdmin: apiKeyAdminMutationsEnabled(),
      }),
    );
    releaseWeak();

    expect(strong).toEqual({ oauth: false, apiKeyAdmin: false });
    await expect(weak).resolves.toEqual({ oauth: true, apiKeyAdmin: true });
  });

  it("generation-scopes cached auth clients instead of retaining a weak first invocation", () => {
    expect(
      withRuntimeEnvironment(
        { STEWARD_RUNTIME: "workers", NODE_ENV: "test", SMS_PROVIDER: "mock" },
        getPhoneAuth,
      ),
    ).toBeDefined();
    expect(() =>
      withRuntimeEnvironment({ STEWARD_RUNTIME: "workers", NODE_ENV: "production" }, getPhoneAuth),
    ).toThrow("SMS provider not configured");
  });

  it("keeps the exact Worker security inventory off the process environment mirror", async () => {
    const files = [
      "../app.ts",
      "../middleware/authorization-signature.ts",
      "../middleware/idempotency.ts",
      "../middleware/redis-enforcement.ts",
      "../middleware/request-expiry.ts",
      "../middleware/tenant-cors.ts",
      "../routes/agents.ts",
      "../routes/audit.ts",
      "../routes/auth.ts",
      "../routes/platform.ts",
      "../routes/tenant-config.ts",
      "../routes/user.ts",
      "../services/evm-simulator.ts",
    ];
    for (const file of files) {
      const source = await Bun.file(new URL(file, import.meta.url)).text();
      expect(source).not.toContain("process.env");
    }
  });
});
