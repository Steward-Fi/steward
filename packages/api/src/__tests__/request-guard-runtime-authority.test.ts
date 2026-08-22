import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import {
  authorizationSignature,
  createAuthorizationSignature,
} from "../middleware/authorization-signature";
import { requestExpiry } from "../middleware/request-expiry";

const PATH = "/vault/agent-1/sign";
const BODY = JSON.stringify({ value: "1" });
const SECRET_A = "request-authority-a-with-enough-entropy";
const SECRET_B = "request-authority-b-with-enough-entropy";

async function headers(secret: string, requestId: string) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = await createAuthorizationSignature(
    {
      method: "POST",
      url: `https://api.test${PATH}`,
      timestamp,
      idempotencyKey: requestId,
      body: BODY,
    },
    secret,
  );
  return {
    "content-type": "application/json",
    "x-steward-request-timestamp": timestamp,
    "idempotency-key": requestId,
    "x-steward-signature": signature,
  };
}

function makeApp(appSecretResolver?: (request: Request) => Promise<string[]>) {
  const app = new Hono<{ Variables: { requestSignatureVerified?: boolean } }>();
  app.use("*", requestExpiry());
  app.use("*", authorizationSignature({ appSecretResolver }));
  app.post(PATH, (c) => c.json({ ok: true, verified: c.get("requestSignatureVerified") }));
  return app;
}

describe("request-local request-guard authority", () => {
  it("observes sequential A -> B -> missing rotations without retaining A", async () => {
    const app = makeApp(async () => []);
    const requestAHeaders = await headers(SECRET_A, "guard-a");
    const requestBHeaders = await headers(SECRET_B, "guard-b");

    const responseA = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_REQUEST_SIGNING_SECRET: SECRET_A,
        STEWARD_REQUIRE_REQUEST_EXPIRY: "true",
      },
      () => app.request(PATH, { method: "POST", headers: requestAHeaders, body: BODY }),
    );
    const staleAUnderB = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_REQUEST_SIGNING_SECRET: SECRET_B,
        STEWARD_REQUIRE_REQUEST_EXPIRY: "true",
      },
      () => app.request(PATH, { method: "POST", headers: requestAHeaders, body: BODY }),
    );
    const responseB = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_REQUEST_SIGNING_SECRET: SECRET_B,
        STEWARD_REQUIRE_REQUEST_EXPIRY: "true",
      },
      () => app.request(PATH, { method: "POST", headers: requestBHeaders, body: BODY }),
    );
    const missing = await withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
      app.request(PATH, { method: "POST", headers: requestAHeaders, body: BODY }),
    );

    expect(responseA.status).toBe(200);
    expect(staleAUnderB.status).toBe(401);
    expect(responseB.status).toBe(200);
    expect(missing.status).toBe(500);
    expect(await missing.json()).toEqual({
      ok: false,
      error: "Request signing is not configured",
    });
  });

  it("pins suspended A while overlapping B uses only B", async () => {
    let markAStarted!: () => void;
    let releaseA!: () => void;
    const aStarted = new Promise<void>((resolve) => {
      markAStarted = resolve;
    });
    const aReleased = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    const app = makeApp(async (request) => {
      if (request.headers.get("idempotency-key") === "guard-overlap-a") {
        markAStarted();
        await aReleased;
      }
      return [];
    });
    const requestAHeaders = await headers(SECRET_A, "guard-overlap-a");
    const requestBHeaders = await headers(SECRET_B, "guard-overlap-b");

    const pendingA = withRuntimeEnvironment(
      { NODE_ENV: "production", STEWARD_REQUEST_SIGNING_SECRET: SECRET_A },
      () => app.request(PATH, { method: "POST", headers: requestAHeaders, body: BODY }),
    );
    await aStarted;
    const responseB = await withRuntimeEnvironment(
      { NODE_ENV: "production", STEWARD_REQUEST_SIGNING_SECRET: SECRET_B },
      () => app.request(PATH, { method: "POST", headers: requestBHeaders, body: BODY }),
    );
    releaseA();
    const responseA = await pendingA;

    expect(responseA.status).toBe(200);
    expect(responseB.status).toBe(200);
  });

  it("resolves request-expiry requirement and windows from each request", async () => {
    const now = 1_700_000_000_000;
    const app = new Hono();
    app.use("*", requestExpiry({ now: () => now }));
    app.post(PATH, (c) => c.json({ ok: true }));

    const optional = await withRuntimeEnvironment({ NODE_ENV: "development" }, () =>
      app.request(PATH, { method: "POST" }),
    );
    const required = await withRuntimeEnvironment(
      { NODE_ENV: "development", STEWARD_REQUIRE_REQUEST_EXPIRY: "true" },
      () => app.request(PATH, { method: "POST" }),
    );
    const narrowWindow = await withRuntimeEnvironment(
      {
        NODE_ENV: "development",
        STEWARD_REQUEST_EXPIRY_MAX_SKEW_MS: "1",
        STEWARD_REQUEST_TIMESTAMP_TTL_MS: "10",
      },
      () =>
        app.request(PATH, {
          method: "POST",
          headers: { "X-Steward-Request-Timestamp": String(now - 1_000) },
        }),
    );

    expect(optional.status).toBe(200);
    expect(required.status).toBe(400);
    expect(narrowWindow.status).toBe(408);
  });
});
