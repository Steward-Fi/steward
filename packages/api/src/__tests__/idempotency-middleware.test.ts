import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Hono } from "hono";
import { idempotencyMiddleware, MemoryIdempotencyStore } from "../middleware/idempotency";
import type { AppVariables } from "../services/context";

const AUTHORIZATION = "Bearer idempotency-test-token";
const appSource = readFileSync(join(import.meta.dir, "..", "app.ts"), "utf8");

function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  const store = new MemoryIdempotencyStore(100);
  let count = 0;

  app.use("*", async (c, next) => {
    c.set("authType", "api-key");
    await next();
  });
  app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
  app.post("/mutate", async (c) => {
    count += 1;
    const body = await c.req.json<{ value: string }>();
    return c.json({ ok: true, count, value: body.value });
  });
  app.post("/auth/refresh", async (c) => {
    count += 1;
    const body = await c.req.json<{ refreshToken: string }>();
    return c.json({
      ok: true,
      count,
      token: `access-${count}`,
      refreshToken: `refresh-${count}-${body.refreshToken}`,
    });
  });
  app.get("/mutate", (c) => c.json({ ok: true, count }));

  return { app, getCount: () => count };
}

describe("idempotencyMiddleware", () => {
  it("replays a completed mutating response for the same key and request", async () => {
    const { app, getCount } = makeApp();
    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-1",
      },
      body: JSON.stringify({ value: "first" }),
    };

    const first = await app.request("/mutate", init);
    const second = await app.request("/mutate", init);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBe("true");
    expect(await first.json()).toEqual({ ok: true, count: 1, value: "first" });
    expect(await second.json()).toEqual({ ok: true, count: 1, value: "first" });
    expect(getCount()).toBe(1);
  });

  it("rejects reuse of a key with a different request fingerprint", async () => {
    const { app, getCount } = makeApp();

    const first = await app.request("/mutate", {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-2",
      },
      body: JSON.stringify({ value: "first" }),
    });
    const second = await app.request("/mutate", {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-2",
      },
      body: JSON.stringify({ value: "second" }),
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency-Key was already used for a different request",
    });
    expect(getCount()).toBe(1);
  });

  it("scopes keys by tenant and credential material", async () => {
    const { app, getCount } = makeApp();
    const first = await app.request("/mutate", {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "X-Steward-Tenant": "tenant-a",
        "Idempotency-Key": "shared-idem-key",
      },
      body: JSON.stringify({ value: "first" }),
    });
    const second = await app.request("/mutate", {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "X-Steward-Tenant": "tenant-b",
        "Idempotency-Key": "shared-idem-key",
      },
      body: JSON.stringify({ value: "second" }),
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ ok: true, count: 2, value: "second" });
    expect(getCount()).toBe(2);
  });

  it("scopes API-key idempotency by delegated signer credentials", async () => {
    const { app, getCount } = makeApp();
    const first = await app.request("/mutate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Key": "tenant-api-key",
        "X-Steward-Signer-Id": "signer-a",
        "X-Steward-Signer-Secret": "secret-a",
        "Idempotency-Key": "delegated-signer-idem-key",
      },
      body: JSON.stringify({ value: "first" }),
    });
    const second = await app.request("/mutate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Key": "tenant-api-key",
        "X-Steward-Signer-Id": "signer-b",
        "X-Steward-Signer-Secret": "secret-b",
        "Idempotency-Key": "delegated-signer-idem-key",
      },
      body: JSON.stringify({ value: "first" }),
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(await first.json()).toEqual({ ok: true, count: 1, value: "first" });
    expect(await second.json()).toEqual({ ok: true, count: 2, value: "first" });
    expect(getCount()).toBe(2);
  });

  it("atomically reserves a key so concurrent duplicate mutations do not both execute", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;
    let releaseRoute: (() => void) | undefined;
    const routeGate = new Promise<void>((resolve) => {
      releaseRoute = resolve;
    });

    app.use("*", async (c, next) => {
      c.set("authType", "api-key");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/mutate", async (c) => {
      count += 1;
      await routeGate;
      return c.json({ ok: true, count });
    });

    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-concurrent",
      },
      body: JSON.stringify({ value: "first" }),
    };
    const firstPromise = app.request("/mutate", init);
    await Promise.resolve();
    const second = await app.request("/mutate", init);
    releaseRoute?.();
    const first = await firstPromise;

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(await first.json()).toEqual({ ok: true, count: 1 });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key is already processing",
    });
    expect(count).toBe(1);
  });

  it("ignores idempotency keys on safe methods", async () => {
    const { app } = makeApp();

    const first = await app.request("/mutate", {
      headers: { "Idempotency-Key": "idem-key-3" },
    });
    const second = await app.request("/mutate", {
      headers: { "Idempotency-Key": "idem-key-3" },
    });

    expect(first.headers.get("Idempotency-Replayed")).toBeNull();
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toEqual({ ok: true, count: 0 });
    expect(await second.json()).toEqual({ ok: true, count: 0 });
  });

  it("suppresses duplicate auth token-minting requests without replaying token bodies", async () => {
    const { app, getCount } = makeApp();
    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-auth-refresh",
      },
      body: JSON.stringify({ refreshToken: "old-refresh" }),
    };

    const first = await app.request("/auth/refresh", init);
    const second = await app.request("/auth/refresh", init);

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toMatchObject({ ok: true, count: 1, token: "access-1" });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(getCount()).toBe(1);
  });

  it("uses a verified request signature as replay-safe auth material", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("requestSignatureVerified", true);
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/auth/refresh", async (c) => {
      count += 1;
      return c.json({ ok: true, count, token: `access-${count}` });
    });

    const init = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-signed-auth-refresh",
        "X-Steward-Signature": "v1=verified-by-previous-middleware",
      },
      body: JSON.stringify({ refreshToken: "old-refresh" }),
    };

    const first = await app.request("/auth/refresh", init);
    const second = await app.request("/auth/refresh", init);

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(await first.json()).toMatchObject({ ok: true, count: 1, token: "access-1" });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(count).toBe(1);
  });

  it("does not treat an unverified signature header as idempotency auth material", async () => {
    const { app, getCount } = makeApp();
    const init = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-unsigned-signature",
        "X-Steward-Signature": "anything",
      },
      body: JSON.stringify({ value: "first" }),
    };

    const first = await app.request("/mutate", init);
    const second = await app.request("/mutate", init);

    expect(first.headers.get("Idempotency-Replayed")).toBeNull();
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toEqual({ ok: true, count: 1, value: "first" });
    expect(await second.json()).toEqual({ ok: true, count: 2, value: "first" });
    expect(getCount()).toBe(2);
  });

  it("does not replay session-scoped requests before route-level MFA checks can run", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("authType", "session-jwt");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/sensitive", async (c) => {
      count += 1;
      return c.json({ ok: true, count });
    });

    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-session",
      },
      body: "{}",
    };

    const first = await app.request("/sensitive", init);
    const second = await app.request("/sensitive", init);

    expect(first.headers.get("Idempotency-Replayed")).toBeNull();
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toEqual({ ok: true, count: 1 });
    expect(await second.json()).toEqual({ ok: true, count: 2 });
  });

  it("replays recent-MFA session-scoped sensitive mutations", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("authType", "session-jwt");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/sensitive", async (c) => {
      count += 1;
      return c.json({ ok: true, count });
    });

    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-session-mfa",
      },
      body: "{}",
    };

    const first = await app.request("/sensitive", init);
    const second = await app.request("/sensitive", init);

    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBe("true");
    expect(await first.json()).toEqual({ ok: true, count: 1 });
    expect(await second.json()).toEqual({ ok: true, count: 1 });
  });

  it("replays platform-key mutations after platform auth has populated context", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("platformKeyHash", "platform-key-hash");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.patch("/platform/users/user-1/metadata", async (c) => {
      count += 1;
      const body = await c.req.json<{ value: string }>();
      return c.json({ ok: true, count, value: body.value });
    });

    const init = {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": "platform-key",
        "Idempotency-Key": "idem-key-platform",
      },
      body: JSON.stringify({ value: "metadata" }),
    };

    const first = await app.request("/platform/users/user-1/metadata", init);
    const second = await app.request("/platform/users/user-1/metadata", init);

    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBe("true");
    expect(await first.json()).toEqual({ ok: true, count: 1, value: "metadata" });
    expect(await second.json()).toEqual({ ok: true, count: 1, value: "metadata" });
    expect(count).toBe(1);
  });

  it("runs global idempotency after protected route authentication middleware", () => {
    const idempotencyStart = appSource.indexOf('app.use("*", idempotencyMiddleware())');
    expect(idempotencyStart).toBeGreaterThanOrEqual(0);
    for (const marker of [
      'app.use("/agents"',
      'app.use("/vault/*"',
      'app.use("/tenants/:id"',
      'app.use("/dashboard/*"',
      'app.use("/webhooks"',
      'app.use("/intents"',
      'app.use("/policies"',
      'app.use("/trade"',
      'app.use("/platform"',
      'app.use("/user"',
    ]) {
      const authStart = appSource.indexOf(marker);
      expect(authStart).toBeGreaterThanOrEqual(0);
      expect(authStart).toBeLessThan(idempotencyStart);
    }
    expect(appSource.indexOf("userSessionAuth", appSource.indexOf('app.use("/user"'))).toBeLessThan(
      idempotencyStart,
    );
  });
});
