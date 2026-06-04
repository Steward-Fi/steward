import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Hono } from "hono";
import {
  getTenantIdempotencyMetrics,
  idempotencyMiddleware,
  MemoryIdempotencyStore,
  resetIdempotencyMetricsForTests,
} from "../middleware/idempotency";
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
  it("records tenant-scoped privacy-preserving counters", async () => {
    resetIdempotencyMetricsForTests();
    const { app } = makeApp();
    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "X-Steward-Tenant": "tenant-metrics",
        "Idempotency-Key": "idem-key-metrics",
      },
      body: JSON.stringify({ value: "first" }),
    };

    await app.request("/mutate", init);
    await app.request("/mutate", init);
    await app.request("/mutate", {
      ...init,
      body: JSON.stringify({ value: "changed" }),
    });

    const metrics = await getTenantIdempotencyMetrics("tenant-metrics");
    expect(metrics.counters.observed).toBe(3);
    expect(metrics.counters.reserved).toBe(1);
    expect(metrics.counters.completed).toBe(1);
    expect(metrics.counters.replayed).toBe(1);
    expect(metrics.counters.conflicts).toBe(1);
    expect(metrics.counters.inFlightConflicts).toBe(0);
    expect(metrics.lastSeenAt).toBeString();
  });

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

  it("suppresses duplicate one-time credential responses and does not store raw secret bodies", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("authType", "api-key");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/webhooks", (c) => {
      count += 1;
      return c.json({ ok: true, data: { secret: `whsec-one-time-${count}` } }, 201);
    });

    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-webhook-secret",
      },
      body: JSON.stringify({ url: "https://example.test/hook" }),
    };

    const first = await app.request("/webhooks", init);
    const second = await app.request("/webhooks", init);

    expect(first.status).toBe(201);
    expect(second.status).toBe(409);
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toEqual({ ok: true, data: { secret: "whsec-one-time-1" } });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(count).toBe(1);
    const serializedStore = JSON.stringify([
      ...(store as unknown as { entries: Map<string, unknown> }).entries.values(),
    ]);
    expect(serializedStore).not.toContain("whsec-one-time-1");
  });

  it("suppresses duplicate agent-token minting responses and does not store raw JWT bodies", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("authType", "api-key");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/agents/:agentId/token", (c) => {
      count += 1;
      return c.json({ ok: true, data: { token: `agent-jwt-one-time-${count}` } }, 201);
    });
    app.post("/v1/agents/:agentId/token", (c) => {
      count += 1;
      return c.json({ ok: true, data: { token: `agent-v1-jwt-one-time-${count}` } }, 201);
    });

    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-agent-token",
      },
      body: JSON.stringify({ expiresIn: "1h" }),
    };
    const v1Init = {
      ...init,
      headers: {
        ...init.headers,
        "Idempotency-Key": "idem-key-v1-agent-token",
      },
    };

    const first = await app.request("/agents/agent-1/token", init);
    const second = await app.request("/agents/agent-1/token", init);
    const v1First = await app.request("/v1/agents/agent-1/token", v1Init);
    const v1Second = await app.request("/v1/agents/agent-1/token", v1Init);

    expect(first.status).toBe(201);
    expect(second.status).toBe(409);
    expect(v1First.status).toBe(201);
    expect(v1Second.status).toBe(409);
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(v1First.headers.get("Idempotency-Replayed")).toBe("false");
    expect(v1Second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toEqual({ ok: true, data: { token: "agent-jwt-one-time-1" } });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(await v1First.json()).toEqual({
      ok: true,
      data: { token: "agent-v1-jwt-one-time-2" },
    });
    expect(await v1Second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(count).toBe(2);
    const serializedStore = JSON.stringify([
      ...(store as unknown as { entries: Map<string, unknown> }).entries.values(),
    ]);
    expect(serializedStore).not.toContain("agent-jwt-one-time-1");
    expect(serializedStore).not.toContain("agent-v1-jwt-one-time-2");
  });

  it("suppresses duplicate pregenerated claim-token responses and does not store raw claim tokens", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("authType", "api-key");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/agents/pregenerated", (c) => {
      count += 1;
      return c.json(
        { ok: true, data: { wallets: [{ claimToken: `claim-token-one-time-${count}` }] } },
        201,
      );
    });
    app.post("/v1/agents/pregenerated", (c) => {
      count += 1;
      return c.json(
        { ok: true, data: { wallets: [{ claimToken: `claim-token-v1-one-time-${count}` }] } },
        201,
      );
    });
    app.post("/agents/pregenerated/:agentId/claim-token/rotate", (c) => {
      count += 1;
      return c.json({ ok: true, data: { claimToken: `claim-token-rotated-${count}` } });
    });

    const init = {
      method: "POST",
      headers: {
        Authorization: AUTHORIZATION,
        "Content-Type": "application/json",
        "Idempotency-Key": "idem-key-pregen-token",
      },
      body: JSON.stringify({ count: 1 }),
    };
    const v1Init = {
      ...init,
      headers: { ...init.headers, "Idempotency-Key": "idem-key-v1-pregen-token" },
    };
    const rotateInit = {
      ...init,
      headers: { ...init.headers, "Idempotency-Key": "idem-key-pregen-token-rotate" },
      body: "{}",
    };

    const first = await app.request("/agents/pregenerated", init);
    const second = await app.request("/agents/pregenerated", init);
    const v1First = await app.request("/v1/agents/pregenerated", v1Init);
    const v1Second = await app.request("/v1/agents/pregenerated", v1Init);
    const rotateFirst = await app.request(
      "/agents/pregenerated/agent-1/claim-token/rotate",
      rotateInit,
    );
    const rotateSecond = await app.request(
      "/agents/pregenerated/agent-1/claim-token/rotate",
      rotateInit,
    );

    expect(first.status).toBe(201);
    expect(second.status).toBe(409);
    expect(v1First.status).toBe(201);
    expect(v1Second.status).toBe(409);
    expect(rotateFirst.status).toBe(200);
    expect(rotateSecond.status).toBe(409);
    expect(await first.json()).toEqual({
      ok: true,
      data: { wallets: [{ claimToken: "claim-token-one-time-1" }] },
    });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(await v1First.json()).toEqual({
      ok: true,
      data: { wallets: [{ claimToken: "claim-token-v1-one-time-2" }] },
    });
    expect(await v1Second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(await rotateFirst.json()).toEqual({
      ok: true,
      data: { claimToken: "claim-token-rotated-3" },
    });
    expect(await rotateSecond.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(count).toBe(3);
    const serializedStore = JSON.stringify([
      ...(store as unknown as { entries: Map<string, unknown> }).entries.values(),
    ]);
    expect(serializedStore).not.toContain("claim-token-one-time-1");
    expect(serializedStore).not.toContain("claim-token-v1-one-time-2");
    expect(serializedStore).not.toContain("claim-token-rotated-3");
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

  it("suppresses duplicate public auth mutations without replaying token bodies", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/auth/email/verify", async (c) => {
      count += 1;
      const body = await c.req.json<{ code: string; email: string }>();
      return c.json({
        ok: true,
        count,
        token: `access-${count}`,
        refreshToken: `refresh-${count}`,
        email: body.email,
      });
    });

    const init = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "public-auth-idem-key",
        "X-Steward-Tenant": "tenant-auth",
        Origin: "https://app.example.com",
      },
      body: JSON.stringify({ email: "user@example.com", code: "123456" }),
    };

    const first = await app.request("/auth/email/verify", init);
    const second = await app.request("/auth/email/verify", init);

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBeNull();
    expect(await first.json()).toMatchObject({ ok: true, count: 1, token: "access-1" });
    expect(await second.json()).toEqual({
      ok: false,
      error: "Idempotency key has already been used",
    });
    expect(count).toBe(1);
  });

  it("scopes unauthenticated public auth idempotency by path and origin", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/auth/email/send", async (c) => {
      count += 1;
      return c.json({ ok: true, count, path: c.req.path });
    });
    app.post("/auth/sms/send", async (c) => {
      count += 1;
      return c.json({ ok: true, count, path: c.req.path });
    });

    const headers = {
      "Content-Type": "application/json",
      "Idempotency-Key": "public-auth-shared-key",
      "X-Steward-Tenant": "tenant-auth",
      Origin: "https://app.example.com",
    };
    const first = await app.request("/auth/email/send", {
      method: "POST",
      headers,
      body: JSON.stringify({ email: "user@example.com" }),
    });
    const second = await app.request("/auth/sms/send", {
      method: "POST",
      headers,
      body: JSON.stringify({ phone: "+15555550123" }),
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(await first.json()).toEqual({ ok: true, count: 1, path: "/auth/email/send" });
    expect(await second.json()).toEqual({ ok: true, count: 2, path: "/auth/sms/send" });
    expect(count).toBe(2);
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
