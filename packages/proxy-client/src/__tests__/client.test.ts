/**
 * Unit tests for StewardProxyClient: header shape, idempotency auto-attach,
 * signature attachment, and https enforcement.
 */

import { describe, expect, test } from "bun:test";
import { StewardProxyClient } from "../client";

interface Captured {
  url: string;
  method: string;
  headers: Headers;
  body: BodyInit | null | undefined;
}

function makeCapturingFetch(): { fetch: typeof fetch; calls: Captured[] } {
  const calls: Captured[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: (init?.method ?? "GET").toUpperCase(),
      headers: new Headers(init?.headers),
      body: init?.body ?? null,
    });
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

describe("StewardProxyClient construction", () => {
  test("requires proxyUrl and token", () => {
    // @ts-expect-error missing token
    expect(() => new StewardProxyClient({ proxyUrl: "https://p" })).toThrow("token is required");
    // @ts-expect-error missing proxyUrl
    expect(() => new StewardProxyClient({ token: "t" })).toThrow("proxyUrl is required");
  });

  test("rejects non-https proxyUrl when requireHttps=true (production mode)", () => {
    expect(
      () =>
        new StewardProxyClient({
          proxyUrl: "http://insecure.local:8080",
          token: "t",
          requireHttps: true,
        }),
    ).toThrow("proxyUrl must be https in production");
  });

  test("allows http proxyUrl when requireHttps=false (dev/test)", () => {
    const client = new StewardProxyClient({
      proxyUrl: "http://localhost:8080",
      token: "t",
      requireHttps: false,
    });
    expect(client).toBeInstanceOf(StewardProxyClient);
  });

  test("requires tenantId/agentId when signingSecret is set", () => {
    expect(
      () =>
        new StewardProxyClient({
          proxyUrl: "https://p",
          token: "t",
          signingSecret: "s",
        }),
    ).toThrow("tenantId and agentId are required");
  });
});

describe("StewardProxyClient.fetch headers", () => {
  test("attaches Authorization: Bearer <token>", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok-123",
      fetch,
    });
    await client.fetch("/openai/v1/models");
    expect(calls[0].headers.get("authorization")).toBe("Bearer tok-123");
    expect(calls[0].url).toBe("https://proxy.test/openai/v1/models");
    expect(calls[0].method).toBe("GET");
  });

  test("auto-attaches Idempotency-Key on POST when not supplied", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      fetch,
    });
    await client.fetch("/openai/v1/chat/completions", { method: "POST", body: "{}" });
    const key = calls[0].headers.get("idempotency-key");
    expect(key).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("does NOT auto-attach Idempotency-Key on GET", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      fetch,
    });
    await client.fetch("/openai/v1/models");
    expect(calls[0].headers.get("idempotency-key")).toBeNull();
  });

  test("preserves a caller-supplied Idempotency-Key", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      fetch,
    });
    await client.fetch("/openai/v1/chat/completions", {
      method: "POST",
      body: "{}",
      headers: { "idempotency-key": "caller-supplied-key" },
    });
    expect(calls[0].headers.get("idempotency-key")).toBe("caller-supplied-key");
  });

  test("attaches signature + timestamp headers when signingSecret is set", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      signingSecret: "signing-secret",
      tenantId: "tenant-1",
      agentId: "agent-1",
      fetch,
    });
    await client.fetch("/openai/v1/chat/completions", { method: "POST", body: "{}" });
    expect(calls[0].headers.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(calls[0].headers.get("x-steward-request-timestamp")).toMatch(/^\d+$/);
  });

  test("does NOT attach signature headers when no signingSecret", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      fetch,
    });
    await client.fetch("/openai/v1/models");
    expect(calls[0].headers.get("x-steward-signature")).toBeNull();
    expect(calls[0].headers.get("x-steward-request-timestamp")).toBeNull();
  });

  test("rejects non-serialized bodies for signed requests", async () => {
    const { fetch } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      signingSecret: "signing-secret",
      tenantId: "tenant-1",
      agentId: "agent-1",
      fetch,
    });
    await expect(
      client.fetch("/openai/v1/chat/completions", {
        method: "POST",
        body: new URLSearchParams({ a: "b" }),
      }),
    ).rejects.toThrow("Serialize before calling");
  });
});

describe("StewardProxyClient.proxyHealth", () => {
  test("GETs /health and returns parsed json", async () => {
    const { fetch, calls } = makeCapturingFetch();
    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.test",
      token: "tok",
      fetch,
    });
    const health = await client.proxyHealth();
    expect(calls[0].url).toBe("https://proxy.test/health");
    expect(calls[0].method).toBe("GET");
    expect(health.ok).toBe(true);
  });
});
