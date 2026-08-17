import { describe, expect, test } from "bun:test";
import { ApiError, StewardApiClient } from "../api";

describe("StewardApiClient", () => {
  test("sends platform key for platform requests and unwraps ApiResponse data", async () => {
    const seen: Record<string, string> = {};
    const client = new StewardApiClient({
      baseUrl: "https://steward.test/",
      platformKey: "platform-secret",
      fetchImpl: (async (_url, init) => {
        Object.assign(seen, init?.headers);
        return new Response(JSON.stringify({ ok: true, data: { id: "tenant" } }), {
          status: 201,
        });
      }) as typeof fetch,
    });

    await expect(
      client.request("POST", "/tenants", { id: "tenant" }, { platform: true }),
    ).resolves.toEqual({
      id: "tenant",
    });
    expect(seen["X-Steward-Platform-Key"]).toBe("platform-secret");
  });

  test("falls back to tenant API key (X-Steward-Key) when no bearer token is set", async () => {
    const seen: Record<string, string> = {};
    const client = new StewardApiClient({
      baseUrl: "https://steward.test",
      tenantId: "acme",
      tenantKey: "stw_tenant_secret",
      fetchImpl: (async (_url, init) => {
        Object.assign(seen, init?.headers);
        return new Response(JSON.stringify({ ok: true, data: [] }), { status: 200 });
      }) as typeof fetch,
    });

    await client.request("GET", "/agents");
    expect(seen["X-Steward-Key"]).toBe("stw_tenant_secret");
    expect(seen["X-Steward-Tenant"]).toBe("acme");
    expect(seen.Authorization).toBeUndefined();
  });

  test("prefers bearer token over tenant API key when both are set", async () => {
    const seen: Record<string, string> = {};
    const client = new StewardApiClient({
      baseUrl: "https://steward.test",
      token: "bearer-token",
      tenantKey: "stw_tenant_secret",
      fetchImpl: (async (_url, init) => {
        Object.assign(seen, init?.headers);
        return new Response(JSON.stringify({ ok: true, data: [] }), { status: 200 });
      }) as typeof fetch,
    });

    await client.request("GET", "/agents");
    expect(seen.Authorization).toBe("Bearer bearer-token");
    expect(seen["X-Steward-Key"]).toBeUndefined();
  });

  test("raises API errors with response status and message", async () => {
    const client = new StewardApiClient({
      baseUrl: "https://steward.test",
      fetchImpl: (async () =>
        new Response(JSON.stringify({ ok: false, error: "nope" }), {
          status: 403,
        })) as unknown as typeof fetch,
    });

    await expect(client.request("GET", "/agents")).rejects.toThrow(ApiError);
    await expect(client.request("GET", "/agents")).rejects.toThrow("nope");
  });

  test("bounds declared and streamed API response bodies", async () => {
    for (const response of [
      new Response("small", { headers: { "content-length": "1048577" } }),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024));
            controller.enqueue(new Uint8Array([1]));
            controller.close();
          },
        }),
      ),
    ]) {
      const client = new StewardApiClient({
        baseUrl: "https://api.example.test",
        fetchImpl: (async () => response) as unknown as typeof fetch,
      });
      await expect(client.request("GET", "/health")).rejects.toThrow("exceeded the 1 MiB limit");
    }
  });

  test("applies a request deadline to every API call", async () => {
    let signal: AbortSignal | undefined;
    let redirect: RequestRedirect | undefined;
    const client = new StewardApiClient({
      baseUrl: "https://api.example.test",
      fetchImpl: (async (_url, init) => {
        signal = init?.signal as AbortSignal;
        redirect = init?.redirect;
        return Response.json({ ok: true, data: {} });
      }) as typeof fetch,
    });
    await client.request("GET", "/health");
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(redirect).toBe("error");
  });

  test("bounds archive downloads and never follows credential-bearing redirects", async () => {
    let signal: AbortSignal | undefined;
    let redirect: RequestRedirect | undefined;
    const client = new StewardApiClient({
      baseUrl: "https://api.example.test",
      token: "secret-bearer",
      fetchImpl: (async (_url, init) => {
        signal = init?.signal as AbortSignal;
        redirect = init?.redirect;
        return new Response("small", { headers: { "content-length": "26214401" } });
      }) as typeof fetch,
    });
    await expect(client.requestText("/audit/archives/id/chunks/0")).rejects.toThrow(
      "26214400 byte limit",
    );
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(redirect).toBe("error");
  });

  test("bounds archive upload responses and never follows redirects", async () => {
    let signal: AbortSignal | undefined;
    let redirect: RequestRedirect | undefined;
    const client = new StewardApiClient({
      baseUrl: "https://api.example.test",
      tenantKey: "tenant-secret",
      fetchImpl: (async (_url, init) => {
        signal = init?.signal as AbortSignal;
        redirect = init?.redirect;
        return new Response("small", { headers: { "content-length": "1048577" } });
      }) as typeof fetch,
    });
    await expect(
      client.requestRaw(
        "PUT",
        "/audit/archives/id/restore/chunks/0",
        "{}\n",
        "application/x-ndjson",
      ),
    ).rejects.toThrow("1 MiB limit");
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(redirect).toBe("error");
  });

  test("rejects credential-bearing and public plaintext API URLs", () => {
    expect(() => new StewardApiClient({ baseUrl: "http://api.example.test" })).toThrow(
      "must use HTTPS",
    );
    expect(() => new StewardApiClient({ baseUrl: "https://user:secret@api.example.test" })).toThrow(
      "must not contain embedded credentials",
    );
    expect(() => new StewardApiClient({ baseUrl: "http://127.0.0.1:3200" })).not.toThrow();
  });
});
