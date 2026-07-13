import { describe, expect, test } from "bun:test";
import { ApiError, StewardApiClient } from "../api";

describe("StewardApiClient", () => {
  test("sends platform key for platform requests and unwraps ApiResponse data", async () => {
    const seen: Record<string, string> = {};
    const client = new StewardApiClient({
      baseUrl: "http://steward.test/",
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

  test("raises API errors with response status and message", async () => {
    const client = new StewardApiClient({
      baseUrl: "http://steward.test",
      fetchImpl: (async () =>
        new Response(JSON.stringify({ ok: false, error: "nope" }), {
          status: 403,
        })) as unknown as typeof fetch,
    });

    await expect(client.request("GET", "/agents")).rejects.toThrow(ApiError);
    await expect(client.request("GET", "/agents")).rejects.toThrow("nope");
  });
});
