import { afterEach, describe, expect, it, mock } from "bun:test";

const originalFetch = globalThis.fetch;

afterEach(() => {
  mock.restore();
  globalThis.fetch = originalFetch;
});

describe("resolvePolicyLimitPx", () => {
  it("returns an explicit sell limitPx untouched", async () => {
    globalThis.fetch = mock(async () => {
      throw new Error("explicit sell limitPx should not fetch a marketable price");
    }) as unknown as typeof fetch;

    const { resolvePolicyLimitPx } = await import("../routes/trade");

    await expect(resolvePolicyLimitPx("BTC", "sell", "65000.5")).resolves.toBe("65000.5");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("uses a marketable sell price when sell limitPx is omitted", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ levels: [[{ px: "60000" }], [{ px: "60100" }]] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const { resolvePolicyLimitPx } = await import("../routes/trade");

    await expect(resolvePolicyLimitPx("BTC", "sell", undefined)).resolves.toBe("59700");
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("keeps buy behavior unchanged", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ levels: [[{ px: "60000" }], [{ px: "60100" }]] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const { resolvePolicyLimitPx } = await import("../routes/trade");

    await expect(resolvePolicyLimitPx("BTC", "buy", 61000)).resolves.toBe(61000);
    expect(globalThis.fetch).not.toHaveBeenCalled();
    await expect(resolvePolicyLimitPx("BTC", "buy", undefined)).resolves.toBe("60401");
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });
});
