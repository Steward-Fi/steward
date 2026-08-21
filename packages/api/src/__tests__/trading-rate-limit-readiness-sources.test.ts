import { describe, expect, it } from "bun:test";

const indexSource = await Bun.file(new URL("../index.ts", import.meta.url)).text();

describe("production trading rate-limit readiness wiring", () => {
  it("makes the mounted /ready Redis check depend on enabled trading and the exact override", () => {
    const readyStart = indexSource.indexOf('app.get("/ready"');
    const readyEnd = indexSource.indexOf("// ─── Database migrations", readyStart);
    const readyRoute = indexSource.slice(readyStart, readyEnd);

    expect(readyStart).toBeGreaterThanOrEqual(0);
    expect(readyRoute).toContain("tradingRateLimitRedisRequired(tradingEnabled)");
    expect(readyRoute).toContain(
      'required: true, error: "Redis is required for production trading"',
    );
    expect(readyRoute).toContain(
      'required: false, error: "Redis is not configured (optional mode)"',
    );
  });
});
