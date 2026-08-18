import { describe, expect, it } from "bun:test";
import { InMemoryRateLimiter, resolveClientIp } from "../services/runtime-gate";

/**
 * SEC-014 regression: the global rate limiter must not key on spoofable
 * client headers. Client-supplied X-Forwarded-For / X-Real-IP are ignored
 * unless they arrive through a declared number of trusted proxy hops, and the
 * in-memory key space is capped (fail closed) so flooding unique identities
 * cannot grow it without bound.
 */
describe("resolveClientIp (SEC-014)", () => {
  function headers(init: Record<string, string>): Headers {
    return new Headers(init);
  }

  it("ignores X-Forwarded-For/X-Real-IP entirely with zero trusted proxy hops", () => {
    expect(resolveClientIp(headers({ "x-forwarded-for": "1.2.3.4" }), "10.0.0.9", 0)).toBe(
      "10.0.0.9",
    );
    expect(resolveClientIp(headers({ "x-real-ip": "1.2.3.4" }), "10.0.0.9", 0)).toBe("10.0.0.9");
    // So rotating a spoofed header cannot mint fresh rate-limit identities:
    expect(resolveClientIp(headers({ "x-forwarded-for": "5.6.7.8" }), "10.0.0.9", 0)).toBe(
      "10.0.0.9",
    );
  });

  it("falls back to a shared unknown bucket when no peer is available", () => {
    expect(resolveClientIp(headers({}), null, 0)).toBe("unknown");
    expect(resolveClientIp(headers({ "x-forwarded-for": "1.2.3.4" }), null, 0)).toBe("unknown");
  });

  it("takes the entry N trusted hops from the right, ignoring spoofed prefixes", () => {
    // client(1.1.1.1) -> proxy1 -> proxy2 -> server, attacker-controlled
    // XFF prefix preserved by append-mode proxies.
    const spoofed = headers({ "x-forwarded-for": "9.9.9.9, 8.8.8.8, 1.1.1.1, 2.2.2.2" });
    expect(resolveClientIp(spoofed, "3.3.3.3", 2)).toBe("1.1.1.1");
    expect(resolveClientIp(spoofed, "3.3.3.3", 1)).toBe("2.2.2.2");
  });

  it("rejects a short forwarded chain instead of trusting its spoofable leftmost entry", () => {
    const h = headers({ "x-forwarded-for": "1.1.1.1" });
    expect(resolveClientIp(h, "2.2.2.2", 3)).toBe("2.2.2.2");
    expect(resolveClientIp(h, null, 3)).toBe("unknown");
  });

  it("never consults X-Real-IP, even with trusted proxy hops configured", () => {
    // X-Real-IP has no chain semantics, so a hop count cannot be applied; when
    // XFF is absent/short a direct client could spoof it to rotate identities.
    expect(resolveClientIp(headers({ "x-real-ip": "1.2.3.4" }), "10.0.0.9", 1)).toBe("10.0.0.9");
    // ...but a spoofed X-Real-IP must not shadow a usable XFF chain either:
    expect(
      resolveClientIp(
        headers({ "x-forwarded-for": "1.1.1.1, 2.2.2.2", "x-real-ip": "9.9.9.9" }),
        "10.0.0.9",
        1,
      ),
    ).toBe("2.2.2.2");
  });
});

describe("InMemoryRateLimiter (SEC-014)", () => {
  it("limits after maxRequests within the window and resets afterwards", () => {
    const limiter = new InMemoryRateLimiter(2, 60_000);
    const now = Date.now();
    expect(limiter.check("ip-a", now)).toEqual({ limited: false });
    expect(limiter.check("ip-a", now)).toEqual({ limited: false });
    const third = limiter.check("ip-a", now);
    expect(third.limited).toBe(true);
    expect(limiter.check("ip-b", now)).toEqual({ limited: false });
    // Window rolls over.
    expect(limiter.check("ip-a", now + 61_000)).toEqual({ limited: false });
  });

  it("caps the key space and fails closed when full", () => {
    const limiter = new InMemoryRateLimiter(100, 60_000, 3);
    const now = Date.now();
    expect(limiter.check("a", now).limited).toBe(false);
    expect(limiter.check("b", now).limited).toBe(false);
    expect(limiter.check("c", now).limited).toBe(false);
    // Fourth distinct identity within the window: rejected rather than
    // growing the map (flooding unique identities cannot cause unbounded
    // memory pressure).
    const verdict = limiter.check("d", now);
    expect(verdict.limited).toBe(true);
    expect(limiter.size).toBe(3);
    // After the window expires the sweep frees space again.
    expect(limiter.check("d", now + 61_000).limited).toBe(false);
  });
});
