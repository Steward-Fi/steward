/**
 * safe-error.test.ts — describeThrown MUST never throw for ANY input, and must
 * preserve useful messages for well-behaved values. This is the unit backstop
 * for the fail-closed catch boundaries (policy composer + generic engine + invoke
 * path) that build their deny reason from an arbitrary thrown value.
 */

import { describe, expect, it } from "bun:test";
import { describeThrown, UNPRINTABLE_THROWN_VALUE } from "../safe-error.js";

describe("describeThrown — well-behaved values (message preserved)", () => {
  it("returns the message of a normal Error", () => {
    expect(describeThrown(new Error("boom"))).toBe("boom");
  });

  it("returns a non-empty string as-is (trimmed)", () => {
    expect(describeThrown("  plain string  ")).toBe("plain string");
  });

  it("coerces primitives via String()", () => {
    expect(describeThrown(42)).toBe("42");
    expect(describeThrown(true)).toBe("true");
    expect(describeThrown(123n)).toBe("123");
  });

  it("falls back for null/undefined (no useful message)", () => {
    // String(null) === "null" is honest and non-hostile; keep it.
    expect(describeThrown(null)).toBe("null");
    expect(describeThrown(undefined)).toBe("undefined");
  });

  it("uses a custom (well-behaved) toString", () => {
    expect(
      describeThrown({
        toString() {
          return "custom description";
        },
      }),
    ).toBe("custom description");
  });
});

describe("describeThrown — HOSTILE values (NEVER throws, static fallback)", () => {
  it("does not throw when toString throws (the exact P0 probe)", () => {
    const hostile = {
      toString() {
        throw new Error("secondary stringify failure");
      },
    };
    let out: string | undefined;
    expect(() => {
      out = describeThrown(hostile);
    }).not.toThrow();
    expect(out).toBe(UNPRINTABLE_THROWN_VALUE);
  });

  it("does not throw when toString AND valueOf AND Symbol.toPrimitive all throw", () => {
    const hostile = {
      toString() {
        throw new Error("toString");
      },
      valueOf() {
        throw new Error("valueOf");
      },
      [Symbol.toPrimitive]() {
        throw new Error("toPrimitive");
      },
    };
    expect(describeThrown(hostile)).toBe(UNPRINTABLE_THROWN_VALUE);
  });

  it("does not throw for a Proxy(Error) whose `.message` getter throws", () => {
    const hostile = new Proxy(new Error("real"), {
      get(_t, prop) {
        if (prop === "message") throw new Error("hostile message getter");
        if (prop === "toString" || prop === Symbol.toPrimitive || prop === "valueOf") {
          return () => {
            throw new Error("hostile coercion");
          };
        }
        return undefined;
      },
    });
    let out: string | undefined;
    expect(() => {
      out = describeThrown(hostile);
    }).not.toThrow();
    expect(out).toBe(UNPRINTABLE_THROWN_VALUE);
  });

  it("prefers a SAFE message on a Proxy(Error) even if coercion is hostile", () => {
    // message getter is safe; only string-coercion is hostile => we should still
    // recover the useful message and never reach the fallback.
    const partlyHostile = new Proxy(new Error("safe message"), {
      get(target, prop) {
        if (prop === "toString" || prop === Symbol.toPrimitive || prop === "valueOf") {
          return () => {
            throw new Error("hostile coercion");
          };
        }
        return Reflect.get(target, prop);
      },
    });
    expect(describeThrown(partlyHostile)).toBe("safe message");
  });

  it("empty / whitespace-only bare string falls back (no signal)", () => {
    expect(describeThrown("")).toBe(UNPRINTABLE_THROWN_VALUE);
    expect(describeThrown("   ")).toBe(UNPRINTABLE_THROWN_VALUE);
  });

  it("an Error with a whitespace-only message degrades to a safe non-throwing coercion (never throws, never empty)", () => {
    // `.message` is whitespace => no signal there, but String(error) is still a
    // safe, honest, non-hostile coercion (e.g. "Error"). The only hard contract
    // is: never throw, never return an empty string.
    let out: string | undefined;
    expect(() => {
      out = describeThrown(new Error("   "));
    }).not.toThrow();
    expect(typeof out).toBe("string");
    expect((out as string).length).toBeGreaterThan(0);
  });
});
