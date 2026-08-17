/**
 * SEC-110 regression coverage: webhook log redaction must recurse into
 * ARRAYS, not just plain objects — batch-shaped payloads (e.g.
 * `items: [{ apiKey: ... }]`) previously logged secrets in the clear.
 */
import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { logWebhook } from "../logger";

let writeSpy: ReturnType<typeof spyOn> | undefined;
let lines: string[];

beforeEach(() => {
  lines = [];
  writeSpy = spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    lines.push(String(chunk));
    return true;
  }) as never);
});

afterEach(() => {
  writeSpy?.mockRestore();
  writeSpy = undefined;
});

function loggedData(): Record<string, unknown> {
  expect(lines).toHaveLength(1);
  return (JSON.parse(lines[0] as string) as { data: Record<string, unknown> }).data;
}

describe("logWebhook redaction (SEC-110)", () => {
  it("redacts sensitive fields nested inside arrays", () => {
    logWebhook({
      event: "test.event",
      data: {
        items: [{ apiKey: "array-secret-value", note: "keep-me" }],
        deeply: { nested: [{ private_key: "0xdeadbeef", ok: 1 }] },
      },
    });
    const data = loggedData();
    const items = data.items as Array<Record<string, unknown>>;
    expect(items[0]?.apiKey).toBe("[redacted]");
    expect(items[0]?.note).toBe("keep-me");
    const deeply = data.deeply as { nested: Array<Record<string, unknown>> };
    expect(deeply.nested[0]?.private_key).toBe("[redacted]");
    expect(deeply.nested[0]?.ok).toBe(1);
    expect(lines[0]).not.toContain("array-secret-value");
    expect(lines[0]).not.toContain("0xdeadbeef");
  });

  it("keeps prior behavior: object-nested redaction, primitives and arrays of primitives untouched", () => {
    logWebhook({
      event: "test.event",
      data: {
        token: "object-secret-value",
        nested: { authorization: "Bearer xyz", fine: true },
        plain: [1, "two", null],
        txHash: "0xabc123",
      },
    });
    const data = loggedData();
    expect(data.token).toBe("[redacted]");
    expect((data.nested as Record<string, unknown>).authorization).toBe("[redacted]");
    expect((data.nested as Record<string, unknown>).fine).toBe(true);
    expect(data.plain).toEqual([1, "two", null]);
    expect(data.txHash).toBe("0xabc123");
    expect(lines[0]).not.toContain("object-secret-value");
  });
});
