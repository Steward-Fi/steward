import { describe, expect, test } from "bun:test";
import { validateApiKey } from "../../../auth/src/api-keys";
import { generateDemoApiKey } from "../demo-api-key";

describe("demo API key", () => {
  test("is fresh, high-entropy, and verifies only against its own hash", () => {
    const first = generateDemoApiKey();
    const second = generateDemoApiKey();

    expect(first.key).toMatch(/^stw_[0-9a-f]{32}$/);
    expect(first.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(second.key).not.toBe(first.key);
    expect(validateApiKey(first.key, first.hash)).toBe(true);
    expect(validateApiKey(second.key, first.hash)).toBe(false);
  });
});
