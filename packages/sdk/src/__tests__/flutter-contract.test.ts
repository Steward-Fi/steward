import { describe, expect, it } from "bun:test";
import { existsSync } from "node:fs";

describe("Flutter SDK artifact contract", () => {
  it("keeps the independently executed Flutter client, models, and tests in the repository", () => {
    for (const path of [
      "../../../flutter/lib/src/client.dart",
      "../../../flutter/lib/src/models.dart",
      "../../../flutter/test/steward_contract_test.dart",
    ]) {
      expect(existsSync(new URL(path, import.meta.url))).toBe(true);
    }
  });
});
