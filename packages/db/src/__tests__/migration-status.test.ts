import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { getMigrationExpectation } from "../migration-status";

describe("migration expectation", () => {
  test("is derived from the checked-in journal tip", () => {
    const journal = JSON.parse(
      readFileSync(new URL("../../drizzle/meta/_journal.json", import.meta.url), "utf8"),
    ) as { entries: Array<{ tag: string; when: number }> };
    const tip = journal.entries.at(-1);
    expect(tip).toBeDefined();
    expect(getMigrationExpectation()).toEqual({
      tag: tip?.tag,
      createdAt: tip?.when,
      count: journal.entries.length,
    });
  });

  test("journals the operator transfer reservation migrations for production", () => {
    const journal = JSON.parse(
      readFileSync(new URL("../../drizzle/meta/_journal.json", import.meta.url), "utf8"),
    ) as { entries: Array<{ tag: string }> };
    expect(
      journal.entries.some((entry) => entry.tag === "0094_operator_transfer_reservations"),
    ).toBe(true);
    expect(
      journal.entries.some((entry) => entry.tag === "0108_operator_transfer_durable_replay"),
    ).toBe(true);
  });
});
