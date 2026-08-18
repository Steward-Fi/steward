import { describe, expect, test } from "bun:test";
import {
  assertCompleteCoverage,
  checkCiTestInventory,
  extractJob,
  extractUnitMatrix,
} from "../check-ci-test-inventory";

describe("CI test inventory", () => {
  test("the repository workflows cover every test-bearing workspace package", () => {
    expect(() => checkCiTestInventory()).not.toThrow();
  });

  test("a future unlisted test package fails closed", () => {
    expect(() =>
      assertCompleteCoverage(["packages/a", "packages/new"], ["packages/a"], []),
    ).toThrow("workspace test packages missing from CI: packages/new");
  });

  test("duplicate and stale declarations are rejected", () => {
    expect(() => assertCompleteCoverage(["packages/a"], ["packages/a", "packages/a"], [])).toThrow(
      "duplicate unit matrix entries: packages/a",
    );
    expect(() =>
      assertCompleteCoverage(["packages/a"], ["packages/a"], ["packages/removed"]),
    ).toThrow("CI inventory contains non-test workspace packages: packages/removed");
  });

  test("workflow extraction is scoped to the unit and dedicated job blocks", () => {
    const workflow = [
      "jobs:",
      "  unit:",
      "    strategy:",
      "      matrix:",
      "        package:",
      "          - packages/a",
      "          - scripts/__tests__",
      "    steps: []",
      "  dedicated:",
      "    steps:",
      "      - run: bun test packages/b",
      "  later:",
      "    steps: []",
    ].join("\n");
    expect(extractUnitMatrix(workflow)).toEqual(["packages/a", "scripts/__tests__"]);
    expect(extractJob(workflow, "dedicated")).toContain("bun test packages/b");
    expect(extractJob(workflow, "dedicated")).not.toContain("later");
  });
});
