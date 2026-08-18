import { describe, expect, test } from "bun:test";
import {
  assertCompleteCoverage,
  checkCiTestInventory,
  extractJob,
  extractUnitMatrix,
  jobExecutesPackageTests,
} from "../check-ci-test-inventory";

describe("CI test inventory", () => {
  test("the repository workflows cover every test-bearing workspace package", () => {
    expect(() => checkCiTestInventory()).not.toThrow();
  });

  test("a future unlisted test package fails closed", () => {
    expect(() =>
      assertCompleteCoverage(["packages/a", "packages/new"], ["packages/a"], []),
    ).toThrow("test-bearing targets missing from CI: packages/new");
  });

  test("duplicate and stale declarations are rejected", () => {
    expect(() => assertCompleteCoverage(["packages/a"], ["packages/a", "packages/a"], [])).toThrow(
      "duplicate CI test inventory entries: packages/a",
    );
    expect(() => assertCompleteCoverage(["packages/a"], ["packages/a"], ["packages/a"])).toThrow(
      "duplicate CI test inventory entries: packages/a",
    );
    expect(() =>
      assertCompleteCoverage(["packages/a"], ["packages/a"], ["packages/removed"]),
    ).toThrow("CI inventory contains non-test targets: packages/removed");
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

  test("dedicated coverage requires an actual package test command", () => {
    const valid = [
      "  dedicated:",
      "    steps:",
      "      - name: Test package",
      "        working-directory: packages/a",
      "        run: bun run test",
    ].join("\n");
    const commentOnly = [
      "  dedicated:",
      "    # bun test packages/a",
      "    steps:",
      "      - name: packages/a bun test",
      "        run: bun run build",
    ].join("\n");
    const unrelated = [
      "  dedicated:",
      "    steps:",
      "      - name: Test another package",
      "        working-directory: packages/b",
      "        run: |",
      "          bun test packages/b",
      "          echo packages/a",
    ].join("\n");
    const echoed = ["  dedicated:", "    steps:", "      - run: echo bun test packages/a"].join(
      "\n",
    );
    const envPrefixed = [
      "  dedicated:",
      "    steps:",
      "      - name: Isolated package runner",
      "        run: TEST_JOBS=1 bun packages/a/scripts/run-tests-isolated.ts",
    ].join("\n");

    expect(jobExecutesPackageTests(extractJob(valid, "dedicated"), "packages/a")).toBe(true);
    expect(jobExecutesPackageTests(extractJob(commentOnly, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(unrelated, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(echoed, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(envPrefixed, "dedicated"), "packages/a")).toBe(true);
  });
});
