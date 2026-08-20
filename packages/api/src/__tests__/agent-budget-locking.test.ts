import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const actionSource = readFileSync(
  new URL("../services/provider-action-service.ts", import.meta.url),
  "utf8",
);
const authoritySource = readFileSync(
  new URL("../services/provider-authority-store.ts", import.meta.url),
  "utf8",
);

describe("provider agent budget namespace serialization", () => {
  test("locks the agent namespace before execution reads budget children", () => {
    const method = actionSource.slice(
      actionSource.indexOf("private async reserveAgentBudgets"),
      actionSource.indexOf(
        "// ── Policy evaluation",
        actionSource.indexOf("private async reserveAgentBudgets"),
      ),
    );
    expect(method.indexOf('.for("share")')).toBeGreaterThan(-1);
    expect(method.indexOf('.for("share")')).toBeLessThan(
      method.indexOf(".from(providerAgentBudgets)"),
    );
  });

  test("takes the conflicting namespace lock for create and update mutations", () => {
    for (const [methodName, mutation] of [
      ["async createAgentBudget", ".insert(providerAgentBudgets)"],
      ["async updateAgentBudget", ".update(providerAgentBudgets)"],
    ] as const) {
      const start = authoritySource.indexOf(methodName);
      const nextMethod = authoritySource.indexOf("\n  async ", start + methodName.length);
      const method = authoritySource.slice(start, nextMethod < 0 ? undefined : nextMethod);
      expect(method, methodName).toContain('.for("update")');
      expect(method.indexOf('.for("update")'), methodName).toBeLessThan(method.indexOf(mutation));
    }
  });
});
