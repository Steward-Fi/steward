import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "intents.ts"), "utf8");

describe("intent read hardening", () => {
  it("redacts signed transaction material from stored intent read responses", () => {
    const responseStart = routeSource.indexOf("function toIntentResponse");
    expect(responseStart).toBeGreaterThanOrEqual(0);
    const responseBody = routeSource.slice(
      responseStart,
      routeSource.indexOf("function redactSignedTransactions", responseStart),
    );
    expect(responseBody).toContain(
      "executionResult: redactSignedTransactions(row.executionResult)",
    );
    expect(responseBody).toContain(
      "execution_result: redactSignedTransactions(row.executionResult)",
    );
    expect(responseBody).not.toContain("executionResult: row.executionResult");
    expect(responseBody).not.toContain("execution_result: row.executionResult");
  });

  it("attributes intent audits to the actual auth type and writes lifecycle authorization audit first", () => {
    const auditStart = routeSource.indexOf("async function writeIntentAudit");
    expect(auditStart).toBeGreaterThanOrEqual(0);
    const auditBody = routeSource.slice(
      auditStart,
      routeSource.indexOf("function dispatchIntentWebhook", auditStart),
    );
    expect(auditBody).toContain("actorType: auditActorType(c)");
    expect(auditBody).not.toContain('actorType: "user"');

    const lifecycleUpdateStart = routeSource.indexOf("const lifecycleStatus = status as");
    expect(lifecycleUpdateStart).toBeGreaterThanOrEqual(0);
    const authorizedAudit = routeSource.indexOf(
      "writeIntentAudit(c, `intent.${lifecycleStatus}.authorized`",
      lifecycleUpdateStart,
    );
    const mutation = routeSource.indexOf(".update(intents)", lifecycleUpdateStart);
    expect(authorizedAudit).toBeGreaterThan(lifecycleUpdateStart);
    expect(mutation).toBeGreaterThan(lifecycleUpdateStart);
    expect(authorizedAudit).toBeLessThan(mutation);
  });

  it("does not allow intent resourceId to choose the transaction primary key", () => {
    const transferStart = routeSource.indexOf("async function executeTransferIntent");
    expect(transferStart).toBeGreaterThanOrEqual(0);
    const transferBody = routeSource.slice(
      transferStart,
      routeSource.indexOf("async function executeSendCallsIntent", transferStart),
    );
    expect(transferBody).toContain("const txId = row.id");
    expect(transferBody).not.toContain("row.resourceId || row.id");
  });
});
