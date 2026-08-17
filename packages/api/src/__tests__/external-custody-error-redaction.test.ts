import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

describe("external custody failure redaction", () => {
  test("primary signing never forwards the raw provider error to logs or webhooks", async () => {
    const source = await readFile(new URL("../routes/vault.ts", import.meta.url), "utf8");
    const catchStart = source.indexOf('const requestId = c.get("requestId") || "unknown";');
    const catchEnd = source.indexOf("if (isRpcError(e))", catchStart);
    expect(catchStart).toBeGreaterThan(0);
    expect(catchEnd).toBeGreaterThan(catchStart);
    const boundary = source.slice(catchStart, catchEnd);
    expect(boundary).toContain("Transaction signing failed");
    expect(boundary).not.toContain("e.message");
    expect(boundary).not.toContain("String(e)");
    expect(boundary).not.toMatch(/console\.error\([^;]*,\s*e\)/s);

    const approvalStart = source.indexOf(
      'const safeFailureMessage = "Transaction approval execution failed";',
    );
    const approvalEnd = source.indexOf("if (isRpcError(e))", approvalStart);
    expect(approvalStart).toBeGreaterThan(0);
    expect(approvalEnd).toBeGreaterThan(approvalStart);
    const approvalBoundary = source.slice(approvalStart, approvalEnd);
    expect(approvalBoundary).not.toContain("e.message");
    expect(approvalBoundary).not.toContain("String(e)");
    expect(approvalBoundary).not.toMatch(/console\.error\([^;]*,\s*e\)/s);
  });
});
