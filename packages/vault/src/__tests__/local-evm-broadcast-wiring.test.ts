import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

describe("local EVM broadcast wiring", () => {
  test("routes local-key broadcasts through the checkpointed raw-transaction lifecycle", async () => {
    const source = await readFile(new URL("../vault.ts", import.meta.url), "utf8");

    expect(source).toContain("return executeLocalEvmBroadcast({");
    expect(source).toContain('status: "outcome_unknown"');
    expect(source).toContain("publicClient.sendRawTransaction({ serializedTransaction })");
    expect(source).toContain("transport: http(rpcUrl, { retryCount: 0 })");
    expect(source).toContain('status: localRecordOptions.status ?? "broadcast"');
    expect(source).not.toContain("client.sendTransaction({");
  });
});
