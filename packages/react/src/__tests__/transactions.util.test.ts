import { describe, expect, mock, test } from "bun:test";
import { getAllTransactions } from "../utils/transactions.js";

describe("getAllTransactions", () => {
  test("exhausts 200-row pages before returning", async () => {
    const first = Array.from({ length: 200 }, (_, i) => ({ id: `tx-${i}` }));
    const second = [{ id: "tx-200" }];
    const listTransactions = mock(async (_agentId: string, opts: { offset?: number }) => ({
      transactions: opts.offset === 0 ? first : second,
      limit: 200,
      offset: opts.offset ?? 0,
    }));

    const result = await getAllTransactions({ listTransactions } as any, "agent/1");

    expect(result).toHaveLength(201);
    expect(listTransactions.mock.calls).toEqual([
      ["agent/1", { limit: 200, offset: 0 }],
      ["agent/1", { limit: 200, offset: 200 }],
    ]);
  });
});
