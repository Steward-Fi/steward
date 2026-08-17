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

  test("restarts once when offset pagination shifts under a new transaction", async () => {
    const first = Array.from({ length: 200 }, (_, i) => ({ id: `tx-${i}` }));
    let calls = 0;
    const listTransactions = mock(async (_agentId: string, opts: { offset?: number }) => {
      calls += 1;
      if (calls === 1) return { transactions: first, limit: 200, offset: 0 };
      if (calls === 2) {
        return { transactions: [{ id: "tx-199" }], limit: 200, offset: 200 };
      }
      return {
        transactions: opts.offset === 0 ? first : [{ id: "tx-200" }],
        limit: 200,
        offset: opts.offset ?? 0,
      };
    });

    const result = await getAllTransactions({ listTransactions } as any, "agent/1");
    expect(result).toHaveLength(201);
    expect(calls).toBe(4);
  });
});
