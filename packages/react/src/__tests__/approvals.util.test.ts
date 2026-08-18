import { describe, expect, mock, test } from "bun:test";
import { getAllPendingApprovals } from "../utils/approvals.js";

function approval(id: string) {
  return { id, agentId: "agent/1", txId: `tx-${id}`, status: "pending" };
}

describe("getAllPendingApprovals", () => {
  test("exhausts agent-filtered 200-row pages before returning", async () => {
    const first = Array.from({ length: 200 }, (_, index) => approval(`approval-${index}`));
    const second = [approval("approval-200")];
    const listApprovals = mock(async (opts: { offset?: number }) =>
      opts.offset === 0 ? first : second,
    );

    const result = await getAllPendingApprovals({ listApprovals } as any, "agent/1");

    expect(result).toHaveLength(201);
    expect(listApprovals.mock.calls).toEqual([
      [{ status: "pending", agentId: "agent/1", limit: 200, offset: 0 }],
      [{ status: "pending", agentId: "agent/1", limit: 200, offset: 200 }],
    ]);
  });

  test("restarts once when a concurrent insert shifts offset pagination", async () => {
    const first = Array.from({ length: 200 }, (_, index) => approval(`approval-${index}`));
    let calls = 0;
    const listApprovals = mock(async (opts: { offset?: number }) => {
      calls += 1;
      if (calls === 1) return first;
      if (calls === 2) return [approval("approval-199")];
      return opts.offset === 0 ? first : [approval("approval-200")];
    });

    const result = await getAllPendingApprovals({ listApprovals } as any, "agent/1");

    expect(result).toHaveLength(201);
    expect(calls).toBe(4);
  });
});
