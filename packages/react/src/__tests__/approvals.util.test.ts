import { describe, expect, mock, test } from "bun:test";
import { getAllPendingApprovals } from "../utils/approvals.js";

function approval(index: number) {
  const id = `approval-${String(index).padStart(3, "0")}`;
  return {
    id,
    agentId: "agent/1",
    txId: `tx-${id}`,
    status: "pending",
    requestedAt: new Date(Date.UTC(2026, 0, 1, 0, 0, 1000 - index)),
  };
}

describe("getAllPendingApprovals", () => {
  test("exhausts agent-filtered 200-row pages before returning", async () => {
    const first = Array.from({ length: 200 }, (_, index) => approval(index));
    const second = [approval(200)];
    const listApprovals = mock(async (opts: { cursorId?: string }) =>
      opts.cursorId === undefined ? first : second,
    );

    const result = await getAllPendingApprovals({ listApprovals } as any, "agent/1");

    expect(result).toHaveLength(201);
    expect(listApprovals.mock.calls).toEqual([
      [{ status: "pending", agentId: "agent/1", limit: 200 }],
      [
        {
          status: "pending",
          agentId: "agent/1",
          limit: 200,
          cursorRequestedAt: first[199]?.requestedAt.toISOString(),
          cursorId: first[199]?.id,
        },
      ],
    ]);
  });

  test("does not skip ID 200 or duplicate rows after a status change and deletion", async () => {
    const first = Array.from({ length: 200 }, (_, index) => approval(index));
    let calls = 0;
    const listApprovals = mock(async (opts: { cursorId?: string }) => {
      calls += 1;
      if (calls === 1) return first;
      // Between pages, one page-1 row changes status and another is deleted.
      // An offset of 200 would now advance past approval-200. The immutable
      // keyset boundary still selects it directly.
      first[20] = { ...first[20], status: "approved" };
      first.splice(40, 1);
      expect(opts.cursorId).toBe("approval-199");
      return [approval(200)];
    });

    const result = await getAllPendingApprovals({ listApprovals } as any, "agent/1");

    expect(result.map(({ id }) => id)).toContain("approval-200");
    expect(new Set(result.map(({ id }) => id)).size).toBe(201);
    expect(calls).toBe(2);
  });
});
