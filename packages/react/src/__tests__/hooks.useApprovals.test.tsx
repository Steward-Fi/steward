/**
 * Tests for useApprovals().
 *
 * The hook routes every call through the credentialed StewardClient
 * (listApprovals / approveVaultTransaction / denyTransaction) — raw fetch must
 * never be used, so credentials always attach (SEC-195 regression).
 *
 * The test runner has no jsdom and renderToString does not flush effects, so
 * we assert on the mocked client calls and thrown errors via an SSR probe,
 * and cover the entry mapping (toQueueEntry) as a pure function.
 */

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const listApprovalsMock = mock(
  async (_opts?: { status?: string; agentId?: string }) => [] as any[],
);
const approveVaultTransactionMock = mock(async (_agentId: string, _txId: string) => ({}) as any);
const denyTransactionMock = mock(async (_txId: string, _reason: string) => ({}) as any);

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: {
      listApprovals: listApprovalsMock,
      approveVaultTransaction: approveVaultTransactionMock,
      denyTransaction: denyTransactionMock,
    },
    agentId: "agent x",
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useApprovals, toQueueEntry } = await import("../hooks/useApprovals.js");

type UseApprovalsReturn = ReturnType<typeof useApprovals>;

function captureHook(): UseApprovalsReturn {
  let captured: UseApprovalsReturn | null = null;
  function Probe() {
    captured = useApprovals();
    return null;
  }
  renderToString(React.createElement(Probe));
  if (!captured) throw new Error("hook did not render");
  return captured;
}

const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof mock>;

describe("useApprovals()", () => {
  beforeEach(() => {
    listApprovalsMock.mockClear();
    listApprovalsMock.mockImplementation(async () => []);
    approveVaultTransactionMock.mockClear();
    denyTransactionMock.mockClear();
    fetchMock = mock(async () => {
      throw new Error("raw fetch must not be used");
    });
    globalThis.fetch = fetchMock as any;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("initial return shape: loading, empty pending, not resolving", () => {
    const api = captureHook();
    expect(api.isLoading).toBe(true);
    expect(api.pending).toEqual([]);
    expect(api.error).toBeNull();
    expect(api.isResolving).toBe(false);
    expect(typeof api.approve).toBe("function");
    expect(typeof api.reject).toBe("function");
    expect(typeof api.refetch).toBe("function");
  });

  test("refetch lists pending approvals via the credentialed client only", async () => {
    const api = captureHook();
    await api.refetch();
    expect(listApprovalsMock).toHaveBeenCalledTimes(1);
    expect(listApprovalsMock).toHaveBeenCalledWith({ status: "pending", agentId: "agent x" });
    // SEC-195: no credential-less raw fetch on any path.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("asks the server to filter before the tenant-wide first page", async () => {
    const otherAgentPage = Array.from({ length: 50 }, (_, index) => ({
      id: `other-${index}`,
      txId: `other-tx-${index}`,
      agentId: "other-agent",
      status: "pending",
      requestedAt: new Date(),
    }));
    const targetApproval = {
      id: "target-approval",
      txId: "target-tx",
      agentId: "agent x",
      status: "pending",
      requestedAt: new Date(),
    };
    listApprovalsMock.mockImplementation(async (opts) =>
      opts?.agentId === "agent x" ? [targetApproval] : otherAgentPage,
    );

    const api = captureHook();
    await api.refetch();

    expect(listApprovalsMock).toHaveBeenCalledWith({ status: "pending", agentId: "agent x" });
    expect(listApprovalsMock.mock.results[0]?.value).resolves.toEqual([targetApproval]);
  });

  test("approve() goes through the credentialed client", async () => {
    const api = captureHook();
    await api.approve("tx-123");
    expect(approveVaultTransactionMock).toHaveBeenCalledTimes(1);
    expect(approveVaultTransactionMock).toHaveBeenCalledWith("agent x", "tx-123");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("approve() propagates client errors", async () => {
    approveVaultTransactionMock.mockImplementation(async () => {
      throw new Error("Approve failed: 500");
    });
    const api = captureHook();
    await expect(api.approve("tx-1")).rejects.toThrow("Approve failed: 500");
  });

  test("reject() sends the reason through the credentialed client", async () => {
    const api = captureHook();
    await api.reject("tx-9", "looks sketchy");
    expect(denyTransactionMock).toHaveBeenCalledTimes(1);
    expect(denyTransactionMock.mock.calls[0]?.[0]).toBe("tx-9");
    expect(denyTransactionMock.mock.calls[0]?.[1]).toBe("looks sketchy");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("reject() propagates client errors", async () => {
    denyTransactionMock.mockImplementation(async () => {
      throw new Error("Reject failed: 403");
    });
    const api = captureHook();
    await expect(api.reject("tx-2")).rejects.toThrow("Reject failed: 403");
  });
});

describe("toQueueEntry()", () => {
  test("maps the SDK approval entry onto the dashboard shape", () => {
    const entry = toQueueEntry({
      id: "ap-1",
      txId: "tx-1",
      agentId: "agent-1",
      status: "pending",
      requestedAt: new Date("2026-01-01T00:00:00Z"),
      toAddress: "0xabc",
      value: "100",
      chainId: 8453,
    } as any);
    expect(entry).toEqual({
      id: "ap-1",
      agentId: "agent-1",
      txId: "tx-1",
      status: "pending",
      to: "0xabc",
      value: "100",
      chainId: 8453,
      policyResults: [],
      createdAt: "2026-01-01T00:00:00.000Z",
      resolvedAt: undefined,
      resolvedBy: undefined,
    });
  });

  test("tolerates missing optional fields and string dates", () => {
    const entry = toQueueEntry({
      id: "ap-2",
      txId: "tx-2",
      agentId: "agent-1",
      status: "rejected",
      requestedAt: "2026-02-02T00:00:00Z",
      resolvedAt: "2026-02-03T00:00:00Z",
      resolvedBy: "user-1",
    } as any);
    expect(entry.to).toBe("");
    expect(entry.value).toBe("0");
    expect(entry.chainId).toBe(0);
    expect(entry.createdAt).toBe("2026-02-02T00:00:00.000Z");
    expect(entry.resolvedAt).toBe("2026-02-03T00:00:00.000Z");
    expect(entry.resolvedBy).toBe("user-1");
  });
});
