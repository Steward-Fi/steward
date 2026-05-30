/**
 * Tests for useWallet().
 *
 * Covers initial return shape and the refetch() wiring: it fans out to
 * client.getAgent / getBalance / getAddresses in parallel, tolerating
 * rejections from getBalance (→ null) and getAddresses (→ empty list). The
 * mount-time polling effect is covered by the browser e2e suite.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const getAgentMock = mock(async (_id: string) => ({ id: "agent-1", name: "Test Agent" }));
const getBalanceMock = mock(async (_id: string) => ({ balances: { native: "0" } }));
const getAddressesMock = mock(async (_id: string) => ({
  addresses: [{ chainFamily: "evm", address: "0xabc" }],
}));

// NOTE on isolation: bun's `mock.module` is process-global. This suite is run
// one-file-per-process by the package's test script, which keeps each file's
// `../provider.js` / hook-module mocks from clobbering each other. Run
// individual files (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: {
      getAgent: getAgentMock,
      getBalance: getBalanceMock,
      getAddresses: getAddressesMock,
      getBaseUrl: () => "https://api.test",
    },
    agentId: "agent-1",
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useWallet } = await import("../hooks/useWallet.js");

type UseWalletReturn = ReturnType<typeof useWallet>;

function captureHook(): UseWalletReturn {
  let captured: UseWalletReturn | null = null;
  function Probe() {
    captured = useWallet();
    return null;
  }
  renderToString(React.createElement(Probe));
  if (!captured) throw new Error("hook did not render");
  return captured;
}

describe("useWallet()", () => {
  beforeEach(() => {
    getAgentMock.mockClear();
    getBalanceMock.mockClear();
    getAddressesMock.mockClear();
    getAgentMock.mockImplementation(async () => ({ id: "agent-1", name: "Test Agent" }));
    getBalanceMock.mockImplementation(async () => ({ balances: { native: "0" } }));
    getAddressesMock.mockImplementation(async () => ({
      addresses: [{ chainFamily: "evm", address: "0xabc" }],
    }));
  });

  test("initial return shape: loading, nulls, empty addresses", () => {
    const api = captureHook();
    expect(api.isLoading).toBe(true);
    expect(api.agent).toBeNull();
    expect(api.balance).toBeNull();
    expect(api.addresses).toEqual([]);
    expect(api.error).toBeNull();
    expect(typeof api.refetch).toBe("function");
  });

  test("refetch fans out to all three client calls with the agent id", async () => {
    const api = captureHook();
    await api.refetch();
    expect(getAgentMock).toHaveBeenCalledTimes(1);
    expect(getBalanceMock).toHaveBeenCalledTimes(1);
    expect(getAddressesMock).toHaveBeenCalledTimes(1);
    expect(getAgentMock.mock.calls[0][0]).toBe("agent-1");
  });

  test("refetch tolerates a getBalance rejection (does not reject overall)", async () => {
    getBalanceMock.mockImplementation(async () => {
      throw new Error("balance endpoint down");
    });
    const api = captureHook();
    // The hook catches getBalance via .catch(() => null); refetch should
    // resolve without throwing.
    await expect(api.refetch()).resolves.toBeUndefined();
    expect(getAgentMock).toHaveBeenCalledTimes(1);
  });

  test("refetch tolerates a getAddresses rejection (falls back to empty list)", async () => {
    getAddressesMock.mockImplementation(async () => {
      throw new Error("addresses endpoint down");
    });
    const api = captureHook();
    await expect(api.refetch()).resolves.toBeUndefined();
  });

  test("refetch surfaces a getAgent rejection by not throwing (error captured in state)", async () => {
    getAgentMock.mockImplementation(async () => {
      throw new Error("agent not found");
    });
    const api = captureHook();
    // getAgent is the only non-catch call; the hook's try/catch swallows it
    // into `error` state, so refetch still resolves.
    await expect(api.refetch()).resolves.toBeUndefined();
  });
});
