import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";
import { Window } from "happy-dom";
import * as React from "react";
import { createRoot, type Root } from "react-dom/client";

const window = new Window();
Object.assign(globalThis, {
  window,
  document: window.document,
  navigator: window.navigator,
  HTMLElement: window.HTMLElement,
  IS_REACT_ACT_ENVIRONMENT: true,
});

let agentId = "agent-a";
let releaseAccountA: ((value: unknown) => void) | undefined;
let releaseAccountB: ((value: unknown) => void) | undefined;
let accountA: Promise<unknown>;
let accountB: Promise<unknown>;

const agent = (id: string) => ({
  id,
  tenantId: "tenant-test",
  name: id === "agent-a" ? "Delayed Agent A" : "Current Agent B",
  walletAddress:
    id === "agent-a"
      ? "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      : "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  walletAddresses: {},
  platformId: `${id}-platform`,
  createdAt: "2026-08-20T00:00:00.000Z",
});

const account = (id: string) => ({
  ...agent(id),
  type: "agent",
  agentId: id,
  wallets: [],
  balances: {
    evm: {
      native: id === "agent-a" ? "11000000000000000000" : "22000000000000000000",
      nativeFormatted: id === "agent-a" ? "11" : "22",
      chainId: 8453,
      symbol: "ETH",
      walletAddress: agent(id).walletAddress,
    },
  },
  spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
  capabilities: [],
  sponsorship: { enabled: false, mode: null, policyId: null },
});

const steward = {
  getAgent: mock(async (id: string) => agent(id)),
  getPolicies: mock(async () => []),
  getTransactionHistory: mock(async () => []),
  listAgentSigners: mock(async () => []),
  getAgentAccount: mock((id: string) => (id === "agent-a" ? accountA : accountB)),
  getBalance: mock(async () => {
    throw new Error("legacy fallback must not run");
  }),
  createAgentSigner: mock(async () => ({})),
  updateAgentSigner: mock(async () => ({})),
  revokeAgentSigner: mock(async () => ({})),
};

mock.module("next/navigation", () => ({ useParams: () => ({ id: agentId }) }));
mock.module("next/link", () => ({
  default: ({ children, href, ...props }: React.AnchorHTMLAttributes<HTMLAnchorElement>) =>
    React.createElement("a", { href: String(href), ...props }, children),
}));
mock.module("framer-motion", () => ({
  AnimatePresence: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  motion: new Proxy(
    {},
    {
      get: (_target, tag: string) =>
        React.forwardRef<HTMLElement, React.HTMLAttributes<HTMLElement>>((props, ref) => {
          const domProps = { ...props } as Record<string, unknown>;
          for (const key of ["animate", "exit", "initial", "layoutId", "transition"]) {
            delete domProps[key];
          }
          return React.createElement(tag, { ...domProps, ref });
        }),
    },
  ),
}));
mock.module("@/lib/api", () => ({ steward }));

const { default: AgentDetailPage } = await import("./page");

let container: HTMLDivElement;
let root: Root | null = null;

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was not reached");
    await React.act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
    });
  }
}

beforeEach(async () => {
  if (root) await React.act(async () => root?.unmount());
  agentId = "agent-a";
  accountA = new Promise((resolve) => {
    releaseAccountA = resolve;
  });
  accountB = new Promise((resolve) => {
    releaseAccountB = resolve;
  });
  steward.getAgentAccount.mockClear();
  container = window.document.createElement("div") as unknown as HTMLDivElement;
  window.document.body.replaceChildren(container as never);
  root = createRoot(container);
});

afterAll(async () => {
  if (root) await React.act(async () => root?.unmount());
  window.close();
});

describe("AgentDetailPage load ownership", () => {
  test("a delayed A response cannot overwrite route B or finish B's loading state", async () => {
    await React.act(async () => root?.render(<AgentDetailPage />));
    await waitFor(() => steward.getAgentAccount.mock.calls.some(([id]) => id === "agent-a"));

    agentId = "agent-b";
    await React.act(async () => root?.render(<AgentDetailPage />));
    await waitFor(() => steward.getAgentAccount.mock.calls.some(([id]) => id === "agent-b"));

    await React.act(async () => releaseAccountA?.(account("agent-a")));
    expect(container.textContent).not.toContain("Delayed Agent A");
    expect(container.textContent).not.toContain("11 ETH");
    expect(container.textContent).not.toContain("Current Agent B");

    await React.act(async () => releaseAccountB?.(account("agent-b")));
    expect(container.textContent).toContain("Current Agent B");
    expect(container.textContent).toContain("22 ETH");
    expect(container.textContent).not.toContain("Delayed Agent A");
    expect(container.textContent).not.toContain("11 ETH");
  });
});
