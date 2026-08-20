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
  KeyboardEvent: window.KeyboardEvent,
  MouseEvent: window.MouseEvent,
  IS_REACT_ACT_ENVIRONMENT: true,
});

const approve = mock(async (_txId: string) => {});
const reject = mock(async (_txId: string) => {});
const onResolve = mock((_txId: string, _status: "approved" | "rejected") => {});
let isResolving = false;

mock.module("../provider.js", () => ({
  useStewardContext: () => ({ features: { showApprovalQueue: true } }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("../hooks/useApprovals.js", () => ({
  useApprovals: () => ({
    pending: [
      {
        id: "approval-1",
        txId: "tx-1",
        to: "0x1234567890abcdef1234567890abcdef12345678",
        value: "1000000000000000000",
        chainId: 8453,
        createdAt: new Date().toISOString(),
        policyResults: [],
      },
      {
        id: "approval-2",
        txId: "tx-2",
        to: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        value: "2000000000000000000",
        chainId: 8453,
        createdAt: new Date().toISOString(),
        policyResults: [],
      },
    ],
    isLoading: false,
    error: null,
    approve,
    reject,
    isResolving,
  }),
}));

const { ApprovalQueue } = await import("../components/ApprovalQueue.js");

let container: HTMLDivElement;
let root: Root | null = null;

function button(name: string, within: ParentNode = container): HTMLButtonElement {
  const match = [...within.querySelectorAll("button")].find(
    (candidate) => candidate.textContent?.trim() === name,
  );
  if (!(match instanceof window.HTMLButtonElement)) {
    throw new Error(`button not found: ${name}`);
  }
  return match as unknown as HTMLButtonElement;
}

function approvalItem(index: number): Element {
  const item = container.querySelectorAll(".stwd-approval-item").item(index);
  if (!item) throw new Error(`approval item not found: ${index}`);
  return item;
}

async function click(target: HTMLButtonElement): Promise<void> {
  await React.act(async () => {
    target.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  });
}

async function pressKey(key: string, shiftKey = false): Promise<void> {
  await React.act(async () => {
    window.document.dispatchEvent(
      new window.KeyboardEvent("keydown", { key, shiftKey, bubbles: true, cancelable: true }),
    );
  });
}

async function rerenderQueue(): Promise<void> {
  await React.act(async () => {
    root?.render(<ApprovalQueue onResolve={onResolve} />);
  });
}

async function renderQueue(): Promise<void> {
  container = window.document.createElement("div") as unknown as HTMLDivElement;
  window.document.body.replaceChildren(container);
  root = createRoot(container);
  await React.act(async () => {
    root?.render(<ApprovalQueue onResolve={onResolve} />);
  });
}

beforeEach(async () => {
  if (root) {
    await React.act(async () => root?.unmount());
  }
  root = null;
  approve.mockReset();
  approve.mockImplementation(async () => {});
  reject.mockReset();
  reject.mockImplementation(async () => {});
  onResolve.mockClear();
  isResolving = false;
  await renderQueue();
});

afterAll(async () => {
  if (root) {
    await React.act(async () => root?.unmount());
  }
  window.close();
});

describe("<ApprovalQueue /> mutation failures", () => {
  test("provides a named modal dialog with bounded keyboard focus and returns focus", async () => {
    const opener = button("Approve", approvalItem(0));
    opener.focus();
    await click(opener);

    const dialog = container.querySelector('[role="dialog"]');
    if (!(dialog instanceof window.HTMLDivElement)) throw new Error("dialog not found");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    const title = window.document.getElementById(dialog.getAttribute("aria-labelledby") ?? "");
    const descriptionIds = (dialog.getAttribute("aria-describedby") ?? "").split(" ");
    expect(title?.textContent).toContain("Approve Transaction?");
    expect(descriptionIds).toHaveLength(1);
    expect(window.document.getElementById(descriptionIds[0])?.textContent).toContain(
      "signed and broadcast",
    );

    const cancel = button("Cancel", dialog);
    const confirm = button("Approve", dialog);
    expect(window.document.activeElement).toBe(cancel);

    await pressKey("Tab", true);
    expect(window.document.activeElement).toBe(confirm);
    await pressKey("Tab");
    expect(window.document.activeElement).toBe(cancel);

    opener.focus();
    await pressKey("Tab");
    expect(window.document.activeElement).toBe(cancel);

    await pressKey("Escape");
    expect(container.querySelector('[role="dialog"]')).toBeNull();
    expect(window.document.activeElement).toBe(opener);
  });

  test("does not dismiss on Escape while a resolution is in progress", async () => {
    const opener = button("Deny", approvalItem(0));
    await click(opener);
    isResolving = true;
    await rerenderQueue();

    await pressKey("Escape");
    expect(container.querySelector('[role="dialog"]')).not.toBeNull();
    expect(button("Cancel").disabled).toBe(true);
    expect(button("Processing...").disabled).toBe(true);

    isResolving = false;
    await rerenderQueue();
    await pressKey("Escape");
    expect(container.querySelector('[role="dialog"]')).toBeNull();
    expect(window.document.activeElement).toBe(opener);
  });

  test("keeps an approve confirmation open, reports a safe error, and succeeds on retry", async () => {
    let finishRetry: (() => void) | undefined;
    approve.mockImplementationOnce(async () => {
      throw new Error("provider secret: upstream account 0xdead failed");
    });
    approve.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishRetry = resolve;
        }),
    );

    await click(button("Approve"));
    await click(button("Approve", container.querySelector(".stwd-modal")!));

    expect(container.textContent).toContain("Approve Transaction?");
    expect(container.textContent).toContain(
      "We couldn't approve this transaction. Check your connection and try again.",
    );
    expect(container.textContent).not.toContain("provider secret");
    expect(onResolve).not.toHaveBeenCalled();
    const dialog = container.querySelector('[role="dialog"]');
    const alert = container.querySelector('[role="alert"]');
    expect(alert?.id).not.toBe("");
    expect((dialog?.getAttribute("aria-describedby") ?? "").split(" ")).toContain(alert?.id);

    await click(button("Approve", container.querySelector(".stwd-modal")!));

    expect(approve).toHaveBeenCalledTimes(2);
    expect(container.textContent).toContain("Approve Transaction?");
    expect(container.textContent).not.toContain("We couldn't approve");

    await React.act(async () => {
      finishRetry?.();
      await Promise.resolve();
    });

    expect(container.textContent).not.toContain("Approve Transaction?");
    expect(container.textContent).not.toContain("We couldn't approve");
    expect(onResolve).toHaveBeenCalledWith("tx-1", "approved");
  });

  test("keeps a deny confirmation open, reports a safe error, and succeeds on retry", async () => {
    reject.mockImplementationOnce(async () => {
      throw new Error("database host and tenant details");
    });

    await click(button("Deny"));
    await click(button("Deny", container.querySelector(".stwd-modal")!));

    expect(container.textContent).toContain("Deny Transaction?");
    expect(container.textContent).toContain(
      "We couldn't reject this transaction. Check your connection and try again.",
    );
    expect(container.textContent).not.toContain("database host");
    expect(onResolve).not.toHaveBeenCalled();

    await click(button("Deny", container.querySelector(".stwd-modal")!));

    expect(reject).toHaveBeenCalledTimes(2);
    expect(container.textContent).not.toContain("Deny Transaction?");
    expect(container.textContent).not.toContain("We couldn't reject");
    expect(onResolve).toHaveBeenCalledWith("tx-1", "rejected");
  });

  test("cancellation clears a stale action error before the modal is reopened", async () => {
    approve.mockImplementationOnce(async () => {
      throw new Error("approve failed");
    });

    await click(button("Approve"));
    await click(button("Approve", container.querySelector(".stwd-modal")!));
    expect(container.textContent).toContain("We couldn't approve");

    await click(button("Cancel"));
    await click(button("Approve"));

    expect(container.textContent).toContain("Approve Transaction?");
    expect(container.textContent).not.toContain("We couldn't approve");
  });

  test("a delayed success cannot close a different confirmation opened after cancellation", async () => {
    let finishApprove: (() => void) | undefined;
    approve.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishApprove = resolve;
        }),
    );

    await click(button("Approve", approvalItem(0)));
    await click(button("Approve", container.querySelector(".stwd-modal")!));
    await click(button("Cancel"));
    await click(button("Deny", approvalItem(1)));

    await React.act(async () => {
      finishApprove?.();
      await Promise.resolve();
    });

    expect(container.textContent).toContain("Deny Transaction?");
    expect(container.textContent).not.toContain("Approve Transaction?");
    expect(onResolve).toHaveBeenCalledWith("tx-1", "approved");
  });

  test("a delayed failure cannot leak into a different confirmation opened after cancellation", async () => {
    let failApprove: ((error: Error) => void) | undefined;
    approve.mockImplementationOnce(
      () =>
        new Promise<void>((_resolve, rejectPromise) => {
          failApprove = rejectPromise;
        }),
    );

    await click(button("Approve", approvalItem(0)));
    await click(button("Approve", container.querySelector(".stwd-modal")!));
    await click(button("Cancel"));
    await click(button("Deny", approvalItem(1)));

    await React.act(async () => {
      failApprove?.(new Error("stale provider failure"));
      await Promise.resolve();
    });

    expect(container.textContent).toContain("Deny Transaction?");
    expect(container.textContent).not.toContain("We couldn't approve");
    expect(onResolve).not.toHaveBeenCalled();
  });
});
