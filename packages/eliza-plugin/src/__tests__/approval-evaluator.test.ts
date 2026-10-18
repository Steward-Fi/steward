import { describe, expect, it, vi } from "vitest";
import { approvalRequiredEvaluator } from "../evaluators/approval.js";

function makeRuntime(connected: boolean) {
  return {
    getService: (name: string) => (name === "steward" ? { isConnected: () => connected } : null),
  } as any;
}

const message = { id: "11111111-0000-4000-8000-000000000000", content: { text: "x" } } as any;

describe("approvalRequired evaluator (core 2.0.x shape)", () => {
  it("exposes the 2.0.x evaluator contract", () => {
    expect(approvalRequiredEvaluator.schema).toMatchObject({ type: "object" });
    expect(typeof approvalRequiredEvaluator.shouldRun).toBe("function");
    expect(typeof approvalRequiredEvaluator.prompt).toBe("function");
    expect(approvalRequiredEvaluator.processors?.length).toBe(1);
  });

  it("runs only when a Steward action in this turn is pending approval", async () => {
    const runtime = makeRuntime(true);
    runtime.getActionResults = () => [{ success: true, data: { status: "completed" } }];
    expect(
      await approvalRequiredEvaluator.shouldRun({ runtime, message, options: {} } as any),
    ).toBe(false);

    runtime.getActionResults = () => [
      { success: true, data: { status: "pending_approval", policies: [{ type: "limit" }] } },
    ];
    const ctx = { runtime, message, options: {} } as any;
    expect(await approvalRequiredEvaluator.shouldRun(ctx)).toBe(true);
    const prepared = await approvalRequiredEvaluator.prepare(ctx);
    expect(approvalRequiredEvaluator.prompt()).toContain("acknowledged");
    const result = await approvalRequiredEvaluator.processors[0].process({ prepared } as any);
    expect(result).toMatchObject({ success: true, data: { pendingApproval: true } });
  });

  it("falls back to state action results when per-message results are absent", async () => {
    vi.spyOn(console, "info").mockImplementation(() => {});
    const runtime = makeRuntime(true);
    const state = {
      data: { actionResults: [{ success: true, data: { status: "pending_approval" } }] },
    };
    expect(
      await approvalRequiredEvaluator.shouldRun({ runtime, message, state, options: {} } as any),
    ).toBe(true);
    const legacy = await approvalRequiredEvaluator.handler(runtime, message, {
      lastActionResult: { data: { status: "pending_approval" } },
    } as any);
    expect(legacy).toMatchObject({ data: { pendingApproval: true } });
  });

  it("does not run when Steward is disconnected", async () => {
    const runtime = makeRuntime(false);
    runtime.getActionResults = () => [{ success: true, data: { status: "pending_approval" } }];
    expect(
      await approvalRequiredEvaluator.shouldRun({
        runtime,
        message,
        options: {},
      } as any),
    ).toBe(false);
  });
});
