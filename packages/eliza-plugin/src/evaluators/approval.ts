import type { ActionResult, Evaluator, IAgentRuntime, Memory, State } from "@elizaos/core";
import type { StewardService } from "../services/StewardService.js";

const APPROVAL_TEXT = "A transaction is awaiting your approval in the Steward dashboard.";

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function isPendingApproval(result: unknown): boolean {
  const data = asRecord(asRecord(result)?.data);
  return data?.status === "pending_approval";
}

/**
 * Find a Steward action result from this turn that is waiting on a human.
 * Looks at the current core's per-message action results, then the state's
 * action results, then the legacy `state.lastActionResult` slot.
 */
export function findPendingApproval(
  runtime: IAgentRuntime | undefined,
  message: Memory | undefined,
  state?: State,
): ActionResult | null {
  const candidates: unknown[] = [];
  const getActionResults = (runtime as { getActionResults?: (id: string) => unknown[] })
    ?.getActionResults;
  if (typeof getActionResults === "function" && typeof message?.id === "string") {
    try {
      const results = getActionResults.call(runtime, message.id);
      if (Array.isArray(results)) candidates.push(...results);
    } catch {
      // older cores do not track per-message results
    }
  }
  const stateData = asRecord(asRecord(state)?.data);
  if (Array.isArray(stateData?.actionResults)) candidates.push(...stateData.actionResults);
  const legacy = asRecord(state)?.lastActionResult;
  if (legacy) candidates.push(legacy);

  for (const candidate of candidates) {
    if (isPendingApproval(candidate)) return candidate as ActionResult;
  }
  return null;
}

function stewardConnected(runtime: IAgentRuntime | undefined): boolean {
  const steward = runtime?.getService?.("steward" as any) as StewardService | null | undefined;
  return steward?.isConnected?.() === true;
}

function approvalResult(pending: ActionResult): ActionResult {
  const data = asRecord(pending.data) ?? {};
  return {
    success: true,
    text: APPROVAL_TEXT,
    data: {
      pendingApproval: true,
      policies: (data.policies ?? null) as any,
    },
  };
}

/**
 * Post-turn evaluator for Steward transactions awaiting manual approval.
 *
 * elizaOS core 2.0.x runs evaluators through `shouldRun` / `prompt` /
 * `processors` with a JSON `schema`. Older alpha cores call `validate` /
 * `handler`. This object carries both shapes so the plugin registers cleanly on
 * either line. On 2.0.x it only activates on turns where a Steward action
 * returned `pending_approval`, so it adds nothing to ordinary turns.
 */
const evaluator = {
  name: "approvalRequired",
  description: "Checks if the last transaction is pending manual approval and adjusts response",
  priority: 200,

  // core 2.0.x contract
  schema: {
    type: "object",
    properties: {
      acknowledged: { type: "boolean" },
    },
    required: ["acknowledged"],
  },
  async shouldRun(context: { runtime: IAgentRuntime; message: Memory; state?: State }) {
    if (!stewardConnected(context.runtime)) return false;
    return findPendingApproval(context.runtime, context.message, context.state) !== null;
  },
  async prepare(context: { runtime: IAgentRuntime; message: Memory; state?: State }) {
    return { pending: findPendingApproval(context.runtime, context.message, context.state) };
  },
  prompt() {
    return [
      "A Steward wallet action in this turn is waiting for a human to approve it in the Steward dashboard.",
      "Nothing has been signed or sent yet.",
      'Return {"acknowledged": true}.',
    ].join("\n");
  },
  parse(output: unknown) {
    return asRecord(output) ?? { acknowledged: true };
  },
  processors: [
    {
      name: "stewardApprovalNotice",
      async process(context: { prepared: { pending: ActionResult | null } | undefined }) {
        const pending = context.prepared?.pending;
        if (!pending) return undefined;
        console.info("[Steward] Transaction pending approval, user action required");
        return approvalResult(pending);
      },
    },
  ],

  // legacy alpha contract
  alwaysRun: false,
  examples: [],
  async validate(_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean> {
    const action = (message?.content as any)?.action;
    return typeof action === "string" && action.startsWith("STEWARD_");
  },
  async handler(
    runtime: IAgentRuntime,
    message: Memory,
    state?: State,
  ): Promise<ActionResult | undefined> {
    if (!stewardConnected(runtime)) return undefined;
    const pending = findPendingApproval(runtime, message, state);
    if (!pending) return undefined;
    console.info("[Steward] Transaction pending approval, user action required");
    return approvalResult(pending);
  },
};

export const approvalRequiredEvaluator = evaluator as unknown as Evaluator & typeof evaluator;
