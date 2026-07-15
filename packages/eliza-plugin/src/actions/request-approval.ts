import type {
  Action,
  ActionResult,
  HandlerOptions,
  IAgentRuntime,
  Memory,
  State,
} from "@elizaos/core";
import type { StewardService } from "../services/StewardService.js";

export const requestApprovalAction: Action = {
  name: "STEWARD_REQUEST_APPROVAL",
  description: "Check and surface a Steward pending proxy approval to an operator",
  similes: ["request approval", "check pending request", "approval status"],
  parameters: [
    {
      name: "id",
      description: "Pending proxy request ID",
      required: true,
      schema: { type: "string" },
    },
  ],
  examples: [],
  async validate(runtime: IAgentRuntime): Promise<boolean> {
    return (runtime.getService("steward" as any) as StewardService | null)?.isConnected() ?? false;
  },
  async handler(
    runtime: IAgentRuntime,
    _message: Memory,
    _state?: State,
    options?: HandlerOptions,
  ): Promise<ActionResult> {
    const id = options?.parameters?.id;
    if (typeof id !== "string")
      return { success: false, error: "id is required", text: "Provide the pending request ID." };
    try {
      const pending = await (
        runtime.getService("steward" as any) as StewardService
      ).getPendingProxyRequest(id);
      return {
        success: true,
        text: `Proxy request ${id} is ${pending.status}. ${pending.status === "pending" ? "An owner or admin must approve it before it can be forwarded." : ""}`.trim(),
        data: { pending },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message, text: `Could not check approval: ${message}` };
    }
  },
};
