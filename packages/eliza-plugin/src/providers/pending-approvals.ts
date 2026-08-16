import type { IAgentRuntime, Memory, Provider, ProviderResult, State } from "@elizaos/core";
import type { StewardService } from "../services/StewardService.js";

export const pendingApprovalsProvider: Provider = {
  name: "stewardPendingApprovals",
  description: "Approval-gated API requests currently visible to this Steward agent",
  async get(runtime: IAgentRuntime, _message: Memory, _state: State): Promise<ProviderResult> {
    const steward = runtime.getService("steward" as any) as StewardService | null;
    if (!steward?.isConnected()) return { text: "", data: {} };
    try {
      const requests = (await steward.listPendingProxyRequests()).filter(
        (item) =>
          item.status === "pending" || item.status === "approved" || item.status === "executing",
      );
      return {
        text: requests.length
          ? `Steward pending API approvals:\n${requests.map((item) => `- ${item.id}: ${item.method} ${item.targetHost}${item.targetPath} [${item.status}]`).join("\n")}`
          : "No pending Steward API approvals.",
        data: { pendingProxyRequests: requests as any },
      };
    } catch {
      return { text: "", data: {} };
    }
  },
};
