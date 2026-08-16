import type { IAgentRuntime, Memory, Provider, ProviderResult, State } from "@elizaos/core";
import type { StewardService } from "../services/StewardService.js";

export const providerActionsProvider: Provider = {
  name: "stewardProviderActions",
  description: "Lifecycle state for provider actions invoked by this Steward agent",
  async get(runtime: IAgentRuntime, _message: Memory, _state: State): Promise<ProviderResult> {
    const steward = runtime.getService("steward" as any) as StewardService | null;
    if (!steward?.isConnected()) return { text: "", data: {} };
    try {
      const actions = await steward.listTrackedProviderActions();
      return {
        text: actions.length
          ? `Steward provider actions:\n${actions
              .map((action) => `- ${action.id}: ${action.status} (case ${action.id})`)
              .join("\n")}`
          : "No provider actions have been invoked by this agent in this runtime.",
        data: {
          providerActions: actions as any,
          // The case id is the action id. Detailed case/evidence reads remain
          // human/MFA-gated and are intentionally not fetched by this provider.
          caseStates: actions.map((action) => ({
            caseId: action.id,
            status: action.status,
          })) as any,
        },
      };
    } catch {
      return { text: "", data: {} };
    }
  },
};
