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
              .map((entry) => {
                if (entry.polling === "ok") {
                  return `- ${entry.action.id}: ${entry.action.status} (binding v${entry.action.version})`;
                }
                const retained = entry.lastKnown
                  ? `; last known ${entry.lastKnown.status} (binding v${entry.lastKnown.version})`
                  : "";
                return `- ${entry.id}: status unavailable (polling error${retained})`;
              })
              .join("\n")}`
          : "No provider actions have been invoked by this agent in this runtime.",
        data: {
          providerActions: actions as any,
          bindingStates: actions.map((entry) =>
            entry.polling === "ok"
              ? {
                  id: entry.action.id,
                  status: entry.action.status,
                  version: entry.action.version,
                  operationId: entry.action.operationId,
                  polling: "ok",
                }
              : {
                  id: entry.id,
                  status: entry.lastKnown?.status ?? "unavailable",
                  version: entry.lastKnown?.version,
                  operationId: entry.lastKnown?.operationId,
                  polling: "error",
                },
          ) as any,
        },
      };
    } catch {
      return { text: "", data: {} };
    }
  },
};
