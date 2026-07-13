import type {
  Action,
  ActionResult,
  HandlerOptions,
  IAgentRuntime,
  Memory,
  State,
} from "@elizaos/core";
import type { StewardService } from "../services/StewardService.js";

export const callGovernedApiAction: Action = {
  name: "STEWARD_CALL_GOVERNED_API",
  description:
    "Call an HTTPS API through Steward so credentials stay hidden and approval policy is enforced",
  similes: ["call governed api", "call secure api", "use steward proxy"],
  parameters: [
    {
      name: "url",
      description: "Absolute HTTPS target URL",
      required: true,
      schema: { type: "string" },
    },
    { name: "method", description: "HTTP method", required: false, schema: { type: "string" } },
    { name: "body", description: "JSON request body", required: false, schema: { type: "object" } },
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
    const params = options?.parameters ?? {};
    try {
      if (typeof params.url !== "string")
        return {
          success: false,
          error: "url is required",
          text: "A governed API call needs an HTTPS URL.",
        };
      const result = await (runtime.getService("steward" as any) as StewardService).callGovernedApi(
        {
          url: params.url,
          method: typeof params.method === "string" ? params.method : undefined,
          body: params.body,
        },
      );
      if (result.held) {
        const held = result.data as { id?: string; pollUrl?: string; expiresAt?: string };
        return {
          success: true,
          text: `Request held for human approval. Pending request: ${held.id ?? "unknown"}. It has not been forwarded.`,
          data: { ...held, held: true },
        };
      }
      return {
        success: result.status >= 200 && result.status < 300,
        text: `Governed API call completed with HTTP ${result.status}.`,
        data: { status: result.status, response: result.data as any },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message, text: `Governed API call failed: ${message}` };
    }
  },
};
