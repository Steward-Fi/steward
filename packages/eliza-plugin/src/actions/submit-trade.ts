import type {
  Action,
  ActionExample,
  ActionResult,
  HandlerOptions,
  IAgentRuntime,
  Memory,
  State,
} from "@elizaos/core";
import type { StewardService } from "../services/StewardService.js";

export const submitTradeAction: Action = {
  name: "STEWARD_SUBMIT_TRADE",
  description: "Submit a Hyperliquid BTC or ETH perp order through Steward trade sessions",
  similes: ["submit trade", "place perp order", "trade hyperliquid"],
  parameters: [
    {
      name: "sessionId",
      description: "Active Steward trade session id",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "asset",
      description: "BTC or ETH",
      required: true,
      schema: { type: "string", enum: ["BTC", "ETH"] },
    },
    {
      name: "side",
      description: "buy or sell",
      required: true,
      schema: { type: "string", enum: ["buy", "sell"] },
    },
    {
      name: "size",
      description: "Order size in USD for MVP policy accounting",
      required: true,
      schema: { type: "number" },
    },
    {
      name: "leverage",
      description: "Leverage, max 2",
      required: true,
      schema: { type: "number" },
    },
    {
      name: "reduceOnly",
      description: "Whether the order may only reduce exposure",
      required: false,
      schema: { type: "boolean" },
    },
  ],
  examples: [
    [
      {
        name: "{{user1}}",
        content: {
          text: "Buy $25 BTC perp at 2x using session ses_123",
          action: "STEWARD_SUBMIT_TRADE",
        },
      },
    ],
  ] as ActionExample[][],

  async validate(runtime: IAgentRuntime, _message: Memory, _state?: State): Promise<boolean> {
    const steward = runtime.getService("steward" as any) as StewardService | null;
    return steward?.isConnected() ?? false;
  },

  async handler(
    runtime: IAgentRuntime,
    _message: Memory,
    _state?: State,
    options?: HandlerOptions,
  ): Promise<ActionResult> {
    const steward = runtime.getService("steward" as any) as StewardService | null;
    if (!steward?.isConnected()) {
      return {
        success: false,
        error: "Steward SDK is not configured",
        text: "Trading is unavailable because Steward is not configured for this agent.",
      };
    }

    const params = options?.parameters ?? {};
    if (!params.sessionId || !params.asset || !params.side || !params.size || !params.leverage) {
      return {
        success: false,
        error: "Missing required trade parameters",
        text: "I need sessionId, asset, side, size, and leverage to submit a trade.",
      };
    }

    try {
      const result = await steward.submitHyperliquidOrder({
        sessionId: String(params.sessionId),
        asset: params.asset as "BTC" | "ETH",
        side: params.side as "buy" | "sell",
        size: Number(params.size),
        leverage: Number(params.leverage),
        reduceOnly: Boolean(params.reduceOnly),
      });
      return {
        success: true,
        text: `Hyperliquid order submitted. Status: ${result.status}. Order: ${result.orderId}`,
        data: result as any,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: msg,
        text: `Trade was not submitted: ${msg}`,
      };
    }
  },
};
