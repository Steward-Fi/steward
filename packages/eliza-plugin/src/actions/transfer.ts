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

/** Known chain name → chainId mapping */
const CHAIN_IDS: Record<string, number> = {
  ethereum: 1,
  base: 8453,
  "base-sepolia": 84532,
  bsc: 56,
  "bsc-testnet": 97,
  gnosis: 100,
};

const NATIVE_SYMBOLS: Record<string, string> = {
  ethereum: "ETH",
  base: "ETH",
  "base-sepolia": "ETH",
  bsc: "BNB",
  "bsc-testnet": "BNB",
  gnosis: "XDAI",
};

/**
 * Parse a human-readable native-token amount such as "0.1 ETH" into wei.
 * This action supports native ETH/BNB transfers only; token-contract transfers
 * are outside this action's contract and must use an ERC-20-aware integration.
 */
export function parseNativeAmount(amountStr: string): { valueWei: string; symbol: string } {
  const cleaned = amountStr.trim();
  const match = cleaned.match(/^(0|[1-9]\d*)(?:\.(\d{1,18}))?\s+([a-zA-Z]+)$/);
  if (!match) {
    throw new Error(`Could not parse amount: "${amountStr}". Expected format like "0.1 ETH"`);
  }

  const whole = BigInt(match[1]);
  const fractional = (match[2] ?? "").padEnd(18, "0");
  const symbol = match[3].toUpperCase();
  const wei = whole * 10n ** 18n + BigInt(fractional || "0");
  if (wei <= 0n) throw new Error("Amount must be greater than zero");
  return { valueWei: wei.toString(), symbol };
}

/**
 * STEWARD_TRANSFER — high-level "send X tokens to Y" action.
 *
 * This is the human-friendly interface. The LLM can invoke it from
 * natural language like "send 0.05 ETH to 0xabc…". It parses the
 * amount, resolves the chain, and delegates to StewardService.signTransaction.
 */
export const transferAction: Action = {
  name: "STEWARD_TRANSFER",
  description: "Send a chain's native EVM asset using the Steward-managed wallet",
  similes: ["send native tokens", "transfer", "send ETH", "send BNB", "pay", "wire"],

  parameters: [
    {
      name: "to",
      description: "Recipient EVM address (0x…)",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "amount",
      description: 'Native-asset amount with an explicit symbol (e.g. "0.1 ETH", "0.5 BNB")',
      required: true,
      schema: { type: "string" },
    },
    {
      name: "chain",
      description: "Target chain name (base, ethereum, bsc, gnosis)",
      required: true,
      schema: {
        type: "string",
        enum: ["base", "ethereum", "bsc", "gnosis", "base-sepolia", "bsc-testnet"],
      },
    },
  ],

  examples: [
    [
      {
        name: "{{user1}}",
        content: {
          text: "Send 0.01 ETH to 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 on Base",
          action: "STEWARD_TRANSFER",
        },
      },
    ],
    [
      {
        name: "{{user1}}",
        content: {
          text: "Transfer 0.5 BNB to 0x1234567890abcdef1234567890abcdef12345678",
          action: "STEWARD_TRANSFER",
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
    message: Memory,
    _state?: State,
    options?: HandlerOptions,
  ): Promise<ActionResult> {
    const steward = runtime.getService("steward" as any) as StewardService;
    const params = options?.parameters;

    if (!params?.to || !params?.amount || !params?.chain) {
      return {
        success: false,
        error: "Missing required parameters: 'to', 'amount', and 'chain'",
        text: "I need a recipient, native-asset amount, and explicit chain. Example: send 0.01 ETH to 0x… on Base.",
      };
    }

    try {
      const { valueWei, symbol } = parseNativeAmount(params.amount as string);
      const chainName = params.chain as string;
      const chainId = CHAIN_IDS[chainName.toLowerCase()];

      if (!chainId) {
        return {
          success: false,
          error: `Unknown chain: ${chainName}`,
          text: `I don't recognize the chain "${chainName}". Supported: ${Object.keys(CHAIN_IDS).join(", ")}`,
        };
      }

      const expectedSymbol = NATIVE_SYMBOLS[chainName.toLowerCase()];
      if (symbol !== expectedSymbol) {
        return {
          success: false,
          error: `${chainName} transfers require the native symbol ${expectedSymbol}; ${symbol} is not supported by this action`,
          text: `I can only send ${expectedSymbol}, the native asset on ${chainName}, with this action.`,
        };
      }

      if (message.id === undefined || String(message.id).length === 0) {
        return {
          success: false,
          error: "A stable message id is required to submit a transfer safely",
        };
      }

      const result = await steward.signTransaction(
        {
          to: params.to as string,
          value: valueWei,
          chainId,
        },
        { idempotencyKey: `eliza-transfer:${String(message.id)}` },
      );

      if ("txHash" in result) {
        return {
          success: true,
          text: `Sent ${params.amount} to ${params.to}. Transaction hash: ${result.txHash}`,
          data: {
            txHash: result.txHash,
            amount: params.amount as string,
            to: params.to as string,
          },
        };
      }

      if ("status" in result && result.status === "pending_approval") {
        return {
          success: true,
          text: `Transfer of ${params.amount} to ${params.to} requires manual approval. The wallet owner needs to approve this transaction.`,
          data: {
            status: "pending_approval",
            amount: params.amount as string,
            to: params.to as string,
            policies: result.results as any,
          },
        };
      }

      return {
        success: false,
        error: "Unexpected response from Steward",
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: msg,
        text: `Transfer failed: ${msg}`,
      };
    }
  },
};
