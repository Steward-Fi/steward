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
const MAX_AMOUNT_TEXT_LENGTH = 128;
const MAX_UINT256 = (1n << 256n) - 1n;

/**
 * Parse a human-readable amount like "0.1 ETH" or "50 USDC" into wei.
 * For now we only handle native token amounts (ETH/BNB).
 * ERC-20 transfers would need contract interaction — future work.
 */
function parseAmount(amountStr: string): { valueWei: string; symbol: string | null } {
  const cleaned = amountStr.trim();
  if (cleaned.length === 0 || cleaned.length > MAX_AMOUNT_TEXT_LENGTH) {
    throw new Error("Amount must be a bounded positive decimal");
  }
  let cursor = 0;
  let sawDigit = false;
  let sawDot = false;
  let dotIndex = -1;
  while (cursor < cleaned.length) {
    const code = cleaned.charCodeAt(cursor);
    if (code >= 0x30 && code <= 0x39) {
      sawDigit = true;
      cursor += 1;
      continue;
    }
    if (code === 0x2e && !sawDot) {
      sawDot = true;
      dotIndex = cursor;
      cursor += 1;
      continue;
    }
    break;
  }
  const numberText = cleaned.slice(0, cursor);
  while (cursor < cleaned.length && cleaned[cursor].trim().length === 0) cursor += 1;
  const symbolStart = cursor;
  while (cursor < cleaned.length) {
    const code = cleaned.charCodeAt(cursor);
    if (
      (code >= 0x30 && code <= 0x39) ||
      (code >= 0x41 && code <= 0x5a) ||
      (code >= 0x61 && code <= 0x7a) ||
      code === 0x5f
    ) {
      cursor += 1;
      continue;
    }
    break;
  }
  if (!sawDigit || cursor !== cleaned.length) {
    throw new Error('Could not parse amount. Expected format like "0.1 ETH"');
  }

  const symbolText = cleaned.slice(symbolStart);
  const symbol = symbolText.length === 0 ? null : symbolText.toUpperCase();
  const whole = dotIndex === -1 ? numberText : numberText.slice(0, dotIndex);
  const fraction = dotIndex === -1 ? "" : numberText.slice(dotIndex + 1);
  if (fraction.length > 18) {
    throw new Error("Amount supports at most 18 decimal places");
  }
  const wei = BigInt(whole || "0") * 10n ** 18n + BigInt((fraction || "0").padEnd(18, "0"));
  if (wei <= 0n || wei > MAX_UINT256) throw new Error("Amount is outside the supported range");
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
  description: "Send tokens to an address using the Steward-managed wallet",
  similes: ["send tokens", "transfer", "send ETH", "send SOL", "send BNB", "pay", "wire"],

  parameters: [
    {
      name: "to",
      description: "Recipient address (0x… for EVM, base58 for Solana) or ENS name",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "amount",
      description: 'Native-token amount (e.g. "0.1 ETH", "0.5 BNB")',
      required: true,
      schema: { type: "string" },
    },
    {
      name: "chain",
      description: "Target chain name (base, ethereum, bsc, gnosis)",
      required: false,
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
    _message: Memory,
    _state?: State,
    options?: HandlerOptions,
  ): Promise<ActionResult> {
    const steward = runtime.getService("steward" as any) as StewardService;
    const params = options?.parameters;

    if (!params?.to || !params?.amount) {
      return {
        success: false,
        error: "Missing required parameters: 'to' and 'amount'",
        text: "I need a recipient address and an amount to send. Example: send 0.01 ETH to 0x…",
      };
    }

    try {
      const chainName = (params.chain as string) ?? "base";
      const chainId = CHAIN_IDS[chainName.toLowerCase()];

      if (!chainId) {
        return {
          success: false,
          error: `Unknown chain: ${chainName}`,
          text: `I don't recognize the chain "${chainName}". Supported: ${Object.keys(CHAIN_IDS).join(", ")}`,
        };
      }
      const { valueWei, symbol } = parseAmount(params.amount as string);
      const expectedSymbol = NATIVE_SYMBOLS[chainName.toLowerCase()];
      if (symbol !== null && symbol !== expectedSymbol) {
        return {
          success: false,
          error: `Only the native ${expectedSymbol} asset is supported on ${chainName}`,
          text: `This action only supports native ${expectedSymbol} transfers on ${chainName}; ERC-20 transfers require a governed token-transfer action.`,
        };
      }

      const result = await steward.signTransaction({
        to: params.to as string,
        value: valueWei,
        chainId,
      });

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
