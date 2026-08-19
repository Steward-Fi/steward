import { existsSync, readFileSync } from "node:fs";
import type {
  Action,
  ActionExample,
  ActionResult,
  HandlerCallback,
  HandlerOptions,
  IAgentRuntime,
  Memory,
  State,
} from "@elizaos/core";
import { assertSecureApiUrl } from "../services/StewardService.js";

const ACTION_NAME = "SUBMIT_TRADE";
const DEFAULT_LEVERAGE = 1;
const STEWARD_REQUEST_TIMEOUT_MS = 10_000;
const MAX_STEWARD_RESPONSE_BYTES = 1024 * 1024;

type Coin = "BTC" | "ETH";
type Side = "buy" | "sell";

interface ParsedTrade {
  coin: Coin;
  side: Side;
  size: number;
  leverage: number;
  sessionId: string;
  limitPx?: number;
  reduceOnly?: boolean;
}

interface StewardOrderResponse {
  orderId?: string;
  status?: string;
  filledQty?: number;
  avgPrice?: number;
  txHash?: string | null;
  [key: string]: unknown;
}

interface StewardErrorResponse {
  code?: string;
  reason?: string;
  error?: string;
  message?: string;
  [key: string]: unknown;
}

function optionParameters(
  options?: HandlerOptions | Record<string, unknown>,
): Record<string, unknown> {
  const maybe = options as { parameters?: Record<string, unknown> } | undefined;
  return maybe?.parameters ?? {};
}

function messageText(message: Memory): string {
  const content = message.content as { text?: unknown } | undefined;
  return typeof content?.text === "string" ? content.text : "";
}

function envValue(runtime: IAgentRuntime, key: string): string | undefined {
  const runtimeWithGetSetting = runtime as IAgentRuntime & {
    getSetting?: (name: string) => string | undefined;
  };
  const setting = runtimeWithGetSetting.getSetting?.(key);
  if (typeof setting === "string" && setting.trim()) return setting.trim();
  const value = process.env[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stewardJwt(runtime: IAgentRuntime): string | undefined {
  const file = envValue(runtime, "STEWARD_JWT_FILE");
  if (file && existsSync(file)) {
    const value = readFileSync(file, "utf8").trim();
    if (value) return value;
  }
  return envValue(runtime, "STEWARD_JWT");
}

function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}

function stewardApiUrl(runtime: IAgentRuntime): string | undefined {
  const configuredUrl = envValue(runtime, "STEWARD_API_URL");
  const apiUrl = configuredUrl ? stripTrailingSlashes(configuredUrl) : undefined;
  // Reject plaintext non-localhost URLs here too: this action reads the env URL
  // directly and would otherwise send the agent JWT in cleartext.
  if (apiUrl) assertSecureApiUrl(apiUrl);
  return apiUrl;
}

function configuredSessionId(runtime: IAgentRuntime): string | undefined {
  return (
    envValue(runtime, "STEWARD_TRADE_SESSION_ID") ??
    envValue(runtime, "STEWARD_SESSION_ID") ??
    envValue(runtime, "TRADE_SESSION_ID")
  );
}

function parseNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value.replace(/[$,]/g, ""));
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function parseBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/^(true|yes|1)$/i.test(value)) return true;
    if (/^(false|no|0)$/i.test(value)) return false;
  }
  return undefined;
}

function parseSide(text: string, rawSide?: unknown): Side | undefined {
  if (typeof rawSide === "string") {
    if (/^(buy|long)$/i.test(rawSide)) return "buy";
    if (/^(sell|short)$/i.test(rawSide)) return "sell";
  }
  if (/\b(buy|long)\b/i.test(text)) return "buy";
  if (/\b(sell|short)\b/i.test(text)) return "sell";
  return undefined;
}

function parseCoin(text: string, rawCoin?: unknown): Coin | undefined {
  const value = typeof rawCoin === "string" ? rawCoin : undefined;
  const source = `${value ?? ""} ${text}`;
  if (/\bBTC\b|\bbitcoin\b/i.test(source)) return "BTC";
  if (/\bETH\b|\bethereum\b/i.test(source)) return "ETH";
  return undefined;
}

function parseSize(text: string, params: Record<string, unknown>, coin?: Coin): number | undefined {
  const explicit = parseNumber(params.size ?? params.amount ?? params.qty ?? params.quantity);
  if (explicit !== undefined) return explicit;

  if (coin) {
    const beforeCoin = new RegExp(
      `(?:^|\\s)([$]?[0-9][0-9_,]*(?:\\.[0-9]+)?)\\s*${coin}\\b`,
      "i",
    ).exec(text);
    if (beforeCoin?.[1]) return parseNumber(beforeCoin[1]);
  }

  const firstNumber = /(?:^|\s)([$]?[0-9][0-9_,]*(?:\.[0-9]+)?)(?=\s|$)/.exec(text);
  return firstNumber?.[1] ? parseNumber(firstNumber[1]) : undefined;
}

function parseLimitPx(text: string, params: Record<string, unknown>): number | undefined {
  const explicit = parseNumber(params.limitPx ?? params.limitPrice ?? params.price);
  if (explicit !== undefined) return explicit;
  const match = /(?:limit(?:\s*(?:price|px))?|at|@)\s*[$]?([0-9][0-9_,]*(?:\.[0-9]+)?)/i.exec(text);
  return match?.[1] ? parseNumber(match[1]) : undefined;
}

function parseLeverage(text: string, params: Record<string, unknown>): number {
  const explicit = parseNumber(params.leverage);
  if (explicit !== undefined) return explicit;
  const match = /\b([0-9]+(?:\.[0-9]+)?)\s*x\b/i.exec(text);
  return match?.[1] ? (parseNumber(match[1]) ?? DEFAULT_LEVERAGE) : DEFAULT_LEVERAGE;
}

export function parseSubmitTrade(
  message: Memory,
  options?: HandlerOptions | Record<string, unknown>,
  runtime?: IAgentRuntime,
): ParsedTrade | null {
  const text = messageText(message);
  const params = optionParameters(options);
  const coin = parseCoin(text, params.coin ?? params.asset);
  const side = parseSide(text, params.side);
  const size = parseSize(text, params, coin);
  const sessionId =
    (typeof params.sessionId === "string" && params.sessionId.trim()) ||
    (runtime ? configuredSessionId(runtime) : undefined);

  if (!coin || !side || size === undefined || !Number.isFinite(size) || size <= 0 || !sessionId) {
    return null;
  }

  return {
    coin,
    side,
    size,
    leverage: parseLeverage(text, params),
    sessionId,
    limitPx: parseLimitPx(text, params),
    reduceOnly: parseBoolean(params.reduceOnly) ?? /\b(reduce[- ]?only|close)\b/i.test(text),
  };
}

async function readResponseText(response: Response, signal: AbortSignal): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
      void response.body?.cancel().catch(() => undefined);
      throw new Error("Invalid Steward response length");
    }
    if (parsedLength > MAX_STEWARD_RESPONSE_BYTES) {
      void response.body?.cancel().catch(() => undefined);
      throw new Error("Steward response exceeded size limit");
    }
  }

  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let rejectAborted: (reason: Error) => void = () => {};
  const aborted = new Promise<never>((_, reject) => {
    rejectAborted = reject;
  });
  const onAbort = () => {
    void reader.cancel().catch(() => undefined);
    rejectAborted(new Error("Steward request timed out"));
  };
  signal.addEventListener("abort", onAbort, { once: true });
  if (signal.aborted) onAbort();
  try {
    while (true) {
      const result = await Promise.race([reader.read(), aborted]);
      if (result.done) break;
      if (!result.value) continue;
      totalBytes += result.value.byteLength;
      if (totalBytes > MAX_STEWARD_RESPONSE_BYTES) {
        void reader.cancel().catch(() => undefined);
        throw new Error("Steward response exceeded size limit");
      }
      chunks.push(result.value);
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("Steward response was not valid UTF-8");
  }
}

async function parseResponseJson(response: Response, signal: AbortSignal): Promise<unknown> {
  const text = await readResponseText(response, signal);
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

async function fetchStewardJson(
  url: string,
  init: RequestInit,
): Promise<{ status: number; ok: boolean; data: unknown }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), STEWARD_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      ...init,
      redirect: "error",
      signal: controller.signal,
    });
    const data = await parseResponseJson(response, controller.signal);
    // cancel() may resolve an outstanding reader.read() with { done: true }
    // before the abort rejection wins Promise.race. Preserve the deadline as
    // the outcome even in that ordering instead of accepting a partial body.
    if (controller.signal.aborted) throw new Error("Steward request timed out");
    return { status: response.status, ok: response.ok, data };
  } catch {
    throw new Error(
      controller.signal.aborted ? "Steward request timed out" : "Steward request failed",
    );
  } finally {
    clearTimeout(timeout);
  }
}

function unwrapOrderResponse(data: unknown): StewardOrderResponse {
  if (data && typeof data === "object" && "data" in data) {
    return ((data as { data?: unknown }).data ?? {}) as StewardOrderResponse;
  }
  return (data ?? {}) as StewardOrderResponse;
}

function policyReason(data: unknown): string {
  const error = (data ?? {}) as StewardErrorResponse;
  return error.reason ?? error.error ?? error.message ?? "order violates trading policy";
}

function confirmation(parsed: ParsedTrade, order: StewardOrderResponse): string {
  const direction = parsed.side === "buy" ? "long" : "short";
  const px = parsed.limitPx ? ` limit ${parsed.limitPx}` : " at market";
  const orderId = order.orderId ?? "unknown";
  return `submitted: ${direction} ${parsed.size} ${parsed.coin}${px} via hyperliquid. order id ${orderId}.`;
}

async function postOrder(
  runtime: IAgentRuntime,
  parsed: ParsedTrade,
): Promise<{ status: number; data: unknown }> {
  const apiUrl = stewardApiUrl(runtime);
  const jwt = stewardJwt(runtime);
  if (!apiUrl || !jwt) {
    throw new Error("STEWARD_API_URL and STEWARD_JWT are required");
  }

  const idempotencyKey = crypto.randomUUID();
  const response = await fetchStewardJson(`${apiUrl}/v1/trade/hyperliquid/order`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      sessionId: parsed.sessionId,
      coin: parsed.coin,
      side: parsed.side,
      size: parsed.size,
      leverage: parsed.leverage,
      limitPx: parsed.limitPx,
      reduceOnly: parsed.reduceOnly ?? false,
      idempotencyKey,
    }),
  });
  return { status: response.status, data: response.data };
}

async function hasActiveSession(runtime: IAgentRuntime): Promise<boolean> {
  let apiUrl: string | undefined;
  try {
    apiUrl = stewardApiUrl(runtime);
  } catch {
    return false;
  }
  const jwt = stewardJwt(runtime);
  const sessionId = configuredSessionId(runtime);
  if (!apiUrl || !jwt || !sessionId) return false;

  try {
    const response = await fetchStewardJson(
      `${apiUrl}/v1/trade/sessions/${encodeURIComponent(sessionId)}`,
      {
        headers: { Authorization: `Bearer ${jwt}`, Accept: "application/json" },
      },
    );
    if (!response.ok) return false;
    const data = response.data;
    const session =
      data && typeof data === "object" && "data" in data
        ? (data as { data?: Record<string, unknown> }).data
        : data;
    return (
      !!session &&
      typeof session === "object" &&
      (session as { status?: unknown }).status === "active"
    );
  } catch {
    return false;
  }
}

export const submitTradeAction: Action = {
  name: ACTION_NAME,
  description:
    "Submit a perp order via Steward custodial. Requires active trade session. Subject to policy: $/day cap, allowed assets, leverage cap.",
  similes: ["buy", "sell", "long", "short", "perp", "trade"],
  parameters: [
    {
      name: "coin",
      description: "Perp market coin, BTC or ETH",
      required: false,
      schema: { type: "string", enum: ["BTC", "ETH"] },
    },
    {
      name: "side",
      description: "buy/long or sell/short",
      required: false,
      schema: { type: "string", enum: ["buy", "sell", "long", "short"] },
    },
    {
      name: "size",
      description: "Order size in base coin units",
      required: false,
      schema: { type: "number" },
    },
    {
      name: "limitPx",
      description: "Optional Hyperliquid limit price. Omit for market order.",
      required: false,
      schema: { type: "number" },
    },
    {
      name: "leverage",
      description: "Order leverage, max 2x by Phase 1 policy",
      required: false,
      schema: { type: "number", default: DEFAULT_LEVERAGE },
    },
    {
      name: "reduceOnly",
      description: "Whether the order may only reduce exposure",
      required: false,
      schema: { type: "boolean" },
    },
    {
      name: "sessionId",
      description: "Active Steward trade session id. Defaults to STEWARD_TRADE_SESSION_ID.",
      required: false,
      schema: { type: "string" },
    },
  ],
  examples: [
    [
      { name: "{{user1}}", content: { text: "buy 0.01 BTC long" } },
      {
        name: "{{agent}}",
        content: {
          text: "submitted: long 0.01 BTC at market via hyperliquid. order id <id>.",
          action: ACTION_NAME,
        },
      },
    ],
    [
      { name: "{{user1}}", content: { text: "sell 0.02 ETH short" } },
      {
        name: "{{agent}}",
        content: {
          text: "submitted: short 0.02 ETH at market via hyperliquid. order id <id>.",
          action: ACTION_NAME,
        },
      },
    ],
    [
      { name: "{{user1}}", content: { text: "buy 0.01 BTC limit 65000" } },
      {
        name: "{{agent}}",
        content: {
          text: "submitted: long 0.01 BTC limit 65000 via hyperliquid. order id <id>.",
          action: ACTION_NAME,
        },
      },
    ],
    [
      { name: "{{user1}}", content: { text: "buy 2 BTC long 10x" } },
      {
        name: "{{agent}}",
        content: {
          text: "policy rejected: leverage-cap: leverage 10 exceeds max 2.",
          action: ACTION_NAME,
        },
      },
    ],
    [
      { name: "{{user1}}", content: { text: "long 0.01 BTC" } },
      {
        name: "{{agent}}",
        content: {
          text: "venue error, will retry later",
          action: ACTION_NAME,
        },
      },
    ],
  ] as ActionExample[][],

  async validate(runtime: IAgentRuntime, _message: Memory, _state?: State): Promise<boolean> {
    return hasActiveSession(runtime);
  },

  async handler(
    runtime: IAgentRuntime,
    message: Memory,
    _state?: State,
    options?: HandlerOptions | Record<string, unknown>,
    callback?: HandlerCallback,
  ): Promise<ActionResult> {
    const parsed = parseSubmitTrade(message, options, runtime);
    if (!parsed) {
      const text =
        "I need coin, side, size, and an active Steward trade session to submit a trade.";
      await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
      return { success: false, error: "Missing required trade fields", text };
    }

    let status: number;
    let data: unknown;
    try {
      const result = await postOrder(runtime, parsed);
      status = result.status;
      data = result.data;
    } catch (err) {
      const text =
        err instanceof Error && /STEWARD_API_URL|STEWARD_JWT|apiUrl/.test(err.message)
          ? "Trading is unavailable because Steward JWT/API env is not configured."
          : "venue error, will retry later";
      await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
      return { success: false, error: err instanceof Error ? err.message : String(err), text };
    }

    if (status >= 200 && status < 300) {
      const order = unwrapOrderResponse(data);
      const text = confirmation(parsed, order);
      await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
      return { success: true, text, data: order as any };
    }

    if (status === 400) {
      const reason = policyReason(data);
      const text = `policy rejected: ${reason}`;
      await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
      return { success: false, error: reason, text, data: data as any };
    }

    if (status === 401) {
      const text = "session expired or invalid, ask shadow to refresh";
      await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
      return { success: false, error: "unauthorized", text };
    }

    if (status >= 500) {
      const text = "venue error, will retry later";
      await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
      return { success: false, error: `steward ${status}`, text };
    }

    const reason = policyReason(data);
    const text = `Trade was not submitted: ${reason}`;
    await callback?.({ text, action: ACTION_NAME }, ACTION_NAME);
    return { success: false, error: reason, text, data: data as any };
  },
};
