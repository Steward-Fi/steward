import { createHash } from "node:crypto";
import {
  AdapterNotConfiguredError,
  AdapterUnavailableError,
  AdapterValidationError,
  type SwapQuote,
} from "@stwd/adapters";
import { and, eq, intents, sql } from "@stwd/db";
import {
  aggregationLookupFromMap,
  aggregationQueriesForPolicies,
  aggregationQueryKey,
} from "@stwd/policy-engine";
import { getAggregationSnapshot } from "@stwd/redis";
import type { ApiResponse, AppVariables, PolicyRule, SignRequest } from "@stwd/shared";
import { toCaip2 } from "@stwd/shared";
import { TradeSessionManager } from "@stwd/trade-sessions";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import type { StewardAppContext } from "../context";

type PreparedSwapResponse = {
  intentId: string;
  intentHash: string;
  status: PreparedIntentStatus;
  expiresAt: string;
  requestDigest: string;
  quoteId: string;
  quoteHash: string;
  simulation: { ok: true; gasEstimate?: string };
  lifecycle: {
    canExecute: boolean;
    terminal: boolean;
    executionStatus: string | null;
  };
  unsignedIntent: {
    kind: "evm-tx";
    chainId: number;
    to: string;
    value: string;
    data: string;
    owner: string;
    category: "swap";
    provider: string;
  };
};

type PreparedIntentStatus =
  | "prepared"
  | "submitting"
  | "submitted"
  | "rejected"
  | "unknown"
  | "revoked"
  | "expired";

type StoredResponse = {
  status: 200 | 400 | 403 | 404 | 409 | 500 | 503;
  body: ApiResponse<PreparedSwapResponse> | ApiResponse | { code: string; reason: string };
};

type RejectedPreparePayload = {
  kind: "evm-swap-prepare-rejection";
  requestDigest: string;
  replay: StoredResponse;
};

type InflightIdempotencyEntry = {
  requestDigest: string;
  promise: Promise<StoredResponse>;
};

const tokenRefSchema = z
  .object({
    address: z.string().regex(/^0x[a-fA-F0-9]{40}$/, "token address must be an EVM address"),
    symbol: z.string().max(32).optional(),
    decimals: z.number().int().min(0).max(36).optional(),
  })
  .strict();

const prepareSwapSchema = z
  .object({
    agentId: z.string().min(1).max(128),
    sessionId: z.string().min(1).max(128),
    chainId: z.number().int().positive(),
    fromToken: tokenRefSchema,
    toToken: tokenRefSchema,
    amount: z.string().regex(/^\d+$/, "amount must be a decimal base-unit string").max(80),
    slippageBps: z.number().int().min(0).max(10_000).optional(),
  })
  .strict();

const evmAddressRe = /^0x[a-fA-F0-9]{40}$/;
const calldataRe = /^0x(?:[a-fA-F0-9]{2})+$/;

function normalizeAddress(value: string): string {
  return value.toLowerCase();
}

function isEvmAddress(value: unknown): value is string {
  return typeof value === "string" && evmAddressRe.test(value);
}

function selectorOf(data: string): string | null {
  if (!calldataRe.test(data) || data.length < 10) return null;
  return data.slice(0, 10).toLowerCase();
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`)
    .join(",")}}`;
}

function sha256(value: unknown): string {
  return createHash("sha256").update(stableStringify(value)).digest("hex");
}

function prefixedSha256(value: unknown): string {
  return `sha256:${sha256(value)}`;
}

function quoteHash(quote: SwapQuote): string {
  return prefixedSha256({
    provider: quote.provider,
    quoteId: quote.quoteId,
    chainId: quote.chainId,
    fromToken: normalizeAddress(quote.fromToken.address),
    toToken: normalizeAddress(quote.toToken.address),
    amountIn: quote.amountIn,
    amountOut: quote.amountOut,
    minAmountOut: quote.minAmountOut,
    slippageBps: quote.slippageBps,
    feeAmount: quote.feeAmount ?? null,
    expiresAt: quote.expiresAt,
  });
}

function canonicalIntentHash(
  intent: SignRequest & { owner: string; category: string; provider: string },
  quote: SwapQuote,
): string {
  return prefixedSha256({
    agentId: intent.agentId,
    tenantId: intent.tenantId,
    chainId: intent.chainId,
    owner: normalizeAddress(intent.owner),
    to: normalizeAddress(intent.to),
    value: intent.value,
    data: intent.data ?? "0x",
    category: intent.category,
    provider: intent.provider,
    quote: {
      quoteId: quote.quoteId,
      fromToken: normalizeAddress(quote.fromToken.address),
      toToken: normalizeAddress(quote.toToken.address),
      amountIn: quote.amountIn,
      minAmountOut: quote.minAmountOut,
      expiresAt: quote.expiresAt,
    },
  });
}

function json<T>(
  c: Context<{ Variables: AppVariables }>,
  body: T,
  status: StoredResponse["status"],
): Response {
  return c.json(body, status);
}

function sanitizeIntent(intent: {
  chainId: number;
  to: string;
  value: string;
  data?: string;
  owner: string;
  category: string;
  provider: string;
}) {
  return {
    chainId: intent.chainId,
    target: normalizeAddress(intent.to),
    selector: selectorOf(intent.data ?? "0x"),
    value: intent.value,
    owner: normalizeAddress(intent.owner),
    category: intent.category,
    provider: intent.provider,
  };
}

function rejectReason(message: string): { code: string; reason: string } {
  return { code: "policy-violation", reason: message };
}

type EvmPolicyInput = {
  agentId: string;
  tenantId: string;
  chainId: number;
  owner: string;
  target: string;
  selector: string;
  value: string;
  provider: string;
  category: string;
  quote: SwapQuote;
  intentMetadata?: Record<string, unknown>;
};

function decimalLte(a: string, b: string): boolean {
  return BigInt(a) <= BigInt(b);
}

function selectorMaxNativeValue(entry: Record<string, unknown>, selector: string): string | null {
  const constraints = entry.constraints;
  if (!constraints || typeof constraints !== "object") return null;
  const normalizedSelector = selector.toLowerCase();
  const constraintsBySelector = constraints as Record<string, unknown>;
  const selectorConfig = Object.hasOwn(constraintsBySelector, normalizedSelector)
    ? constraintsBySelector[normalizedSelector]
    : Object.entries(constraintsBySelector).find(
        ([key]) => key.toLowerCase() === normalizedSelector,
      )?.[1];
  if (!selectorConfig || typeof selectorConfig !== "object") return null;
  const value = (selectorConfig as Record<string, unknown>).maxNativeValueWei;
  return typeof value === "string" && /^\d+$/.test(value) ? value : null;
}

export function validateGovernedEvmExecutionPolicy(
  policies: PolicyRule[],
  input: EvmPolicyInput,
): { ok: true } | { ok: false; reason: string } {
  if (policies.length === 0) return { ok: false, reason: "EVM execution policy is required" };
  if (input.category !== "swap") return { ok: false, reason: "adapter category must be swap" };
  if (input.provider !== input.quote.provider) {
    return { ok: false, reason: "adapter provider does not match quote provider" };
  }
  if (input.chainId !== input.quote.chainId) {
    return { ok: false, reason: "intent chain does not match quote chain" };
  }
  if (!isEvmAddress(input.owner)) {
    return { ok: false, reason: "intent owner must be an EVM address" };
  }
  if (!isEvmAddress(input.target)) {
    return { ok: false, reason: "intent target must be an EVM address" };
  }
  if (!/^0x[a-f0-9]{8}$/.test(input.selector)) {
    return { ok: false, reason: "intent calldata must include a 4-byte selector" };
  }
  if (input.quote.expiresAt <= Date.now()) return { ok: false, reason: "quote has expired" };
  if (input.intentMetadata?.quoteId !== input.quote.quoteId) {
    return { ok: false, reason: "intent is not bound to the quote id" };
  }
  if (input.intentMetadata?.amountIn !== input.quote.amountIn) {
    return { ok: false, reason: "intent is not bound to quote amount" };
  }
  if (input.intentMetadata?.minAmountOut !== input.quote.minAmountOut) {
    return { ok: false, reason: "intent is not bound to quote minimum output" };
  }

  const caip2 = toCaip2(input.chainId);
  const hasChain = policies.some(
    (policy) =>
      policy.enabled !== false &&
      policy.type === "allowed-chains" &&
      Array.isArray(policy.config.chains) &&
      caip2 &&
      policy.config.chains.includes(caip2),
  );
  if (!hasChain) return { ok: false, reason: "EVM policy must allowlist the chain" };

  const target = normalizeAddress(input.target);
  const hasContract = policies.some((policy) => {
    if (policy.enabled === false || policy.type !== "contract-allowlist") return false;
    const contracts = policy.config.contracts;
    if (!Array.isArray(contracts)) return false;
    return contracts.some((raw) => {
      if (!raw || typeof raw !== "object") return false;
      const entry = raw as Record<string, unknown>;
      if (typeof entry.address !== "string" || normalizeAddress(entry.address) !== target) {
        return false;
      }
      const selectors = Array.isArray(entry.selectors) ? entry.selectors : [];
      if (!selectors.some((selector) => String(selector).toLowerCase() === input.selector)) {
        return false;
      }
      const maxValue = selectorMaxNativeValue(entry, input.selector);
      return Boolean(maxValue && decimalLte(input.value, maxValue));
    });
  });
  if (!hasContract) {
    return {
      ok: false,
      reason: "EVM policy must allowlist target, selector, and max native value",
    };
  }

  return { ok: true };
}

async function loadConditionSets(
  ctx: StewardAppContext,
  tenantId: string,
  policySet: PolicyRule[],
): Promise<Record<string, string[]>> {
  const conditionPolicies = policySet.filter((policy) => policy.type === "condition-set");
  const ids = [
    ...new Set(
      conditionPolicies
        .map((policy) => policy.config.conditionSetId)
        .filter((id): id is string => typeof id === "string" && id.length > 0),
    ),
  ];
  if (ids.length === 0) return {};
  const { conditionSetItems, conditionSets, and, eq, inArray } = await import("@stwd/db");
  const existing = await ctx.db
    .select({ id: conditionSets.id })
    .from(conditionSets)
    .where(and(eq(conditionSets.tenantId, tenantId), inArray(conditionSets.id, ids)));
  if (existing.length === 0) return {};
  const existingIds = existing.map((row) => row.id);
  const rows = await ctx.db
    .select({ conditionSetId: conditionSetItems.conditionSetId, value: conditionSetItems.value })
    .from(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.tenantId, tenantId),
        inArray(conditionSetItems.conditionSetId, existingIds),
      ),
    );
  const loaded: Record<string, string[]> = {};
  for (const id of existingIds) loaded[id] = [];
  for (const row of rows) loaded[row.conditionSetId].push(row.value);
  return loaded;
}

async function getTransactionStats(ctx: StewardAppContext, agentId: string, chainId: number) {
  const { and, eq, gte, sql, transactions } = await import("@stwd/db");
  const now = new Date();
  const oneHourAgo = new Date(now.getTime() - 3600_000);
  const oneDayAgo = new Date(now.getTime() - 86400_000);
  const oneWeekAgo = new Date(now.getTime() - 604800_000);
  const [stats] = await ctx.db
    .select({
      recentTxCount1h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneHourAgo.toISOString()}::timestamptz)`,
      recentTxCount24h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneDayAgo.toISOString()}::timestamptz)`,
      spentToday: sql<string>`coalesce(sum((${transactions.value})::numeric) filter (where ${transactions.createdAt} >= ${oneDayAgo.toISOString()}::timestamptz and ${transactions.chainId} = ${chainId}), 0)::text`,
      spentThisWeek: sql<string>`coalesce(sum((${transactions.value})::numeric) filter (where ${transactions.chainId} = ${chainId}), 0)::text`,
    })
    .from(transactions)
    .where(
      and(
        eq(transactions.agentId, agentId),
        gte(transactions.createdAt, oneWeekAgo),
        sql`${transactions.status} in ('signed', 'broadcast', 'confirmed')`,
      ),
    );
  return {
    recentTxCount1h: Number(stats?.recentTxCount1h ?? 0),
    recentTxCount24h: Number(stats?.recentTxCount24h ?? 0),
    spentToday: BigInt(stats?.spentToday ?? "0"),
    spentThisWeek: BigInt(stats?.spentThisWeek ?? "0"),
  };
}

async function loadAggregations(policySet: PolicyRule[], request: SignRequest) {
  const queries = aggregationQueriesForPolicies(policySet, request);
  const snapshots = new Map<string, bigint>();
  await Promise.all(
    queries.map(async (query) => {
      const value = await getAggregationSnapshot(query, Date.now());
      if (value !== null) snapshots.set(aggregationQueryKey(query), value);
    }),
  );
  return aggregationLookupFromMap(snapshots);
}

async function resolveEvmWallet(
  ctx: StewardAppContext,
  agent: { id: string; walletAddress: string; walletAddresses?: { evm?: string } },
  chainId: number,
) {
  try {
    return (await ctx.vault.getWallet({ agentId: agent.id, chainId })).address;
  } catch {
    return agent?.walletAddresses?.evm ?? agent?.walletAddress ?? null;
  }
}

function auditActor(c: Context<{ Variables: AppVariables }>, agentId: string) {
  return { actorType: "agent" as const, actorId: c.get("agentScope") ?? agentId };
}

function replay(c: Context<{ Variables: AppVariables }>, response: StoredResponse) {
  c.header("Idempotency-Replayed", "true");
  return c.json(response.body, response.status);
}

function getSessionManager(ctx: StewardAppContext): TradeSessionManager {
  return new TradeSessionManager({ redis: ctx.getRedisClient() });
}

function isPreparedStatus(value: unknown): value is PreparedIntentStatus {
  return (
    value === "prepared" ||
    value === "submitting" ||
    value === "submitted" ||
    value === "rejected" ||
    value === "unknown" ||
    value === "revoked" ||
    value === "expired"
  );
}

function preparedResponseFromRow(row: typeof intents.$inferSelect): PreparedSwapResponse {
  const payload = row.payload as Record<string, unknown>;
  const execution = (row.executionResult ?? {}) as Record<string, unknown>;
  const unsignedIntent = payload.unsignedIntent as PreparedSwapResponse["unsignedIntent"];
  const simulation = payload.simulation as PreparedSwapResponse["simulation"];
  const quote = payload.quote as Record<string, unknown>;
  return {
    intentId: row.id,
    intentHash: String(row.intentHash ?? payload.intentHash),
    status: isPreparedStatus(row.status) ? row.status : "rejected",
    expiresAt: (row.expiresAt ?? new Date()).toISOString(),
    requestDigest: String(row.semanticRequestHash ?? payload.requestDigest),
    quoteId: String(quote.quoteId),
    quoteHash: String(payload.quoteHash),
    simulation,
    lifecycle: {
      canExecute: row.status === "prepared" && (!row.expiresAt || row.expiresAt > new Date()),
      terminal:
        row.status === "submitted" ||
        row.status === "rejected" ||
        row.status === "revoked" ||
        row.status === "expired",
      executionStatus: typeof execution.status === "string" ? execution.status : null,
    },
    unsignedIntent,
  };
}

function rejectedPrepareReplayFromRow(row: typeof intents.$inferSelect): StoredResponse | null {
  const payload = row.payload as Partial<RejectedPreparePayload>;
  if (payload.kind !== "evm-swap-prepare-rejection") return null;
  const replayed = payload.replay;
  if (!replayed || typeof replayed !== "object") return null;
  const status = replayed.status;
  if (status !== 400 && status !== 403 && status !== 404 && status !== 409) {
    return null;
  }
  return { status, body: replayed.body };
}

async function loadPreparedIntent(
  ctx: StewardAppContext,
  tenantId: string,
  agentId: string | null,
  idOrHash: string,
) {
  const conditions = [
    eq(intents.tenantId, tenantId),
    eq(intents.intentType, "evm_swap"),
    sql`(${intents.id} = ${idOrHash} or ${intents.intentHash} = ${idOrHash})`,
  ];
  if (agentId) conditions.push(eq(intents.agentId, agentId));
  const [row] = await ctx.db
    .select()
    .from(intents)
    .where(and(...conditions));
  if (!row) return null;
  if (row.status === "prepared" && row.expiresAt && row.expiresAt <= new Date()) {
    const [expired] = await ctx.db
      .update(intents)
      .set({
        status: "expired",
        expiredAt: new Date(),
        expiredBy: "system",
        updatedAt: new Date(),
        executionResult: {
          ...((row.executionResult ?? {}) as Record<string, unknown>),
          status: "expired",
          reason: "prepared intent expired before execution",
        },
      })
      .where(and(eq(intents.id, row.id), eq(intents.status, "prepared")))
      .returning();
    return expired ?? row;
  }
  return row;
}

function intentAuditActor(c: Context<{ Variables: AppVariables }>) {
  const scopedAgent = c.get("agentScope");
  if (scopedAgent) return { actorType: "agent" as const, actorId: scopedAgent };
  if (c.get("authType") === "platform") {
    return { actorType: "platform" as const, actorId: "platform" };
  }
  const userId = c.get("userId");
  if (userId) return { actorType: "user" as const, actorId: userId };
  return { actorType: "api-key" as const, actorId: c.get("tenantId") };
}

export function createEvmSwapRoutes(ctx: StewardAppContext): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();
  const inflightIdempotency = new Map<string, InflightIdempotencyEntry>();

  routes.post("/evm/swap/prepare", async (c) => {
    const idempotencyKey = c.req.header("Idempotency-Key");
    if (!idempotencyKey) {
      return json(c, { ok: false, error: "Idempotency-Key is required" }, 400);
    }
    if (idempotencyKey.length > 200) {
      return json(c, { ok: false, error: "Idempotency-Key is too long" }, 400);
    }

    const raw = await ctx.safeJsonParse(c);
    const parsed = prepareSwapSchema.safeParse(raw);
    if (!parsed.success) return json(c, { ok: false, error: parsed.error.message }, 400);

    const tenantId = c.get("tenantId");
    const scopedAgent = c.get("agentScope");
    if (!scopedAgent) return json(c, { ok: false, error: "Agent JWT required" }, 403);
    if (parsed.data.agentId !== scopedAgent) {
      return json(
        c,
        { ok: false, error: "Forbidden: agent token cannot act for another agent" },
        403,
      );
    }
    const agent = await ctx.ensureAgentForTenant(tenantId, parsed.data.agentId);
    if (!agent) return json(c, { ok: false, error: "Agent not found" }, 404);

    const requestDigest = prefixedSha256({
      agentId: parsed.data.agentId,
      sessionId: parsed.data.sessionId,
      chainId: parsed.data.chainId,
      fromToken: normalizeAddress(parsed.data.fromToken.address),
      toToken: normalizeAddress(parsed.data.toToken.address),
      amount: parsed.data.amount,
      slippageBps: parsed.data.slippageBps ?? null,
    });
    const [existingByKey] = await ctx.db
      .select()
      .from(intents)
      .where(
        and(
          eq(intents.tenantId, tenantId),
          eq(intents.agentId, parsed.data.agentId),
          eq(intents.intentType, "evm_swap"),
          eq(intents.idempotencyKey, idempotencyKey),
        ),
      );
    if (existingByKey) {
      if (existingByKey.semanticRequestHash !== requestDigest) {
        return json(
          c,
          { ok: false, error: "Idempotency key reused with different semantics" },
          409,
        );
      }
      const rejectedReplay = rejectedPrepareReplayFromRow(existingByKey);
      if (rejectedReplay) return replay(c, rejectedReplay);
      const replayRow =
        (await loadPreparedIntent(ctx, tenantId, parsed.data.agentId, existingByKey.id)) ??
        existingByKey;
      return replay(c, {
        status: 200,
        body: { ok: true, data: preparedResponseFromRow(replayRow) },
      });
    }
    const idempotencyScope = `${tenantId}:${parsed.data.agentId}:${idempotencyKey}`;
    const inflight = inflightIdempotency.get(idempotencyScope);
    if (inflight) {
      if (inflight.requestDigest !== requestDigest) {
        return json(
          c,
          { ok: false, error: "Idempotency key reused with different semantics" },
          409,
        );
      }
      return replay(c, await inflight.promise);
    }

    const prepare = (async (): Promise<StoredResponse> => {
      const actor = auditActor(c, parsed.data.agentId);
      await ctx.writeAuditEvent({
        tenantId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action: "trade.evm.swap.prepare.requested",
        resourceType: "trade",
        resourceId: parsed.data.agentId,
        metadata: {
          agentId: parsed.data.agentId,
          sessionId: parsed.data.sessionId,
          chainId: parsed.data.chainId,
          fromToken: parsed.data.fromToken.address,
          toToken: parsed.data.toToken.address,
          amount: parsed.data.amount,
          slippageBps: parsed.data.slippageBps ?? null,
          requestDigest,
        },
      });

      const reject = async (
        status: StoredResponse["status"],
        reason: string,
      ): Promise<StoredResponse> => {
        const response: StoredResponse = {
          status,
          body: status === 400 ? rejectReason(reason) : { ok: false, error: reason },
        };
        await ctx.writeAuditEvent({
          tenantId,
          actorType: actor.actorType,
          actorId: actor.actorId,
          action: "trade.evm.swap.prepare.rejected",
          resourceType: "trade",
          resourceId: parsed.data.agentId,
          metadata: { reason, agentId: parsed.data.agentId, chainId: parsed.data.chainId },
        });
        if (status >= 500) return response;

        const now = new Date();
        const [created] = await ctx.db
          .insert(intents)
          .values({
            id: `evm_rej_${crypto.randomUUID()}`,
            tenantId,
            agentId: parsed.data.agentId,
            intentType: "evm_swap",
            status: "rejected",
            resourceType: "trade.evm.swap.prepare",
            resourceId: requestDigest,
            createdByType: "agent",
            createdById: actor.actorId,
            idempotencyKey,
            semanticRequestHash: requestDigest,
            authorizationDetails: [
              {
                kind: "evm-swap-prepare-rejection",
                status,
                sessionId: parsed.data.sessionId,
                chainId: parsed.data.chainId,
              },
            ],
            payload: {
              kind: "evm-swap-prepare-rejection",
              requestDigest,
              replay: response,
            } satisfies RejectedPreparePayload,
            executionResult: { status: "rejected" },
            rejectedAt: now,
            rejectedBy: actor.actorId,
            rejectionReason: reason,
            createdAt: now,
            updatedAt: now,
          })
          .onConflictDoNothing()
          .returning();
        if (created) return response;

        const [existing] = await ctx.db
          .select()
          .from(intents)
          .where(
            and(
              eq(intents.tenantId, tenantId),
              eq(intents.agentId, parsed.data.agentId),
              eq(intents.intentType, "evm_swap"),
              eq(intents.idempotencyKey, idempotencyKey),
            ),
          );
        if (existing?.semanticRequestHash && existing.semanticRequestHash !== requestDigest) {
          return {
            status: 409,
            body: { ok: false, error: "Idempotency key reused with different semantics" },
          };
        }
        return rejectedPrepareReplayFromRow(existing ?? created) ?? response;
      };

      if (!ctx.evmSimulator) return reject(503, "EVM simulator is not configured");
      const owner = await resolveEvmWallet(ctx, agent, parsed.data.chainId);
      if (!owner || !isEvmAddress(owner)) return reject(403, "Agent EVM wallet not found");
      const sessionManager = getSessionManager(ctx);
      const session = await sessionManager.getSession({ tenantId, id: parsed.data.sessionId });
      if (
        !session ||
        session.agentId !== parsed.data.agentId ||
        session.venue !== "evm" ||
        session.status !== "active" ||
        session.expiresAt <= new Date()
      ) {
        return reject(403, "Active EVM trade session required");
      }
      if (!session.allowedAssets.includes(toCaip2(parsed.data.chainId) ?? "")) {
        return reject(403, "EVM trade session does not allow this chain");
      }
      if (normalizeAddress(session.walletId) !== normalizeAddress(owner)) {
        return reject(409, "EVM trade session wallet no longer matches the agent wallet");
      }

      const swap = ctx.adapterRegistry.swap();
      if (!swap.enabled) return reject(503, "Swap adapter is disabled");
      const quote = await swap.getQuote({
        fromToken: parsed.data.fromToken,
        toToken: parsed.data.toToken,
        amount: parsed.data.amount,
        chainId: parsed.data.chainId,
        taker: owner,
        slippageBps: parsed.data.slippageBps,
      });
      if (
        quote.provider !== swap.provider ||
        quote.chainId !== parsed.data.chainId ||
        normalizeAddress(quote.fromToken.address) !==
          normalizeAddress(parsed.data.fromToken.address) ||
        normalizeAddress(quote.toToken.address) !== normalizeAddress(parsed.data.toToken.address) ||
        quote.amountIn !== parsed.data.amount ||
        (parsed.data.slippageBps !== undefined && quote.slippageBps !== parsed.data.slippageBps) ||
        !Number.isSafeInteger(quote.expiresAt)
      ) {
        return reject(400, "Adapter quote is not bound to the semantic swap request");
      }
      const intent = await swap.buildSwap(quote, owner);
      if (intent.signed !== false || intent.kind !== "evm-tx") {
        return reject(503, "Adapter returned an invalid unsigned EVM intent");
      }
      const data = intent.data ?? "0x";
      const selector = selectorOf(data);
      if (!selector) return reject(400, "intent calldata must include a 4-byte selector");
      if (!isEvmAddress(intent.to) || !isEvmAddress(intent.owner)) {
        return reject(400, "intent contains an invalid EVM address");
      }
      if (!/^\d+$/.test(intent.value)) return reject(400, "intent value must be decimal wei");
      if (normalizeAddress(intent.owner) !== normalizeAddress(owner)) {
        return reject(403, "intent owner does not match the agent wallet");
      }

      const policySet = await ctx.getPolicySet(tenantId, parsed.data.agentId);
      const strict = validateGovernedEvmExecutionPolicy(policySet, {
        agentId: parsed.data.agentId,
        tenantId,
        chainId: intent.chainId,
        owner: intent.owner,
        target: intent.to,
        selector,
        value: intent.value,
        provider: intent.provider,
        category: intent.category,
        quote,
        intentMetadata: intent.metadata,
      });
      if (!strict.ok) return reject(400, strict.reason);

      const request: SignRequest = {
        agentId: parsed.data.agentId,
        tenantId,
        to: intent.to,
        value: intent.value,
        data,
        chainId: intent.chainId,
        broadcast: false,
        walletAddress: owner,
      };
      const [stats, conditionSets, aggregations] = await Promise.all([
        getTransactionStats(ctx, parsed.data.agentId, intent.chainId),
        loadConditionSets(ctx, tenantId, policySet),
        loadAggregations(policySet, request),
      ]);
      const policyEvaluation = await ctx.policyEngine.evaluate(policySet, {
        request,
        ...stats,
        conditionSets,
        aggregations,
        priceOracle: ctx.priceOracle,
        correlationId: idempotencyKey,
        venue: intent.provider,
      });
      if (!policyEvaluation.approved) {
        return reject(
          400,
          policyEvaluation.results.find((result) => !result.passed)?.reason ??
            "EVM execution rejected by policy",
        );
      }

      const intentHash = canonicalIntentHash(
        {
          ...request,
          owner,
          category: "swap",
          provider: intent.provider,
        },
        quote,
      );
      const qHash = quoteHash(quote);
      const simulation = await ctx.evmSimulator.simulate({
        chainId: intent.chainId,
        from: owner,
        to: intent.to,
        value: intent.value,
        data,
        intentHash,
      });
      if (!simulation.ok) {
        return reject(503, simulation.revertReason ?? "EVM simulation failed");
      }

      const sanitized = sanitizeIntent(intent);
      const createdAt = new Date();
      const expiresAt = new Date(Math.min(quote.expiresAt, session.expiresAt.getTime()));
      const preparedRow = await sessionManager.withActiveSubmissionFence(
        { tenantId, id: parsed.data.sessionId },
        async (freshSession, db) => {
          if (
            freshSession.agentId !== parsed.data.agentId ||
            freshSession.venue !== "evm" ||
            normalizeAddress(freshSession.walletId) !== normalizeAddress(owner) ||
            !freshSession.allowedAssets.includes(toCaip2(parsed.data.chainId) ?? "")
          ) {
            return null;
          }
          const [row] = await db
            .insert(intents)
            .values({
              id: `evm_${crypto.randomUUID()}`,
              tenantId,
              agentId: parsed.data.agentId,
              intentType: "evm_swap",
              status: "prepared",
              resourceType: "trade.evm.swap",
              resourceId: intentHash,
              createdByType: "agent",
              createdById: actor.actorId,
              idempotencyKey,
              semanticRequestHash: requestDigest,
              intentHash,
              authorizationDetails: [
                {
                  kind: "evm-prepared-swap",
                  sessionId: parsed.data.sessionId,
                  wallet: normalizeAddress(owner),
                  provider: intent.provider,
                  chainId: intent.chainId,
                  target: sanitized.target,
                  selector: sanitized.selector,
                  value: sanitized.value,
                  minAmountOut: quote.minAmountOut,
                  quoteHash: qHash,
                  policyApproved: true,
                  simulationOk: true,
                },
              ],
              payload: {
                requestDigest,
                quoteHash: qHash,
                intentHash,
                sessionId: parsed.data.sessionId,
                wallet: normalizeAddress(owner),
                provider: intent.provider,
                chainId: intent.chainId,
                target: sanitized.target,
                selector: sanitized.selector,
                value: sanitized.value,
                minAmountOut: quote.minAmountOut,
                semanticRequest: {
                  chainId: parsed.data.chainId,
                  fromToken: {
                    ...parsed.data.fromToken,
                    address: normalizeAddress(parsed.data.fromToken.address),
                  },
                  toToken: {
                    ...parsed.data.toToken,
                    address: normalizeAddress(parsed.data.toToken.address),
                  },
                  amount: parsed.data.amount,
                  slippageBps: parsed.data.slippageBps ?? null,
                },
                quote: {
                  provider: quote.provider,
                  quoteId: quote.quoteId,
                  amountIn: quote.amountIn,
                  amountOut: quote.amountOut,
                  minAmountOut: quote.minAmountOut,
                  expiresAt: new Date(quote.expiresAt).toISOString(),
                },
                simulation: { ok: true, gasEstimate: simulation.gasEstimate },
                policy: {
                  approved: true,
                  resultCount: policyEvaluation.results.length,
                  failedCount: policyEvaluation.results.filter((result) => !result.passed).length,
                },
                unsignedIntent: {
                  kind: "evm-tx",
                  chainId: intent.chainId,
                  to: normalizeAddress(intent.to),
                  value: intent.value,
                  data,
                  owner: normalizeAddress(owner),
                  category: "swap",
                  provider: intent.provider,
                },
                lifecycle: {
                  allowedTransitions: {
                    prepared: ["submitting", "revoked", "expired"],
                    submitting: ["submitted", "rejected", "unknown"],
                    unknown: ["submitted", "rejected"],
                  },
                  retry: "never blind retry unknown; reconcile by intent id or transaction hash",
                },
              },
              executionResult: { status: "prepared", transactionHash: null },
              expiresAt,
              createdAt,
              updatedAt: createdAt,
            })
            .onConflictDoNothing()
            .returning();
          if (row) return row;
          const [existing] = await db
            .select()
            .from(intents)
            .where(
              and(
                eq(intents.tenantId, tenantId),
                eq(intents.agentId, parsed.data.agentId),
                eq(intents.intentType, "evm_swap"),
                eq(intents.idempotencyKey, idempotencyKey),
              ),
            );
          return existing ?? null;
        },
      );
      if (!preparedRow) {
        return reject(409, "Trade session was revoked before intent persistence");
      }
      if (preparedRow.semanticRequestHash !== requestDigest) {
        return {
          status: 409,
          body: { ok: false, error: "Idempotency key reused with different semantics" },
        };
      }
      const rejectedReplay = rejectedPrepareReplayFromRow(preparedRow);
      if (rejectedReplay) return rejectedReplay;
      await ctx.writeAuditEvent({
        tenantId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action: "trade.evm.swap.prepare.prepared",
        resourceType: "trade",
        resourceId: intentHash,
        metadata: {
          ...sanitized,
          agentId: parsed.data.agentId,
          sessionId: parsed.data.sessionId,
          intentId: preparedRow.id,
          intentHash,
          quoteId: quote.quoteId,
          quoteHash: qHash,
          requestDigest,
          gasEstimate: simulation.gasEstimate ?? null,
        },
        requestId: idempotencyKey,
      });

      return {
        status: 200,
        body: {
          ok: true,
          data: preparedResponseFromRow(preparedRow),
        },
      };
    })().catch(async (error): Promise<StoredResponse> => {
      const adapterReason =
        error instanceof AdapterValidationError ||
        error instanceof AdapterNotConfiguredError ||
        error instanceof AdapterUnavailableError
          ? error.message
          : null;
      const reason = adapterReason ?? "EVM swap preparation failed";
      await ctx.writeAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: parsed.data.agentId,
        action: "trade.evm.swap.prepare.rejected",
        resourceType: "trade",
        resourceId: parsed.data.agentId,
        metadata: { reason, agentId: parsed.data.agentId, chainId: parsed.data.chainId },
      });
      if (error instanceof AdapterValidationError) {
        return { status: 400, body: rejectReason(error.message) };
      }
      if (error instanceof AdapterNotConfiguredError || error instanceof AdapterUnavailableError) {
        return { status: 503, body: { ok: false, error: error.message } };
      }
      return { status: 500, body: { ok: false, error: "Internal server error" } };
    });

    inflightIdempotency.set(idempotencyScope, { requestDigest, promise: prepare });
    const response = await prepare.finally(() => {
      inflightIdempotency.delete(idempotencyScope);
    });
    return c.json(response.body, response.status);
  });

  routes.get("/evm/swap/intents/:id", async (c) => {
    const tenantId = c.get("tenantId");
    const scopedAgent = c.get("agentScope");
    const row = await loadPreparedIntent(ctx, tenantId, scopedAgent ?? null, c.req.param("id"));
    if (!row) return json(c, { ok: false, error: "Prepared intent not found" }, 404);
    return c.json({ ok: true, data: preparedResponseFromRow(row) }, 200);
  });

  routes.post("/evm/swap/intents/:id/revoke", async (c) => {
    const tenantId = c.get("tenantId");
    const scopedAgent = c.get("agentScope");
    const existing = await loadPreparedIntent(
      ctx,
      tenantId,
      scopedAgent ?? null,
      c.req.param("id"),
    );
    if (!existing) return json(c, { ok: false, error: "Prepared intent not found" }, 404);
    if (existing.status === "revoked" || existing.status === "expired") {
      return c.json({ ok: true, data: preparedResponseFromRow(existing) }, 200);
    }
    if (existing.status !== "prepared") {
      return json(
        c,
        { ok: false, error: `Cannot revoke prepared intent in ${existing.status} status` },
        409,
      );
    }
    const now = new Date();
    const actor = intentAuditActor(c);
    const [revoked] = await ctx.db
      .update(intents)
      .set({
        status: "revoked",
        canceledAt: now,
        canceledBy: actor.actorId,
        cancellationReason: scopedAgent ? "revoked by agent" : "revoked by recovery auth",
        updatedAt: now,
        executionResult: {
          ...((existing.executionResult ?? {}) as Record<string, unknown>),
          status: "revoked",
          reason: "revoked before execution",
        },
      })
      .where(and(eq(intents.id, existing.id), eq(intents.status, "prepared")))
      .returning();
    if (!revoked) {
      const reloaded = await loadPreparedIntent(ctx, tenantId, scopedAgent ?? null, existing.id);
      return json(
        c,
        {
          ok: false,
          error: `Cannot revoke prepared intent in ${reloaded?.status ?? "unknown"} status`,
        },
        409,
      );
    }
    await ctx.writeAuditEvent({
      tenantId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      action: "trade.evm.swap.intent.revoked",
      resourceType: "trade.evm.swap",
      resourceId: revoked.id,
      metadata: {
        intentId: revoked.id,
        intentHash: revoked.intentHash,
        status: revoked.status,
      },
    });
    return c.json({ ok: true, data: preparedResponseFromRow(revoked) }, 200);
  });

  return routes;
}
