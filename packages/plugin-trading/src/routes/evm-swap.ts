import { createHash } from "node:crypto";
import type { SwapQuote } from "@stwd/adapters";
import {
  aggregationLookupFromMap,
  aggregationQueriesForPolicies,
  aggregationQueryKey,
} from "@stwd/policy-engine";
import { getAggregationSnapshot } from "@stwd/redis";
import type { ApiResponse, AppVariables, PolicyRule, SignRequest } from "@stwd/shared";
import { toCaip2 } from "@stwd/shared";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import type { StewardAppContext } from "../context";

type PreparedSwapResponse = {
  intentHash: string;
  quoteId: string;
  simulation: { ok: true; gasEstimate?: string };
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

type StoredResponse = {
  status: 200 | 400 | 403 | 404 | 409 | 500 | 503;
  body: ApiResponse<PreparedSwapResponse> | ApiResponse | { code: string; reason: string };
};

type IdempotencyEntry = {
  bodyHash: string;
  expiresAt: number;
  promise: Promise<StoredResponse>;
  response?: StoredResponse;
};

const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_IDEMPOTENCY_ENTRIES = 1_000;

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

function canonicalIntentHash(
  intent: SignRequest & { owner: string; category: string; provider: string },
  quote: SwapQuote,
): string {
  return `sha256:${sha256({
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
  })}`;
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
  const selectorConfig = (constraints as Record<string, unknown>)[selector];
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

export function createEvmSwapRoutes(ctx: StewardAppContext): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();
  const idempotency = new Map<string, IdempotencyEntry>();

  function remember(
    tenantId: string,
    agentId: string,
    key: string,
    bodyHash: string,
    promise: Promise<StoredResponse>,
  ) {
    const now = Date.now();
    for (const [entryKey, entry] of idempotency) {
      if (entry.expiresAt <= now || idempotency.size >= MAX_IDEMPOTENCY_ENTRIES) {
        idempotency.delete(entryKey);
      }
      if (idempotency.size < MAX_IDEMPOTENCY_ENTRIES) break;
    }
    const mapKey = `${tenantId}:${agentId}:${key}`;
    const entry: IdempotencyEntry = { bodyHash, expiresAt: now + IDEMPOTENCY_TTL_MS, promise };
    idempotency.set(mapKey, entry);
    promise.then((response) => {
      if (response.status >= 500) {
        idempotency.delete(mapKey);
        return;
      }
      entry.response = response;
    });
  }

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

    const bodyHash = sha256(parsed.data);
    const mapKey = `${tenantId}:${parsed.data.agentId}:${idempotencyKey}`;
    const existing = idempotency.get(mapKey);
    if (existing && existing.expiresAt > Date.now()) {
      if (existing.bodyHash !== bodyHash) {
        return json(c, { ok: false, error: "Idempotency key reused with a different body" }, 409);
      }
      return replay(c, existing.response ?? (await existing.promise));
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
          chainId: parsed.data.chainId,
          fromToken: parsed.data.fromToken.address,
          toToken: parsed.data.toToken.address,
          amount: parsed.data.amount,
          slippageBps: parsed.data.slippageBps ?? null,
        },
      });

      const reject = async (
        status: StoredResponse["status"],
        reason: string,
      ): Promise<StoredResponse> => {
        await ctx.writeAuditEvent({
          tenantId,
          actorType: actor.actorType,
          actorId: actor.actorId,
          action: "trade.evm.swap.prepare.rejected",
          resourceType: "trade",
          resourceId: parsed.data.agentId,
          metadata: { reason, agentId: parsed.data.agentId, chainId: parsed.data.chainId },
        });
        return {
          status,
          body: status === 400 ? rejectReason(reason) : { ok: false, error: reason },
        };
      };

      if (!ctx.evmSimulator) return reject(503, "EVM simulator is not configured");
      const owner = await resolveEvmWallet(ctx, agent, parsed.data.chainId);
      if (!owner || !isEvmAddress(owner)) return reject(403, "Agent EVM wallet not found");

      const swap = ctx.adapterRegistry.swap();
      if (!swap.enabled) return reject(503, "Swap adapter is disabled");
      const quote = await swap.getQuote({
        fromToken: parsed.data.fromToken,
        toToken: parsed.data.toToken,
        amount: parsed.data.amount,
        chainId: parsed.data.chainId,
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
          intentHash,
          quoteId: quote.quoteId,
          gasEstimate: simulation.gasEstimate ?? null,
        },
        requestId: idempotencyKey,
      });

      return {
        status: 200,
        body: {
          ok: true,
          data: {
            intentHash,
            quoteId: quote.quoteId,
            simulation: { ok: true, gasEstimate: simulation.gasEstimate },
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
          },
        },
      };
    })().catch(async (): Promise<StoredResponse> => {
      const reason = "EVM swap preparation failed";
      await ctx.writeAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: parsed.data.agentId,
        action: "trade.evm.swap.prepare.rejected",
        resourceType: "trade",
        resourceId: parsed.data.agentId,
        metadata: { reason, agentId: parsed.data.agentId, chainId: parsed.data.chainId },
      });
      return { status: 500, body: { ok: false, error: "Internal server error" } };
    });

    remember(tenantId, parsed.data.agentId, idempotencyKey, bodyHash, prepare);
    const response = await prepare;
    return c.json(response.body, response.status);
  });

  return routes;
}
