/**
 * Financial-service adapter routes (@stwd/adapters seam).
 *
 * Tenant/agent-scoped endpoints for swaps, earn/yield, fiat onramp/offramp, KYC,
 * TOS/consent, and custodial wallets, backed by the pluggable AdapterRegistry.
 *
 * SECURITY POSTURE (money-path):
 *   - Any endpoint that produces a fund-moving tx/intent (swap build, earn
 *     deposit/withdraw) MUST (a) build the unsigned intent via the adapter, then
 *     (b) run it through the SAME policy/spend gate the trade route uses
 *     (`evaluateTradeOrder`) BEFORE returning anything signable. Adapters never
 *     get a signing shortcut: the returned artifact is ALWAYS unsigned and must
 *     still traverse the existing vault/policy signing path to move value.
 *   - Quote/status/read endpoints are non-fund-moving and only require auth.
 *   - The custodial signature endpoint can NEVER return a fabricated signature;
 *     the mock fails closed (501).
 *
 * Mount: app.route("/adapters", adapterRoutes) — registered after the webhooks
 * route in app.ts.
 */

import {
  AdapterNotConfiguredError,
  AdapterUnavailableError,
  AdapterValidationError,
  adapterRegistry,
  type BridgeQuote,
  type UnsignedTxIntent,
} from "@stwd/adapters";
import { getDb, tenantAppClients, userTenants } from "@stwd/db";
import {
  dailySpendCapEvaluator,
  evaluateTradeOrder,
  perOrderCapEvaluator,
} from "@stwd/policy-engine";
import { and, eq } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { z } from "zod";
import { checkAgentSpendLimit } from "../middleware/redis";
import { type ActorType, writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  ensureAgentForTenant,
  requireTenantLevel,
  safeJsonParse,
  setNoStoreHeaders,
} from "../services/context";

export const adapterRoutes = new Hono<{ Variables: AppVariables }>();

// ─── Auth / actor helpers ─────────────────────────────────────────────────────

function callerAgentId(c: Context<{ Variables: AppVariables }>): string | null {
  return c.get("agentScope") ?? null;
}

/**
 * Resolve the agent the request acts for, honoring agent-token scope binding.
 *
 * Both branches end pinned to an agent the CALLER is authorized for:
 *   - Agent-token callers are bound to their own `agentScope`; naming any other
 *     agent is a 403.
 *   - Tenant-level callers (owner/admin/api-key) must name an agent explicitly,
 *     and that agent MUST belong to the caller's tenant. We verify ownership via
 *     `ensureAgentForTenant` (→ `vault.getAgent`, which filters BOTH
 *     `agents.id` AND `agents.tenantId`) exactly like agents.ts /
 *     policies-standalone.ts do — without it a tenant-A caller could name a
 *     tenant-B agentId, leaking a daily-cap boolean oracle through the spend
 *     gate and writing a self-tenant audit row referencing a foreign agent.
 *     A mismatch fails closed with 404 (the same not-found shape used elsewhere
 *     for unowned agents), revealing nothing about the foreign agent.
 */
async function resolveAgentId(
  c: Context<{ Variables: AppVariables }>,
  requested?: string,
): Promise<{ ok: true; agentId: string } | { ok: false; response: Response }> {
  const scoped = callerAgentId(c);
  if (scoped) {
    // Agent-token callers may only act as themselves.
    if (requested && requested !== scoped) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Forbidden: agent token cannot act for another agent" },
          403,
        ),
      };
    }
    return { ok: true, agentId: scoped };
  }
  // Tenant-level callers must name the agent explicitly.
  if (!requireTenantLevel(c)) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403),
    };
  }
  if (!requested) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "agentId is required" }, 400),
    };
  }
  // Ownership check: the named agent must belong to the caller's tenant.
  const owned = await ensureAgentForTenant(c.get("tenantId"), requested);
  if (!owned) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404),
    };
  }
  return { ok: true, agentId: requested };
}

async function tenantHasUser(tenantId: string, userId: string): Promise<boolean> {
  const [membership] = await getDb()
    .select({ userId: userTenants.userId })
    .from(userTenants)
    .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, userId)));
  return Boolean(membership);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function resolveAdapterUserId(
  c: Context<{ Variables: AppVariables }>,
  requested?: string,
): Promise<{ ok: true; userId: string } | { ok: false; response: Response }> {
  const sessionUserId = c.get("userId");
  if (sessionUserId) {
    if (requested && requested !== sessionUserId) {
      return {
        ok: false,
        response: c.json<ApiResponse>(
          { ok: false, error: "Forbidden: user session cannot act for another user" },
          403,
        ),
      };
    }
    return { ok: true, userId: sessionUserId };
  }
  if (!requireTenantLevel(c)) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403),
    };
  }
  if (!requested) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "userId is required" }, 400),
    };
  }
  if (!isUuid(requested)) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "userId must be a UUID" }, 400),
    };
  }
  if (!(await tenantHasUser(c.get("tenantId"), requested))) {
    return {
      ok: false,
      response: c.json<ApiResponse>({ ok: false, error: "User not found" }, 404),
    };
  }
  return { ok: true, userId: requested };
}

async function requireAdapterUserAccess(
  c: Context<{ Variables: AppVariables }>,
  userId: string,
): Promise<Response | null> {
  const resolved = await resolveAdapterUserId(c, userId);
  return resolved.ok ? null : resolved.response;
}

async function requireAdapterSessionAccess(
  c: Context<{ Variables: AppVariables }>,
  session: { tenantId: string; userId: string },
): Promise<Response | null> {
  if (session.tenantId !== c.get("tenantId")) {
    return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
  }
  return requireAdapterUserAccess(c, session.userId);
}

async function assertAllowedAdapterReturnUrl(
  c: Context<{ Variables: AppVariables }>,
  returnUrl: string,
): Promise<Response | null> {
  let parsed: URL;
  try {
    parsed = new URL(returnUrl);
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "returnUrl must be a valid URL" }, 400);
  }
  const allowed = await getDb()
    .select({ allowedRedirectUrls: tenantAppClients.allowedRedirectUrls })
    .from(tenantAppClients)
    .where(
      and(eq(tenantAppClients.tenantId, c.get("tenantId")), eq(tenantAppClients.enabled, true)),
    );
  const entries = allowed
    .flatMap((row) => row.allowedRedirectUrls ?? [])
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0 && entry !== "*");
  if (entries.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "returnUrl allowlist is not configured" }, 400);
  }
  const normalized = parsed.toString();
  if (!entries.includes(normalized)) {
    return c.json<ApiResponse>({ ok: false, error: "returnUrl is not allowed" }, 400);
  }
  return null;
}

function auditActorType(c: Context<{ Variables: AppVariables }>): ActorType {
  if (c.get("userId")) return "user";
  if (c.get("authType") === "agent-token") return "agent";
  if (c.get("authType") === "api-key") return "api-key";
  return "platform";
}

function auditActorId(c: Context<{ Variables: AppVariables }>): string {
  return (
    c.get("userId") ?? callerAgentId(c) ?? `${c.get("authType") ?? "tenant"}:${c.get("tenantId")}`
  );
}

async function auditAdapterEvent(
  c: Context<{ Variables: AppVariables }>,
  action: string,
  resourceId: string,
  metadata: Record<string, unknown>,
): Promise<void> {
  await writeAuditEvent({
    tenantId: c.get("tenantId"),
    actorType: auditActorType(c),
    actorId: auditActorId(c),
    action,
    resourceType: "adapter",
    resourceId,
    metadata,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

// ─── Error mapping ──────────────────────────────────────────────────────────

function adapterErrorStatus(err: unknown): {
  status: 400 | 501 | 503 | 500;
  message: string;
} {
  if (err instanceof AdapterValidationError) return { status: 400, message: err.message };
  if (err instanceof AdapterNotConfiguredError) return { status: 503, message: err.message };
  if (err instanceof AdapterUnavailableError) return { status: 501, message: err.message };
  return { status: 500, message: "Internal server error" };
}

function handleAdapterError(c: Context<{ Variables: AppVariables }>, err: unknown): Response {
  const { status, message } = adapterErrorStatus(err);
  if (status === 500) {
    const requestId = c.get("requestId") ?? "unknown";
    console.error(`[${requestId}] adapter route error:`, err);
  }
  return c.json<ApiResponse>({ ok: false, error: message }, status);
}

function ok<T>(data: T): ApiResponse<T> {
  return { ok: true, data };
}

/**
 * Decode standard base64 to raw bytes using runtime-agnostic `atob` (works on
 * Bun and Workers; the Node `Buffer` global is typed away under workers-types).
 * Returns null on malformed input so callers can emit a clean 400.
 */
function decodeBase64(value: string): Uint8Array | null {
  // Reject anything that isn't well-formed standard base64 before decoding so a
  // malformed payload is a 400 rather than a lenient/partial decode.
  if (value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

// ─── Fund-moving policy gate ──────────────────────────────────────────────────

/**
 * Run an unsigned fund-moving intent through the SAME policy gate the trade
 * route uses. We treat the adapter operation as a generic "trade order" against
 * the agent's per-request budget so a deny here blocks the route from returning
 * any signable artifact. `estimatedUsd` is the route's notional estimate.
 *
 * The daily cap is enforced against the agent's REAL rolling daily USD spend,
 * sourced from the same Redis counter the signing path records into
 * (`recordVaultSpend` → `recordAgentSpend` → `recordSpend`'s `total` field).
 * This is what makes `STEWARD_ADAPTER_DAILY_CAP_USD` actually accumulate across
 * the day instead of evaluating every order in isolation (which would let a
 * caller issue unlimited per-order-cap-sized operations). `checkAgentSpendLimit`
 * fails CLOSED (allowed:false) when Redis is configured but unavailable, and
 * also reports allowed:false once the agent is already at/over the daily cap —
 * both cases must block, consistent with the money-path fail-closed posture.
 *
 * Returns `{ allow: true }` when allowed; `{ allow: false, reason }` when denied.
 */
async function enforceFundMovingPolicy(
  c: Context<{ Variables: AppVariables }>,
  params: {
    agentId: string;
    estimatedUsd: number;
    perOrderCapUsd: number;
    dailyCapUsd: number;
  },
): Promise<{ allow: true } | { allow: false; reason: string }> {
  const spendStatus = await checkAgentSpendLimit(params.agentId, params.dailyCapUsd, "day");
  if (!spendStatus.allowed) {
    return {
      allow: false,
      reason:
        "daily-spend-cap: agent is at or over the daily spend cap, or spend enforcement is unavailable (fail-closed)",
    };
  }
  const result = evaluateTradeOrder(
    {
      perOrderCapUsd: params.perOrderCapUsd,
      dailyCapUsd: params.dailyCapUsd,
      // Real rolling daily spend (USD) for this agent, not a hardcoded 0.
      dailySpendUsd: spendStatus.spent,
    },
    {
      estimatedOrderUsd: params.estimatedUsd,
    },
    // Adapter ops are not venue/asset/leverage constrained the way perps are, so
    // we run ONLY the USD-cap evaluators (per-order + daily). This reuses the
    // exact same spend-gate code the trade route uses; a deny here blocks the
    // route from returning any signable artifact.
    [perOrderCapEvaluator, dailySpendCapEvaluator],
  );
  if (result.allow) return { allow: true };
  return { allow: false, reason: result.reason ?? "operation violates spend policy" };
}

/** Per-request spend caps. Configurable via env; conservative defaults. */
function spendCaps(): { perOrderCapUsd: number; dailyCapUsd: number } {
  const perOrder = Number(process.env.STEWARD_ADAPTER_PER_OP_CAP_USD);
  const daily = Number(process.env.STEWARD_ADAPTER_DAILY_CAP_USD);
  return {
    perOrderCapUsd: Number.isFinite(perOrder) && perOrder > 0 ? perOrder : 10_000,
    dailyCapUsd: Number.isFinite(daily) && daily > 0 ? daily : 50_000,
  };
}

/**
 * Defense-in-depth assertion: the artifact an adapter route returns to a caller
 * MUST be unsigned. If an adapter ever produces something with a truthy
 * signature/signed flag, we refuse rather than hand back a broadcastable blob.
 */
function assertUnsigned(intent: UnsignedTxIntent): void {
  const suspect = intent as unknown as Record<string, unknown>;
  if (
    intent.signed !== false ||
    suspect.signature !== undefined ||
    suspect.rawTransaction !== undefined ||
    suspect.signedTx !== undefined
  ) {
    throw new AdapterUnavailableError(
      intent.category,
      "Adapter returned a signed artifact; refusing. Adapters must return unsigned intents only.",
    );
  }
}

// ─── Schemas ────────────────────────────────────────────────────────────────

const tokenRefSchema = z.object({
  address: z.string().min(1).max(128),
  symbol: z.string().max(32).optional(),
  decimals: z.number().int().min(0).max(36).optional(),
});

const swapQuoteSchema = z.object({
  agentId: z.string().min(1).max(128).optional(),
  fromToken: tokenRefSchema,
  toToken: tokenRefSchema,
  amount: z.string().min(1).max(80),
  chainId: z.number().int().positive(),
  slippageBps: z.number().int().min(0).max(10_000).optional(),
  /** Caller's USD notional estimate for the input amount (for the spend gate). */
  estimatedUsd: z.number().positive().max(1e12).optional(),
});

const earnDepositSchema = z.object({
  agentId: z.string().min(1).max(128).optional(),
  vault: z.string().min(1).max(128),
  assets: z.string().min(1).max(80),
  estimatedUsd: z.number().positive().max(1e12).optional(),
});

const earnWithdrawSchema = z.object({
  agentId: z.string().min(1).max(128).optional(),
  vault: z.string().min(1).max(128),
  shares: z.string().min(1).max(80),
  estimatedUsd: z.number().positive().max(1e12).optional(),
});

const onrampQuoteSchema = z.object({
  fiatCurrency: z.string().length(3),
  fiatAmount: z.number().positive().max(1e9),
  cryptoAsset: z.string().min(1).max(64),
  chainId: z.number().int().positive(),
});

const onrampSessionSchema = onrampQuoteSchema.extend({
  userId: z.string().min(1).max(128).optional(),
  destinationAddress: z.string().min(1).max(128),
});

const offrampQuoteSchema = z.object({
  cryptoAsset: z.string().min(1).max(64),
  cryptoAmount: z.string().min(1).max(80),
  chainId: z.number().int().positive(),
  fiatCurrency: z.string().length(3),
});

const offrampSessionSchema = offrampQuoteSchema.extend({
  userId: z.string().min(1).max(128).optional(),
  payoutMethodId: z.string().min(1).max(128),
});

const kycStartSchema = z.object({
  userId: z.string().min(1).max(128).optional(),
  level: z.enum(["basic", "standard", "enhanced"]),
});

const tosRecordSchema = z.object({
  userId: z.string().min(1).max(128).optional(),
  documentId: z.string().min(1).max(128),
  version: z.string().min(1).max(64),
});

const custodialCreateSchema = z.object({
  userId: z.string().min(1).max(128).optional(),
  chain: z.enum(["evm", "solana"]),
});

const custodialSignSchema = z.object({
  walletId: z.string().min(1).max(128),
  payload: z.string().min(2).max(100_000),
  scheme: z.enum(["evm-personal", "evm-typed-data", "evm-tx", "solana-tx"]),
});

const bridgeQuoteSchema = z.object({
  agentId: z.string().min(1).max(128).optional(),
  fromChainId: z.number().int().positive(),
  toChainId: z.number().int().positive(),
  fromToken: tokenRefSchema,
  toToken: tokenRefSchema,
  amount: z.string().min(1).max(80),
  recipient: z.string().min(1).max(128),
  slippageBps: z.number().int().min(0).max(10_000).optional(),
  estimatedUsd: z.number().positive().max(1e12).optional(),
});

const bridgeBuildSchema = z.object({
  agentId: z.string().min(1).max(128).optional(),
  owner: z.string().min(1).max(128),
  quote: z.record(z.string(), z.unknown()),
  estimatedUsd: z.number().positive().max(1e12).optional(),
});

const bridgeSessionSchema = z.object({
  userId: z.string().min(1).max(128).optional(),
  quote: z.record(z.string(), z.unknown()),
});

const exchangeSessionSchema = z.object({
  userId: z.string().min(1).max(128).optional(),
  provider: z.enum(["kraken", "coinbase", "binance", "mock"]),
  returnUrl: z.string().min(1).max(2048),
  scopes: z.array(z.string().min(1).max(64)).min(1).max(16).optional(),
  locale: z.string().min(1).max(32).optional(),
});

const exchangeOrderSchema = z.object({
  provider: z.string().min(1).max(64).optional(),
  symbol: z.string().min(1).max(64).optional(),
  side: z.enum(["buy", "sell"]).optional(),
  amount: z.string().min(1).max(80).optional(),
});

// ─── Health / introspection ───────────────────────────────────────────────────

adapterRoutes.get("/", (c) => {
  // Non-sensitive: which provider is resolved per category and whether enabled.
  return c.json(ok({ adapters: adapterRegistry.describe() }));
});

// ─── Swap ─────────────────────────────────────────────────────────────────────

adapterRoutes.post("/swap/quote", async (c) => {
  const raw = await safeJsonParse(c);
  const parsed = swapQuoteSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolution = await resolveAgentId(c, parsed.data.agentId);
  if (!resolution.ok) return resolution.response;

  try {
    const quote = await adapterRegistry.swap().getQuote({
      fromToken: parsed.data.fromToken,
      toToken: parsed.data.toToken,
      amount: parsed.data.amount,
      chainId: parsed.data.chainId,
      slippageBps: parsed.data.slippageBps,
    });
    return c.json(ok({ quote }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/swap/build", async (c) => {
  const raw = (await safeJsonParse<Record<string, unknown>>(c)) ?? {};
  // Quote must be supplied by the caller (echoed from /swap/quote).
  const quoteInput = raw.quote;
  const parsed = swapQuoteSchema.pick({ agentId: true, estimatedUsd: true }).safeParse(raw);
  if (!parsed.success || !quoteInput || typeof quoteInput !== "object") {
    return c.json<ApiResponse>({ ok: false, error: "quote and agentId are required" }, 400);
  }
  const resolution = await resolveAgentId(c, parsed.data.agentId);
  if (!resolution.ok) return resolution.response;
  const agentId = resolution.agentId;
  const walletAddress = typeof raw.agentAddress === "string" ? raw.agentAddress : "";

  try {
    const swap = adapterRegistry.swap();
    // Build the UNSIGNED intent first.
    const intent = await swap.buildSwap(
      quoteInput as Parameters<typeof swap.buildSwap>[0],
      walletAddress,
    );
    assertUnsigned(intent);

    // Fund-moving: gate BEFORE returning anything signable.
    const caps = spendCaps();
    const estimatedUsd = parsed.data.estimatedUsd ?? caps.perOrderCapUsd; // assume worst-case if unknown
    const gate = await enforceFundMovingPolicy(c, {
      agentId,
      estimatedUsd,
      perOrderCapUsd: caps.perOrderCapUsd,
      dailyCapUsd: caps.dailyCapUsd,
    });
    if (!gate.allow) {
      await auditAdapterEvent(c, "adapter.swap.policy-rejected", agentId, {
        reason: gate.reason,
        estimatedUsd,
      });
      return c.json({ code: "policy-violation", reason: gate.reason }, 400);
    }

    await auditAdapterEvent(c, "adapter.swap.build.authorized", agentId, {
      chainId: intent.chainId,
      to: intent.to,
      estimatedUsd,
    });
    // Returned artifact is UNSIGNED — caller must route it through the signing path.
    return c.json(ok({ unsignedIntent: intent }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── Earn (ERC-4626) ───────────────────────────────────────────────────────────

adapterRoutes.get("/earn/vaults", async (c) => {
  const chainIdRaw = c.req.query("chainId");
  const chainId = chainIdRaw ? Number(chainIdRaw) : Number.NaN;
  if (!Number.isInteger(chainId) || chainId <= 0) {
    return c.json<ApiResponse>({ ok: false, error: "chainId query param is required" }, 400);
  }
  try {
    const vaults = await adapterRegistry.earn().listVaults(chainId);
    return c.json(ok({ vaults }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/earn/vaults/:vault/position", async (c) => {
  const owner = c.req.query("owner") ?? "";
  try {
    const position = await adapterRegistry.earn().getPosition(c.req.param("vault"), owner);
    return c.json(ok({ position }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/earn/deposit", async (c) => {
  const raw = await safeJsonParse(c);
  const parsed = earnDepositSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolution = await resolveAgentId(c, parsed.data.agentId);
  if (!resolution.ok) return resolution.response;
  const agentId = resolution.agentId;
  const owner =
    typeof (raw as Record<string, unknown>).owner === "string"
      ? ((raw as Record<string, unknown>).owner as string)
      : "";

  try {
    const earn = adapterRegistry.earn();
    const intent = await earn.buildDeposit({
      vault: parsed.data.vault,
      assets: parsed.data.assets,
      owner,
    });
    assertUnsigned(intent);

    const caps = spendCaps();
    const estimatedUsd = parsed.data.estimatedUsd ?? caps.perOrderCapUsd;
    const gate = await enforceFundMovingPolicy(c, {
      agentId,
      estimatedUsd,
      perOrderCapUsd: caps.perOrderCapUsd,
      dailyCapUsd: caps.dailyCapUsd,
    });
    if (!gate.allow) {
      await auditAdapterEvent(c, "adapter.earn.deposit.policy-rejected", agentId, {
        reason: gate.reason,
        estimatedUsd,
      });
      return c.json({ code: "policy-violation", reason: gate.reason }, 400);
    }

    await auditAdapterEvent(c, "adapter.earn.deposit.authorized", agentId, {
      vault: parsed.data.vault,
      estimatedUsd,
    });
    return c.json(ok({ unsignedIntent: intent }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/earn/withdraw", async (c) => {
  const raw = await safeJsonParse(c);
  const parsed = earnWithdrawSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolution = await resolveAgentId(c, parsed.data.agentId);
  if (!resolution.ok) return resolution.response;
  const agentId = resolution.agentId;
  const owner =
    typeof (raw as Record<string, unknown>).owner === "string"
      ? ((raw as Record<string, unknown>).owner as string)
      : "";

  try {
    const earn = adapterRegistry.earn();
    const intent = await earn.buildWithdraw({
      vault: parsed.data.vault,
      shares: parsed.data.shares,
      owner,
    });
    assertUnsigned(intent);

    const caps = spendCaps();
    const estimatedUsd = parsed.data.estimatedUsd ?? caps.perOrderCapUsd;
    const gate = await enforceFundMovingPolicy(c, {
      agentId,
      estimatedUsd,
      perOrderCapUsd: caps.perOrderCapUsd,
      dailyCapUsd: caps.dailyCapUsd,
    });
    if (!gate.allow) {
      await auditAdapterEvent(c, "adapter.earn.withdraw.policy-rejected", agentId, {
        reason: gate.reason,
        estimatedUsd,
      });
      return c.json({ code: "policy-violation", reason: gate.reason }, 400);
    }

    await auditAdapterEvent(c, "adapter.earn.withdraw.authorized", agentId, {
      vault: parsed.data.vault,
      estimatedUsd,
    });
    return c.json(ok({ unsignedIntent: intent }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── Bridge ──────────────────────────────────────────────────────────────────

adapterRoutes.post("/bridge/quote", async (c) => {
  const parsed = bridgeQuoteSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolution = await resolveAgentId(c, parsed.data.agentId);
  if (!resolution.ok) return resolution.response;

  try {
    const quote = await adapterRegistry.bridge().getQuote({
      fromChainId: parsed.data.fromChainId,
      toChainId: parsed.data.toChainId,
      fromToken: parsed.data.fromToken,
      toToken: parsed.data.toToken,
      amount: parsed.data.amount,
      recipient: parsed.data.recipient,
      slippageBps: parsed.data.slippageBps,
    });
    return c.json(ok({ quote }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/bridge/build", async (c) => {
  const parsed = bridgeBuildSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolution = await resolveAgentId(c, parsed.data.agentId);
  if (!resolution.ok) return resolution.response;
  const agentId = resolution.agentId;

  try {
    const bridge = adapterRegistry.bridge();
    const intent = await bridge.buildBridge({
      quote: parsed.data.quote as unknown as BridgeQuote,
      owner: parsed.data.owner,
    });
    assertUnsigned(intent);

    const caps = spendCaps();
    const estimatedUsd = parsed.data.estimatedUsd ?? caps.perOrderCapUsd;
    const gate = await enforceFundMovingPolicy(c, {
      agentId,
      estimatedUsd,
      perOrderCapUsd: caps.perOrderCapUsd,
      dailyCapUsd: caps.dailyCapUsd,
    });
    if (!gate.allow) {
      await auditAdapterEvent(c, "adapter.bridge.policy-rejected", agentId, {
        reason: gate.reason,
        estimatedUsd,
      });
      return c.json({ code: "policy-violation", reason: gate.reason }, 400);
    }

    await auditAdapterEvent(c, "adapter.bridge.build.authorized", agentId, {
      fromChainId: intent.chainId,
      to: intent.to,
      estimatedUsd,
      bridge: intent.metadata,
    });
    return c.json(ok({ unsignedIntent: intent }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/bridge/sessions", async (c) => {
  const parsed = bridgeSessionSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  try {
    const session = await adapterRegistry
      .bridge()
      .createSession(parsed.data.quote as unknown as BridgeQuote, {
        tenantId: c.get("tenantId"),
        userId: resolvedUser.userId,
      });
    await auditAdapterEvent(c, "adapter.bridge.session.created", session.id, {
      quoteId: session.quoteId,
      fromChainId: session.fromChainId,
      toChainId: session.toChainId,
      recipient: session.recipient,
    });
    setNoStoreHeaders(c);
    return c.json(ok({ session }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── Exchange Embed ──────────────────────────────────────────────────────────

adapterRoutes.post("/exchange/sessions", async (c) => {
  const parsed = exchangeSessionSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  const userId = resolvedUser.userId;
  const returnUrlError = await assertAllowedAdapterReturnUrl(c, parsed.data.returnUrl);
  if (returnUrlError) return returnUrlError;
  try {
    const session = await adapterRegistry.exchange().createEmbedSession({
      userId,
      tenantId: c.get("tenantId"),
      provider: parsed.data.provider,
      returnUrl: parsed.data.returnUrl,
      scopes: parsed.data.scopes,
      locale: parsed.data.locale,
    });
    await auditAdapterEvent(c, "adapter.exchange.session.created", session.id, {
      provider: session.provider,
      userId,
      scopes: session.scopes,
    });
    setNoStoreHeaders(c);
    return c.json(ok({ session }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/exchange/sessions/:id", async (c) => {
  try {
    const session = await adapterRegistry.exchange().getEmbedSession(c.req.param("id"));
    if (!session) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
    if (session.tenantId !== c.get("tenantId")) {
      return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
    }
    const accessError = await requireAdapterUserAccess(c, session.userId);
    if (accessError) return accessError;
    setNoStoreHeaders(c);
    return c.json(ok({ session }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/exchange/accounts", async (c) => {
  const resolvedUser = await resolveAdapterUserId(c, c.req.query("userId"));
  if (!resolvedUser.ok) return resolvedUser.response;
  const userId = resolvedUser.userId;
  try {
    const accounts = await adapterRegistry.exchange().listLinkedAccounts(userId);
    return c.json(ok({ accounts }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.delete("/exchange/accounts/:id", async (c) => {
  try {
    const exchange = adapterRegistry.exchange();
    const existing = await exchange.getLinkedAccount(c.req.param("id"));
    if (!existing) return c.json<ApiResponse>({ ok: false, error: "Account not found" }, 404);
    const accessError = await requireAdapterUserAccess(c, existing.userId);
    if (accessError) return accessError;
    const account = await exchange.revokeLinkedAccount(c.req.param("id"));
    await auditAdapterEvent(c, "adapter.exchange.account.revoked", account.id, {
      provider: account.provider,
      userId: account.userId,
    });
    return c.json(ok({ account }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/exchange/orders", async (c) => {
  const parsed = exchangeOrderSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  try {
    await adapterRegistry.exchange().createOrder(parsed.data);
    return c.json<ApiResponse>({ ok: false, error: "unreachable" }, 500);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/bridge/sessions/:id", async (c) => {
  try {
    const session = await adapterRegistry.bridge().getSession(c.req.param("id"));
    if (!session) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
    const accessError = await requireAdapterSessionAccess(c, session);
    if (accessError) return accessError;
    setNoStoreHeaders(c);
    return c.json(ok({ session }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── Onramp ─────────────────────────────────────────────────────────────────

adapterRoutes.post("/onramp/quote", async (c) => {
  const parsed = onrampQuoteSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  try {
    const quote = await adapterRegistry.onramp().getQuote(parsed.data);
    return c.json(ok({ quote }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/onramp/sessions", async (c) => {
  const parsed = onrampSessionSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  try {
    const onramp = adapterRegistry.onramp();
    const quote = await onramp.getQuote(parsed.data);
    const session = await onramp.createSession(quote, parsed.data.destinationAddress, {
      tenantId: c.get("tenantId"),
      userId: resolvedUser.userId,
    });
    await auditAdapterEvent(c, "adapter.onramp.session.created", session.id, {
      fiatCurrency: session.fiatCurrency,
      fiatAmount: session.fiatAmount,
      cryptoAsset: session.cryptoAsset,
    });
    setNoStoreHeaders(c);
    return c.json(ok({ session }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/onramp/sessions/:id", async (c) => {
  try {
    const session = await adapterRegistry.onramp().getSession(c.req.param("id"));
    if (!session) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
    const accessError = await requireAdapterSessionAccess(c, session);
    if (accessError) return accessError;
    setNoStoreHeaders(c);
    return c.json(ok({ session }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── Offramp ────────────────────────────────────────────────────────────────

adapterRoutes.post("/offramp/quote", async (c) => {
  const parsed = offrampQuoteSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  try {
    const quote = await adapterRegistry.offramp().getQuote(parsed.data);
    return c.json(ok({ quote }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/offramp/sessions", async (c) => {
  const parsed = offrampSessionSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  try {
    const offramp = adapterRegistry.offramp();
    const quote = await offramp.getQuote(parsed.data);
    const session = await offramp.createSession(
      quote,
      {
        payoutMethodId: parsed.data.payoutMethodId,
      },
      { tenantId: c.get("tenantId"), userId: resolvedUser.userId },
    );
    await auditAdapterEvent(c, "adapter.offramp.session.created", session.id, {
      cryptoAsset: session.cryptoAsset,
      cryptoAmount: session.cryptoAmount,
      fiatCurrency: session.fiatCurrency,
    });
    setNoStoreHeaders(c);
    return c.json(ok({ session }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/offramp/sessions/:id", async (c) => {
  try {
    const session = await adapterRegistry.offramp().getSession(c.req.param("id"));
    if (!session) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
    const accessError = await requireAdapterSessionAccess(c, session);
    if (accessError) return accessError;
    setNoStoreHeaders(c);
    return c.json(ok({ session }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── KYC ──────────────────────────────────────────────────────────────────────

adapterRoutes.post("/kyc/verifications", async (c) => {
  const parsed = kycStartSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  const userId = resolvedUser.userId;
  try {
    const verification = await adapterRegistry.kyc().startVerification({
      userId,
      level: parsed.data.level,
    });
    await auditAdapterEvent(c, "adapter.kyc.verification.started", verification.id, {
      level: verification.level,
    });
    return c.json(ok({ verification }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/kyc/verifications/:id", async (c) => {
  try {
    const verification = await adapterRegistry.kyc().getStatus(c.req.param("id"));
    if (!verification) {
      return c.json<ApiResponse>({ ok: false, error: "Verification not found" }, 404);
    }
    const accessError = await requireAdapterUserAccess(c, verification.userId);
    if (accessError) return accessError;
    return c.json(ok({ verification }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/kyc/verifications/:id/documents", async (c) => {
  const raw = (await safeJsonParse<Record<string, unknown>>(c)) ?? {};
  const documentType = typeof raw.documentType === "string" ? raw.documentType : "";
  // Accept base64 content; decode to bytes which the adapter hashes and discards.
  const contentB64 = typeof raw.contentBase64 === "string" ? raw.contentBase64 : "";
  if (!documentType || !contentB64) {
    return c.json<ApiResponse>(
      { ok: false, error: "documentType and contentBase64 are required" },
      400,
    );
  }
  const content = decodeBase64(contentB64);
  if (!content) {
    return c.json<ApiResponse>({ ok: false, error: "contentBase64 is not valid base64" }, 400);
  }
  try {
    const kyc = adapterRegistry.kyc();
    const existing = await kyc.getStatus(c.req.param("id"));
    if (!existing) return c.json<ApiResponse>({ ok: false, error: "Verification not found" }, 404);
    const accessError = await requireAdapterUserAccess(c, existing.userId);
    if (accessError) return accessError;
    const verification = await kyc.submitDocument({
      verificationId: c.req.param("id"),
      documentType,
      content,
    });
    await auditAdapterEvent(c, "adapter.kyc.document.submitted", verification.id, {
      documentType,
      // Audit the HASH, never the contents.
      contentHash: verification.documents.at(-1)?.contentHash,
      status: verification.status,
    });
    return c.json(ok({ verification }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── TOS / consent ──────────────────────────────────────────────────────────

adapterRoutes.post("/tos/acceptances", async (c) => {
  const parsed = tosRecordSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  const userId = resolvedUser.userId;
  try {
    const acceptance = await adapterRegistry.tos().recordAcceptance({
      userId,
      documentId: parsed.data.documentId,
      version: parsed.data.version,
      // Coarse audit signal only.
      ip: c.req.header("x-forwarded-for") ?? undefined,
    });
    await auditAdapterEvent(c, "adapter.tos.acceptance.recorded", parsed.data.documentId, {
      version: acceptance.version,
    });
    return c.json(ok({ acceptance }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/tos/acceptances/:documentId", async (c) => {
  const resolvedUser = await resolveAdapterUserId(c, c.req.query("userId"));
  if (!resolvedUser.ok) return resolvedUser.response;
  const userId = resolvedUser.userId;
  try {
    const tos = adapterRegistry.tos();
    const acceptance = await tos.getAcceptance(userId, c.req.param("documentId"));
    const currentVersion = c.req.query("version");
    const accepted = currentVersion
      ? await tos.isCurrentVersionAccepted(userId, c.req.param("documentId"), currentVersion)
      : Boolean(acceptance);
    return c.json(ok({ acceptance, accepted }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

// ─── Custodial wallets ──────────────────────────────────────────────────────

adapterRoutes.post("/custodial/wallets", async (c) => {
  const parsed = custodialCreateSchema.safeParse(await safeJsonParse(c));
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const resolvedUser = await resolveAdapterUserId(c, parsed.data.userId);
  if (!resolvedUser.ok) return resolvedUser.response;
  const userId = resolvedUser.userId;
  try {
    const wallet = await adapterRegistry.custodial().createCustodialWallet({
      userId,
      chain: parsed.data.chain,
    });
    await auditAdapterEvent(c, "adapter.custodial.wallet.created", wallet.id, {
      chain: wallet.chain,
      provider: wallet.provider,
    });
    return c.json(ok({ wallet }), 201);
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.get("/custodial/wallets/:id", async (c) => {
  try {
    const wallet = await adapterRegistry.custodial().getWallet(c.req.param("id"));
    if (!wallet) return c.json<ApiResponse>({ ok: false, error: "Wallet not found" }, 404);
    const accessError = await requireAdapterUserAccess(c, wallet.userId);
    if (accessError) return accessError;
    return c.json(ok({ wallet }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});

adapterRoutes.post("/custodial/wallets/:id/sign", async (c) => {
  const raw = (await safeJsonParse<Record<string, unknown>>(c)) ?? {};
  const parsed = custodialSignSchema.safeParse({ ...raw, walletId: c.req.param("id") });
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  try {
    const custodial = adapterRegistry.custodial();
    const wallet = await custodial.getWallet(parsed.data.walletId);
    if (!wallet) return c.json<ApiResponse>({ ok: false, error: "Wallet not found" }, 404);
    const accessError = await requireAdapterUserAccess(c, wallet.userId);
    if (accessError) return accessError;
    const result = await custodial.requestSignature({
      walletId: parsed.data.walletId,
      payload: parsed.data.payload,
      scheme: parsed.data.scheme,
    });
    // CRITICAL: the mock can ONLY return the fail-closed result. Map a refusal to
    // 501 and NEVER expose a fabricated signature.
    if (!result.ok) {
      await auditAdapterEvent(c, "adapter.custodial.sign.unavailable", parsed.data.walletId, {
        provider: result.provider,
      });
      return c.json<ApiResponse>({ ok: false, error: result.reason }, 501);
    }
    // Only reachable with a real configured custodian.
    await auditAdapterEvent(c, "adapter.custodial.sign.completed", parsed.data.walletId, {
      provider: result.provider,
    });
    setNoStoreHeaders(c);
    return c.json(ok({ signature: result.signature, provider: result.provider }));
  } catch (err) {
    return handleAdapterError(c, err);
  }
});
