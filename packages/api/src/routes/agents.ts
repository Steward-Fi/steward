/**
 * Agent CRUD, batch creation, token generation, and policy management routes.
 *
 * Mount: app.route("/agents", agentRoutes)
 */

import { agentPolicies, isPersistedPolicyType, toPersistedPolicyRule } from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { trackAuditEvent, writeAuditEvent } from "../services/audit";
import {
  AGENT_TOKEN_EXPIRY,
  type AgentIdentity,
  type ApiResponse,
  type AppVariables,
  agents,
  agentWallets,
  approvalQueue,
  createAgentToken,
  db,
  encryptedChainKeys,
  encryptedKeys,
  ensureAgentForTenant,
  isNonEmptyString,
  isValidAgentId,
  type PolicyRule,
  parseAgentTokenScopes,
  policies,
  requireAgentAccess,
  requireTenantLevel,
  safeJsonParse,
  sanitizeErrorMessage,
  toPolicyRule,
  transactions,
  vault,
} from "../services/context";

export const agentRoutes = new Hono<{ Variables: AppVariables }>();

const TRADE_POLICY_DEFAULTS = {
  dailyCap: 1000,
  perOrderCap: 500,
  leverageCap: 10,
  allowedAssets: ["BTC", "ETH", "BNB"],
  allowedVenues: ["hyperliquid"],
} as const;

const TRADE_POLICY_LAYER_1_MAX = {
  dailyCap: 50_000,
  perOrderCap: 10_000,
  leverageCap: 50,
} as const;

type AgentTradePolicyResponse = {
  agentId: string;
  dailyCap: number;
  perOrderCap: number;
  leverageCap: number;
  allowedAssets: string[];
  allowedVenues: string[];
  updatedAt: string;
  updatedBy: string;
  updatedReason: string | null;
};

type AgentTradePolicySnapshot = Omit<
  AgentTradePolicyResponse,
  "updatedAt" | "updatedBy" | "updatedReason"
>;

type AgentTradePolicyPatch = {
  dailyCap?: unknown;
  perOrderCap?: unknown;
  leverageCap?: unknown;
  allowedAssets?: unknown;
  allowedVenues?: unknown;
  reason?: unknown;
  multisigApproval?: unknown;
};

function parseNumericPolicyValue(value: string | number): number {
  return typeof value === "number" ? value : Number(value);
}

function policyRowToResponse(row: typeof agentPolicies.$inferSelect): AgentTradePolicyResponse {
  return {
    agentId: row.agentId,
    dailyCap: parseNumericPolicyValue(row.dailyCapUsd),
    perOrderCap: parseNumericPolicyValue(row.perOrderCapUsd),
    leverageCap: parseNumericPolicyValue(row.leverageCap),
    allowedAssets: row.allowedAssets,
    allowedVenues: row.allowedVenues,
    updatedAt: row.updatedAt.toISOString(),
    updatedBy: row.updatedBy,
    updatedReason: row.updatedReason ?? null,
  };
}

function defaultPolicySnapshot(agentId: string): AgentTradePolicySnapshot {
  return {
    agentId,
    dailyCap: TRADE_POLICY_DEFAULTS.dailyCap,
    perOrderCap: TRADE_POLICY_DEFAULTS.perOrderCap,
    leverageCap: TRADE_POLICY_DEFAULTS.leverageCap,
    allowedAssets: [...TRADE_POLICY_DEFAULTS.allowedAssets],
    allowedVenues: [...TRADE_POLICY_DEFAULTS.allowedVenues],
  };
}

function policyDiff(before: AgentTradePolicySnapshot, after: AgentTradePolicyResponse) {
  return {
    dailyCap: { before: before.dailyCap, after: after.dailyCap },
    perOrderCap: { before: before.perOrderCap, after: after.perOrderCap },
    leverageCap: { before: before.leverageCap, after: after.leverageCap },
    allowedAssets: { before: before.allowedAssets, after: after.allowedAssets },
    allowedVenues: { before: before.allowedVenues, after: after.allowedVenues },
  };
}

function validatePolicyNumber(
  name: "dailyCap" | "perOrderCap" | "leverageCap",
  value: unknown,
): number | string {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return `${name} must be a positive number`;
  }
  if (value > TRADE_POLICY_LAYER_1_MAX[name]) {
    return `${name} exceeds platform ceiling ${TRADE_POLICY_LAYER_1_MAX[name]}`;
  }
  return value;
}

function validatePolicyStringArray(name: string, value: unknown): string[] | string {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    return `${name} must be a non-empty string array`;
  }
  return [...new Set(value)];
}

// ─── Create agent ─────────────────────────────────────────────────────────────

agentRoutes.post("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent creation requires tenant-level authentication",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    id: string;
    name: string;
    platformId?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isValidAgentId(body.id)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)",
      },
      400,
    );
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>(
      { ok: false, error: "name is required and must be a non-empty string" },
      400,
    );
  }

  try {
    const identity = await vault.createAgent(tenantId, body.id, body.name, body.platformId);
    trackAuditEvent({
      tenantId,
      actorType: "user",
      actorId: tenantId,
      action: "agent.create",
      resourceType: "agent",
      resourceId: body.id,
      metadata: { name: body.name, platformId: body.platformId ?? null },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: identity });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── List agents ──────────────────────────────────────────────────────────────

agentRoutes.get("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent listing requires tenant-level authentication",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const tenantAgents = await vault.listAgentsByTenant(tenantId);
  return c.json<ApiResponse<AgentIdentity[]>>({ ok: true, data: tenantAgents });
});

// ─── Agent token generation ───────────────────────────────────────────────────

agentRoutes.post("/:agentId/token", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Agent tokens cannot generate other agent tokens" },
      403,
    );
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{ expiresIn?: string; scopes?: string[] | string }>(c);
  const expiresIn = body?.expiresIn || AGENT_TOKEN_EXPIRY;
  const scopes = parseAgentTokenScopes(body?.scopes ?? c.req.query("scopes"));
  if (!scopes) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid scopes — supported values: agent, api:proxy" },
      400,
    );
  }

  try {
    const token = await createAgentToken(agentId, tenantId, expiresIn, scopes);
    trackAuditEvent({
      tenantId,
      actorType: "user",
      actorId: tenantId,
      action: "agent.token.create",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { scopes, expiresIn },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return c.json<
      ApiResponse<{
        token: string;
        agentId: string;
        tenantId: string;
        scope: string;
        scopes: string[];
        expiresIn: string;
      }>
    >({
      ok: true,
      data: { token, agentId, tenantId, scope: "agent", scopes, expiresIn },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Failed to generate agent token for ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: "Failed to generate token" }, 500);
  }
});

// Create venue-scoped wallet (Sprint 4)
//
// POST /agents/:agentId/wallets
// Body: { venue: string, chainType: "evm" | "solana", purpose?: string }
//
// Creates a venue-scoped wallet under (agentId, chainFamily, venue).
// Required before trading on a venue: /v1/trade/sessions and
// /v1/trade/orders/hyperliquid both call vault.getWallet({ agentId, venue })
// and reject if no row exists.
//
// Tenant-level auth required (provisions wallets, not Sol's own JWT).

agentRoutes.post("/:agentId/wallets", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Venue wallet creation requires tenant-level authentication" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    venue?: string;
    chainType?: "evm" | "solana";
    purpose?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isNonEmptyString(body.venue)) {
    return c.json<ApiResponse>({ ok: false, error: "venue is required" }, 400);
  }
  if (body.chainType !== "evm" && body.chainType !== "solana") {
    return c.json<ApiResponse>({ ok: false, error: 'chainType must be "evm" or "solana"' }, 400);
  }

  try {
    const wallet = await vault.createWallet({
      agentId,
      venue: body.venue,
      chainType: body.chainType,
      purpose: body.purpose,
    });
    trackAuditEvent({
      tenantId,
      actorType: "user",
      actorId: tenantId,
      action: "agent.wallet.create",
      resourceType: "agent",
      resourceId: agentId,
      metadata: {
        venue: body.venue,
        chainType: body.chainType,
        purpose: body.purpose ?? null,
        address: wallet.address,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return c.json<
      ApiResponse<{
        agentId: string;
        chainFamily: "evm" | "solana";
        venue: string;
        purpose: string | null;
        address: string;
      }>
    >({ ok: true, data: wallet });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Agent trade policy ──────────────────────────────────────────────────────

agentRoutes.get("/:agentId/policy", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const [policy] = await db
    .select()
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentId, agentId), eq(agentPolicies.tenantId, tenantId)));

  if (!policy) {
    return c.json<ApiResponse<{ defaults: typeof TRADE_POLICY_DEFAULTS; message: string }>>(
      {
        ok: false,
        error: "Agent policy not found",
        data: {
          defaults: TRADE_POLICY_DEFAULTS,
          message: "No agent policy row exists. Defaults apply until PUT creates one.",
        },
      },
      404,
    );
  }

  return c.json<ApiResponse<AgentTradePolicyResponse>>({
    ok: true,
    data: policyRowToResponse(policy),
  });
});

agentRoutes.put("/:agentId/policy", async (c) => {
  // SECURITY: policy/cap changes are PATRON/OWNER-only, never the agent itself.
  // An agent must NOT be able to raise its own caps, leverage, or withdrawal
  // allowlist — that would defeat the entire policy system. Require tenant-level
  // auth (tenant API key / owner session); reject agent-token auth.
  if (c.get("authType") === "agent-token") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Forbidden: agents cannot modify their own policy; patron/owner auth required",
      },
      403,
    );
  }
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy updates require patron/owner (tenant-level) authentication" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<AgentTradePolicyPatch>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (typeof body.reason !== "string" || body.reason.trim().length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "reason is required" }, 400);
  }

  const [existing] = await db
    .select()
    .from(agentPolicies)
    .where(and(eq(agentPolicies.agentId, agentId), eq(agentPolicies.tenantId, tenantId)));
  const before = existing ? policyRowToResponse(existing) : defaultPolicySnapshot(agentId);

  const nextDailyCap =
    body.dailyCap === undefined ? before.dailyCap : validatePolicyNumber("dailyCap", body.dailyCap);
  const nextPerOrderCap =
    body.perOrderCap === undefined
      ? before.perOrderCap
      : validatePolicyNumber("perOrderCap", body.perOrderCap);
  const nextLeverageCap =
    body.leverageCap === undefined
      ? before.leverageCap
      : validatePolicyNumber("leverageCap", body.leverageCap);
  const nextAllowedAssets =
    body.allowedAssets === undefined
      ? before.allowedAssets
      : validatePolicyStringArray("allowedAssets", body.allowedAssets);
  const nextAllowedVenues =
    body.allowedVenues === undefined
      ? before.allowedVenues
      : validatePolicyStringArray("allowedVenues", body.allowedVenues);

  const validationError = [
    nextDailyCap,
    nextPerOrderCap,
    nextLeverageCap,
    nextAllowedAssets,
    nextAllowedVenues,
  ].find((value) => typeof value === "string");
  if (typeof validationError === "string") {
    return c.json<ApiResponse>({ ok: false, error: validationError }, 400);
  }

  const dailyCapValue = nextDailyCap as number;
  const perOrderCapValue = nextPerOrderCap as number;
  const leverageCapValue = nextLeverageCap as number;
  const allowedAssetsValue = nextAllowedAssets as string[];
  const allowedVenuesValue = nextAllowedVenues as string[];

  if (perOrderCapValue > dailyCapValue) {
    return c.json<ApiResponse>({ ok: false, error: "perOrderCap cannot exceed dailyCap" }, 400);
  }

  const updatedBy = c.get("agentSubject") ?? `agent:${agentId}`;
  const updatedReason = body.reason.trim();
  const [upserted] = await db
    .insert(agentPolicies)
    .values({
      agentId,
      tenantId,
      dailyCapUsd: String(dailyCapValue),
      perOrderCapUsd: String(perOrderCapValue),
      leverageCap: String(leverageCapValue),
      allowedAssets: allowedAssetsValue,
      allowedVenues: allowedVenuesValue,
      updatedAt: new Date(),
      updatedBy,
      updatedReason,
    })
    .onConflictDoUpdate({
      target: agentPolicies.agentId,
      set: {
        dailyCapUsd: String(dailyCapValue),
        perOrderCapUsd: String(perOrderCapValue),
        leverageCap: String(leverageCapValue),
        allowedAssets: allowedAssetsValue,
        allowedVenues: allowedVenuesValue,
        updatedAt: new Date(),
        updatedBy,
        updatedReason,
      },
    })
    .returning();

  const after = policyRowToResponse(upserted);
  const diff = policyDiff(before, after);
  await writeAuditEvent({
    tenantId,
    actorType: "agent",
    actorId: updatedBy,
    action: "agent.policy.updated",
    resourceType: "agent_policy",
    resourceId: agentId,
    metadata: {
      agentId,
      reason: updatedReason,
      diff,
      before,
      after,
      multisigApprovalProvided: body.multisigApproval !== undefined,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  return c.json<
    ApiResponse<{ policy: AgentTradePolicyResponse; diff: ReturnType<typeof policyDiff> }>
  >({
    ok: true,
    data: { policy: after, diff },
  });
});

// ─── Get agent ────────────────────────────────────────────────────────────────

agentRoutes.get("/:agentId", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agent = await vault.getAgent(tenantId, c.req.param("agentId"));
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  return c.json<ApiResponse<AgentIdentity>>({ ok: true, data: agent });
});

// ─── Delete agent ─────────────────────────────────────────────────────────────

agentRoutes.delete("/:agentId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Agent deletion requires tenant-level authentication",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    await db.transaction(async (tx) => {
      // Cascade delete in dependency order
      await tx.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
      await tx.delete(transactions).where(eq(transactions.agentId, agentId));
      await tx.delete(policies).where(eq(policies.agentId, agentId));
      await tx.delete(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, agentId));
      await tx.delete(encryptedKeys).where(eq(encryptedKeys.agentId, agentId));
      await tx.delete(agentWallets).where(eq(agentWallets.agentId, agentId));
      await tx.delete(agents).where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    });

    trackAuditEvent({
      tenantId,
      actorType: "user",
      actorId: tenantId,
      action: "agent.delete",
      resourceType: "agent",
      resourceId: agentId,
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    return c.json<ApiResponse<{ deleted: string }>>({
      ok: true,
      data: { deleted: agentId },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Failed to delete agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Agent balance ────────────────────────────────────────────────────────────

agentRoutes.get("/:agentId/balance", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const chainIdParam = c.req.query("chainId");
  const chainId = chainIdParam ? parseInt(chainIdParam, 10) : undefined;

  try {
    const balance = await vault.getBalance(tenantId, agentId, chainId);
    return c.json<ApiResponse>({
      ok: true,
      data: {
        agentId,
        walletAddress: balance.walletAddress,
        balances: {
          native: balance.native.toString(),
          nativeFormatted: balance.nativeFormatted,
          chainId: balance.chainId,
          symbol: balance.symbol,
        },
      },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Agent token balances (ERC-20) ────────────────────────────────────────────

agentRoutes.get("/:agentId/tokens", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const chainIdParam = c.req.query("chainId");
  const chainId = chainIdParam ? parseInt(chainIdParam, 10) : undefined;
  const tokensParam = c.req.query("tokens");
  const customTokens = tokensParam
    ? tokensParam
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
    : undefined;

  try {
    // Fetch native balance
    const balance = await vault.getBalance(tenantId, agentId, chainId);

    // Fetch ERC-20 token balances
    const tokenBalances = await vault.getTokenBalances(tenantId, agentId, chainId, customTokens);

    return c.json<ApiResponse>({
      ok: true,
      data: {
        agentId,
        walletAddress: balance.walletAddress,
        chainId: balance.chainId,
        native: {
          symbol: balance.symbol,
          balance: balance.native.toString(),
          formatted: balance.nativeFormatted,
        },
        tokens: tokenBalances,
      },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Batch create agents ──────────────────────────────────────────────────────

agentRoutes.post("/batch", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Batch agent creation requires tenant-level authentication",
      },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    agents: Array<{ id: string; name: string; platformId?: string }>;
    applyPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!Array.isArray(body.agents) || body.agents.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "agents array is required and must not be empty" },
      400,
    );
  }

  for (const agentSpec of body.agents) {
    if (!isValidAgentId(agentSpec.id)) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `Invalid agent id "${String(agentSpec.id)}" — must be 1-128 alphanumeric characters (plus _ - . :)`,
        },
        400,
      );
    }
    if (!isNonEmptyString(agentSpec.name)) {
      return c.json<ApiResponse>(
        { ok: false, error: `Agent "${agentSpec.id}" is missing a name` },
        400,
      );
    }
  }

  const created: AgentIdentity[] = [];
  const errors: Array<{ id: string; error: string }> = [];

  for (const agentSpec of body.agents) {
    try {
      const identity = await vault.createAgent(
        tenantId,
        agentSpec.id,
        agentSpec.name,
        agentSpec.platformId,
      );

      if (body.applyPolicies && body.applyPolicies.length > 0) {
        const persistedPolicies = body.applyPolicies.map(toPersistedPolicyRule);
        await db.delete(policies).where(eq(policies.agentId, agentSpec.id));
        await db.insert(policies).values(
          persistedPolicies.map((policy) => ({
            id: policy.id || crypto.randomUUID(),
            agentId: agentSpec.id,
            type: policy.type,
            enabled: policy.enabled,
            config: policy.config,
          })),
        );
      }

      created.push(identity);
      trackAuditEvent({
        tenantId,
        actorType: "user",
        actorId: tenantId,
        action: "agent.create",
        resourceType: "agent",
        resourceId: agentSpec.id,
        metadata: {
          name: agentSpec.name,
          platformId: agentSpec.platformId ?? null,
          batch: true,
          appliedPolicyCount: body.applyPolicies?.length ?? 0,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (e: unknown) {
      errors.push({
        id: agentSpec.id,
        error: e instanceof Error ? e.message : "Unknown error",
      });
    }
  }

  return c.json<
    ApiResponse<{
      created: AgentIdentity[];
      errors: Array<{ id: string; error: string }>;
    }>
  >({
    ok: true,
    data: { created, errors },
  });
});

// ─── Get agent policies ───────────────────────────────────────────────────────

agentRoutes.get("/:agentId/policies", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const agentPolicies = await db.select().from(policies).where(eq(policies.agentId, agentId));

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: agentPolicies.map(toPolicyRule),
  });
});

// ─── Update agent policies ────────────────────────────────────────────────────

agentRoutes.put("/:agentId/policies", async (c) => {
  // SECURITY: policy/cap changes are PATRON/OWNER-only, never the agent itself.
  // See PUT /:agentId/policy above — an agent raising its own policy rules
  // (caps, leverage, withdrawal allowlist) would defeat the policy system.
  if (c.get("authType") === "agent-token") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Forbidden: agents cannot modify their own policies; patron/owner auth required",
      },
      403,
    );
  }
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy updates require patron/owner (tenant-level) authentication" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const nextPolicies = await safeJsonParse<PolicyRule[]>(c);

  if (!nextPolicies || !Array.isArray(nextPolicies)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Request body must be a JSON array of policies" },
      400,
    );
  }

  const validPolicyTypes = [
    "spending-limit",
    "approved-addresses",
    "auto-approve-threshold",
    "time-window",
    "rate-limit",
    "allowed-chains",
    "reputation-threshold",
    "reputation-scaling",
  ] as const;
  for (const policy of nextPolicies) {
    if (!isNonEmptyString(policy.type)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Each policy must have a non-empty 'type' field" },
        400,
      );
    }
    if (!isPersistedPolicyType(policy.type)) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `Unknown policy type "${policy.type}" — supported types: ${validPolicyTypes.join(", ")}`,
        },
        400,
      );
    }
    if (typeof policy.enabled !== "boolean") {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `Policy "${policy.id || policy.type}": enabled must be a boolean`,
        },
        400,
      );
    }
    if (
      typeof policy.config !== "object" ||
      policy.config === null ||
      Array.isArray(policy.config)
    ) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `Policy "${policy.id || policy.type}": config must be an object`,
        },
        400,
      );
    }
  }

  await db.delete(policies).where(eq(policies.agentId, agentId));

  if (nextPolicies.length > 0) {
    const persistedPolicies = nextPolicies.map(toPersistedPolicyRule);
    await db.insert(policies).values(
      persistedPolicies.map((policy) => ({
        id: policy.id || crypto.randomUUID(),
        agentId,
        type: policy.type,
        enabled: policy.enabled,
        config: policy.config,
      })),
    );
  }

  const storedPolicies = await db.select().from(policies).where(eq(policies.agentId, agentId));

  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: tenantId,
    action: "agent.policies.update",
    resourceType: "agent",
    resourceId: agentId,
    metadata: {
      count: storedPolicies.length,
      types: storedPolicies.map((p) => p.type),
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  return c.json<ApiResponse<PolicyRule[]>>({
    ok: true,
    data: storedPolicies.map(toPolicyRule),
  });
});
