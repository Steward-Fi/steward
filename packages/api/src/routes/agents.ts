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
  agentKeyQuorums,
  agentSigners,
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
import { createSignerCredentialHash } from "../services/signer-credentials";

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

const MAX_AGENT_SIGNER_PERMISSIONS = 32;
const MAX_AGENT_SIGNER_METADATA_BYTES = 8_192;
const MAX_AGENT_KEY_QUORUM_MEMBERS = 32;
const AGENT_SIGNER_TYPES = new Set(["owner", "delegated", "service", "quorum_member"]);
const AGENT_SIGNER_SUBJECT_TYPES = new Set(["user", "wallet", "api_key", "external"]);
const AGENT_SIGNER_STATUSES = new Set(["active", "paused", "revoked"]);
const AGENT_KEY_QUORUM_STATUSES = new Set(["active", "paused", "revoked"]);
const RESERVED_SIGNER_METADATA_KEYS = new Set([
  "credentialHash",
  "credentialCreatedAt",
  "credentialLastUsedAt",
]);

type AgentSignerRow = typeof agentSigners.$inferSelect;
type AgentKeyQuorumRow = typeof agentKeyQuorums.$inferSelect;

async function writeAgentAudit(
  c: Parameters<typeof requireTenantLevel>[0],
  event: {
    tenantId: string;
    action: string;
    resourceType: string;
    resourceId: string;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await writeAuditEvent({
    tenantId: event.tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? event.tenantId,
    action: event.action,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    metadata: event.metadata,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

function requireTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

async function deleteAgentSignerRow(signerId: string): Promise<void> {
  await db.delete(agentSigners).where(eq(agentSigners.id, signerId));
}

async function restoreAgentSigner(row: AgentSignerRow): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(agentSigners).where(eq(agentSigners.id, row.id));
    await tx.insert(agentSigners).values(row);
  });
}

async function deleteAgentKeyQuorumRow(quorumId: string): Promise<void> {
  await db.delete(agentKeyQuorums).where(eq(agentKeyQuorums.id, quorumId));
}

async function restoreAgentKeyQuorum(row: AgentKeyQuorumRow): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(agentKeyQuorums).where(eq(agentKeyQuorums.id, row.id));
    await tx.insert(agentKeyQuorums).values(row);
  });
}

function normalizeOptionalText(value: unknown, field: string, maxLength: number): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${field} must be a non-empty string`);
  }
  const normalized = value.trim();
  if (normalized.length > maxLength) throw new Error(`${field} is too long`);
  return normalized;
}

function normalizeRequiredText(value: unknown, field: string, maxLength: number): string {
  const normalized = normalizeOptionalText(value, field, maxLength);
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function normalizeSignerPermissions(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("permissions must be an array of strings");
  if (value.length > MAX_AGENT_SIGNER_PERMISSIONS) {
    throw new Error(`permissions cannot contain more than ${MAX_AGENT_SIGNER_PERMISSIONS} entries`);
  }
  return [
    ...new Set(
      value.map((permission) => {
        if (typeof permission !== "string" || !permission.trim()) {
          throw new Error("permissions must be non-empty strings");
        }
        const normalized = permission.trim();
        if (normalized.length > 128) {
          throw new Error("permissions entries must be 128 chars or less");
        }
        return normalized;
      }),
    ),
  ];
}

function hasRecentSessionMfa(c: Parameters<typeof requireTenantLevel>[0], maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function requireRecentAdminMfa(c: Parameters<typeof requireTenantLevel>[0], reason: string) {
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

function normalizeSignerMetadata(value: unknown): Record<string, unknown> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("metadata must be an object");
  }
  if (JSON.stringify(value).length > MAX_AGENT_SIGNER_METADATA_BYTES) {
    throw new Error(`metadata cannot exceed ${MAX_AGENT_SIGNER_METADATA_BYTES} bytes`);
  }
  for (const key of Object.keys(value)) {
    if (RESERVED_SIGNER_METADATA_KEYS.has(key)) {
      throw new Error(`metadata.${key} is reserved and cannot be set by clients`);
    }
  }
  return value as Record<string, unknown>;
}

function mergeSignerMetadataPreservingReserved(
  existing: unknown,
  next: Record<string, unknown>,
): Record<string, unknown> {
  const merged = { ...next };
  if (existing && typeof existing === "object" && !Array.isArray(existing)) {
    for (const key of RESERVED_SIGNER_METADATA_KEYS) {
      const value = (existing as Record<string, unknown>)[key];
      if (value !== undefined) merged[key] = value;
    }
  }
  return merged;
}

function normalizeQuorumMemberSignerIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("memberSignerIds must be a non-empty array");
  }
  if (value.length > MAX_AGENT_KEY_QUORUM_MEMBERS) {
    throw new Error(`memberSignerIds cannot contain more than ${MAX_AGENT_KEY_QUORUM_MEMBERS}`);
  }
  return [
    ...new Set(
      value.map((id) => {
        if (typeof id !== "string" || !id.trim()) {
          throw new Error("memberSignerIds must contain non-empty strings");
        }
        return id.trim();
      }),
    ),
  ];
}

function normalizeQuorumThreshold(value: unknown, memberCount: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new Error("threshold must be a positive integer");
  }
  const threshold = Number(value);
  if (threshold > memberCount) throw new Error("threshold cannot exceed member count");
  return threshold;
}

async function validateQuorumMembers(
  tenantId: string,
  agentId: string,
  memberSignerIds: string[],
): Promise<string | null> {
  const rows = await db
    .select({ id: agentSigners.id, status: agentSigners.status })
    .from(agentSigners)
    .where(and(eq(agentSigners.tenantId, tenantId), eq(agentSigners.agentId, agentId)));
  const byId = new Map(rows.map((row) => [row.id, row.status]));
  for (const id of memberSignerIds) {
    const status = byId.get(id);
    if (!status) return `memberSignerIds contains unknown signer ${id}`;
    if (status !== "active") return `memberSignerIds contains inactive signer ${id}`;
  }
  return null;
}

function toAgentKeyQuorumResponse(row: typeof agentKeyQuorums.$inferSelect) {
  return {
    id: row.id,
    tenantId: row.tenantId,
    agentId: row.agentId,
    name: row.name,
    threshold: row.threshold,
    memberSignerIds: row.memberSignerIds,
    permissions: row.permissions,
    metadata: row.metadata,
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function createSignerSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `stwd_signer_${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function redactSignerMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
  const {
    credentialHash: _credentialHash,
    credentialCreatedAt: _credentialCreatedAt,
    credentialLastUsedAt: _credentialLastUsedAt,
    ...safeMetadata
  } = metadata;
  return safeMetadata;
}

function toAgentSignerResponse(row: typeof agentSigners.$inferSelect) {
  return {
    id: row.id,
    tenantId: row.tenantId,
    agentId: row.agentId,
    signerType: row.signerType,
    subjectType: row.subjectType,
    subjectId: row.subjectId,
    address: row.address,
    chainFamily: row.chainFamily,
    label: row.label,
    permissions: row.permissions,
    metadata: redactSignerMetadata(row.metadata),
    hasCredential: typeof row.metadata.credentialHash === "string",
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
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

// ─── Agent owners and delegated signers ──────────────────────────────────────

agentRoutes.get("/:agentId/signers", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer inventory requires owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const status = c.req.query("status");
  if (status && !AGENT_SIGNER_STATUSES.has(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid signer status filter" }, 400);
  }

  const conditions = [eq(agentSigners.tenantId, tenantId), eq(agentSigners.agentId, agentId)];
  if (status) conditions.push(eq(agentSigners.status, status));
  const rows = await db
    .select()
    .from(agentSigners)
    .where(and(...conditions))
    .orderBy(agentSigners.createdAt);

  return c.json<ApiResponse>({
    ok: true,
    data: { signers: rows.map(toAgentSignerResponse) },
  });
});

agentRoutes.post("/:agentId/signers", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer creation requires owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (
    body.credentialSecret !== undefined &&
    body.credentialSecret !== null &&
    body.credentialSecret !== ""
  ) {
    return c.json<ApiResponse>(
      { ok: false, error: "credentialSecret is server-generated; use issueCredential=true" },
      400,
    );
  }

  const credentialRequested = body.issueCredential === true;
  if (credentialRequested) {
    const mfaResponse = requireRecentAdminMfa(c, "Signer credential issuance");
    if (mfaResponse) return mfaResponse;
  }

  let signerType: string;
  let subjectType: string;
  let subjectId: string;
  let address: string | null;
  let chainFamily: "evm" | "solana" | null;
  let label: string | null;
  let permissions: string[];
  let metadata: Record<string, unknown>;
  let credentialSecret: string | null;
  try {
    signerType = normalizeRequiredText(body.signerType, "signerType", 32);
    subjectType = normalizeRequiredText(body.subjectType, "subjectType", 32);
    subjectId = normalizeRequiredText(body.subjectId, "subjectId", 255);
    if (!AGENT_SIGNER_TYPES.has(signerType)) {
      throw new Error("signerType must be one of: owner, delegated, service, quorum_member");
    }
    if (!AGENT_SIGNER_SUBJECT_TYPES.has(subjectType)) {
      throw new Error("subjectType must be one of: user, wallet, api_key, external");
    }
    address = normalizeOptionalText(body.address, "address", 128);
    if (
      address &&
      !/^0x[a-fA-F0-9]{40}$/.test(address) &&
      !/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(address)
    ) {
      throw new Error("address must be an EVM or Solana address");
    }
    chainFamily =
      body.chainFamily === undefined || body.chainFamily === null
        ? null
        : body.chainFamily === "evm" || body.chainFamily === "solana"
          ? body.chainFamily
          : (() => {
              throw new Error("chainFamily must be evm or solana");
            })();
    label = normalizeOptionalText(body.label, "label", 255);
    permissions = normalizeSignerPermissions(body.permissions);
    metadata = normalizeSignerMetadata(body.metadata);
    credentialSecret = body.issueCredential === true ? createSignerSecret() : null;
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid signer payload" },
      400,
    );
  }

  const [existingSigner] = await db
    .select({ id: agentSigners.id })
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
        eq(agentSigners.subjectType, subjectType),
        eq(agentSigners.subjectId, subjectId),
      ),
    );
  if (existingSigner) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer already exists for this agent and subject" },
      409,
    );
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.signer.create.authorized",
    resourceType: "agent",
    resourceId: agentId,
    metadata: { signerType, subjectType, subjectId, permissions },
  });

  try {
    const storedMetadata = {
      ...metadata,
      ...(credentialSecret
        ? {
            credentialHash: await createSignerCredentialHash(credentialSecret),
            credentialCreatedAt: new Date().toISOString(),
          }
        : {}),
    };
    const [row] = await db
      .insert(agentSigners)
      .values({
        tenantId,
        agentId,
        signerType,
        subjectType,
        subjectId,
        address,
        chainFamily,
        label,
        permissions,
        metadata: storedMetadata,
        status: "active",
        createdBy: c.get("userId") ?? c.get("authType") ?? null,
      })
      .returning();

    try {
      await writeAgentAudit(c, {
        tenantId,
        action: "agent.signer.create",
        resourceType: "agent_signer",
        resourceId: row.id,
        metadata: { agentId, signerType, subjectType, subjectId },
      });
    } catch (error) {
      await deleteAgentSignerRow(row.id);
      throw error;
    }

    return c.json<ApiResponse>(
      {
        ok: true,
        data: {
          ...toAgentSignerResponse(row),
          ...(credentialSecret ? { credentialSecret } : {}),
        },
      },
      201,
    );
  } catch (error) {
    const message = sanitizeErrorMessage(error);
    const duplicateSigner =
      message.includes("agent_signers_agent_subject_idx") ||
      message.toLowerCase().includes("duplicate key") ||
      message.toLowerCase().includes("unique constraint");
    return c.json<ApiResponse>(
      {
        ok: false,
        error: duplicateSigner ? "Signer already exists for this agent and subject" : message,
      },
      duplicateSigner ? 409 : 500,
    );
  }
});

agentRoutes.patch("/:agentId/signers/:signerId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer updates require owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const signerId = c.req.param("signerId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [existingSigner] = await db
    .select()
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    );
  if (!existingSigner) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const updates: Partial<typeof agentSigners.$inferInsert> = {};
  let privilegedSignerUpdate = false;
  try {
    if (body.signerType !== undefined) {
      const signerType = normalizeRequiredText(body.signerType, "signerType", 32);
      if (!AGENT_SIGNER_TYPES.has(signerType)) {
        throw new Error("signerType must be one of: owner, delegated, service, quorum_member");
      }
      if (signerType !== existingSigner.signerType) privilegedSignerUpdate = true;
      updates.signerType = signerType;
    }
    if (body.address !== undefined) {
      const address = normalizeOptionalText(body.address, "address", 128);
      if (
        address &&
        !/^0x[a-fA-F0-9]{40}$/.test(address) &&
        !/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(address)
      ) {
        throw new Error("address must be an EVM or Solana address");
      }
      // Re-pointing the resolvable address of an active signer is functionally
      // credential takeover for any flow that resolves authority through
      // agentSigners.address, so this needs the same recent-MFA gate as a
      // permissions/status change. Matches the key-quorum PATCH model.
      if ((address ?? null) !== (existingSigner.address ?? null)) privilegedSignerUpdate = true;
      updates.address = address;
    }
    if (body.chainFamily !== undefined) {
      const chainFamily =
        body.chainFamily === null
          ? null
          : body.chainFamily === "evm" || body.chainFamily === "solana"
            ? body.chainFamily
            : (() => {
                throw new Error("chainFamily must be evm or solana");
              })();
      if ((chainFamily ?? null) !== (existingSigner.chainFamily ?? null)) {
        privilegedSignerUpdate = true;
      }
      updates.chainFamily = chainFamily;
    }
    if (body.label !== undefined) updates.label = normalizeOptionalText(body.label, "label", 255);
    if (body.permissions !== undefined) {
      privilegedSignerUpdate = true;
      updates.permissions = normalizeSignerPermissions(body.permissions);
    }
    if (body.metadata !== undefined) {
      privilegedSignerUpdate = true;
      updates.metadata = mergeSignerMetadataPreservingReserved(
        existingSigner.metadata,
        normalizeSignerMetadata(body.metadata),
      );
    }
    if (body.status !== undefined) {
      const status = normalizeRequiredText(body.status, "status", 32);
      if (!AGENT_SIGNER_STATUSES.has(status)) {
        throw new Error("status must be one of: active, paused, revoked");
      }
      if (status !== existingSigner.status) privilegedSignerUpdate = true;
      updates.status = status;
    }
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid signer update" },
      400,
    );
  }

  if (Object.keys(updates).length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "No signer updates provided" }, 400);
  }
  // Single MFA gate for any privileged field change, mirroring the key-quorum PATCH
  // handler. Cosmetic-only updates (label) are exempt; everything that affects
  // signer authority requires a recent step-up.
  if (privilegedSignerUpdate) {
    const mfaResponse = requireRecentAdminMfa(c, "Signer updates");
    if (mfaResponse) return mfaResponse;
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.signer.update.authorized",
    resourceType: "agent_signer",
    resourceId: signerId,
    metadata: { agentId, fields: Object.keys(updates) },
  });

  const [row] = await db
    .update(agentSigners)
    .set(updates)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    )
    .returning();

  if (!row) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.signer.update",
      resourceType: "agent_signer",
      resourceId: row.id,
      metadata: { agentId, status: row.status },
    });
  } catch (error) {
    await restoreAgentSigner(existingSigner);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentSignerResponse(row) });
});

agentRoutes.delete("/:agentId/signers/:signerId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Signer revocation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Signer revocation");
  if (mfaResponse) return mfaResponse;
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const signerId = c.req.param("signerId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }
  const [existingSigner] = await db
    .select()
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    );
  if (!existingSigner) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.signer.revoke.authorized",
    resourceType: "agent_signer",
    resourceId: signerId,
    metadata: { agentId },
  });

  const [row] = await db
    .update(agentSigners)
    .set({ status: "revoked" })
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    )
    .returning();

  if (!row) return c.json<ApiResponse>({ ok: false, error: "Signer not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.signer.revoke",
      resourceType: "agent_signer",
      resourceId: row.id,
      metadata: { agentId },
    });
  } catch (error) {
    await restoreAgentSigner(existingSigner);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentSignerResponse(row) });
});

// ─── Agent key quorums ───────────────────────────────────────────────────────

agentRoutes.get("/:agentId/key-quorums", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum inventory requires owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const status = c.req.query("status");
  if (status && !AGENT_KEY_QUORUM_STATUSES.has(status)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid key quorum status filter" }, 400);
  }
  const conditions = [eq(agentKeyQuorums.tenantId, tenantId), eq(agentKeyQuorums.agentId, agentId)];
  if (status) conditions.push(eq(agentKeyQuorums.status, status));
  const rows = await db
    .select()
    .from(agentKeyQuorums)
    .where(and(...conditions))
    .orderBy(agentKeyQuorums.createdAt);

  return c.json<ApiResponse>({
    ok: true,
    data: { quorums: rows.map(toAgentKeyQuorumResponse) },
  });
});

agentRoutes.post("/:agentId/key-quorums", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Key quorum creation");
  if (mfaResponse) return mfaResponse;
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  let name: string;
  let threshold: number;
  let memberSignerIds: string[];
  let permissions: string[];
  let metadata: Record<string, unknown>;
  try {
    name = normalizeRequiredText(body.name, "name", 255);
    memberSignerIds = normalizeQuorumMemberSignerIds(body.memberSignerIds);
    threshold = normalizeQuorumThreshold(body.threshold, memberSignerIds.length);
    permissions = normalizeSignerPermissions(body.permissions);
    metadata = normalizeSignerMetadata(body.metadata);
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid key quorum payload" },
      400,
    );
  }
  const memberError = await validateQuorumMembers(tenantId, agentId, memberSignerIds);
  if (memberError) return c.json<ApiResponse>({ ok: false, error: memberError }, 400);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.key_quorum.create.authorized",
    resourceType: "agent_key_quorum",
    resourceId: agentId,
    metadata: { agentId, name, threshold, memberSignerIds, permissions },
  });

  const [row] = await db
    .insert(agentKeyQuorums)
    .values({
      tenantId,
      agentId,
      name,
      threshold,
      memberSignerIds,
      permissions,
      metadata,
      status: "active",
      createdBy: c.get("userId") ?? c.get("authType") ?? null,
    })
    .returning();

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.key_quorum.create",
      resourceType: "agent_key_quorum",
      resourceId: row.id,
      metadata: { agentId, threshold, memberSignerIds },
    });
  } catch (error) {
    await deleteAgentKeyQuorumRow(row.id);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentKeyQuorumResponse(row) }, 201);
});

agentRoutes.patch("/:agentId/key-quorums/:quorumId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum updates require owner or admin session" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const quorumId = c.req.param("quorumId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const [existing] = await db
    .select()
    .from(agentKeyQuorums)
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    );
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Key quorum not found" }, 404);

  const body = await safeJsonParse<Record<string, unknown>>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  const updates: Partial<typeof agentKeyQuorums.$inferInsert> = {};
  let privilegedUpdate = false;
  try {
    if (body.name !== undefined) updates.name = normalizeRequiredText(body.name, "name", 255);
    const nextMemberSignerIds =
      body.memberSignerIds === undefined
        ? existing.memberSignerIds
        : normalizeQuorumMemberSignerIds(body.memberSignerIds);
    if (body.memberSignerIds !== undefined) {
      updates.memberSignerIds = nextMemberSignerIds;
      privilegedUpdate = true;
    }
    if (body.threshold !== undefined) {
      updates.threshold = normalizeQuorumThreshold(body.threshold, nextMemberSignerIds.length);
      privilegedUpdate = true;
    } else if (
      body.memberSignerIds !== undefined &&
      existing.threshold > nextMemberSignerIds.length
    ) {
      throw new Error("threshold cannot exceed member count");
    }
    if (body.permissions !== undefined) {
      updates.permissions = normalizeSignerPermissions(body.permissions);
      privilegedUpdate = true;
    }
    if (body.metadata !== undefined) updates.metadata = normalizeSignerMetadata(body.metadata);
    if (body.status !== undefined) {
      const status = normalizeRequiredText(body.status, "status", 32);
      if (!AGENT_KEY_QUORUM_STATUSES.has(status)) {
        throw new Error("status must be one of: active, paused, revoked");
      }
      updates.status = status;
      if (status !== existing.status) privilegedUpdate = true;
    }
    if (body.memberSignerIds !== undefined) {
      const memberError = await validateQuorumMembers(tenantId, agentId, nextMemberSignerIds);
      if (memberError) throw new Error(memberError);
    }
  } catch (error) {
    return c.json<ApiResponse>(
      { ok: false, error: error instanceof Error ? error.message : "Invalid key quorum update" },
      400,
    );
  }

  if (Object.keys(updates).length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "No key quorum updates provided" }, 400);
  }
  if (privilegedUpdate) {
    const mfaResponse = requireRecentAdminMfa(c, "Key quorum privilege updates");
    if (mfaResponse) return mfaResponse;
  }

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.key_quorum.update.authorized",
    resourceType: "agent_key_quorum",
    resourceId: quorumId,
    metadata: { agentId, fields: Object.keys(updates) },
  });

  const [row] = await db
    .update(agentKeyQuorums)
    .set({ ...updates, updatedAt: new Date() })
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    )
    .returning();

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.key_quorum.update",
      resourceType: "agent_key_quorum",
      resourceId: row.id,
      metadata: { agentId, status: row.status },
    });
  } catch (error) {
    await restoreAgentKeyQuorum(existing);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentKeyQuorumResponse(row) });
});

agentRoutes.delete("/:agentId/key-quorums/:quorumId", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key quorum revocation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Key quorum revocation");
  if (mfaResponse) return mfaResponse;
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const quorumId = c.req.param("quorumId");
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  const [existing] = await db
    .select()
    .from(agentKeyQuorums)
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    );
  if (!existing) return c.json<ApiResponse>({ ok: false, error: "Key quorum not found" }, 404);

  await writeAgentAudit(c, {
    tenantId,
    action: "agent.key_quorum.revoke.authorized",
    resourceType: "agent_key_quorum",
    resourceId: quorumId,
    metadata: { agentId },
  });

  const [row] = await db
    .update(agentKeyQuorums)
    .set({ status: "revoked", updatedAt: new Date() })
    .where(
      and(
        eq(agentKeyQuorums.id, quorumId),
        eq(agentKeyQuorums.tenantId, tenantId),
        eq(agentKeyQuorums.agentId, agentId),
      ),
    )
    .returning();
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Key quorum not found" }, 404);

  try {
    await writeAgentAudit(c, {
      tenantId,
      action: "agent.key_quorum.revoke",
      resourceType: "agent_key_quorum",
      resourceId: row.id,
      metadata: { agentId },
    });
  } catch (error) {
    await restoreAgentKeyQuorum(existing);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: toAgentKeyQuorumResponse(row) });
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
