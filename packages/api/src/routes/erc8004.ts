/**
 * ERC-8004 on-chain identity, reputation, and discovery routes.
 *
 * Mount: app.route("/agents", erc8004Routes)   (nested under /agents/:id/...)
 *        app.route("/discovery", erc8004Routes) (for /discovery/agents, /discovery/registries)
 *
 * These routes share the /agents prefix with the main agent CRUD routes,
 * so tenantAuth is already applied by the parent middleware.
 */

import { agentRegistrations, registryIndex } from "@stwd/db";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  ensureAgentForTenant,
  hasAgentTokenScope,
  requireTenantLevel,
} from "../services/context";
import { validateWebhookUrl } from "../services/webhook-url";

export const erc8004Routes = new Hono<{ Variables: AppVariables }>();
type AgentRegistrationRow = typeof agentRegistrations.$inferSelect;

const agentCardTextSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9 _./:-]+$/);

const registerOnchainSchema = z.object({
  chainId: z.number().int().positive().max(2_147_483_647).default(8453),
  apiUrl: z
    .union([z.literal(""), z.string().trim().max(2048).url()])
    .optional()
    .default(""),
  capabilities: z.array(agentCardTextSchema).max(32).optional().default([]),
  services: z.array(agentCardTextSchema).max(32).optional().default([]),
});

const feedbackSchema = z.object({
  fromAddress: z
    .string()
    .trim()
    .regex(/^0x[0-9a-fA-F]{40}$/, "fromAddress must be an EVM address"),
  chainId: z.number().int().positive().max(2_147_483_647).default(8453),
  score: z.number().int().min(1).max(5),
  comment: z.string().max(2048).optional(),
  taskId: z.string().trim().min(1).max(128),
});

function getRows<T>(result: T[] | { rows?: T[] }): T[] {
  return Array.isArray(result) ? result : (result.rows ?? []);
}

function requireTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
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

function signedFeedbackWritesEnabled(): boolean {
  return false;
}

function validateAgentCardApiUrl(apiUrl: string): string | null {
  if (!apiUrl) return null;
  const destinationError = validateWebhookUrl(apiUrl);
  if (destinationError) return `apiUrl ${destinationError}`;
  if (new URL(apiUrl).protocol !== "https:") return "apiUrl must use https";
  return null;
}

function publicDiscoveryAgentRow(row: Record<string, unknown>) {
  // Reputation scores are NOT yet verifiable on-chain (registry contracts are
  // not deployed; `score_onchain` is never populated by a verified indexer).
  // We therefore must not surface a numeric score that consumers would treat as
  // an authoritative on-chain reputation. Expose only the identity facts and an
  // explicit unverified flag instead of a fabricated score.
  return {
    token_id: row.token_id,
    chain_id: row.chain_id,
    registry_address: row.registry_address,
    reputation_verified: false,
    feedback_count: row.feedback_count,
  };
}

async function snapshotAgentRegistration(
  tenantId: string,
  agentId: string,
  chainId: number,
): Promise<AgentRegistrationRow | null> {
  const [row] = await db
    .select()
    .from(agentRegistrations)
    .where(
      and(
        eq(agentRegistrations.tenantId, tenantId),
        eq(agentRegistrations.agentId, agentId),
        eq(agentRegistrations.chainId, chainId),
      ),
    );
  return row ?? null;
}

async function restoreAgentRegistration(
  tenantId: string,
  agentId: string,
  chainId: number,
  snapshot: AgentRegistrationRow | null,
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .delete(agentRegistrations)
      .where(
        and(
          eq(agentRegistrations.tenantId, tenantId),
          eq(agentRegistrations.agentId, agentId),
          eq(agentRegistrations.chainId, chainId),
        ),
      );
    if (snapshot) {
      await tx.insert(agentRegistrations).values(snapshot);
    }
  });
}

function canReadAgentOnchain(
  c: Parameters<typeof requireTenantLevel>[0],
  agentId: string,
): boolean {
  const agentScope = c.get("agentScope");
  if (agentScope) return agentScope === agentId && hasAgentTokenScope(c.get("agentScopes"));
  return requireTenantLevel(c);
}

// ─── POST /agents/:id/register-onchain ────────────────────────────────────────
// Initiate on-chain registration for an agent. Creates a DB record with status
// "pending" and returns the registration info. Actual on-chain tx is async.

erc8004Routes.post("/:id/register-onchain", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "ERC-8004 registration requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "ERC-8004 registration");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("id");

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const raw = await c.req.json().catch(() => null);
  const parsed = registerOnchainSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }

  const { chainId, apiUrl, capabilities, services } = parsed.data;
  const apiUrlError = validateAgentCardApiUrl(apiUrl);
  if (apiUrlError) {
    return c.json<ApiResponse>({ ok: false, error: apiUrlError }, 400);
  }
  const registryAddress = "0x0000000000000000000000000000000000008004";

  const agentCard = {
    name: agentId,
    description: `Steward agent ${agentId}`,
    walletAddress: agent.walletAddress,
    apiUrl,
    capabilities,
    services,
  };

  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "erc8004.register.authorized",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { chainId, registryAddress, walletAddress: agent.walletAddress },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    const previousRegistration = await snapshotAgentRegistration(tenantId, agentId, chainId);
    const result = await db.execute(sql`
      INSERT INTO agent_registrations (tenant_id, agent_id, chain_id, registry_address, agent_card_json, status)
      VALUES (${tenantId}, ${agentId}, ${chainId}, ${registryAddress}, ${JSON.stringify(agentCard)}::jsonb, 'pending')
      ON CONFLICT (tenant_id, agent_id, chain_id)
      DO UPDATE SET agent_card_json = ${JSON.stringify(agentCard)}::jsonb, status = 'pending', updated_at = NOW()
      RETURNING id, status, created_at
    `);
    const rows = getRows(result);

    try {
      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "erc8004.register",
        resourceType: "agent",
        resourceId: agentId,
        metadata: { chainId, registryAddress, walletAddress: agent.walletAddress },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      await restoreAgentRegistration(tenantId, agentId, chainId, previousRegistration);
      throw error;
    }

    return c.json<ApiResponse>({
      ok: true,
      data: {
        agentId,
        chainId,
        registryAddress,
        status: "pending",
        agentCard,
        record: rows[0] ?? null,
      },
    });
  } catch (err: unknown) {
    console.error("[erc8004] register-onchain error:", err);
    return c.json<ApiResponse>({ ok: false, error: "Failed to create registration" }, 500);
  }
});

// ─── GET /agents/:id/onchain ──────────────────────────────────────────────────
// Read on-chain registration + reputation cache for an agent.

erc8004Routes.get("/:id/onchain", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("id");
  const agentScope = c.get("agentScope");

  if (agentScope && agentScope !== agentId) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden: agent scope mismatch" }, 403);
  }
  if (!canReadAgentOnchain(c, agentId)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level agent access required" }, 403);
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const registrations = await db.execute(sql`
      SELECT * FROM agent_registrations
      WHERE tenant_id = ${tenantId} AND agent_id = ${agentId}
      ORDER BY chain_id
    `);

    const reputation = await db.execute(sql`
      SELECT rc.*
      FROM reputation_cache rc
      INNER JOIN agents a ON a.id = rc.agent_id
      WHERE rc.agent_id = ${agentId} AND a.tenant_id = ${tenantId}
      ORDER BY chain_id
    `);

    // Reputation rows carry `score_onchain` / `score_combined` columns, but no
    // verified on-chain indexer populates them (the registry contracts are not
    // deployed). Flag every row as unverified so callers never treat these
    // numbers as authoritative on-chain reputation.
    const reputationRows = getRows(reputation).map((row) => ({
      ...(row as Record<string, unknown>),
      verified: false,
    }));

    return c.json<ApiResponse>({
      ok: true,
      data: {
        registrations: getRows(registrations),
        reputation: reputationRows,
        reputationVerified: false,
      },
    });
  } catch (err: unknown) {
    console.error("[erc8004] onchain lookup error:", err);
    return c.json<ApiResponse>({ ok: false, error: "Failed to fetch on-chain data" }, 500);
  }
});

// ─── POST /agents/:id/feedback ────────────────────────────────────────────────
// Persist feedback in reputation_cache until on-chain writes are wired up.

erc8004Routes.post("/:id/feedback", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "ERC-8004 feedback requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "ERC-8004 feedback");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("id");

  // Verify the agent belongs to the authenticated tenant before accepting feedback
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  if (!signedFeedbackWritesEnabled()) {
    return c.json<ApiResponse>(
      { ok: false, error: "ERC-8004 feedback writes require signed feedback proof" },
      403,
    );
  }

  const raw = await c.req.json().catch(() => null);
  const parsed = feedbackSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }

  const { chainId, score, fromAddress, taskId } = parsed.data;
  const feedbackReplayKey = `erc8004-feedback:${tenantId}:${agentId}:${chainId}:${taskId}:${fromAddress.toLowerCase()}`;

  try {
    const duplicate = await db.transaction(async (tx) => {
      if (
        process.env.STEWARD_DB_MODE !== "pglite" &&
        process.env.STEWARD_PGLITE_MEMORY !== "true"
      ) {
        await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${feedbackReplayKey}))`);
      }

      const duplicateFeedback = await tx.execute(sql`
        SELECT id
        FROM audit_events
        WHERE tenant_id = ${tenantId}
          AND action = 'erc8004.feedback'
          AND resource_id = ${agentId}
          AND metadata->>'taskId' = ${taskId}
          AND lower(metadata->>'fromAddress') = ${fromAddress.toLowerCase()}
          AND (metadata->>'chainId')::int = ${chainId}
        LIMIT 1
      `);
      if (getRows(duplicateFeedback).length > 0) return true;

      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "erc8004.feedback.authorized",
        resourceType: "agent",
        resourceId: agentId,
        metadata: {
          chainId,
          score,
          taskId,
          fromAddress,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      // Upsert reputation_cache: increment private tenant feedback aggregate.
      await tx.execute(sql`
        INSERT INTO reputation_cache (agent_id, chain_id, token_id, score_internal, feedback_count, last_updated)
        VALUES (${agentId}, ${chainId}, ${agentId}, ${score}, 1, NOW())
        ON CONFLICT (agent_id, chain_id)
        DO UPDATE SET
          score_internal = (reputation_cache.score_internal * reputation_cache.feedback_count + ${score})
                           / (reputation_cache.feedback_count + 1),
          feedback_count = reputation_cache.feedback_count + 1,
          last_updated = NOW()
      `);

      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "erc8004.feedback",
        resourceType: "agent",
        resourceId: agentId,
        metadata: {
          chainId,
          score,
          taskId,
          fromAddress,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      return false;
    });

    if (duplicate) {
      return c.json<ApiResponse>({ ok: false, error: "Feedback has already been recorded" }, 409);
    }

    return c.json<ApiResponse>({
      ok: true,
      data: {
        agentId,
        chainId,
        score,
        comment: parsed.data.comment ?? "",
        taskId,
        fromAddress,
      },
    });
  } catch (err: unknown) {
    console.error("[erc8004] feedback error:", err);
    return c.json<ApiResponse>({ ok: false, error: "Failed to record feedback" }, 500);
  }
});

// ─── Discovery routes ─────────────────────────────────────────────────────────

export const discoveryRoutes = new Hono<{ Variables: AppVariables }>();

// GET /discovery/agents — query registered agents across registries.

discoveryRoutes.get("/agents", async (c) => {
  const rawChainId = c.req.query("chainId");
  const parsedChainId = rawChainId ? Number(rawChainId) : undefined;
  if (
    rawChainId &&
    (!Number.isSafeInteger(parsedChainId) || parsedChainId === undefined || parsedChainId <= 0)
  ) {
    return c.json<ApiResponse>({ ok: false, error: "chainId must be a positive integer" }, 400);
  }
  const status = "confirmed";
  const rawLimit = Number(c.req.query("limit") ?? "50");
  const limit = Number.isSafeInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 200) : 50;

  try {
    let query;
    if (parsedChainId) {
      query = sql`
        SELECT COALESCE(ar.token_id, rc.token_id) AS token_id,
               ar.chain_id, ar.registry_address,
               0::integer AS feedback_count
        FROM agent_registrations ar
        LEFT JOIN reputation_cache rc ON ar.agent_id = rc.agent_id AND ar.chain_id = rc.chain_id
        WHERE ar.chain_id = ${parsedChainId} AND ar.status = ${status}
        ORDER BY rc.score_onchain DESC NULLS LAST
        LIMIT ${limit}
      `;
    } else {
      query = sql`
        SELECT COALESCE(ar.token_id, rc.token_id) AS token_id,
               ar.chain_id, ar.registry_address,
               0::integer AS feedback_count
        FROM agent_registrations ar
        LEFT JOIN reputation_cache rc ON ar.agent_id = rc.agent_id AND ar.chain_id = rc.chain_id
        WHERE ar.status = ${status}
        ORDER BY rc.score_onchain DESC NULLS LAST
        LIMIT ${limit}
      `;
    }

    const result = await db.execute(query);
    const agents = getRows(result).map((row) =>
      publicDiscoveryAgentRow(row as Record<string, unknown>),
    );
    return c.json<ApiResponse>({
      ok: true,
      data: agents,
    });
  } catch (err: unknown) {
    console.error("[erc8004] discovery/agents error:", err);
    return c.json<ApiResponse>({ ok: false, error: "Failed to query agents" }, 500);
  }
});

// GET /discovery/registries — list known registries.

discoveryRoutes.get("/registries", async (c) => {
  try {
    const rows = await db
      .select({
        chain_id: registryIndex.chainId,
        name: registryIndex.name,
        registry_address: registryIndex.registryAddress,
        created_at: registryIndex.createdAt,
      })
      .from(registryIndex)
      .where(eq(registryIndex.isActive, true));
    return c.json<ApiResponse>({
      ok: true,
      data: rows.sort((a, b) => a.chain_id - b.chain_id),
    });
  } catch (err: unknown) {
    console.error("[erc8004] discovery/registries error:", err);
    return c.json<ApiResponse>({ ok: false, error: "Failed to query registries" }, 500);
  }
});
