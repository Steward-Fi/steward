/**
 * Approval workflow routes — tenant-level approval management.
 *
 * Mount: app.route("/approvals", approvalRoutes)
 */

import { and, desc, eq, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  agents,
  approvalQueue,
  autoApprovalRules,
  db,
  requireTenantLevel,
  safeJsonParse,
  transactions,
} from "../services/context";
import { dispatchWebhook } from "../services/webhook-dispatch";

export const approvalRoutes = new Hono<{ Variables: AppVariables }>();

type ApprovalStatusFilter = "pending" | "approved" | "rejected" | "all";

const APPROVAL_STATUS_FILTERS = new Set<ApprovalStatusFilter>([
  "pending",
  "approved",
  "rejected",
  "all",
]);
const MAX_APPROVAL_LIST_LIMIT = 200;
const MAX_APPROVAL_LIST_OFFSET = 10_000;
const MAX_APPROVAL_TEXT_LENGTH = 1_000;

const approvalTransactionMatchesQueue = sql`${transactions.agentId} = ${approvalQueue.agentId}`;

function approvalActor(c: Context<{ Variables: AppVariables }>): string {
  return c.get("userId") ?? `${c.get("authType") ?? "tenant"}:${c.get("tenantId")}`;
}

function requireHumanApprover(c: Context<{ Variables: AppVariables }>): boolean {
  const authType = c.get("authType");
  const role = c.get("tenantRole");
  return (
    (authType === "session-jwt" || authType === "dashboard-jwt") &&
    Boolean(c.get("userId")) &&
    (role === "owner" || role === "admin")
  );
}

function hasRecentSessionMfa(c: Context<{ Variables: AppVariables }>, maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function approvalIntentActionType(actionType: string | null | undefined): string {
  if (actionType === "transfer") return "wallet_action.transfer";
  if (actionType === "send_calls") return "wallet_action.send_calls";
  if (actionType === "user_operation") return "user_operation";
  if (actionType === "authorization") return "eip7702_authorization";
  return "transaction";
}

function dispatchApprovalIntentWebhook(
  tenantId: string,
  agentId: string,
  type: "intent.authorized" | "intent.rejected",
  payload: {
    txId: string;
    actionType?: string | null;
    status: "authorized" | "rejected";
    approvalId: string;
    reason?: string;
  },
): void {
  dispatchWebhook(tenantId, agentId, type, {
    intent_id: payload.txId,
    txId: payload.txId,
    transaction_id: payload.txId,
    wallet_id: agentId,
    action_type: approvalIntentActionType(payload.actionType),
    status: payload.status,
    approval_id: payload.approvalId,
    ...(payload.reason ? { reason: payload.reason } : {}),
  });
}

function isNonNegativeIntegerString(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
  try {
    return BigInt(value) >= 0n;
  } catch {
    return false;
  }
}

function parseNonNegativeIntegerParam(value: string | undefined, fallback: number): number | null {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function parseApprovalListParams(c: Context<{ Variables: AppVariables }>) {
  const rawStatus = c.req.query("status") || "pending";
  if (!APPROVAL_STATUS_FILTERS.has(rawStatus as ApprovalStatusFilter)) {
    return { ok: false as const, error: "status must be pending, approved, rejected, or all" };
  }

  const rawLimit = parseNonNegativeIntegerParam(c.req.query("limit"), 50);
  if (rawLimit === null || rawLimit < 1 || rawLimit > MAX_APPROVAL_LIST_LIMIT) {
    return {
      ok: false as const,
      error: `limit must be an integer from 1 to ${MAX_APPROVAL_LIST_LIMIT}`,
    };
  }

  const rawOffset = parseNonNegativeIntegerParam(c.req.query("offset"), 0);
  if (rawOffset === null || rawOffset > MAX_APPROVAL_LIST_OFFSET) {
    return {
      ok: false as const,
      error: `offset must be an integer from 0 to ${MAX_APPROVAL_LIST_OFFSET}`,
    };
  }

  return {
    ok: true as const,
    status: rawStatus as ApprovalStatusFilter,
    limit: rawLimit,
    offset: rawOffset,
  };
}

function parseBoundedText(value: unknown, required = false): string | null {
  if (typeof value !== "string") return required ? null : "";
  const trimmed = value.trim();
  if (required && trimmed.length === 0) return null;
  if (trimmed.length > MAX_APPROVAL_TEXT_LENGTH) return null;
  return trimmed;
}

async function writeApprovalAudit(
  c: Context<{ Variables: AppVariables }>,
  event: {
    action: string;
    resourceType: string;
    resourceId: string;
    metadata: Record<string, unknown>;
  },
): Promise<void> {
  await writeAuditEvent({
    tenantId: c.get("tenantId"),
    actorType: "user",
    actorId: approvalActor(c),
    action: event.action,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    metadata: event.metadata,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

// ─── List pending approvals for a tenant ──────────────────────────────────────

approvalRoutes.get("/", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  if (!requireHumanApprover(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval queue requires an owner or admin user session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval queue access requires recent MFA verification" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const params = parseApprovalListParams(c);
  if (!params.ok) {
    return c.json<ApiResponse>({ ok: false, error: params.error }, 400);
  }
  const { status: statusFilter, limit, offset } = params;

  // Join approval_queue with agents to filter by tenant
  const results = await db
    .select({
      id: approvalQueue.id,
      txId: approvalQueue.txId,
      agentId: approvalQueue.agentId,
      agentName: agents.name,
      status: approvalQueue.status,
      requestedAt: approvalQueue.requestedAt,
      resolvedAt: approvalQueue.resolvedAt,
      resolvedBy: approvalQueue.resolvedBy,
      // Transaction details
      toAddress: transactions.toAddress,
      value: transactions.value,
      chainId: transactions.chainId,
      txStatus: transactions.status,
    })
    .from(approvalQueue)
    .innerJoin(agents, eq(approvalQueue.agentId, agents.id))
    .innerJoin(transactions, eq(approvalQueue.txId, transactions.id))
    .where(
      and(
        eq(agents.tenantId, tenantId),
        approvalTransactionMatchesQueue,
        statusFilter !== "all" ? eq(approvalQueue.status, statusFilter) : undefined,
      ),
    )
    .orderBy(desc(approvalQueue.requestedAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({ ok: true, data: results });
});

// ─── Approval stats ───────────────────────────────────────────────────────────

approvalRoutes.get("/stats", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  if (!requireHumanApprover(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Manual approval requires an owner or admin user session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval stats access requires recent MFA verification" },
      403,
    );
  }

  const tenantId = c.get("tenantId");

  const [stats] = await db
    .select({
      pending: sql<number>`count(*) filter (where ${approvalQueue.status} = 'pending')`,
      approved: sql<number>`count(*) filter (where ${approvalQueue.status} = 'approved')`,
      rejected: sql<number>`count(*) filter (where ${approvalQueue.status} = 'rejected')`,
      total: sql<number>`count(*)`,
      avgWaitSeconds: sql<number>`
        coalesce(
          avg(
            extract(epoch from (${approvalQueue.resolvedAt} - ${approvalQueue.requestedAt}))
          ) filter (where ${approvalQueue.resolvedAt} is not null),
          0
        )::integer
      `,
    })
    .from(approvalQueue)
    .innerJoin(agents, eq(approvalQueue.agentId, agents.id))
    .where(eq(agents.tenantId, tenantId));

  return c.json<ApiResponse>({
    ok: true,
    data: {
      pending: Number(stats?.pending ?? 0),
      approved: Number(stats?.approved ?? 0),
      rejected: Number(stats?.rejected ?? 0),
      total: Number(stats?.total ?? 0),
      avgWaitSeconds: Number(stats?.avgWaitSeconds ?? 0),
    },
  });
});

// ─── Approve transaction ──────────────────────────────────────────────────────

approvalRoutes.post("/:txId/approve", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  if (!requireHumanApprover(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Manual approval requires an owner or admin user session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Manual approval requires recent MFA verification" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const txId = c.req.param("txId");

  const body = await safeJsonParse<{ comment?: string; approvedBy?: string }>(c);
  const comment = parseBoundedText(body?.comment);
  if (comment === null) {
    return c.json<ApiResponse>(
      { ok: false, error: `comment must be at most ${MAX_APPROVAL_TEXT_LENGTH} characters` },
      400,
    );
  }

  // Find approval entry, verify it belongs to this tenant
  const [entry] = await db
    .select({
      id: approvalQueue.id,
      txId: approvalQueue.txId,
      agentId: approvalQueue.agentId,
      status: approvalQueue.status,
      tenantId: agents.tenantId,
      actionType: transactions.actionType,
      transactionStatus: transactions.status,
    })
    .from(approvalQueue)
    .innerJoin(agents, eq(approvalQueue.agentId, agents.id))
    .innerJoin(transactions, eq(approvalQueue.txId, transactions.id))
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(agents.tenantId, tenantId),
        approvalTransactionMatchesQueue,
      ),
    );

  if (!entry) {
    return c.json<ApiResponse>({ ok: false, error: "Approval not found" }, 404);
  }

  if (entry.status !== "pending") {
    return c.json<ApiResponse>({ ok: false, error: `Approval already ${entry.status}` }, 400);
  }
  if (entry.transactionStatus !== "pending") {
    return c.json<ApiResponse>(
      { ok: false, error: `Approval transaction already ${entry.transactionStatus}` },
      409,
    );
  }
  return c.json<ApiResponse>(
    {
      ok: false,
      error:
        "Vault transaction approvals must be executed through POST /vault/:agentId/approve/:txId",
      data: { agentId: entry.agentId, txId },
    },
    409,
  );
});

// ─── Deny transaction ─────────────────────────────────────────────────────────

approvalRoutes.post("/:txId/deny", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  if (!requireHumanApprover(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Manual denial requires an owner or admin user session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Manual denial requires recent MFA verification" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const txId = c.req.param("txId");

  const body = await safeJsonParse<{ reason: string; deniedBy?: string }>(c);

  const reason = parseBoundedText(body?.reason, true);
  if (reason === null) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `reason is required and must be at most ${MAX_APPROVAL_TEXT_LENGTH} characters`,
      },
      400,
    );
  }

  // Find approval entry, verify it belongs to this tenant
  const [entry] = await db
    .select({
      id: approvalQueue.id,
      txId: approvalQueue.txId,
      agentId: approvalQueue.agentId,
      status: approvalQueue.status,
      tenantId: agents.tenantId,
      actionType: transactions.actionType,
      transactionStatus: transactions.status,
    })
    .from(approvalQueue)
    .innerJoin(agents, eq(approvalQueue.agentId, agents.id))
    .innerJoin(transactions, eq(approvalQueue.txId, transactions.id))
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(agents.tenantId, tenantId),
        approvalTransactionMatchesQueue,
      ),
    );

  if (!entry) {
    return c.json<ApiResponse>({ ok: false, error: "Approval not found" }, 404);
  }

  if (entry.status !== "pending") {
    return c.json<ApiResponse>({ ok: false, error: `Approval already ${entry.status}` }, 400);
  }
  if (entry.transactionStatus !== "pending") {
    return c.json<ApiResponse>(
      { ok: false, error: `Approval transaction already ${entry.transactionStatus}` },
      409,
    );
  }

  const resolvedBy = approvalActor(c);

  await writeApprovalAudit(c, {
    action: "approval.deny.authorized",
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      approvalId: entry.id,
      agentId: entry.agentId,
      previousStatus: entry.status,
      previousTransactionStatus: entry.transactionStatus,
      reason,
    },
  });

  const [updated] = await db
    .transaction(async (tx) => {
      const updatedRows = await tx
        .update(approvalQueue)
        .set({
          status: "rejected",
          resolvedAt: new Date(),
          resolvedBy: `${resolvedBy}: ${reason}`,
        })
        .where(and(eq(approvalQueue.id, entry.id), eq(approvalQueue.status, "pending")))
        .returning();
      if (updatedRows[0]) {
        const transactionRows = await tx
          .update(transactions)
          .set({ status: "rejected" })
          .where(
            and(
              eq(transactions.id, txId),
              eq(transactions.agentId, entry.agentId),
              eq(transactions.status, "pending"),
            ),
          )
          .returning({ id: transactions.id });
        if (!transactionRows[0]) throw new Error("Approval transaction already resolved");
      }
      return updatedRows;
    })
    .catch((error: unknown) => {
      if (error instanceof Error && error.message === "Approval transaction already resolved") {
        return [];
      }
      throw error;
    });
  if (!updated) {
    return c.json<ApiResponse>({ ok: false, error: "Approval already resolved" }, 409);
  }

  try {
    await writeApprovalAudit(c, {
      action: "approval.deny",
      resourceType: "transaction",
      resourceId: txId,
      metadata: { approvalId: entry.id, agentId: entry.agentId, reason },
    });
  } catch (err) {
    await db.transaction(async (tx) => {
      await tx
        .update(approvalQueue)
        .set({ status: "pending", resolvedAt: null, resolvedBy: null })
        .where(eq(approvalQueue.id, entry.id));
      await tx
        .update(transactions)
        .set({ status: "pending" })
        .where(and(eq(transactions.id, txId), eq(transactions.agentId, entry.agentId)));
    });
    throw err;
  }

  dispatchWebhook(tenantId, entry.agentId, "tx.denied", {
    txId,
    approvalId: entry.id,
    reason,
  });
  dispatchApprovalIntentWebhook(tenantId, entry.agentId, "intent.rejected", {
    txId,
    actionType: entry.actionType,
    status: "rejected",
    approvalId: entry.id,
    reason,
  });

  return c.json<ApiResponse>({
    ok: true,
    data: {
      ...updated,
      reason,
    },
  });
});

// ─── Auto-approval rules ─────────────────────────────────────────────────────

approvalRoutes.get("/rules", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  if (!requireHumanApprover(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval rule access requires an owner or admin user session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval rule access requires recent MFA verification" },
      403,
    );
  }

  const tenantId = c.get("tenantId");

  const [rule] = await db
    .select()
    .from(autoApprovalRules)
    .where(eq(autoApprovalRules.tenantId, tenantId));

  return c.json<ApiResponse>({ ok: true, data: rule || null });
});

approvalRoutes.put("/rules", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant-level auth required" }, 403);
  }
  if (!requireHumanApprover(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval rule changes require an owner or admin user session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Approval rule changes require recent MFA verification" },
      403,
    );
  }

  const tenantId = c.get("tenantId");

  const body = await safeJsonParse<{
    maxAmountWei?: string;
    autoDenyAfterHours?: number | null;
    escalateAboveWei?: string | null;
    enabled?: boolean;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (body.maxAmountWei !== undefined && !isNonNegativeIntegerString(body.maxAmountWei)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "maxAmountWei must be a non-negative integer string",
      },
      400,
    );
  }

  if (
    body.escalateAboveWei !== undefined &&
    body.escalateAboveWei !== null &&
    !isNonNegativeIntegerString(body.escalateAboveWei)
  ) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "escalateAboveWei must be a non-negative integer string or null",
      },
      400,
    );
  }

  if (body.autoDenyAfterHours !== undefined && body.autoDenyAfterHours !== null) {
    if (typeof body.autoDenyAfterHours !== "number" || body.autoDenyAfterHours <= 0) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "autoDenyAfterHours must be a positive number or null",
        },
        400,
      );
    }
  }

  // Upsert
  const [existing] = await db
    .select()
    .from(autoApprovalRules)
    .where(eq(autoApprovalRules.tenantId, tenantId));

  if (existing) {
    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (body.maxAmountWei !== undefined) updates.maxAmountWei = body.maxAmountWei;
    if (body.autoDenyAfterHours !== undefined) updates.autoDenyAfterHours = body.autoDenyAfterHours;
    if (body.escalateAboveWei !== undefined) updates.escalateAboveWei = body.escalateAboveWei;
    if (body.enabled !== undefined) updates.enabled = body.enabled;

    await writeApprovalAudit(c, {
      action: "approval_rule.update.authorized",
      resourceType: "approval_rule",
      resourceId: existing.id,
      metadata: { before: existing, updates },
    });

    const [updated] = await db
      .update(autoApprovalRules)
      .set(updates)
      .where(eq(autoApprovalRules.tenantId, tenantId))
      .returning();
    try {
      await writeApprovalAudit(c, {
        action: "approval_rule.update",
        resourceType: "approval_rule",
        resourceId: updated.id,
        metadata: { before: existing, after: updated },
      });
    } catch (err) {
      await db
        .update(autoApprovalRules)
        .set({
          maxAmountWei: existing.maxAmountWei,
          autoDenyAfterHours: existing.autoDenyAfterHours,
          escalateAboveWei: existing.escalateAboveWei,
          enabled: existing.enabled,
          updatedAt: existing.updatedAt,
        })
        .where(eq(autoApprovalRules.id, existing.id));
      throw err;
    }

    return c.json<ApiResponse>({ ok: true, data: updated });
  }

  await writeApprovalAudit(c, {
    action: "approval_rule.create.authorized",
    resourceType: "approval_rule",
    resourceId: tenantId,
    metadata: { requested: body },
  });

  const [created] = await db
    .insert(autoApprovalRules)
    .values({
      tenantId,
      maxAmountWei: body.maxAmountWei || "0",
      autoDenyAfterHours: body.autoDenyAfterHours ?? null,
      escalateAboveWei: body.escalateAboveWei ?? null,
      enabled: body.enabled ?? true,
    })
    .returning();
  try {
    await writeApprovalAudit(c, {
      action: "approval_rule.create",
      resourceType: "approval_rule",
      resourceId: created.id,
      metadata: { after: created },
    });
  } catch (err) {
    await db.delete(autoApprovalRules).where(eq(autoApprovalRules.id, created.id));
    throw err;
  }

  return c.json<ApiResponse>({ ok: true, data: created }, 201);
});
