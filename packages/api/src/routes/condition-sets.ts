/**
 * Privy-style condition set CRUD.
 *
 * Condition sets are tenant-scoped lists of string values that policy rules can
 * reference with the `condition-set` policy type and `in_condition_set` operator.
 */

import { randomUUID } from "node:crypto";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { and, count, desc, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { withTenantAuditedTransaction, writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  conditionSetItems,
  conditionSets,
  db,
  isNonEmptyString,
  requireTenantLevel,
  safeJsonParse,
} from "../services/context";
import { isRecentMfaTimestamp } from "../services/recent-mfa";

type ConditionSetResponse = {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  ownerId: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

type ConditionSetItemResponse = {
  id: string;
  conditionSetId: string;
  tenantId: string;
  value: string;
  label: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

type CreateConditionSetBody = {
  name: string;
  description?: string | null;
  ownerId: string;
  metadata?: Record<string, unknown>;
};

type UpdateConditionSetBody = Partial<CreateConditionSetBody>;

type UpsertItemBody = {
  value: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
};

type UpdateItemBody = {
  value?: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
};

type ReplaceItemsBody = {
  items: UpsertItemBody[];
};

type ConditionSetItemRow = typeof conditionSetItems.$inferSelect;

class ConditionSetValidationError extends Error {}

function conditionSetMutationError(c: Parameters<typeof requireTenantLevel>[0], error: unknown) {
  if (error instanceof ConditionSetValidationError) {
    return c.json<ApiResponse>({ ok: false, error: error.message }, 400);
  }
  console.error("[condition-sets] persistence failure", redactedThrownDiagnostics(error));
  return c.json<ApiResponse>({ ok: false, error: "Internal server error" }, 500);
}

function iso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : String(value);
}

function setToResponse(row: typeof conditionSets.$inferSelect): ConditionSetResponse {
  return {
    id: row.id,
    tenantId: row.tenantId,
    name: row.name,
    description: row.description,
    ownerId: row.ownerId,
    metadata: row.metadata ?? {},
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

function itemToResponse(row: typeof conditionSetItems.$inferSelect): ConditionSetItemResponse {
  return {
    id: row.id,
    conditionSetId: row.conditionSetId,
    tenantId: row.tenantId,
    value: row.value,
    label: row.label,
    metadata: row.metadata ?? {},
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

function normalizeMetadata(value: unknown): Record<string, unknown> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ConditionSetValidationError("metadata must be an object");
  }
  if (JSON.stringify(value).length > MAX_ITEM_METADATA_BYTES) {
    throw new ConditionSetValidationError(
      `metadata must not exceed ${MAX_ITEM_METADATA_BYTES} bytes`,
    );
  }
  return value as Record<string, unknown>;
}

function normalizeRequiredText(value: unknown, field: string, maxLength: number): string {
  if (!isNonEmptyString(value)) {
    throw new ConditionSetValidationError(`${field} is required`);
  }
  const trimmed = value.trim();
  if (trimmed.length > maxLength) {
    throw new ConditionSetValidationError(`${field} must not exceed ${maxLength} characters`);
  }
  return trimmed;
}

function normalizeOptionalText(
  value: unknown,
  field: string,
  maxLength: number,
): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new ConditionSetValidationError(`${field} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength) {
    throw new ConditionSetValidationError(`${field} must not exceed ${maxLength} characters`);
  }
  return trimmed;
}

function normalizeItem(body: UpsertItemBody): UpsertItemBody {
  if (!isNonEmptyString(body.value)) {
    throw new ConditionSetValidationError("item value is required and must be a non-empty string");
  }
  if (body.value.trim().length > MAX_CONDITION_SET_ITEM_VALUE_LENGTH) {
    throw new ConditionSetValidationError(
      `item value must not exceed ${MAX_CONDITION_SET_ITEM_VALUE_LENGTH} characters`,
    );
  }
  const label =
    normalizeOptionalText(body.label, "item label", MAX_CONDITION_SET_ITEM_LABEL_LENGTH) ?? null;
  return {
    value: body.value.trim(),
    label,
    metadata: normalizeMetadata(body.metadata),
  };
}

function normalizeItemUpdate(current: ConditionSetItemRow, body: UpdateItemBody): UpsertItemBody {
  const value =
    body.value !== undefined
      ? normalizeRequiredText(body.value, "item value", MAX_CONDITION_SET_ITEM_VALUE_LENGTH)
      : current.value;
  const label =
    body.label !== undefined
      ? (normalizeOptionalText(body.label, "item label", MAX_CONDITION_SET_ITEM_LABEL_LENGTH) ??
        null)
      : current.label;
  return {
    value,
    label,
    metadata: body.metadata !== undefined ? normalizeMetadata(body.metadata) : current.metadata,
  };
}

async function ensureConditionSet(tenantId: string, id: string) {
  const [set] = await db
    .select()
    .from(conditionSets)
    .where(and(eq(conditionSets.id, id), eq(conditionSets.tenantId, tenantId)));
  return set ?? null;
}

export const conditionSetRoutes = new Hono<{ Variables: AppVariables }>();

const MAX_CONDITION_SETS = 100;
const MAX_CONDITION_SET_NAME_LENGTH = 255;
const MAX_CONDITION_SET_DESCRIPTION_LENGTH = 2_000;
const MAX_CONDITION_SET_OWNER_ID_LENGTH = 255;
const MAX_CONDITION_SET_ITEMS = 1_000;
const MAX_CONDITION_SET_ITEM_VALUE_LENGTH = 1_024;
const MAX_CONDITION_SET_ITEM_LABEL_LENGTH = 255;
const MAX_ITEM_METADATA_BYTES = 4_096;

function shouldUsePostgresAdvisoryLocks(): boolean {
  return process.env.STEWARD_DB_MODE !== "pglite" && process.env.STEWARD_PGLITE_MEMORY !== "true";
}

async function lockConditionSet(tx: typeof db, tenantId: string, conditionSetId: string) {
  if (shouldUsePostgresAdvisoryLocks()) {
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtextextended(${`condition_set:${tenantId}:${conditionSetId}`}, 0))`,
    );
  }
}

async function readLockedConditionSet(tx: typeof db, tenantId: string, conditionSetId: string) {
  await lockConditionSet(tx, tenantId, conditionSetId);
  const query = tx
    .select()
    .from(conditionSets)
    .where(and(eq(conditionSets.id, conditionSetId), eq(conditionSets.tenantId, tenantId)));
  const [set] = shouldUsePostgresAdvisoryLocks() ? await query.for("update") : await query;
  return set ?? null;
}

function parsePaginationParam(
  value: string | undefined,
  defaultValue: number,
  min: number,
  max: number,
): number | null {
  if (value === undefined) return defaultValue;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) return null;
  return parsed;
}

function requireTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function hasRecentSessionMfa(c: Parameters<typeof requireTenantLevel>[0], maxAgeMs = 5 * 60_000) {
  return isRecentMfaTimestamp(c.get("sessionMfaVerifiedAt"), maxAgeMs);
}

function requireRecentAdminMfa(c: Parameters<typeof requireTenantLevel>[0], reason: string) {
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

conditionSetRoutes.get("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set access");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const limit = parsePaginationParam(c.req.query("limit"), 100, 1, 200);
  const offset = parsePaginationParam(c.req.query("offset"), 0, 0, 100_000);
  if (limit === null || offset === null) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid pagination parameters" }, 400);
  }

  const rows = await db
    .select()
    .from(conditionSets)
    .where(eq(conditionSets.tenantId, tenantId))
    .orderBy(desc(conditionSets.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<
    ApiResponse<{ conditionSets: ConditionSetResponse[]; limit: number; offset: number }>
  >({
    ok: true,
    data: { conditionSets: rows.map(setToResponse), limit, offset },
  });
});

conditionSetRoutes.post("/", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set creation");
  if (mfaResponse) return mfaResponse;

  const body = await safeJsonParse<CreateConditionSetBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  try {
    const name = normalizeRequiredText(body.name, "name", MAX_CONDITION_SET_NAME_LENGTH);
    const ownerId = normalizeRequiredText(
      body.ownerId,
      "ownerId",
      MAX_CONDITION_SET_OWNER_ID_LENGTH,
    );
    const description =
      normalizeOptionalText(
        body.description,
        "description",
        MAX_CONDITION_SET_DESCRIPTION_LENGTH,
      ) ?? null;
    const metadata = normalizeMetadata(body.metadata);
    const setId = randomUUID();
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.create.authorized",
      resourceType: "condition_set",
      resourceId: setId,
      metadata: { name, ownerId },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    const row = await withTenantAuditedTransaction(tenantId, async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof db;
      if (shouldUsePostgresAdvisoryLocks()) {
        await tx.execute(
          sql`select pg_advisory_xact_lock(hashtextextended(${`condition_sets:${tenantId}`}, 0))`,
        );
      }

      const [{ total } = { total: 0 }] = await tx
        .select({ total: count() })
        .from(conditionSets)
        .where(eq(conditionSets.tenantId, tenantId));
      if (Number(total) >= MAX_CONDITION_SETS) {
        throw new ConditionSetValidationError(
          `tenant cannot contain more than ${MAX_CONDITION_SETS} condition sets`,
        );
      }

      const [created] = await tx
        .insert(conditionSets)
        .values({
          id: setId,
          tenantId,
          name,
          description,
          ownerId,
          metadata,
        })
        .returning();

      await appendRequiredAudit({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.create",
        resourceType: "condition_set",
        resourceId: created.id,
        metadata: { name: created.name, ownerId: created.ownerId },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
      return created;
    });

    return c.json<ApiResponse<ConditionSetResponse>>({ ok: true, data: setToResponse(row) }, 201);
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});

conditionSetRoutes.get("/:id", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set access");
  if (mfaResponse) return mfaResponse;

  const set = await ensureConditionSet(c.get("tenantId"), c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);
  return c.json<ApiResponse<ConditionSetResponse>>({ ok: true, data: setToResponse(set) });
});

conditionSetRoutes.patch("/:id", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set updates");
  if (mfaResponse) return mfaResponse;

  const body = await safeJsonParse<UpdateConditionSetBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  try {
    const current = await ensureConditionSet(tenantId, c.req.param("id"));
    if (!current) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);
    const namePatch =
      body.name !== undefined
        ? normalizeRequiredText(body.name, "name", MAX_CONDITION_SET_NAME_LENGTH)
        : undefined;
    const descriptionPatch =
      body.description !== undefined
        ? normalizeOptionalText(
            body.description,
            "description",
            MAX_CONDITION_SET_DESCRIPTION_LENGTH,
          )
        : undefined;
    const ownerIdPatch =
      body.ownerId !== undefined
        ? normalizeRequiredText(body.ownerId, "ownerId", MAX_CONDITION_SET_OWNER_ID_LENGTH)
        : undefined;
    const metadataPatch =
      body.metadata !== undefined ? normalizeMetadata(body.metadata) : undefined;

    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.update.authorized",
      resourceType: "condition_set",
      resourceId: current.id,
      metadata: {},
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    const row = await withTenantAuditedTransaction(tenantId, async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof db;
      const locked = await readLockedConditionSet(tx, tenantId, current.id);
      if (!locked) return null;
      const [updated] = await tx
        .update(conditionSets)
        .set({
          name: namePatch ?? locked.name,
          description: descriptionPatch === undefined ? locked.description : descriptionPatch,
          ownerId: ownerIdPatch ?? locked.ownerId,
          metadata: metadataPatch ?? locked.metadata,
          updatedAt: new Date(),
        })
        .where(and(eq(conditionSets.id, locked.id), eq(conditionSets.tenantId, tenantId)))
        .returning();
      if (!updated) return null;
      await appendRequiredAudit({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.update",
        resourceType: "condition_set",
        resourceId: updated.id,
        metadata: {},
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
      return updated;
    });

    if (!row) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

    return c.json<ApiResponse<ConditionSetResponse>>({ ok: true, data: setToResponse(row) });
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});

conditionSetRoutes.delete("/:id", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set deletion requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set deletion");
  if (mfaResponse) return mfaResponse;

  const current = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!current) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? tenantId,
    action: "condition_set.delete.authorized",
    resourceType: "condition_set",
    resourceId: current.id,
    metadata: {},
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  try {
    const deleted = await withTenantAuditedTransaction(
      tenantId,
      async (txRaw, appendRequiredAudit) => {
        const tx = txRaw as typeof db;
        const locked = await readLockedConditionSet(tx, tenantId, current.id);
        if (!locked) return null;
        const [row] = await tx
          .delete(conditionSets)
          .where(and(eq(conditionSets.id, locked.id), eq(conditionSets.tenantId, tenantId)))
          .returning({ id: conditionSets.id });
        if (!row) return null;
        await appendRequiredAudit({
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? tenantId,
          action: "condition_set.delete",
          resourceType: "condition_set",
          resourceId: row.id,
          metadata: {},
          ipAddress: c.req.header("x-forwarded-for") ?? null,
          userAgent: c.req.header("user-agent") ?? null,
          requestId: c.get("requestId") ?? null,
        });
        return row;
      },
    );

    if (!deleted) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

    return c.json<ApiResponse>({ ok: true });
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});

conditionSetRoutes.get("/:id/items", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set item access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set item access");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const set = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  const limit = parsePaginationParam(c.req.query("limit"), 200, 1, 200);
  const offset = parsePaginationParam(c.req.query("offset"), 0, 0, 100_000);
  if (limit === null || offset === null) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid pagination parameters" }, 400);
  }

  const rows = await db
    .select()
    .from(conditionSetItems)
    .where(
      and(eq(conditionSetItems.tenantId, tenantId), eq(conditionSetItems.conditionSetId, set.id)),
    )
    .orderBy(desc(conditionSetItems.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<
    ApiResponse<{
      items: ConditionSetItemResponse[];
      limit: number;
      offset: number;
    }>
  >({
    ok: true,
    data: { items: rows.map(itemToResponse), limit, offset },
  });
});

conditionSetRoutes.post("/:id/items", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set item updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set item updates");
  if (mfaResponse) return mfaResponse;

  const set = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  const body = await safeJsonParse<UpsertItemBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  try {
    const item = normalizeItem(body);
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.item.upsert.authorized",
      resourceType: "condition_set",
      resourceId: set.id,
      metadata: { value: item.value },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    const row = await withTenantAuditedTransaction(tenantId, async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof db;
      const lockedSet = await readLockedConditionSet(tx, tenantId, set.id);
      if (!lockedSet) return null;

      const [existing] = await tx
        .select({ id: conditionSetItems.id })
        .from(conditionSetItems)
        .where(
          and(
            eq(conditionSetItems.tenantId, tenantId),
            eq(conditionSetItems.conditionSetId, lockedSet.id),
            eq(conditionSetItems.value, item.value),
          ),
        );

      if (!existing) {
        const [{ total } = { total: 0 }] = await tx
          .select({ total: count() })
          .from(conditionSetItems)
          .where(
            and(
              eq(conditionSetItems.tenantId, tenantId),
              eq(conditionSetItems.conditionSetId, lockedSet.id),
            ),
          );
        if (Number(total) >= MAX_CONDITION_SET_ITEMS) {
          throw new ConditionSetValidationError(
            `condition set cannot contain more than ${MAX_CONDITION_SET_ITEMS} items`,
          );
        }
      }

      const [upserted] = await tx
        .insert(conditionSetItems)
        .values({
          conditionSetId: lockedSet.id,
          tenantId,
          value: item.value,
          label: item.label,
          metadata: item.metadata,
        })
        .onConflictDoUpdate({
          target: [conditionSetItems.conditionSetId, conditionSetItems.value],
          set: {
            label: item.label,
            metadata: item.metadata,
            updatedAt: new Date(),
          },
        })
        .returning();
      await appendRequiredAudit({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.item.upsert",
        resourceType: "condition_set_item",
        resourceId: upserted.id,
        metadata: { conditionSetId: lockedSet.id, value: upserted.value },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
      return upserted;
    });
    if (!row) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

    return c.json<ApiResponse<ConditionSetItemResponse>>(
      { ok: true, data: itemToResponse(row) },
      201,
    );
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});

conditionSetRoutes.put("/:id/items", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set item replacement requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set item replacement");
  if (mfaResponse) return mfaResponse;

  const set = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  const body = await safeJsonParse<ReplaceItemsBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  if (!Array.isArray(body.items)) {
    return c.json<ApiResponse>({ ok: false, error: "items must be an array" }, 400);
  }
  if (body.items.length > MAX_CONDITION_SET_ITEMS) {
    return c.json<ApiResponse>(
      { ok: false, error: `items cannot contain more than ${MAX_CONDITION_SET_ITEMS} entries` },
      400,
    );
  }

  try {
    const items = body.items.map(normalizeItem);
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.items.replace.authorized",
      resourceType: "condition_set",
      resourceId: set.id,
      metadata: { itemCount: items.length },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    const rows = await withTenantAuditedTransaction(
      tenantId,
      async (txRaw, appendRequiredAudit) => {
        const tx = txRaw as typeof db;
        const lockedSet = await readLockedConditionSet(tx, tenantId, set.id);
        if (!lockedSet) return null;
        if (items.length > MAX_CONDITION_SET_ITEMS) {
          throw new ConditionSetValidationError(
            `items cannot contain more than ${MAX_CONDITION_SET_ITEMS} entries`,
          );
        }

        await tx
          .delete(conditionSetItems)
          .where(
            and(
              eq(conditionSetItems.tenantId, tenantId),
              eq(conditionSetItems.conditionSetId, lockedSet.id),
            ),
          );

        const replaced =
          items.length === 0
            ? []
            : await tx
                .insert(conditionSetItems)
                .values(
                  items.map((item) => ({
                    conditionSetId: lockedSet.id,
                    tenantId,
                    value: item.value,
                    label: item.label,
                    metadata: item.metadata,
                  })),
                )
                .returning();

        await appendRequiredAudit({
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? tenantId,
          action: "condition_set.items.replace",
          resourceType: "condition_set",
          resourceId: lockedSet.id,
          metadata: { itemCount: replaced.length },
          ipAddress: c.req.header("x-forwarded-for") ?? null,
          userAgent: c.req.header("user-agent") ?? null,
          requestId: c.get("requestId") ?? null,
        });
        return replaced;
      },
    );

    if (!rows) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

    return c.json<ApiResponse<ConditionSetItemResponse[]>>({
      ok: true,
      data: rows.map(itemToResponse),
    });
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});

conditionSetRoutes.get("/:id/items/:itemId", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set item access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set item access");
  if (mfaResponse) return mfaResponse;

  const set = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  const [item] = await db
    .select()
    .from(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.id, c.req.param("itemId")),
        eq(conditionSetItems.tenantId, tenantId),
        eq(conditionSetItems.conditionSetId, set.id),
      ),
    );
  if (!item) return c.json<ApiResponse>({ ok: false, error: "Condition set item not found" }, 404);

  return c.json<ApiResponse<ConditionSetItemResponse>>({ ok: true, data: itemToResponse(item) });
});

conditionSetRoutes.patch("/:id/items/:itemId", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set item updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set item updates");
  if (mfaResponse) return mfaResponse;

  const set = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  const body = await safeJsonParse<UpdateItemBody>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

  const [current] = await db
    .select()
    .from(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.id, c.req.param("itemId")),
        eq(conditionSetItems.tenantId, tenantId),
        eq(conditionSetItems.conditionSetId, set.id),
      ),
    );
  if (!current)
    return c.json<ApiResponse>({ ok: false, error: "Condition set item not found" }, 404);

  try {
    const authorizedItem = normalizeItemUpdate(current, body);
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.item.update.authorized",
      resourceType: "condition_set_item",
      resourceId: current.id,
      metadata: { conditionSetId: set.id, value: authorizedItem.value },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    const row = await withTenantAuditedTransaction(tenantId, async (txRaw, appendRequiredAudit) => {
      const tx = txRaw as typeof db;
      const lockedSet = await readLockedConditionSet(tx, tenantId, set.id);
      if (!lockedSet) return { kind: "set_not_found" as const };
      const query = tx
        .select()
        .from(conditionSetItems)
        .where(
          and(
            eq(conditionSetItems.id, current.id),
            eq(conditionSetItems.tenantId, tenantId),
            eq(conditionSetItems.conditionSetId, lockedSet.id),
          ),
        );
      const [lockedItem] = shouldUsePostgresAdvisoryLocks()
        ? await query.for("update")
        : await query;
      if (!lockedItem) return { kind: "item_not_found" as const };
      const item = normalizeItemUpdate(lockedItem, body);
      const [updated] = await tx
        .update(conditionSetItems)
        .set({
          value: item.value,
          label: item.label,
          metadata: item.metadata,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(conditionSetItems.id, lockedItem.id),
            eq(conditionSetItems.tenantId, tenantId),
            eq(conditionSetItems.conditionSetId, lockedSet.id),
          ),
        )
        .returning();
      if (!updated) return { kind: "item_not_found" as const };
      await appendRequiredAudit({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.item.update",
        resourceType: "condition_set_item",
        resourceId: updated.id,
        metadata: { conditionSetId: lockedSet.id, value: updated.value },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
      return { kind: "updated" as const, row: updated };
    });

    if (row.kind === "set_not_found") {
      return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);
    }
    if (row.kind === "item_not_found") {
      return c.json<ApiResponse>({ ok: false, error: "Condition set item not found" }, 404);
    }

    return c.json<ApiResponse<ConditionSetItemResponse>>({
      ok: true,
      data: itemToResponse(row.row),
    });
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});

conditionSetRoutes.delete("/:id/items/:itemId", async (c) => {
  const tenantId = c.get("tenantId");
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Condition set item deletion requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Condition set item deletion");
  if (mfaResponse) return mfaResponse;

  const set = await ensureConditionSet(tenantId, c.req.param("id"));
  if (!set) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  const [current] = await db
    .select({ id: conditionSetItems.id, value: conditionSetItems.value })
    .from(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.id, c.req.param("itemId")),
        eq(conditionSetItems.tenantId, tenantId),
        eq(conditionSetItems.conditionSetId, set.id),
      ),
    );

  if (!current)
    return c.json<ApiResponse>({ ok: false, error: "Condition set item not found" }, 404);

  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? tenantId,
    action: "condition_set.item.delete.authorized",
    resourceType: "condition_set_item",
    resourceId: current.id,
    metadata: { conditionSetId: set.id, value: current.value },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  try {
    const deleted = await withTenantAuditedTransaction(
      tenantId,
      async (txRaw, appendRequiredAudit) => {
        const tx = txRaw as typeof db;
        const lockedSet = await readLockedConditionSet(tx, tenantId, set.id);
        if (!lockedSet) return { kind: "set_not_found" as const };
        const [row] = await tx
          .delete(conditionSetItems)
          .where(
            and(
              eq(conditionSetItems.id, c.req.param("itemId")),
              eq(conditionSetItems.tenantId, tenantId),
              eq(conditionSetItems.conditionSetId, lockedSet.id),
            ),
          )
          .returning({ id: conditionSetItems.id, value: conditionSetItems.value });
        if (!row) return { kind: "item_not_found" as const };
        await appendRequiredAudit({
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? tenantId,
          action: "condition_set.item.delete",
          resourceType: "condition_set_item",
          resourceId: row.id,
          metadata: { conditionSetId: lockedSet.id, value: row.value },
          ipAddress: c.req.header("x-forwarded-for") ?? null,
          userAgent: c.req.header("user-agent") ?? null,
          requestId: c.get("requestId") ?? null,
        });
        return { kind: "deleted" as const };
      },
    );

    if (deleted.kind === "set_not_found") {
      return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);
    }
    if (deleted.kind === "item_not_found") {
      return c.json<ApiResponse>({ ok: false, error: "Condition set item not found" }, 404);
    }

    return c.json<ApiResponse>({ ok: true });
  } catch (err) {
    return conditionSetMutationError(c, err);
  }
});
