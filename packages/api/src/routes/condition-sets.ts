/**
 * Privy-style condition set CRUD.
 *
 * Condition sets are tenant-scoped lists of string values that policy rules can
 * reference with the `condition-set` policy type and `in_condition_set` operator.
 */

import { randomUUID } from "node:crypto";
import { and, count, desc, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
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

type ReplaceItemsBody = {
  items: UpsertItemBody[];
};

type ConditionSetRow = typeof conditionSets.$inferSelect;
type ConditionSetItemRow = typeof conditionSetItems.$inferSelect;

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
    throw new Error("metadata must be an object");
  }
  if (JSON.stringify(value).length > MAX_ITEM_METADATA_BYTES) {
    throw new Error(`metadata must not exceed ${MAX_ITEM_METADATA_BYTES} bytes`);
  }
  return value as Record<string, unknown>;
}

function normalizeRequiredText(value: unknown, field: string, maxLength: number): string {
  if (!isNonEmptyString(value)) {
    throw new Error(`${field} is required`);
  }
  const trimmed = value.trim();
  if (trimmed.length > maxLength) {
    throw new Error(`${field} must not exceed ${maxLength} characters`);
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
    throw new Error(`${field} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength) {
    throw new Error(`${field} must not exceed ${maxLength} characters`);
  }
  return trimmed;
}

function normalizeItem(body: UpsertItemBody): UpsertItemBody {
  if (!isNonEmptyString(body.value)) {
    throw new Error("item value is required and must be a non-empty string");
  }
  if (body.value.trim().length > MAX_CONDITION_SET_ITEM_VALUE_LENGTH) {
    throw new Error(`item value must not exceed ${MAX_CONDITION_SET_ITEM_VALUE_LENGTH} characters`);
  }
  const label =
    normalizeOptionalText(body.label, "item label", MAX_CONDITION_SET_ITEM_LABEL_LENGTH) ?? null;
  return {
    value: body.value.trim(),
    label,
    metadata: normalizeMetadata(body.metadata),
  };
}

async function ensureConditionSet(tenantId: string, id: string) {
  const [set] = await db
    .select()
    .from(conditionSets)
    .where(and(eq(conditionSets.id, id), eq(conditionSets.tenantId, tenantId)));
  return set ?? null;
}

async function snapshotConditionSetItems(
  tenantId: string,
  conditionSetId: string,
): Promise<ConditionSetItemRow[]> {
  return db
    .select()
    .from(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.tenantId, tenantId),
        eq(conditionSetItems.conditionSetId, conditionSetId),
      ),
    );
}

async function restoreConditionSet(
  tenantId: string,
  set: ConditionSetRow,
  items: ConditionSetItemRow[],
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .delete(conditionSetItems)
      .where(
        and(eq(conditionSetItems.tenantId, tenantId), eq(conditionSetItems.conditionSetId, set.id)),
      );
    await tx
      .delete(conditionSets)
      .where(and(eq(conditionSets.id, set.id), eq(conditionSets.tenantId, tenantId)));
    await tx.insert(conditionSets).values(set);
    if (items.length > 0) {
      await tx.insert(conditionSetItems).values(items);
    }
  });
}

async function restoreConditionSetItems(
  tenantId: string,
  conditionSetId: string,
  items: ConditionSetItemRow[],
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .delete(conditionSetItems)
      .where(
        and(
          eq(conditionSetItems.tenantId, tenantId),
          eq(conditionSetItems.conditionSetId, conditionSetId),
        ),
      );
    if (items.length > 0) {
      await tx.insert(conditionSetItems).values(items);
    }
  });
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

    const [row] = await db.transaction(async (tx) => {
      if (shouldUsePostgresAdvisoryLocks()) {
        await tx.execute(
          sql`select pg_advisory_xact_lock(hashtext(${`condition_sets:${tenantId}`}))`,
        );
      }

      const [{ total } = { total: 0 }] = await tx
        .select({ total: count() })
        .from(conditionSets)
        .where(eq(conditionSets.tenantId, tenantId));
      if (Number(total) >= MAX_CONDITION_SETS) {
        throw new Error(`tenant cannot contain more than ${MAX_CONDITION_SETS} condition sets`);
      }

      return tx
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
    });

    try {
      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.create",
        resourceType: "condition_set",
        resourceId: row.id,
        metadata: { name: row.name, ownerId: row.ownerId },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      await db
        .delete(conditionSets)
        .where(and(eq(conditionSets.id, row.id), eq(conditionSets.tenantId, tenantId)));
      throw error;
    }

    return c.json<ApiResponse<ConditionSetResponse>>({ ok: true, data: setToResponse(row) }, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to create condition set";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
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
    const name =
      body.name !== undefined
        ? normalizeRequiredText(body.name, "name", MAX_CONDITION_SET_NAME_LENGTH)
        : current.name;
    const description =
      body.description !== undefined
        ? normalizeOptionalText(
            body.description,
            "description",
            MAX_CONDITION_SET_DESCRIPTION_LENGTH,
          )
        : current.description;
    const ownerId =
      body.ownerId !== undefined
        ? normalizeRequiredText(body.ownerId, "ownerId", MAX_CONDITION_SET_OWNER_ID_LENGTH)
        : current.ownerId;
    const metadata =
      body.metadata !== undefined ? normalizeMetadata(body.metadata) : current.metadata;

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

    const [row] = await db
      .update(conditionSets)
      .set({
        name,
        description,
        ownerId,
        metadata,
        updatedAt: new Date(),
      })
      .where(and(eq(conditionSets.id, current.id), eq(conditionSets.tenantId, tenantId)))
      .returning();

    if (!row) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

    try {
      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.update",
        resourceType: "condition_set",
        resourceId: current.id,
        metadata: {},
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      const currentItems = await snapshotConditionSetItems(tenantId, current.id);
      await restoreConditionSet(tenantId, current, currentItems);
      throw error;
    }

    return c.json<ApiResponse<ConditionSetResponse>>({ ok: true, data: setToResponse(row) });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to update condition set";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
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
  const currentItems = await snapshotConditionSetItems(tenantId, current.id);

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

  const [deleted] = await db
    .delete(conditionSets)
    .where(and(eq(conditionSets.id, current.id), eq(conditionSets.tenantId, tenantId)))
    .returning({ id: conditionSets.id });

  if (!deleted) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.delete",
      resourceType: "condition_set",
      resourceId: deleted.id,
      metadata: {},
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (error) {
    await restoreConditionSet(tenantId, current, currentItems);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true });
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

  return c.json<ApiResponse<ConditionSetItemResponse[]>>({
    ok: true,
    data: rows.map(itemToResponse),
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
    const previousItems = await snapshotConditionSetItems(tenantId, set.id);
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

    const [row] = await db.transaction(async (tx) => {
      if (shouldUsePostgresAdvisoryLocks()) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${set.id}))`);
      }

      const [existing] = await tx
        .select({ id: conditionSetItems.id })
        .from(conditionSetItems)
        .where(
          and(
            eq(conditionSetItems.tenantId, tenantId),
            eq(conditionSetItems.conditionSetId, set.id),
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
              eq(conditionSetItems.conditionSetId, set.id),
            ),
          );
        if (Number(total) >= MAX_CONDITION_SET_ITEMS) {
          throw new Error(
            `condition set cannot contain more than ${MAX_CONDITION_SET_ITEMS} items`,
          );
        }
      }

      return tx
        .insert(conditionSetItems)
        .values({
          conditionSetId: set.id,
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
    });

    try {
      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.item.upsert",
        resourceType: "condition_set_item",
        resourceId: row.id,
        metadata: { conditionSetId: set.id, value: row.value },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      await restoreConditionSetItems(tenantId, set.id, previousItems);
      throw error;
    }

    return c.json<ApiResponse<ConditionSetItemResponse>>(
      { ok: true, data: itemToResponse(row) },
      201,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to add condition set item";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
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
    const previousItems = await snapshotConditionSetItems(tenantId, set.id);
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

    const rows = await db.transaction(async (tx) => {
      const [currentSet] = await tx
        .select({ id: conditionSets.id })
        .from(conditionSets)
        .where(and(eq(conditionSets.id, set.id), eq(conditionSets.tenantId, tenantId)));
      if (!currentSet) return null;

      await tx
        .delete(conditionSetItems)
        .where(
          and(
            eq(conditionSetItems.tenantId, tenantId),
            eq(conditionSetItems.conditionSetId, set.id),
          ),
        );

      if (items.length === 0) return [];

      return tx
        .insert(conditionSetItems)
        .values(
          items.map((item) => ({
            conditionSetId: set.id,
            tenantId,
            value: item.value,
            label: item.label,
            metadata: item.metadata,
          })),
        )
        .returning();
    });

    if (!rows) return c.json<ApiResponse>({ ok: false, error: "Condition set not found" }, 404);

    try {
      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? tenantId,
        action: "condition_set.items.replace",
        resourceType: "condition_set",
        resourceId: set.id,
        metadata: { itemCount: rows.length },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      await restoreConditionSetItems(tenantId, set.id, previousItems);
      throw error;
    }

    return c.json<ApiResponse<ConditionSetItemResponse[]>>({
      ok: true,
      data: rows.map(itemToResponse),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to replace condition set items";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
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
  const previousItems = await snapshotConditionSetItems(tenantId, set.id);

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

  const [deleted] = await db
    .delete(conditionSetItems)
    .where(
      and(
        eq(conditionSetItems.id, c.req.param("itemId")),
        eq(conditionSetItems.tenantId, tenantId),
        eq(conditionSetItems.conditionSetId, set.id),
      ),
    )
    .returning({ id: conditionSetItems.id, value: conditionSetItems.value });

  if (!deleted)
    return c.json<ApiResponse>({ ok: false, error: "Condition set item not found" }, 404);

  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "condition_set.item.delete",
      resourceType: "condition_set_item",
      resourceId: deleted.id,
      metadata: { conditionSetId: set.id, value: deleted.value },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (error) {
    await restoreConditionSetItems(tenantId, set.id, previousItems);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true });
});
