/**
 * Standalone Policy Template CRUD, assignment, and simulation routes.
 *
 * Mount: app.route("/policies", policiesStandaloneRoutes)
 */

import { toPersistedPolicyRule } from "@stwd/db";
import { eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  ensureAgentForTenant,
  getConditionSetReferenceValidationError,
  getPolicySet,
  getTransactionStats,
  isNonEmptyString,
  isValidAgentId,
  isValidAnyAddress,
  loadConditionSetsForPolicies,
  type PolicyRule,
  policies,
  policyEngine,
  priceOracle,
  requireTenantLevel,
  safeJsonParse,
} from "../services/context";
import { getPolicyRulesValidationError } from "../services/policy-validation";

type PolicyRow = typeof policies.$inferSelect;

// ─── Types ────────────────────────────────────────────────────────────────────

interface PolicyTemplate {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  rules: PolicyRule[];
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

interface CreateTemplateBody {
  name: string;
  description?: string;
  rules: PolicyRule[];
  isDefault?: boolean;
}

interface AssignBody {
  agentIds: string[];
}

type TransactionSimRequest = {
  kind?: "transaction";
  to: string;
  value: string;
  data?: string;
  chainId?: number;
};

type ProxySimRequest = {
  kind?: "proxy";
  method: string;
  url: string;
  body?: unknown;
  data?: unknown;
  value?: string;
  chainId?: number;
};

type SimRequest = TransactionSimRequest | ProxySimRequest;

interface SimulateBody {
  policyId?: string;
  rules?: PolicyRule[];
  agentId?: string;
  request?: SimRequest;
  kind?: "transaction" | "proxy";
  to?: string;
  value?: string;
  data?: unknown;
  chainId?: number;
  method?: string;
  url?: string;
  body?: unknown;
}

async function snapshotAgentPolicies(agentIds: string[]): Promise<PolicyRow[]> {
  if (agentIds.length === 0) return [];
  return db.select().from(policies).where(inArray(policies.agentId, agentIds));
}

async function restoreAgentPolicies(agentIds: string[], snapshot: PolicyRow[]): Promise<void> {
  if (agentIds.length === 0) return;
  await db.transaction(async (tx) => {
    await tx.delete(policies).where(inArray(policies.agentId, agentIds));
    if (snapshot.length > 0) {
      await tx.insert(policies).values(snapshot);
    }
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const MAX_POLICY_ASSIGN_AGENTS = 100;
const MAX_POLICY_TEMPLATES_PER_TENANT = 100;
const MAX_POLICY_TEMPLATE_NAME_LENGTH = 120;
const MAX_POLICY_TEMPLATE_DESCRIPTION_LENGTH = 2_000;
const MAX_POLICY_TEMPLATE_LIST_LIMIT = 100;
const MAX_POLICY_TEMPLATE_LIST_OFFSET = 10_000;
const MAX_SIMULATION_VALUE_DIGITS = 78; // uint256 decimal length
const MAX_SIMULATION_DATA_BYTES = 32_768;
const ALLOWED_SIMULATION_PROXY_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function rowToTemplate(row: any): PolicyTemplate {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    description: row.description,
    rules: typeof row.rules === "string" ? JSON.parse(row.rules) : row.rules,
    isDefault: row.is_default,
    createdAt:
      row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
    updatedAt:
      row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
  };
}

async function listTemplatesPage(
  tenantId: string,
  limit: number,
  offset: number,
): Promise<PolicyTemplate[]> {
  const rows = await db.execute(
    sql`SELECT id, tenant_id, name, description, rules, is_default, created_at, updated_at
        FROM policy_templates
        WHERE tenant_id = ${tenantId}
        ORDER BY created_at DESC
        LIMIT ${limit}
        OFFSET ${offset}`,
  );
  return (rows as any[]).map(rowToTemplate);
}

async function getTemplate(tenantId: string, id: string): Promise<PolicyTemplate | null> {
  const rows = await db.execute(
    sql`SELECT id, tenant_id, name, description, rules, is_default, created_at, updated_at
        FROM policy_templates
        WHERE id = ${id}::uuid AND tenant_id = ${tenantId}`,
  );
  const row = (rows as any[])[0];
  return row ? rowToTemplate(row) : null;
}

async function _insertTemplate(
  tenantId: string,
  body: CreateTemplateBody,
  id = crypto.randomUUID(),
): Promise<PolicyTemplate> {
  const rows = await db.execute(
    sql`INSERT INTO policy_templates (id, tenant_id, name, description, rules, is_default)
        VALUES (${id}::uuid, ${tenantId}, ${body.name}, ${body.description ?? null}, ${JSON.stringify(body.rules ?? [])}::jsonb, ${body.isDefault ?? false})
        RETURNING id, tenant_id, name, description, rules, is_default, created_at, updated_at`,
  );
  return rowToTemplate((rows as any[])[0]);
}

async function insertTemplateWithQuota(
  tenantId: string,
  body: CreateTemplateBody,
  id: string,
): Promise<PolicyTemplate> {
  return db.transaction(async (tx) => {
    if (process.env.STEWARD_DB_MODE !== "pglite" && process.env.STEWARD_PGLITE_MEMORY !== "true") {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtext(${`policy_templates:${tenantId}`}))`,
      );
    }

    const countRows = await tx.execute(
      sql`SELECT count(*)::integer AS count
          FROM policy_templates
          WHERE tenant_id = ${tenantId}`,
    );
    const currentCount = Number((countRows as Array<{ count?: number | string }>)[0]?.count ?? 0);
    if (currentCount >= MAX_POLICY_TEMPLATES_PER_TENANT) {
      throw new Error(
        `Tenant cannot have more than ${MAX_POLICY_TEMPLATES_PER_TENANT} policy templates`,
      );
    }

    const rows = await tx.execute(
      sql`INSERT INTO policy_templates (id, tenant_id, name, description, rules, is_default)
          VALUES (${id}::uuid, ${tenantId}, ${body.name}, ${body.description ?? null}, ${JSON.stringify(body.rules ?? [])}::jsonb, ${body.isDefault ?? false})
          RETURNING id, tenant_id, name, description, rules, is_default, created_at, updated_at`,
    );
    return rowToTemplate((rows as any[])[0]);
  });
}

async function updateTemplate(
  tenantId: string,
  id: string,
  body: Partial<CreateTemplateBody>,
): Promise<PolicyTemplate | null> {
  // Build parameterized update using drizzle sql template literals.
  // Each field is set conditionally via CASE/COALESCE to avoid raw SQL injection.
  const hasName = body.name !== undefined;
  const hasDesc = body.description !== undefined;
  const hasRules = body.rules !== undefined;
  const hasDefault = body.isDefault !== undefined;

  if (!hasName && !hasDesc && !hasRules && !hasDefault) return getTemplate(tenantId, id);

  const rows = await db.execute(
    sql`UPDATE policy_templates SET
      name = CASE WHEN ${hasName} THEN ${body.name ?? ""} ELSE name END,
      description = CASE WHEN ${hasDesc} THEN ${body.description ?? null} ELSE description END,
      rules = CASE WHEN ${hasRules} THEN ${JSON.stringify(body.rules ?? [])}::jsonb ELSE rules END,
      is_default = CASE WHEN ${hasDefault} THEN ${body.isDefault ?? false} ELSE is_default END,
      updated_at = now()
    WHERE id = ${id}::uuid AND tenant_id = ${tenantId}
    RETURNING id, tenant_id, name, description, rules, is_default, created_at, updated_at`,
  );
  const row = (rows as any[])[0];
  return row ? rowToTemplate(row) : null;
}

async function deleteTemplate(tenantId: string, id: string): Promise<boolean> {
  const result = await db.execute(
    sql`DELETE FROM policy_templates WHERE id = ${id}::uuid AND tenant_id = ${tenantId} RETURNING id`,
  );
  return (result as any[]).length > 0;
}

async function restoreTemplateSnapshot(snapshot: PolicyTemplate): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.execute(
      sql`DELETE FROM policy_templates WHERE id = ${snapshot.id}::uuid AND tenant_id = ${snapshot.tenantId}`,
    );
    await tx.execute(
      sql`INSERT INTO policy_templates
          (id, tenant_id, name, description, rules, is_default, created_at, updated_at)
          VALUES (
            ${snapshot.id}::uuid,
            ${snapshot.tenantId},
            ${snapshot.name},
            ${snapshot.description},
            ${JSON.stringify(snapshot.rules)}::jsonb,
            ${snapshot.isDefault},
            ${new Date(snapshot.createdAt)},
            ${new Date(snapshot.updatedAt)}
          )`,
    );
  });
}

function isWeiSimulationValue(value: unknown): value is string {
  return (
    typeof value === "string" && /^\d+$/.test(value) && value.length <= MAX_SIMULATION_VALUE_DIGITS
  );
}

function parseListLimit(value: string | undefined): number | null {
  if (value === undefined || value === "") return MAX_POLICY_TEMPLATE_LIST_LIMIT;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_POLICY_TEMPLATE_LIST_LIMIT) {
    return null;
  }
  return parsed;
}

function parseListOffset(value: string | undefined): number | null {
  if (value === undefined || value === "") return 0;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_POLICY_TEMPLATE_LIST_OFFSET) {
    return null;
  }
  return parsed;
}

function validateTemplateText(body: Partial<CreateTemplateBody>): string | null {
  if (body.name !== undefined) {
    if (!isNonEmptyString(body.name)) return "name is required and must be a non-empty string";
    if (body.name.trim().length > MAX_POLICY_TEMPLATE_NAME_LENGTH) {
      return `name must be at most ${MAX_POLICY_TEMPLATE_NAME_LENGTH} characters`;
    }
  }
  if (body.description !== undefined) {
    if (typeof body.description !== "string") return "description must be a string";
    if (body.description.length > MAX_POLICY_TEMPLATE_DESCRIPTION_LENGTH) {
      return `description must be at most ${MAX_POLICY_TEMPLATE_DESCRIPTION_LENGTH} characters`;
    }
  }
  return null;
}

function isValidSimulationChainId(value: unknown): value is number {
  return (
    value === undefined ||
    (Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= 2_147_483_647)
  );
}

function isValidSimulationData(value: unknown): value is string | undefined {
  if (value === undefined) return true;
  if (typeof value !== "string") return false;
  if (!/^0x[0-9a-fA-F]*$/.test(value)) return false;
  return (value.length - 2) / 2 <= MAX_SIMULATION_DATA_BYTES;
}

function isValidSimulationUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function isValidTemplateId(id: string): boolean {
  return UUID_RE.test(id);
}

function getNestedProxySimulationValue(request: Record<string, unknown>): unknown {
  for (const key of ["body", "data"] as const) {
    const candidate = request[key];
    if (candidate && typeof candidate === "object" && "value" in candidate) {
      return (candidate as { value?: unknown }).value;
    }
  }
  return undefined;
}

function normalizeSimulationRequest(body: SimulateBody): SimRequest | null {
  const request = (body.request ?? body) as Record<string, unknown>;
  const kind = request.kind ?? body.kind;

  if (kind === "proxy" || (isNonEmptyString(request.method) && isNonEmptyString(request.url))) {
    if (!isNonEmptyString(request.method) || !isNonEmptyString(request.url)) return null;
    const method = request.method.toUpperCase();
    if (!ALLOWED_SIMULATION_PROXY_METHODS.has(method)) return null;
    if (!isValidSimulationUrl(request.url)) return null;
    const nestedValue = getNestedProxySimulationValue(request);
    const proxyValue = request.value !== undefined ? request.value : nestedValue;
    if (proxyValue !== undefined && !isWeiSimulationValue(String(proxyValue))) return null;
    if (!isValidSimulationChainId(request.chainId)) return null;
    return {
      kind: "proxy",
      method,
      url: request.url,
      body: "body" in request ? request.body : undefined,
      data: "data" in request ? request.data : undefined,
      value: proxyValue !== undefined ? String(proxyValue) : undefined,
      chainId: typeof request.chainId === "number" ? request.chainId : undefined,
    };
  }

  if (kind === "transaction" || (isNonEmptyString(request.to) && request.value !== undefined)) {
    if (!isNonEmptyString(request.to) || request.value === undefined || request.value === null) {
      return null;
    }
    const value = String(request.value);
    if (!isValidAnyAddress(request.to)) return null;
    if (!isWeiSimulationValue(value)) return null;
    if (!isValidSimulationData(request.data)) return null;
    if (!isValidSimulationChainId(request.chainId)) return null;
    return {
      kind: "transaction",
      to: request.to,
      value,
      data: typeof request.data === "string" ? request.data : undefined,
      chainId: typeof request.chainId === "number" ? request.chainId : undefined,
    };
  }

  return null;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

export const policiesStandaloneRoutes = new Hono<{ Variables: AppVariables }>();

function requireTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function policyAuditActor(c: Parameters<typeof requireTenantLevel>[0], tenantId: string) {
  const userId = c.get("userId");
  return {
    actorType: userId ? ("user" as const) : ("api-key" as const),
    actorId: userId ?? c.get("authType") ?? tenantId,
  };
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

function hasConditionSetRule(rules: PolicyRule[]): boolean {
  return rules.some((rule) => rule.enabled !== false && rule.type === "condition-set");
}

// List policy templates for tenant
policiesStandaloneRoutes.get("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy template access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy template access");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const limit = parseListLimit(c.req.query("limit"));
  const offset = parseListOffset(c.req.query("offset"));
  if (limit === null || offset === null) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `limit must be 1-${MAX_POLICY_TEMPLATE_LIST_LIMIT}; offset must be 0-${MAX_POLICY_TEMPLATE_LIST_OFFSET}`,
      },
      400,
    );
  }
  const templates = await listTemplatesPage(tenantId, limit, offset);
  return c.json<ApiResponse<PolicyTemplate[]>>({ ok: true, data: templates });
});

// Create policy template
policiesStandaloneRoutes.post("/", async (c) => {
  const tenantId = c.get("tenantId");

  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy template creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy template creation");
  if (mfaResponse) return mfaResponse;

  const body = await safeJsonParse<CreateTemplateBody>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const textError = validateTemplateText(body);
  if (textError) return c.json<ApiResponse>({ ok: false, error: textError }, 400);

  if (!Array.isArray(body.rules)) {
    return c.json<ApiResponse>({ ok: false, error: "rules must be an array" }, 400);
  }
  const rulesValidationError = getPolicyRulesValidationError(body.rules);
  if (rulesValidationError) {
    return c.json<ApiResponse>({ ok: false, error: rulesValidationError }, 400);
  }
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    tenantId,
    body.rules,
  );
  if (conditionSetValidationError) {
    return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
  }

  try {
    const templateId = crypto.randomUUID();
    const actor = policyAuditActor(c, tenantId);
    await writeAuditEvent({
      tenantId,
      ...actor,
      action: "policy.template.create.authorized",
      resourceType: "policy_template",
      resourceId: templateId,
      metadata: {
        name: body.name,
        ruleCount: body.rules.length,
        isDefault: body.isDefault ?? false,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    const template = await insertTemplateWithQuota(tenantId, body, templateId);
    try {
      await writeAuditEvent({
        tenantId,
        ...actor,
        action: "policy.template.create",
        resourceType: "policy_template",
        resourceId: template.id,
        metadata: {
          name: template.name,
          ruleCount: template.rules.length,
          isDefault: template.isDefault,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      await deleteTemplate(tenantId, template.id);
      throw error;
    }
    return c.json<ApiResponse<PolicyTemplate>>({ ok: true, data: template }, 201);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    if (message.includes("more than")) {
      return c.json<ApiResponse>({ ok: false, error: message }, 409);
    }
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// Get single policy template
policiesStandaloneRoutes.get("/:id", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy template access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy template access");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const id = c.req.param("id");
  if (!isValidTemplateId(id)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid policy template id format" }, 400);
  }

  const template = await getTemplate(tenantId, id);
  if (!template) {
    return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
  }

  return c.json<ApiResponse<PolicyTemplate>>({ ok: true, data: template });
});

// Update policy template
policiesStandaloneRoutes.put("/:id", async (c) => {
  const tenantId = c.get("tenantId");
  const id = c.req.param("id");
  if (!isValidTemplateId(id)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid policy template id format" }, 400);
  }

  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy template updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy template updates");
  if (mfaResponse) return mfaResponse;

  const body = await safeJsonParse<Partial<CreateTemplateBody>>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const textError = validateTemplateText(body);
  if (textError) return c.json<ApiResponse>({ ok: false, error: textError }, 400);

  if (body.rules !== undefined && !Array.isArray(body.rules)) {
    return c.json<ApiResponse>({ ok: false, error: "rules must be an array" }, 400);
  }
  if (body.rules !== undefined) {
    const rulesValidationError = getPolicyRulesValidationError(body.rules);
    if (rulesValidationError) {
      return c.json<ApiResponse>({ ok: false, error: rulesValidationError }, 400);
    }
    if (hasConditionSetRule(body.rules)) {
      if (!requireTenantAdminSession(c)) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: "Inline condition-set simulation requires owner or admin session",
          },
          403,
        );
      }
      const mfaResponse = requireRecentAdminMfa(c, "Inline condition-set simulation");
      if (mfaResponse) return mfaResponse;
    }
    const conditionSetValidationError = await getConditionSetReferenceValidationError(
      tenantId,
      body.rules,
    );
    if (conditionSetValidationError) {
      return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
    }
  }

  try {
    const before = await getTemplate(tenantId, id);
    if (!before) {
      return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
    }
    const actor = policyAuditActor(c, tenantId);
    await writeAuditEvent({
      tenantId,
      ...actor,
      action: "policy.template.update.authorized",
      resourceType: "policy_template",
      resourceId: before.id,
      metadata: {
        name: before.name,
        ruleCount: body.rules?.length ?? before.rules.length,
        isDefault: body.isDefault ?? before.isDefault,
        fields: Object.keys(body),
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    const template = await updateTemplate(tenantId, id, body);
    if (!template) {
      return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
    }
    try {
      await writeAuditEvent({
        tenantId,
        ...actor,
        action: "policy.template.update",
        resourceType: "policy_template",
        resourceId: template.id,
        metadata: {
          name: template.name,
          ruleCount: template.rules.length,
          isDefault: template.isDefault,
          fields: Object.keys(body),
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });
    } catch (error) {
      await restoreTemplateSnapshot(before);
      throw error;
    }
    return c.json<ApiResponse<PolicyTemplate>>({ ok: true, data: template });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// Delete policy template
policiesStandaloneRoutes.delete("/:id", async (c) => {
  const tenantId = c.get("tenantId");
  const id = c.req.param("id");
  if (!isValidTemplateId(id)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid policy template id format" }, 400);
  }

  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy template deletion requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy template deletion");
  if (mfaResponse) return mfaResponse;

  const existing = await getTemplate(tenantId, id);
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
  }
  const actor = policyAuditActor(c, tenantId);
  await writeAuditEvent({
    tenantId,
    ...actor,
    action: "policy.template.delete.authorized",
    resourceType: "policy_template",
    resourceId: id,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
  const deleted = await deleteTemplate(tenantId, id);
  if (!deleted) {
    return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
  }
  try {
    await writeAuditEvent({
      tenantId,
      ...actor,
      action: "policy.template.delete",
      resourceType: "policy_template",
      resourceId: id,
      metadata: { name: existing.name, ruleCount: existing.rules.length },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (error) {
    await restoreTemplateSnapshot(existing);
    throw error;
  }

  return c.json<ApiResponse>({ ok: true, data: { deleted: true } });
});

// Assign template rules to agents
policiesStandaloneRoutes.post("/:id/assign", async (c) => {
  const tenantId = c.get("tenantId");
  const id = c.req.param("id");
  if (!isValidTemplateId(id)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid policy template id format" }, 400);
  }

  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy template assignment requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Policy template assignment");
  if (mfaResponse) return mfaResponse;

  const body = await safeJsonParse<AssignBody>(c);
  if (!body || !Array.isArray(body.agentIds) || body.agentIds.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "agentIds must be a non-empty array" }, 400);
  }
  const uniqueAgentIds = Array.from(new Set(body.agentIds));
  if (
    uniqueAgentIds.length > MAX_POLICY_ASSIGN_AGENTS ||
    uniqueAgentIds.some((agentId) => !isValidAgentId(agentId))
  ) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `agentIds must contain 1-${MAX_POLICY_ASSIGN_AGENTS} unique valid agent IDs`,
      },
      400,
    );
  }

  const template = await getTemplate(tenantId, id);
  if (!template) {
    return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
  }
  const rulesValidationError = getPolicyRulesValidationError(template.rules);
  if (rulesValidationError) {
    return c.json<ApiResponse>({ ok: false, error: rulesValidationError }, 400);
  }
  const conditionSetValidationError = await getConditionSetReferenceValidationError(
    tenantId,
    template.rules,
  );
  if (conditionSetValidationError) {
    return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
  }
  const persistedRules = template.rules.map(toPersistedPolicyRule);

  // Validate all agents exist for this tenant
  const invalidAgents: string[] = [];
  for (const agentId of uniqueAgentIds) {
    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) invalidAgents.push(agentId);
  }

  if (invalidAgents.length > 0) {
    return c.json<ApiResponse>(
      { ok: false, error: `Agents not found: ${invalidAgents.join(", ")}` },
      404,
    );
  }

  const actor = policyAuditActor(c, tenantId);
  await writeAuditEvent({
    tenantId,
    ...actor,
    action: "policy.template.assign.authorized",
    resourceType: "policy_template",
    resourceId: id,
    metadata: { assignedAgents: uniqueAgentIds, rulesApplied: template.rules.length },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  // Copy template rules to each agent's policies (replace existing)
  const assigned: string[] = [];
  const previousPolicies = await snapshotAgentPolicies(uniqueAgentIds);
  await db.transaction(async (tx) => {
    for (const agentId of uniqueAgentIds) {
      await tx.delete(policies).where(eq(policies.agentId, agentId));

      if (persistedRules.length > 0) {
        await tx.insert(policies).values(
          persistedRules.map((rule) => ({
            id: crypto.randomUUID(),
            agentId,
            type: rule.type,
            enabled: rule.enabled,
            config: rule.config,
          })),
        );
      }
      assigned.push(agentId);
    }
  });
  try {
    await writeAuditEvent({
      tenantId,
      ...actor,
      action: "policy.template.assign",
      resourceType: "policy_template",
      resourceId: id,
      metadata: { assignedAgents: assigned, rulesApplied: template.rules.length },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (error) {
    await restoreAgentPolicies(uniqueAgentIds, previousPolicies);
    throw error;
  }

  return c.json<ApiResponse>({
    ok: true,
    data: {
      templateId: id,
      assignedAgents: assigned,
      rulesApplied: template.rules.length,
    },
  });
});

// Simulate policy evaluation against a mock transaction
policiesStandaloneRoutes.post("/simulate", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy simulation requires tenant-level authentication" },
      403,
    );
  }
  const tenantId = c.get("tenantId");

  const body = await safeJsonParse<SimulateBody>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  const hasPolicySelector = Object.hasOwn(body, "policyId");
  const hasAgentSelector = Object.hasOwn(body, "agentId");
  if (hasPolicySelector) {
    if (!isNonEmptyString(body.policyId) || !isValidTemplateId(body.policyId)) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid policy template id format" }, 400);
    }
  }
  if (hasAgentSelector) {
    if (!isNonEmptyString(body.agentId) || !isValidAgentId(body.agentId)) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid agent id format" }, 400);
    }
  }
  if (hasPolicySelector || hasAgentSelector) {
    if (!requireTenantAdminSession(c)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Stored policy simulation requires owner or admin session" },
        403,
      );
    }
    const mfaResponse = requireRecentAdminMfa(c, "Stored policy simulation");
    if (mfaResponse) return mfaResponse;
  }

  const request = normalizeSimulationRequest(body);
  if (!request) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "request must be either { to, value, chainId?, data? } or { method, url, body?, data? }",
      },
      400,
    );
  }

  // Get rules: from inline, a template, or agent's current policies
  let rules: PolicyRule[] = [];
  const agentScope = c.get("agentScope");

  if (body.rules && Array.isArray(body.rules)) {
    if (agentScope) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: agent tokens cannot simulate inline policies" },
        403,
      );
    }
    const rulesValidationError = getPolicyRulesValidationError(body.rules);
    if (rulesValidationError) {
      return c.json<ApiResponse>({ ok: false, error: rulesValidationError }, 400);
    }
    if (hasConditionSetRule(body.rules)) {
      if (!requireTenantAdminSession(c)) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: "Inline condition-set simulation requires owner or admin session",
          },
          403,
        );
      }
      const mfaResponse = requireRecentAdminMfa(c, "Inline condition-set simulation");
      if (mfaResponse) return mfaResponse;
    }
    const conditionSetValidationError = await getConditionSetReferenceValidationError(
      tenantId,
      body.rules,
    );
    if (conditionSetValidationError) {
      return c.json<ApiResponse>({ ok: false, error: conditionSetValidationError }, 400);
    }
    rules = body.rules;
  } else if (hasPolicySelector) {
    if (agentScope) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: agent tokens cannot simulate policy templates" },
        403,
      );
    }
    const template = await getTemplate(tenantId, body.policyId as string);
    if (!template) {
      return c.json<ApiResponse>({ ok: false, error: "Policy template not found" }, 404);
    }
    rules = template.rules;
  } else if (hasAgentSelector) {
    if (agentScope && agentScope !== body.agentId) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: token scope does not match agent" },
        403,
      );
    }
    const agentId = body.agentId as string;
    const owned = await ensureAgentForTenant(tenantId, agentId);
    if (!owned) {
      return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
    }
    rules = await getPolicySet(tenantId, agentId);
  }

  if (rules.length === 0) {
    return c.json<ApiResponse>({
      ok: true,
      data: {
        approved: true,
        results: [],
        requiresManualApproval: false,
        note: "No rules to evaluate, request would be auto-approved",
      },
    });
  }

  try {
    const conditionSets = await loadConditionSetsForPolicies(tenantId, rules);
    const liveStats = hasAgentSelector ? await getTransactionStats(body.agentId as string) : null;
    const result = await policyEngine.simulate(rules, {
      request: request as any,
      recentTxCount24h: liveStats?.recentTxCount24h ?? 0,
      recentTxCount1h: liveStats?.recentTxCount1h ?? 0,
      spentToday: liveStats?.spentToday ?? 0n,
      spentThisWeek: liveStats?.spentThisWeek ?? 0n,
      priceOracle,
      conditionSets,
    });

    return c.json<ApiResponse>({
      ok: true,
      data: {
        approved: result.approved,
        requiresManualApproval: result.requiresManualApproval,
        results: result.results,
        counters: hasAgentSelector
          ? {
              source: "live",
              recentTxCount24h: liveStats?.recentTxCount24h ?? 0,
              recentTxCount1h: liveStats?.recentTxCount1h ?? 0,
              spentToday: (liveStats?.spentToday ?? 0n).toString(),
              spentThisWeek: (liveStats?.spentThisWeek ?? 0n).toString(),
            }
          : { source: "synthetic-zero" },
      },
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Simulation failed";
    return c.json<ApiResponse>({ ok: false, error: message }, 500);
  }
});
