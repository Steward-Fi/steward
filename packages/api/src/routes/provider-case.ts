/**
 * Correlated provider case-evidence routes.
 *
 *   GET /v2/provider-actions/:id/case      → ProviderCaseManifestV1 (manifest only)
 *   GET /v2/provider-actions/:id/evidence  → ProviderCaseEvidenceV1 (manifest + signed bundle)
 *
 * Authz (spec §5.2): the SAME owner/admin + recent-MFA gate as `/audit/*`
 * (imported from middleware/audit-gate, never a weaker one, spec §6.3). Agent
 * tokens are rejected. `:id` is the intent/case id. A foreign-tenant,
 * foreign-workspace, or nonexistent case returns a uniform 404 CASE_NOT_FOUND
 * (non-enumerating, spec §5.4 / D2). `/evidence` additionally requires the audit
 * signing key (503 CASE_EVIDENCE_SIGNING_DISABLED when unset), mirroring
 * `/audit/bundle`.
 *
 * Scoping note (spec §5.2): the shared gate admits tenant `owner`/`admin`
 * sessions; those callers may read ANY workspace in their tenant, so we
 * authorize all tenant workspace ids. The session gate carries tenant roles,
 * so workspace-scoped roles do not authorize these routes.
 */

import { getDb, workspaces } from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { auditOwnerAdminMfaGate } from "../middleware/audit-gate";
import { AuditSigningKeyError, isCheckpointSigningConfigured } from "../services/audit-checkpoint";
import { AuditCheckpointAnchorError } from "../services/audit-checkpoint-anchor";
import {
  type ApiResponse,
  type AppVariables,
  setNoStoreHeaders,
  tenantAuth,
  withAuthenticatedTenantDatabase,
} from "../services/context";
import {
  CaseRangeTooLargeError,
  getProviderCase,
  readProviderCaseEvidenceSnapshot,
  signProviderCaseEvidenceSnapshot,
} from "../services/provider-case";

export const providerCaseRoutes = new Hono<{ Variables: AppVariables }>();

// Same owner/admin + recent-MFA gate as /audit/* (spec §5.2/§6.3). Scoped to
// the two case/evidence paths only (registered concretely below) so it does not
// gate the sibling `/v2/provider-actions` create/read paths, which use the
// agent-token auth path instead.
providerCaseRoutes.use("/provider-actions/:id/case", auditOwnerAdminMfaGate);
providerCaseRoutes.use("/provider-actions/:id/evidence", auditOwnerAdminMfaGate);

// A case id is `pa_<uuid>` (see provider-action-service). Validate strictly so a
// path-traversal / null-byte / control-char id (N37/N38/N39) is rejected before
// any DB access and returns the SAME uniform 404 as a genuine miss.
const CASE_ID_PATTERN = /^pa_[0-9a-fA-F-]{36}$/;
const SNAPSHOT_CHARACTERISTICS = {
  isolationLevel: "repeatable read" as const,
  readOnly: true,
};

function isValidCaseId(id: string): boolean {
  return CASE_ID_PATTERN.test(id);
}

/** All workspace ids in the caller's tenant (tenant owner/admin sees all). */
async function tenantWorkspaceIds(tenantId: string): Promise<string[]> {
  const rows = await getDb()
    .select({ id: workspaces.id })
    .from(workspaces)
    .where(eq(workspaces.tenantId, tenantId));
  return rows.map((r) => r.id);
}

providerCaseRoutes.get("/provider-actions/:id/case", async (c) => {
  const tenantId = c.get("tenantId");
  const caseId = c.req.param("id");
  if (!isValidCaseId(caseId)) {
    // Non-enumerating: identical to a genuine not-found (§5.4).
    return c.json<ApiResponse>({ ok: false, error: "CASE_NOT_FOUND" }, 404);
  }

  let manifestOrNull;
  try {
    const userId = c.get("userId");
    if (!userId) return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
    const assembly = await withAuthenticatedTenantDatabase(
      tenantId,
      "provider-case-snapshot",
      userId,
      async () => {
        const authorized = await tenantWorkspaceIds(tenantId);
        return getProviderCase(tenantId, caseId, authorized);
      },
      userId,
      SNAPSHOT_CHARACTERISTICS,
    );
    manifestOrNull = assembly?.manifest ?? null;
  } catch (err) {
    console.error(
      `[provider-case] /case read failed for ${tenantId}/${caseId}`,
      redactedThrownDiagnostics(err),
    );
    return c.json<ApiResponse>({ ok: false, error: "CASE_CHAIN_UNAVAILABLE" }, 500);
  }

  if (!manifestOrNull) {
    return c.json<ApiResponse>({ ok: false, error: "CASE_NOT_FOUND" }, 404);
  }
  return c.json(manifestOrNull);
});

providerCaseRoutes.get("/provider-actions/:id/evidence", async (c) => {
  const tenantId = c.get("tenantId");
  const caseId = c.req.param("id");
  if (!isValidCaseId(caseId)) {
    return c.json<ApiResponse>({ ok: false, error: "CASE_NOT_FOUND" }, 404);
  }

  // /evidence requires the signing key (mirrors /audit/bundle at audit.ts).
  if (!isCheckpointSigningConfigured()) {
    return c.json<ApiResponse>({ ok: false, error: "CASE_EVIDENCE_SIGNING_DISABLED" }, 503);
  }

  let evidence;
  try {
    const userId = c.get("userId");
    if (!userId) return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
    const snapshot = await withAuthenticatedTenantDatabase(
      tenantId,
      "provider-case-snapshot",
      userId,
      async () => {
        const authorized = await tenantWorkspaceIds(tenantId);
        return readProviderCaseEvidenceSnapshot(tenantId, caseId, authorized);
      },
      userId,
      SNAPSHOT_CHARACTERISTICS,
    );
    evidence = snapshot ? await signProviderCaseEvidenceSnapshot(snapshot) : null;
  } catch (err) {
    if (err instanceof AuditSigningKeyError) {
      return c.json<ApiResponse>({ ok: false, error: "CASE_EVIDENCE_SIGNING_DISABLED" }, 503);
    }
    if (err instanceof AuditCheckpointAnchorError) {
      return c.json<ApiResponse>({ ok: false, error: "CASE_EVIDENCE_ANCHOR_UNAVAILABLE" }, 503);
    }
    if (err instanceof CaseRangeTooLargeError) {
      // Pathological same-tenant interleave (KC15): the case segment is too
      // large to export as one signed bundle. /case still serves the manifest.
      return c.json<ApiResponse>({ ok: false, error: "CASE_RANGE_TOO_LARGE" }, 400);
    }
    console.error(
      `[provider-case] /evidence read failed for ${tenantId}/${caseId}`,
      redactedThrownDiagnostics(err),
    );
    return c.json<ApiResponse>({ ok: false, error: "CASE_CHAIN_UNAVAILABLE" }, 500);
  }

  if (!evidence) {
    return c.json<ApiResponse>({ ok: false, error: "CASE_NOT_FOUND" }, 404);
  }
  return c.json(evidence);
});

/**
 * Register the case/evidence routes CONCRETELY on the app under `/v2` and
 * BEFORE the `/v2` authority wildcard sub-app, so `/v2/provider-actions/:id/case`
 * and `/v2/provider-actions/:id/evidence` win over the authority
 * `/provider-accounts/:id/...` and the `/v2/provider-actions/:id` read wildcards
 * (same collision-avoidance pattern as registerProviderActionRoutes).
 *
 * CRITICAL: `tenantAuth` MUST be registered on the concrete case/evidence paths
 * directly on the app so it populates `authType`/`tenantRole`/`tenantId`/
 * `sessionMfaVerifiedAt` BEFORE the sub-app's `auditOwnerAdminMfaGate` consumes
 * them (identical pattern to `registerProviderApprovalRoutes` for
 * `/v2/provider-actions/:id/{approval,execute}`). The global app.ts middleware
 * only wires `tenantAuth` for `/v2/workspaces|provider-accounts|...` — NOT for
 * `/v2/provider-actions/*` — so without this the gate would see an unpopulated
 * context and reject EVERY request with 403, making the routes unreachable.
 */
export function registerProviderCaseRoutes(app: Hono<{ Variables: AppVariables }>): void {
  const casePaths = ["/v2/provider-actions/:id/case", "/v2/provider-actions/:id/evidence"];
  for (const p of casePaths) {
    app.use(p, async (c, next) => {
      setNoStoreHeaders(c);
      await next();
    });
    app.use(p, (c, next) => tenantAuth(c, next, { bindTenantDatabase: false }));
  }
  app.route("/v2", providerCaseRoutes);
}
