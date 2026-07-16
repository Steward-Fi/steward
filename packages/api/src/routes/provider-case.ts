/**
 * PR5 correlated case-evidence routes.
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
 * authorize all tenant workspace ids. Workspace-scoped `workspace_admin` /
 * `workspace_auditor` session access is deferred ("if later added", §5.2) since
 * the session gate carries a tenant role, not a workspace role. Reported as a
 * design note in the PR body.
 */

import { getDb, workspaces } from "@stwd/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { auditOwnerAdminMfaGate } from "../middleware/audit-gate";
import { AuditSigningKeyError, isCheckpointSigningConfigured } from "../services/audit-checkpoint";
import { type ApiResponse, type AppVariables } from "../services/context";
import {
  CaseRangeTooLargeError,
  getProviderCase,
  getProviderCaseEvidence,
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
    const authorized = await tenantWorkspaceIds(tenantId);
    const assembly = await getProviderCase(tenantId, caseId, authorized);
    manifestOrNull = assembly?.manifest ?? null;
  } catch (err) {
    console.error(`[provider-case] /case read failed for ${tenantId}/${caseId}:`, err);
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
    const authorized = await tenantWorkspaceIds(tenantId);
    evidence = await getProviderCaseEvidence(tenantId, caseId, authorized);
  } catch (err) {
    if (err instanceof AuditSigningKeyError) {
      return c.json<ApiResponse>({ ok: false, error: "CASE_EVIDENCE_SIGNING_DISABLED" }, 503);
    }
    if (err instanceof CaseRangeTooLargeError) {
      // Pathological same-tenant interleave (KC15): the case segment is too
      // large to export as one signed bundle. /case still serves the manifest.
      return c.json<ApiResponse>({ ok: false, error: "CASE_RANGE_TOO_LARGE" }, 400);
    }
    console.error(`[provider-case] /evidence read failed for ${tenantId}/${caseId}:`, err);
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
 */
export function registerProviderCaseRoutes(app: Hono<{ Variables: AppVariables }>): void {
  app.route("/v2", providerCaseRoutes);
}
