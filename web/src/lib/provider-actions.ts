/**
 * PR6 minimal trust-UX client for the governed-provider routes (PR3 approval,
 * PR5 case/evidence). These routes are NOT in `@stwd/sdk`, so the two detail
 * pages fetch them directly with the session bearer + tenant header, exactly
 * like the tenants page does for `/user/me/tenants`.
 *
 * SAFETY:
 * - The approval-detail payload is the SAFE SUMMARY + digests only (the API
 *   never returns canonical bytes or comment text, PR3 §5.3 / U4). This client
 *   only surfaces what the route returns; it adds NO field.
 * - The evidence bundle is downloaded for OFFLINE verification against an
 *   out-of-band key fingerprint (E7); it is never rendered as "verified" by the
 *   UI on its own (U5).
 */

import { API_URL } from "./api";

export interface ApprovalDetail {
  id: string;
  status: string;
  version: number;
  requestHash: string;
  actionDigest: string;
  expiresAt: string | null;
  // Safe, redacted summary (never canonical bytes / body text).
  safeSummary: Record<string, unknown> | null;
  operationId: string;
  providerAccountId: string;
  workspaceId: string;
}

export type CaseCompleteness = "complete" | "incomplete" | "unknown";

export interface CaseManifest {
  caseId: string;
  tenantId: string;
  workspaceId: string;
  terminalState: string;
  completeness: CaseCompleteness;
  missingRequiredRoles: string[];
  incompletenessReasons: string[];
  actionDigest: string;
  requestHash: string;
  idempotencyKeyHash: string;
  operation: { id: string; key: string; revision: number; riskClass: string };
  execution: {
    dispatchState: string;
    upstreamStatusCode: number | null;
    reconciled: boolean;
    providerIdempotencyKeyHash: string | null;
  } | null;
  safeSummary: Record<string, unknown> | null;
  genesisAt: string | null;
  terminalAt: string | null;
}

function authHeaders(token: string | null, tenantId: string | null): HeadersInit {
  return {
    Accept: "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(tenantId ? { "X-Steward-Tenant": tenantId } : {}),
  };
}

async function readJsonOrThrow(res: Response): Promise<unknown> {
  const text = await res.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const code =
      parsed && typeof parsed === "object" && "error" in parsed
        ? String((parsed as { error: { code?: string } }).error?.code ?? parsed)
        : `HTTP ${res.status}`;
    // Non-enumerating 404/403 surfaces as a uniform "not found / not authorized"
    // (SCOPE_RESOURCE_NOT_FOUND and CASE_NOT_FOUND both collapse here, §7.3).
    throw new ProviderActionError(code, res.status);
  }
  return parsed;
}

export class ProviderActionError extends Error {
  constructor(
    public readonly code: string,
    public readonly httpStatus: number,
  ) {
    super(code);
    this.name = "ProviderActionError";
  }
}

function unwrap<T>(payload: unknown): T {
  if (payload && typeof payload === "object" && "data" in payload) {
    return (payload as { data: T }).data;
  }
  return payload as T;
}

/** GET /v2/provider-actions/:id/approval (PR3) — approval detail. */
export async function getApprovalDetail(
  id: string,
  token: string | null,
  tenantId: string | null,
): Promise<ApprovalDetail> {
  const res = await fetch(`${API_URL}/v2/provider-actions/${encodeURIComponent(id)}/approval`, {
    headers: authHeaders(token, tenantId),
  });
  return unwrap<ApprovalDetail>(await readJsonOrThrow(res));
}

/** POST /v2/provider-actions/:id/approval (PR3) — approve/deny with typed reason. */
export async function decideApproval(
  id: string,
  input: {
    decision: "approve" | "deny";
    reason: string;
    expectedVersion: number;
    expectedRequestHash: string;
    expectedActionDigest: string;
  },
  token: string | null,
  tenantId: string | null,
): Promise<unknown> {
  // The route REQUIRES an idempotencyKey (rejects with APPROVAL_FIELD_INVALID
  // otherwise), so the caller cannot double-apply a decision on a retry. Derive a
  // stable key from the decision inputs (same decision on the same version/hashes
  // -> same key -> idempotent). 8..255 visible-ASCII per the route's IDEM_KEY_RE.
  const idempotencyKey =
    `decide-${input.decision}-${id}-${input.expectedVersion}-${input.expectedActionDigest}`.slice(
      0,
      255,
    );
  const res = await fetch(`${API_URL}/v2/provider-actions/${encodeURIComponent(id)}/approval`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token, tenantId) },
    body: JSON.stringify({
      decision: input.decision,
      reason: input.reason,
      // reasonCode is an allowed field; the UI supplies a null free-form reason
      // code (the typed prose reason is the operator's rationale).
      reasonCode: null,
      expectedVersion: input.expectedVersion,
      expectedRequestHash: input.expectedRequestHash,
      expectedActionDigest: input.expectedActionDigest,
      idempotencyKey,
    }),
  });
  return readJsonOrThrow(res);
}

/** GET /v2/provider-actions/:id/case (PR5) — case manifest. */
export async function getCase(
  id: string,
  token: string | null,
  tenantId: string | null,
): Promise<CaseManifest> {
  const res = await fetch(`${API_URL}/v2/provider-actions/${encodeURIComponent(id)}/case`, {
    headers: authHeaders(token, tenantId),
  });
  const payload = unwrap<{ manifest?: CaseManifest } | CaseManifest>(await readJsonOrThrow(res));
  // The route may return the manifest directly or wrapped; normalize.
  return (payload as { manifest?: CaseManifest }).manifest ?? (payload as CaseManifest);
}

/** GET /v2/provider-actions/:id/evidence (PR5) — signed bundle for offline verify. */
export async function getEvidence(
  id: string,
  token: string | null,
  tenantId: string | null,
): Promise<unknown> {
  const res = await fetch(`${API_URL}/v2/provider-actions/${encodeURIComponent(id)}/evidence`, {
    headers: authHeaders(token, tenantId),
  });
  return unwrap(await readJsonOrThrow(res));
}

/** Terminal states where decision controls MUST be disabled (honest UX, U4). */
export function isDecidableStatus(status: string): boolean {
  return status === "pending_approval" || status === "approved" || status === "pending";
}
