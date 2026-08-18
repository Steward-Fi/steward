/**
 * Minimal trust-UX client for governed-provider approval and evidence routes.
 * These routes are not in `@stwd/sdk`, so the two detail
 * pages fetch them directly with the session bearer + tenant header, exactly
 * like the tenants page does for `/user/me/tenants`.
 *
 * SAFETY:
 * - The approval-detail payload is the SAFE SUMMARY + digests only (the API
 *   never returns canonical bytes or comment text). This client
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

/** Fetch the safe approval detail for a provider action. */
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

/** Approve or deny a provider action with the required typed reason. */
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
  // reasonCode is OMITTED (not null): the route's strict schema rejects a
  // present `reasonCode` unless isApprovalReasonCode(value) passes, and
  // isApprovalReasonCode(null) is false -> APPROVAL_FIELD_INVALID. The UI's
  // free-form prose reason is the operator rationale; no structured code is
  // supplied, so the key must be absent, not null.
  const res = await fetch(`${API_URL}/v2/provider-actions/${encodeURIComponent(id)}/approval`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders(token, tenantId) },
    body: JSON.stringify({
      decision: input.decision,
      reason: input.reason,
      expectedVersion: input.expectedVersion,
      expectedRequestHash: input.expectedRequestHash,
      expectedActionDigest: input.expectedActionDigest,
      idempotencyKey,
    }),
  });
  return readJsonOrThrow(res);
}

/** Fetch the correlated case manifest. */
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

/** Fetch the signed evidence bundle for offline verification. */
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

/**
 * A provider-action approval is decidable ONLY while its binding is still
 * awaiting a human decision (`pending_approval`). Every other binding status
 * (`approved`, `execution_ready`, `executing`, `denied`, `stale`, `expired`,
 * terminal) is past the decision point, so the approve/deny controls MUST be
 * disabled and the honest terminal-state banner shown (U4). Enabling controls on
 * an already-`approved` action would let a follow-up decision hit a server-side
 * conflict instead of being blocked in the UI.
 */
export function isDecidableStatus(status: string): boolean {
  return status === "pending_approval";
}
