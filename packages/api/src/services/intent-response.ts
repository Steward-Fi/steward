import { intents } from "@stwd/db";

const SENSITIVE_INTENT_KEY_SUFFIX = /(?:token|credential|apikey|signedtx)$/;
const SECRET_TEXT =
  /(?:bearer\s+|(?:api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|credential|password|passphrase|private[-_]?key|cookie|authorization)["'\s:=]+)[^\s,"'}]+/gi;
const PEM_PRIVATE_KEY = /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----/i;
const URL_USERINFO = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+(?::[^\s/@]*)?@/i;

function isSensitiveIntentKey(key: string): boolean {
  const normalized = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
  if (normalized === "auth" || normalized.includes("authorization")) return true;
  if (normalized.includes("password") || normalized.includes("passphrase")) return true;
  if (normalized.includes("clientsecret") || normalized.includes("privatekey")) return true;
  if (normalized.includes("cookie")) return true;
  if (normalized === "secret" || normalized.includes("credential")) return true;
  return SENSITIVE_INTENT_KEY_SUFFIX.test(normalized) && normalized !== "tokenaddress";
}

/**
 * Recursively remove credential-shaped material from generic intent fields.
 *
 * Intent payloads and execution results are intentionally extensible JSON. A
 * new producer must not be able to accidentally turn GET /intents/:id (or the
 * agent-scoped provider-action status view) into a credential-read endpoint.
 * Credential key names (including producer-prefixed names such as
 * `githubAccessToken`) are redacted while legitimate fields such as
 * `tokenAddress` remain intact. String values also have common bearer/secret
 * assignments scrubbed as a defense in depth.
 */
export function redactIntentResponseValue(value: unknown, depth = 0): unknown {
  if (depth > 20) return "[redacted]";
  if (typeof value === "string") {
    if (PEM_PRIVATE_KEY.test(value) || URL_USERINFO.test(value)) return "[redacted]";
    return value.replace(SECRET_TEXT, "[redacted]");
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactIntentResponseValue(item, depth + 1));
  }
  if (value && typeof value === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      redacted[key] = isSensitiveIntentKey(key)
        ? "[redacted]"
        : redactIntentResponseValue(nested, depth + 1);
    }
    return redacted;
  }
  return value;
}

export interface ProviderActionStatusResponse {
  id: string;
  status: string;
  version: number;
  workspaceId: string;
  providerAccountId: string;
  operationId: string;
  operationRevision: number;
  actionDigest: string;
  requestHash: string;
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Least-privilege agent status view for a governed provider action.
 *
 * Keep this allowlist scalar-only. In particular, generic intent JSON and the
 * binding's extensible requestEnvelope/safeSummary/decision documents must
 * never be added here: this endpoint is reachable with an agent JWT.
 */
export function toProviderActionStatusResponse(input: ProviderActionStatusResponse) {
  return {
    id: input.id,
    status: input.status,
    version: input.version,
    workspaceId: input.workspaceId,
    providerAccountId: input.providerAccountId,
    operationId: input.operationId,
    operationRevision: input.operationRevision,
    actionDigest: input.actionDigest,
    requestHash: input.requestHash,
    expiresAt: input.expiresAt,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };
}

/** The canonical public intent response shared by every intent status route. */
export function toIntentResponse(row: typeof intents.$inferSelect) {
  const authorizationDetails = redactIntentResponseValue(row.authorizationDetails);
  const payload = redactIntentResponseValue(row.payload);
  const executionResult = redactIntentResponseValue(row.executionResult);

  return {
    id: row.id,
    intent_id: row.id,
    tenantId: row.tenantId,
    agentId: row.agentId,
    wallet_id: row.agentId,
    intentType: row.intentType,
    intent_type: row.intentType,
    status: row.status,
    resourceType: row.resourceType,
    resource_id: row.resourceId,
    resourceId: row.resourceId,
    createdByType: row.createdByType,
    created_by_id: row.createdById,
    createdById: row.createdById,
    created_by_display_name: row.createdByDisplayName,
    createdByDisplayName: row.createdByDisplayName,
    authorizationDetails,
    authorization_details: authorizationDetails,
    payload,
    executionResult,
    execution_result: executionResult,
    expiresAt: row.expiresAt,
    expires_at: row.expiresAt?.getTime() ?? null,
    authorizedBy: row.authorizedBy,
    authorized_by: row.authorizedBy,
    canceledAt: row.canceledAt,
    canceledBy: row.canceledBy,
    canceled_by: row.canceledBy,
    cancellationReason: row.cancellationReason,
    cancellation_reason: row.cancellationReason,
    expiredAt: row.expiredAt,
    expiredBy: row.expiredBy,
    expired_by: row.expiredBy,
    rejectedAt: row.rejectedAt,
    rejectedBy: row.rejectedBy,
    rejected_by: row.rejectedBy,
    rejectionReason: row.rejectionReason,
    rejection_reason: row.rejectionReason,
    executedBy: row.executedBy,
    executed_by: row.executedBy,
    failedAt: row.failedAt,
    failedBy: row.failedBy,
    failed_by: row.failedBy,
    failureReason: row.failureReason,
    failure_reason: row.failureReason,
    createdAt: row.createdAt,
    created_at: row.createdAt.getTime(),
    updatedAt: row.updatedAt,
    authorizedAt: row.authorizedAt,
    executedAt: row.executedAt,
  };
}
