import { intents } from "@stwd/db";

const SENSITIVE_INTENT_KEY =
  /(?:authorization|cookie|token|secret|credential|api[-_]?key|private[-_]?key|signed[-_]?tx)$/i;
const SECRET_TEXT =
  /(?:bearer\s+|(?:api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|credential|private[-_]?key)["'\s:=]+)[^\s,"'}]+/gi;

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
  if (typeof value === "string") return value.replace(SECRET_TEXT, "[redacted]");
  if (Array.isArray(value)) {
    return value.map((item) => redactIntentResponseValue(item, depth + 1));
  }
  if (value && typeof value === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      redacted[key] = SENSITIVE_INTENT_KEY.test(key)
        ? "[redacted]"
        : redactIntentResponseValue(nested, depth + 1);
    }
    return redacted;
  }
  return value;
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
