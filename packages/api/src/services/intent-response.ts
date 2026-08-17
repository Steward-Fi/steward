import { intents } from "@stwd/db";

/**
 * Recursively remove signed transaction material from intent execution data.
 *
 * This preserves the established generic intent response, webhook, and stored
 * execution-result contract. The agent-readable provider-action route does not
 * use these extensible fields at all; its separate scalar DTO below is the
 * least-privilege security boundary.
 */
export function redactSignedTransactions(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSignedTransactions);
  if (!value || typeof value !== "object") return value;
  const redacted: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (key === "signedTx" || key === "signed_tx") {
      redacted[key] = "[redacted]";
    } else {
      redacted[key] = redactSignedTransactions(nested);
    }
  }
  return redacted;
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
  const executionResult = redactSignedTransactions(row.executionResult);

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
    authorizationDetails: row.authorizationDetails,
    authorization_details: row.authorizationDetails,
    payload: row.payload,
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
