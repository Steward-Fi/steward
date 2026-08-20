import {
  agents,
  agentWallets,
  approvalQueue,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  pendingProxyRequests,
  policies,
  providerActionBindings,
  secretRoutes,
  transactions,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
} from "@stwd/db";
import { and, eq, inArray, sql } from "drizzle-orm";
import { type AuditEventInput, withTenantAuditedTransaction } from "./audit";

// The lease owner scrubs these states only after confirmed provider revocation
// (`revoked`/`failed`) or provider expiry (`expired`). Unknown/lost-ack outcomes
// remain `needs_attention` or `revoking`; deletion never scrubs lease material.
const TERMINAL_LEASE_STATUSES = new Set(["revoked", "expired", "failed"]);

export type AgentDeletionResult =
  | "deleted"
  | "missing"
  | "blocked_by_upstream_lease"
  | "blocked_by_executing_proxy"
  | "blocked_by_unresolved_execution";

interface DeleteAgentAuthorityInput {
  tenantId: string;
  agentId: string;
  completionAudit: AuditEventInput;
  beforeDelete?: () => Promise<void>;
}

function leaseIsTerminalAndScrubbed(row: {
  status: string;
  tokenHash: string | null;
  tokenCiphertext: string | null;
  tokenIv: string | null;
  tokenAuthTag: string | null;
  tokenSalt: string | null;
}): boolean {
  return (
    TERMINAL_LEASE_STATUSES.has(row.status) &&
    row.tokenHash === null &&
    row.tokenCiphertext === null &&
    row.tokenIv === null &&
    row.tokenAuthTag === null &&
    row.tokenSalt === null
  );
}

function resultRows<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: T[] } | null)?.rows ?? [])) as T[];
}

/**
 * Retire every local authority owned by an agent in one required-audit
 * transaction. Upstream provider credentials are deliberately not revoked or
 * relabeled here: deletion is refused until their independent lifecycle has
 * reached a terminal, secret-free state.
 */
export async function deleteAgentAuthority(
  input: DeleteAgentAuthorityInput,
): Promise<AgentDeletionResult> {
  const { tenantId, agentId } = input;
  return withTenantAuditedTransaction(tenantId, async (txRaw, appendRequiredAudit) => {
    const tx = txRaw as ReturnType<typeof getDb>;
    const [lockedAgent] = await tx
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)))
      .for("update");
    if (!lockedAgent) return "missing";

    const [executingProxyRequest] = await tx
      .select({ id: pendingProxyRequests.id })
      .from(pendingProxyRequests)
      .where(
        and(
          eq(pendingProxyRequests.tenantId, tenantId),
          eq(pendingProxyRequests.agentId, agentId),
          eq(pendingProxyRequests.status, "executing"),
        ),
      )
      .limit(1)
      .for("update");
    if (executingProxyRequest) return "blocked_by_executing_proxy";

    const [unresolvedTransaction] = await tx
      .select({ id: transactions.id })
      .from(transactions)
      .where(
        and(
          eq(transactions.agentId, agentId),
          inArray(transactions.status, ["signed", "broadcast", "outcome_unknown"]),
        ),
      )
      .limit(1)
      .for("update");
    const [unresolvedProviderAction] = await tx
      .select({ intentId: providerActionBindings.intentId })
      .from(providerActionBindings)
      .where(
        and(
          eq(providerActionBindings.tenantId, tenantId),
          eq(providerActionBindings.actorAgentId, agentId),
          inArray(providerActionBindings.status, [
            "execution_ready",
            "executing",
            "outcome_unknown",
          ]),
        ),
      )
      .limit(1)
      .for("update");
    if (unresolvedTransaction || unresolvedProviderAction) {
      return "blocked_by_unresolved_execution";
    }

    const leases = await tx
      .select({
        id: upstreamCredentialLeases.id,
        status: upstreamCredentialLeases.status,
        tokenHash: upstreamCredentialLeases.tokenHash,
        tokenCiphertext: upstreamCredentialLeases.tokenCiphertext,
        tokenIv: upstreamCredentialLeases.tokenIv,
        tokenAuthTag: upstreamCredentialLeases.tokenAuthTag,
        tokenSalt: upstreamCredentialLeases.tokenSalt,
      })
      .from(upstreamCredentialLeases)
      .where(
        and(
          eq(upstreamCredentialLeases.tenantId, tenantId),
          eq(upstreamCredentialLeases.agentId, agentId),
        ),
      )
      .for("update");
    if (leases.some((lease) => !leaseIsTerminalAndScrubbed(lease))) {
      return "blocked_by_upstream_lease";
    }

    if (leases.length > 0) {
      await tx.insert(upstreamCredentialLeaseEvents).values(
        leases.map((lease) => ({
          leaseId: lease.id,
          tenantId,
          action: "lease.agent_authority_deleted",
          decision: "deny",
          metadata: { terminalStatus: lease.status },
        })),
      );
    }

    // The capability plugin is optional, but its tables can remain after the
    // plugin is disabled. Revoke any surviving grant inside the same agent-row
    // lock used by plugin migration 0002's writer fence. This prevents an old
    // active grant from surviving deletion or becoming live again if an agent
    // identifier is later reused.
    const capabilityTable = resultRows<{ relation: string | null }>(
      await tx.execute(sql`SELECT to_regclass('public.capability_grants')::text AS relation`),
    )[0]?.relation;
    if (capabilityTable) {
      await tx.execute(sql`
        UPDATE public.capability_grants
        SET status = 'revoked'
        WHERE tenant_id = ${tenantId}
          AND agent_id = ${agentId}
          AND status = 'active'
      `);
    }

    await input.beforeDelete?.();

    await tx
      .update(secretRoutes)
      .set({ enabled: false })
      .where(
        and(
          eq(secretRoutes.tenantId, tenantId),
          eq(secretRoutes.agentId, agentId),
          eq(secretRoutes.enabled, true),
        ),
      );
    const terminalizedAt = new Date();
    await tx
      .update(pendingProxyRequests)
      .set({
        status: "denied",
        deniedAt: terminalizedAt,
        deniedBy: "system:agent-delete",
        denialReason: "agent authority deleted",
        updatedAt: terminalizedAt,
      })
      .where(
        and(
          eq(pendingProxyRequests.tenantId, tenantId),
          eq(pendingProxyRequests.agentId, agentId),
          inArray(pendingProxyRequests.status, ["pending", "approved"]),
        ),
      );
    await tx.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
    await tx.delete(transactions).where(eq(transactions.agentId, agentId));
    await tx.delete(policies).where(eq(policies.agentId, agentId));
    await tx.delete(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, agentId));
    await tx.delete(encryptedKeys).where(eq(encryptedKeys.agentId, agentId));
    await tx.delete(agentWallets).where(eq(agentWallets.agentId, agentId));
    const removedAgents = await tx
      .delete(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)))
      .returning({ id: agents.id });
    if (removedAgents.length !== 1) throw new Error("Agent changed concurrently");
    await appendRequiredAudit(input.completionAudit);
    return "deleted";
  });
}
