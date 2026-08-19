import {
  agents,
  agentWallets,
  approvalQueue,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  pendingProxyRequests,
  policies,
  secretRoutes,
  transactions,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
} from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";
import { type AuditEventInput, withTenantAuditedTransaction } from "./audit";

// The lease owner scrubs these states only after confirmed provider revocation
// (`revoked`/`failed`) or provider expiry (`expired`). Unknown/lost-ack outcomes
// remain `needs_attention` or `revoking`; deletion never scrubs lease material.
const TERMINAL_LEASE_STATUSES = new Set(["revoked", "expired", "failed"]);

export type AgentDeletionResult =
  | "deleted"
  | "missing"
  | "blocked_by_upstream_lease"
  | "blocked_by_executing_proxy";

interface DeleteAgentAuthorityInput {
  tenantId: string;
  agentId: string;
  completionAudit: AuditEventInput;
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
