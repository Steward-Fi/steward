import { agents, getDb, type SecretRoute, secretRoutes } from "@stwd/db";
import {
  secretRouteHostPatternsOverlap,
  secretRouteMethodPatternsOverlap,
  secretRoutePathPatternsOverlap,
} from "@stwd/shared";
import { and, eq, inArray } from "drizzle-orm";

type DbBase = ReturnType<typeof getDb>;
export type RouteAuthorityTx = Parameters<Parameters<DbBase["transaction"]>[0]>[0];

export class SecretRouteAuthorityConflict extends Error {}

const GOVERNED_ROUTE_TARGET_FIELDS = [
  "agentId",
  "hostPattern",
  "pathPattern",
  "method",
  "injectAs",
  "injectKey",
  "injectFormat",
] as const;

type RouteAuthorityCandidate = Pick<
  SecretRoute,
  "id" | "tenantId" | "hostPattern" | "pathPattern" | "method" | "enabled" | "authorityMode"
> & { agentId: string };

export function secretRouteAuthorityPatternsOverlap(
  left: Pick<RouteAuthorityCandidate, "hostPattern" | "pathPattern" | "method">,
  right: Pick<RouteAuthorityCandidate, "hostPattern" | "pathPattern" | "method">,
): boolean {
  return (
    secretRouteHostPatternsOverlap(left.hostPattern, right.hostPattern) &&
    secretRoutePathPatternsOverlap(left.pathPattern ?? "/*", right.pathPattern ?? "/*") &&
    secretRouteMethodPatternsOverlap(left.method, right.method)
  );
}

export function assertGovernedRouteUpdateIsSafe(
  existing: SecretRoute,
  update: Partial<
    Pick<
      SecretRoute,
      | "agentId"
      | "hostPattern"
      | "pathPattern"
      | "method"
      | "injectAs"
      | "injectKey"
      | "injectFormat"
      | "enabled"
    >
  >,
): void {
  if (existing.authorityMode !== "governed_v2") return;
  const changesTarget = GOVERNED_ROUTE_TARGET_FIELDS.some(
    (field) => update[field] !== undefined && update[field] !== existing[field],
  );
  if (changesTarget || (existing.enabled === false && update.enabled === true)) {
    throw new SecretRouteAuthorityConflict(
      "governed route targets can only be changed through provider operation authoring",
    );
  }
}

/**
 * Serialize every authority-changing mutation for an agent route namespace.
 * Sorting makes a route move between two agents deadlock-safe.
 */
export async function lockSecretRouteNamespaces(
  tx: RouteAuthorityTx,
  tenantId: string,
  agentIds: readonly string[],
): Promise<void> {
  const uniqueIds = [...new Set(agentIds)].sort();
  if (uniqueIds.length === 0) return;
  const locked = await tx
    .select({ id: agents.id })
    .from(agents)
    .where(and(eq(agents.tenantId, tenantId), inArray(agents.id, uniqueIds)))
    .orderBy(agents.id)
    .for("update");
  if (locked.length !== uniqueIds.length) {
    throw new SecretRouteAuthorityConflict("agent route namespace no longer exists");
  }
}

/** Fail closed when an enabled route overlaps a route under the other authority model. */
export async function assertNoOppositeAuthorityOverlap(
  tx: RouteAuthorityTx,
  candidate: RouteAuthorityCandidate,
): Promise<void> {
  if (!candidate.enabled) return;
  const siblings = await tx
    .select()
    .from(secretRoutes)
    .where(
      and(
        eq(secretRoutes.tenantId, candidate.tenantId),
        eq(secretRoutes.agentId, candidate.agentId),
      ),
    );
  const ambiguous = siblings.some(
    (sibling) =>
      sibling.id !== candidate.id &&
      sibling.authorityMode !== candidate.authorityMode &&
      // A governed route reserves its namespace even while disabled: otherwise
      // disable -> create/enable legacy -> direct credential injection bypasses
      // the provider operation. Disabled legacy routes do not reserve anything;
      // promotion only conflicts with a legacy route that can actually inject.
      (candidate.authorityMode === "legacy" || sibling.enabled) &&
      secretRouteAuthorityPatternsOverlap(candidate, sibling),
  );
  if (ambiguous) {
    throw new SecretRouteAuthorityConflict(
      "credential route overlaps an enabled route under a different authority model",
    );
  }
}

function sameRouteSnapshot(left: SecretRoute, right: SecretRoute): boolean {
  return (
    left.id === right.id &&
    left.tenantId === right.tenantId &&
    left.agentId === right.agentId &&
    left.secretId === right.secretId &&
    left.hostPattern === right.hostPattern &&
    left.pathPattern === right.pathPattern &&
    left.method === right.method &&
    left.injectAs === right.injectAs &&
    left.injectKey === right.injectKey &&
    left.injectFormat === right.injectFormat &&
    left.priority === right.priority &&
    left.enabled === right.enabled &&
    left.requiresApproval === right.requiresApproval &&
    JSON.stringify(left.approvalConfig) === JSON.stringify(right.approvalConfig) &&
    left.authorityRevision === right.authorityRevision &&
    left.authorityMode === right.authorityMode &&
    left.providerOperationId === right.providerOperationId
  );
}

async function lockedCurrentRoute(
  tx: RouteAuthorityTx,
  snapshot: SecretRoute,
): Promise<SecretRoute | null> {
  if (!snapshot.agentId) return null;
  await lockSecretRouteNamespaces(tx, snapshot.tenantId, [snapshot.agentId]);
  const [current] = await tx
    .select()
    .from(secretRoutes)
    .where(and(eq(secretRoutes.id, snapshot.id), eq(secretRoutes.tenantId, snapshot.tenantId)))
    .limit(1)
    .for("update");
  return current ?? null;
}

/** Remove a just-created route only if no concurrent authority transition changed it. */
export async function compensateCreatedSecretRoute(
  db: DbBase,
  created: SecretRoute,
): Promise<boolean> {
  try {
    return await db.transaction(async (tx) => {
      const current = await lockedCurrentRoute(tx, created);
      if (!current || !sameRouteSnapshot(current, created)) return false;
      const removed = await tx
        .delete(secretRoutes)
        .where(and(eq(secretRoutes.id, created.id), eq(secretRoutes.tenantId, created.tenantId)))
        .returning({ id: secretRoutes.id });
      return removed.length === 1;
    });
  } catch {
    return false;
  }
}

/** Restore an update only when the exact post-update row is still current and restoration is safe. */
export async function compensateUpdatedSecretRoute(
  db: DbBase,
  before: SecretRoute,
  after: SecretRoute,
): Promise<boolean> {
  if (!before.agentId || !after.agentId) return false;
  const beforeAgentId = before.agentId;
  const afterAgentId = after.agentId;
  try {
    return await db.transaction(async (tx) => {
      await lockSecretRouteNamespaces(tx, before.tenantId, [beforeAgentId, afterAgentId]);
      const [current] = await tx
        .select()
        .from(secretRoutes)
        .where(and(eq(secretRoutes.id, after.id), eq(secretRoutes.tenantId, after.tenantId)))
        .limit(1)
        .for("update");
      if (!current || !sameRouteSnapshot(current, after)) return false;
      const [restored] = await tx
        .update(secretRoutes)
        .set({
          agentId: before.agentId,
          secretId: before.secretId,
          hostPattern: before.hostPattern,
          pathPattern: before.pathPattern,
          method: before.method,
          injectAs: before.injectAs,
          injectKey: before.injectKey,
          injectFormat: before.injectFormat,
          priority: before.priority,
          enabled: before.enabled,
          requiresApproval: before.requiresApproval,
          approvalConfig: before.approvalConfig,
          authorityMode: before.authorityMode,
          providerOperationId: before.providerOperationId,
        })
        .where(and(eq(secretRoutes.id, after.id), eq(secretRoutes.tenantId, after.tenantId)))
        .returning();
      await assertNoOppositeAuthorityOverlap(tx, { ...restored, agentId: beforeAgentId });
      return true;
    });
  } catch {
    return false;
  }
}

/** Reinsert a deleted route only if its exact authority namespace is still safe. */
export async function compensateDeletedSecretRoute(
  db: DbBase,
  deleted: SecretRoute,
): Promise<boolean> {
  if (!deleted.agentId) return false;
  const deletedAgentId = deleted.agentId;
  try {
    return await db.transaction(async (tx) => {
      await lockSecretRouteNamespaces(tx, deleted.tenantId, [deletedAgentId]);
      const [occupied] = await tx
        .select({ id: secretRoutes.id })
        .from(secretRoutes)
        .where(and(eq(secretRoutes.id, deleted.id), eq(secretRoutes.tenantId, deleted.tenantId)))
        .limit(1)
        .for("update");
      if (occupied) return false;
      const [restored] = await tx.insert(secretRoutes).values(deleted).returning();
      await assertNoOppositeAuthorityOverlap(tx, { ...restored, agentId: deletedAgentId });
      return true;
    });
  } catch {
    return false;
  }
}
