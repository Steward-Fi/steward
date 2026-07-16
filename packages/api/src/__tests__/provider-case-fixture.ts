/**
 * PR5 case-evidence test fixture. Reuses the PR3 approval fixture's seed and adds
 * helpers to drive a case to each terminal state (denied_access, pending,
 * approved, execution_ready, succeeded-stub) plus utilities to read the
 * correlated audit events and reset the audit chain between tests.
 */

import {
  approvalQueue,
  getDb,
  intents,
  providerAccounts,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { buildGithubAction } from "@stwd/provider-github";
import { and, eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";
import { F, principal, seedFixture } from "./provider-approval-fixture";

const ALLOW_ONLY_OP = "40000000-0000-4000-8000-0000000000a0";
const ALLOW_ONLY_OP_KEY = "github.issue.list";
const ALLOW_ONLY_GRANT = "a0000000-0000-4000-8000-0000000000a0";

/** Allow-only policy for a read op (no approval) so the case reaches the stub. */
const ALLOW_ONLY_RULES = [
  {
    id: "33333333-3333-4333-8333-333333333333",
    type: "capability-intent",
    enabled: true,
    config: { capabilities: [ALLOW_ONLY_OP_KEY], effect: "allow" },
  },
];

/** Seed the base fixture + an allow-only read operation and matching grant. */
export async function seedCaseFixture(): Promise<void> {
  await seedFixture();
  const db = getDb();
  // Give the admin user (APPROVER_2) a membership in TENANT_B too, so the
  // N01 foreign-tenant test exercises the ROUTE-LEVEL tenant scoping (a valid
  // admin of tenant B must get a uniform 404 for tenant A's case, not leak
  // membership) rather than tripping tenantAuth's not-a-member 403 first.
  await db
    .insert(userTenants)
    .values([{ userId: F.APPROVER_2, tenantId: F.TENANT_B, role: "admin" }])
    .onConflictDoNothing();
  await db.insert(providerOperations).values([
    {
      id: ALLOW_ONLY_OP,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      operationKey: ALLOW_ONLY_OP_KEY,
      riskClass: "read",
      secretRouteId: F.ROUTE,
      requestProfile: { policyRules: ALLOW_ONLY_RULES },
    },
  ]);
  await db.insert(providerGrants).values([
    {
      id: ALLOW_ONLY_GRANT,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      agentId: F.AGENT,
      operationKeys: [ALLOW_ONLY_OP_KEY, F.OP_KEY],
      environment: "production",
      expiresAt: new Date(Date.now() + 365 * 24 * 3600_000),
      grantedByUserId: F.GRANTOR,
      reason: "test",
    },
  ]);
}

/** Wipe all provider + audit state between tests (audit chain included). */
export async function wipeCase(): Promise<void> {
  const db = getDb();
  await db.execute(sql`DELETE FROM provider_action_audit_outbox`);
  await db.execute(sql`DELETE FROM execution_authorization_nonces`);
  await db.delete(approvalQueue);
  await db.delete(providerActionBindings);
  await db.delete(intents);
  await db.delete(providerGrants);
  await db.delete(providerRoleBindings);
  await db.delete(providerOperations);
  await db.delete(providerAccounts);
  await db.delete(secretRoutes);
  await db.delete(secrets);
  await db.delete(workspaces);
  await db.delete(userTenants);
  await db.delete(users);
  await db.delete(tenants);
  await db.execute(sql`DELETE FROM audit_events`);
  await db.execute(sql`DELETE FROM audit_chain_heads`);
  await db.execute(sql`DELETE FROM audit_checkpoints`);
}

function idem(seed: string): string {
  return `sha256:${Buffer.from(seed.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

/** Create an ALLOWED read action that runs the stub → succeeded/failed. */
export async function createAllowedCase(seed = "allow001"): Promise<string> {
  const now = new Date();
  const out = await providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: F.WORKSPACE,
    providerAccountId: F.ACCOUNT,
    operationKey: ALLOW_ONLY_OP_KEY,
    build: buildGithubAction(ALLOW_ONLY_OP_KEY, {
      owner: "octo",
      repo: "hello",
    }),
    idempotencyKeyHash: idem(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
  if (out.kind !== "allowed") {
    throw new Error(`expected allowed, got ${out.kind} (${(out as { code?: string }).code})`);
  }
  return out.intentId;
}

/** Create a DENIED-by-access case (Client B account guessed / no grant match). */
export async function createAccessDeniedCase(seed = "deny0001"): Promise<string> {
  const now = new Date();
  // Use workspace 2 which has no provider account/operation → scope_not_found
  // does NOT create an intent. To get an access-DENY WITH a binding, we call the
  // approval op with an agent that lacks a grant (revoke first) — but simplest:
  // create in WORKSPACE with the approval op after revoking the grant.
  await getDb()
    .update(providerGrants)
    .set({ status: "revoked" })
    .where(and(eq(providerGrants.tenantId, F.TENANT)));
  const out = await providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: F.WORKSPACE,
    providerAccountId: F.ACCOUNT,
    operationKey: F.OP_KEY,
    build: buildGithubAction(F.OP_KEY, {
      owner: "octo",
      repo: "hello",
      pullNumber: 1,
      body: "hi",
    }),
    idempotencyKeyHash: idem(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
  if (out.kind !== "access_denied") {
    throw new Error(`expected access_denied, got ${out.kind}`);
  }
  return out.intentId;
}

/** Create an approval-required case, returning identifiers for decide(). */
export async function createPendingCase(seed = "pend0001"): Promise<{
  intentId: string;
  requestHash: string;
  actionDigest: string;
}> {
  const now = new Date();
  const out = await providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: F.WORKSPACE,
    providerAccountId: F.ACCOUNT,
    operationKey: F.OP_KEY,
    build: buildGithubAction(F.OP_KEY, {
      owner: "octo",
      repo: "hello",
      pullNumber: 1,
      body: "hi",
    }),
    idempotencyKeyHash: idem(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
  if (out.kind !== "approval_required") {
    throw new Error(`expected approval_required, got ${out.kind}`);
  }
  return { intentId: out.intentId, requestHash: out.requestHash, actionDigest: out.actionDigest };
}

/** Approve a pending case (→ approved binding + decided audit). */
export async function approveCase(
  intentId: string,
  requestHash: string,
  actionDigest: string,
): Promise<void> {
  const res = await providerApprovalService.decide({
    intentId,
    tenantId: F.TENANT,
    authenticatedUserId: F.APPROVER,
    sessionMfaVerifiedAt: Date.now(),
    decision: "approve",
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: null,
    idempotencyKey: `decide-${intentId.slice(0, 8)}`,
  });
  if (!res.ok) throw new Error(`approve failed: ${(res as { error?: string }).error}`);
}

/** Deny a pending case (→ approval_denied binding + decided audit). */
export async function denyCase(
  intentId: string,
  requestHash: string,
  actionDigest: string,
): Promise<void> {
  const res = await providerApprovalService.decide({
    intentId,
    tenantId: F.TENANT,
    authenticatedUserId: F.APPROVER,
    sessionMfaVerifiedAt: Date.now(),
    decision: "deny",
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: null,
    idempotencyKey: `deny-${intentId.slice(0, 8)}`,
  });
  if (!res.ok) throw new Error(`deny failed: ${(res as { error?: string }).error}`);
}

/** Read raw correlated audit rows for a case (for assertions). */
export async function readCorrelated(intentId: string): Promise<
  Array<{
    seq: number;
    action: string;
    resource_type: string;
    resource_id: string;
    intentMeta: unknown;
  }>
> {
  const res = await getDb().execute(
    sql`SELECT seq, action, resource_type, resource_id, metadata->>'intentId' AS intent_meta
        FROM audit_events
        WHERE tenant_id = ${F.TENANT} AND resource_type = 'provider_action' AND resource_id = ${intentId}
        ORDER BY seq ASC`,
  );
  const rows = Array.isArray(res) ? res : ((res as { rows?: unknown[] }).rows ?? []);
  return (rows as Array<Record<string, unknown>>).map((r) => ({
    seq: Number(r.seq),
    action: String(r.action),
    resource_type: String(r.resource_type),
    resource_id: String(r.resource_id),
    intentMeta: r.intent_meta,
  }));
}

export type { ProviderPrincipalV1 };
export { F, principal };
