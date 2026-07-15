/**
 * Shared PGLite fixture for the PR3 provider-approval test suite. Seeds a full
 * tenant with a workspace, provider account (+credential), a governed operation
 * (+route), an active agent grant, and an eligible human workspace_approver so
 * an approval-required provider action can be created and decided end-to-end.
 */

import {
  agents,
  approvalQueue,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  userTenants,
  users,
  workspaces,
} from "@stwd/db";
import { buildGithubAction } from "@stwd/provider-github";
import { eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";

export const F = {
  TENANT: "tenant-appr",
  TENANT_B: "tenant-b",
  AGENT: "agent-a",
  AGENT_OWNER: "70000000-0000-4000-8000-000000000001",
  WORKSPACE: "20000000-0000-4000-8000-000000000001",
  WORKSPACE_2: "20000000-0000-4000-8000-000000000002",
  ACCOUNT: "30000000-0000-4000-8000-000000000001",
  OP: "40000000-0000-4000-8000-000000000001",
  OP_KEY: "github.pr.comment.create",
  SECRET: "50000000-0000-4000-8000-000000000001",
  ROUTE: "60000000-0000-4000-8000-000000000001",
  GRANTOR: "10000000-0000-4000-8000-000000000001",
  APPROVER: "80000000-0000-4000-8000-000000000001",
  APPROVER_2: "80000000-0000-4000-8000-000000000002",
  APPROVER_BINDING: "90000000-0000-4000-8000-000000000001",
  GRANT: "a0000000-0000-4000-8000-000000000001",
};

const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);

export function principal(agentId = F.AGENT, tenantId = F.TENANT): ProviderPrincipalV1 {
  return {
    type: "agent",
    agentId,
    tenantId,
    platformId: null,
    issuer: "eliza-cloud",
    subject: `agent:${agentId}`,
    tokenId: null,
    scopes: [],
    authenticatedAt: new Date().toISOString(),
    expiresAt: null,
    authnMethod: "agent-jwt-rs256",
  };
}

/** A require-approval policy rule for the op (allow + require-approval => approval). */
export const APPROVAL_RULES = [
  {
    id: "11111111-1111-4111-8111-111111111111",
    type: "capability-intent",
    enabled: true,
    config: { capabilities: [F.OP_KEY], effect: "allow" },
  },
  {
    id: "22222222-2222-4222-8222-222222222222",
    type: "capability-intent",
    enabled: true,
    config: { capabilities: [F.OP_KEY], effect: "require-approval" },
  },
];

export async function seedFixture(opts: { requesterSeparation?: boolean } = {}) {
  const db = getDb();
  await db.insert(tenants).values([
    { id: F.TENANT, name: "Appr", apiKeyHash: "h" },
    { id: F.TENANT_B, name: "B", apiKeyHash: "h2" },
  ]);
  await db.insert(users).values([
    { id: F.GRANTOR, email: "g@t.test" },
    { id: F.APPROVER, email: "approver@t.test" },
    { id: F.APPROVER_2, email: "approver2@t.test" },
    { id: F.AGENT_OWNER, email: "owner@t.test" },
  ]);
  await db.insert(userTenants).values([
    { userId: F.APPROVER, tenantId: F.TENANT, role: "member" },
    { userId: F.APPROVER_2, tenantId: F.TENANT, role: "admin" },
    { userId: F.AGENT_OWNER, tenantId: F.TENANT, role: "member" },
  ]);
  await db.insert(agents).values([
    {
      id: F.AGENT,
      tenantId: F.TENANT,
      name: "A",
      walletAddress: "0x1",
      ownerUserId: opts.requesterSeparation ? F.AGENT_OWNER : null,
    },
  ]);
  await db.insert(secrets).values([
    {
      id: F.SECRET,
      tenantId: F.TENANT,
      name: "github",
      ciphertext: "x",
      iv: "x",
      authTag: "x",
      salt: "x",
      version: 1,
    },
  ]);
  await db.insert(secretRoutes).values([
    {
      id: F.ROUTE,
      tenantId: F.TENANT,
      secretId: F.SECRET,
      hostPattern: "api.github.com",
      pathPattern: "/*",
      method: "*",
      injectAs: "header",
      injectKey: "authorization",
    },
  ]);
  await db.insert(workspaces).values([
    {
      id: F.WORKSPACE,
      tenantId: F.TENANT,
      key: "client-a",
      name: "A",
      environment: "production",
      createdBy: F.GRANTOR,
    },
    {
      id: F.WORKSPACE_2,
      tenantId: F.TENANT,
      key: "client-2",
      name: "2",
      environment: "production",
      createdBy: F.GRANTOR,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: F.ACCOUNT,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      adapterKey: "github",
      externalRef: "a",
      displayName: "A",
      credentialSecretId: F.SECRET,
      credentialVersion: 1,
    },
  ]);
  await db.insert(providerOperations).values([
    {
      id: F.OP,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      operationKey: F.OP_KEY,
      riskClass: "consequential",
      secretRouteId: F.ROUTE,
      requestProfile: {
        policyRules: APPROVAL_RULES,
        ...(opts.requesterSeparation
          ? { approvalRequirements: { requesterSeparation: true } }
          : {}),
      },
    },
  ]);
  await db.insert(providerGrants).values([
    {
      id: F.GRANT,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      agentId: F.AGENT,
      operationKeys: [F.OP_KEY],
      environment: "production",
      expiresAt: FUTURE,
      grantedByUserId: F.GRANTOR,
      reason: "test",
    },
  ]);
  // Eligible human workspace_approver for the exact workspace.
  await db.insert(providerRoleBindings).values([
    {
      id: F.APPROVER_BINDING,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      principalType: "human",
      principalId: F.APPROVER,
      roleKey: "workspace_approver",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: F.GRANTOR,
      reason: "approver",
    },
  ]);
}

/** Create an approval-required provider action and return its intentId. */
export async function createApprovalRequired(idem = "aaaaaaaa"): Promise<{
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
    idempotencyKeyHash: `sha256:${Buffer.from(idem.padEnd(32, "0")).toString("hex").slice(0, 64)}`,
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: idem.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
  if (out.kind !== "approval_required") {
    throw new Error(`expected approval_required, got ${out.kind} (${(out as { code?: string }).code})`);
  }
  return { intentId: out.intentId, requestHash: out.requestHash, actionDigest: out.actionDigest };
}

export async function bindingRow(intentId: string) {
  const [b] = await getDb()
    .select()
    .from(providerActionBindings)
    .where(eq(providerActionBindings.intentId, intentId));
  return b;
}

export async function queueRow(intentId: string) {
  const [q] = await getDb()
    .select()
    .from(approvalQueue)
    .where(eq(approvalQueue.intentId, intentId));
  return q;
}

export async function intentRow(intentId: string) {
  const [i] = await getDb().select().from(intents).where(eq(intents.id, intentId));
  return i;
}

export async function auditCount(tenantId = F.TENANT, action?: string): Promise<number> {
  const rows = await getDb().execute(
    action
      ? sql`SELECT count(*)::int AS n FROM audit_events WHERE tenant_id = ${tenantId} AND action = ${action}`
      : sql`SELECT count(*)::int AS n FROM audit_events WHERE tenant_id = ${tenantId}`,
  );
  const arr = Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? []);
  return Number((arr[0] as { n: number }).n);
}

/** Distinct audit rows correlated to a case by top-level resource_id (PR5 C1). */
export async function correlatedAudit(
  intentId: string,
  tenantId = F.TENANT,
): Promise<Array<{ action: string; resource_type: string; resource_id: string; intent_meta: string }>> {
  const rows = await getDb().execute(
    sql`SELECT action, resource_type, resource_id, (metadata->>'intentId') AS intent_meta
        FROM audit_events
        WHERE tenant_id = ${tenantId} AND resource_type = 'provider_action' AND resource_id = ${intentId}
        ORDER BY seq ASC`,
  );
  const arr = Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? []);
  return arr as Array<{ action: string; resource_type: string; resource_id: string; intent_meta: string }>;
}

export function freshMfa(): number {
  return Date.now() - 1000;
}
