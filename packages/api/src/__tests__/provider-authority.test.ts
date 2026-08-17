import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  auditEvents as persistedAuditEvents,
  providerAccounts,
  providerAgentBudgets,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { type AuthorityAudit, ProviderAuthorityStore } from "../services/provider-authority-store";

setDefaultTimeout(120_000);
process.env.STEWARD_AUDIT_HMAC_KEY ??=
  "provider-authority-test-audit-hmac-key-with-adequate-entropy";

const OWNER = "10000000-0000-4000-8000-000000000001";
const ADMIN = "10000000-0000-4000-8000-000000000002";
const OTHER = "10000000-0000-4000-8000-000000000003";
const WORKSPACE_A = "20000000-0000-4000-8000-000000000001";
const WORKSPACE_B = "20000000-0000-4000-8000-000000000002";
const ACCOUNT_A = "30000000-0000-4000-8000-000000000001";
const ACCOUNT_B = "30000000-0000-4000-8000-000000000002";
const OP_A_READ = "40000000-0000-4000-8000-000000000001";
const OP_A_WRITE = "40000000-0000-4000-8000-000000000002";
const OP_B_READ = "40000000-0000-4000-8000-000000000003";
const store = new ProviderAuthorityStore();
const auditEvents: Array<{ action: string; resourceType: string }> = [];
const audit: AuthorityAudit = async (event) => {
  auditEvents.push(event);
};

function mutation(
  overrides: Partial<{
    tenantId: string;
    actorUserId: string;
    tenantRole: string;
    mfaVerifiedAt: number;
    idempotencyKey: string;
    expectedRevision: number;
    reason: string;
    audit: AuthorityAudit;
  }> = {},
) {
  return {
    tenantId: "tenant-main",
    actorUserId: OWNER,
    tenantRole: "owner",
    mfaVerifiedAt: Date.now(),
    idempotencyKey: `idem-${crypto.randomUUID()}`,
    expectedRevision: 0,
    reason: "authority test",
    audit,
    ...overrides,
  };
}

async function seedCore() {
  const db = getDb();
  await db.insert(tenants).values([
    { id: "tenant-main", name: "Main", apiKeyHash: "main-hash" },
    { id: "tenant-foreign", name: "Foreign", apiKeyHash: "foreign-hash" },
  ]);
  await db.insert(users).values([
    { id: OWNER, email: "owner@authority.test" },
    { id: ADMIN, email: "admin@authority.test" },
    { id: OTHER, email: "other@authority.test" },
  ]);
  await db.insert(userTenants).values([
    { userId: OWNER, tenantId: "tenant-main", role: "owner" },
    { userId: ADMIN, tenantId: "tenant-main", role: "admin" },
    { userId: OTHER, tenantId: "tenant-main", role: "member" },
  ]);
  await db.insert(agents).values([
    { id: "agent-x", tenantId: "tenant-main", name: "X", walletAddress: "0x1" },
    { id: "agent-y", tenantId: "tenant-main", name: "Y", walletAddress: "0x2" },
    {
      id: "foreign-agent",
      tenantId: "tenant-foreign",
      name: "F",
      walletAddress: "0x3",
    },
  ]);
  await db.insert(workspaces).values([
    {
      id: WORKSPACE_A,
      tenantId: "tenant-main",
      key: "client-a",
      name: "Client A",
      environment: "production",
      createdBy: OWNER,
    },
    {
      id: WORKSPACE_B,
      tenantId: "tenant-main",
      key: "client-b",
      name: "Client B",
      environment: "production",
      createdBy: OWNER,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: ACCOUNT_A,
      tenantId: "tenant-main",
      workspaceId: WORKSPACE_A,
      adapterKey: "github",
      externalRef: "a",
      displayName: "A",
    },
    {
      id: ACCOUNT_B,
      tenantId: "tenant-main",
      workspaceId: WORKSPACE_B,
      adapterKey: "github",
      externalRef: "b",
      displayName: "B",
    },
  ]);
  await db.insert(providerOperations).values([
    {
      id: OP_A_READ,
      tenantId: "tenant-main",
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_A,
      operationKey: "github.issue.list",
      riskClass: "read",
    },
    {
      id: OP_A_WRITE,
      tenantId: "tenant-main",
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_A,
      operationKey: "github.pr.comment.create",
      riskClass: "consequential",
    },
    {
      id: OP_B_READ,
      tenantId: "tenant-main",
      workspaceId: WORKSPACE_B,
      providerAccountId: ACCOUNT_B,
      operationKey: "github.issue.list",
      riskClass: "read",
    },
  ]);
}

describe("provider authority foundation", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await seedCore();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("owner bootstrap transitions one way to explicit tenant authority", async () => {
    const binding = await store.issueRoleBinding(mutation(), {
      principalType: "human",
      principalId: ADMIN,
      roleKey: "tenant_authority_admin",
      operationKeys: [],
    });
    expect(binding.roleKey).toBe("tenant_authority_admin");
    await expect(
      store.createWorkspace(mutation({ expectedRevision: 1 }), {
        key: "owner-after-bootstrap",
        name: "Denied",
        environment: "production",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    const created = await store.createWorkspace(
      mutation({
        actorUserId: ADMIN,
        tenantRole: "admin",
        expectedRevision: 1,
      }),
      { key: "explicit-admin", name: "Allowed", environment: "production" },
    );
    expect(created.key).toBe("explicit-admin");
  });

  test("every mutation requires authority, recent MFA, idempotency, revision, and successful pre-commit audit", async () => {
    const base = mutation({
      actorUserId: ADMIN,
      tenantRole: "admin",
      expectedRevision: 2,
    });
    await expect(
      store.createWorkspace(base, {
        key: 123 as unknown as string,
        name: "Malformed",
        environment: "production",
      }),
    ).rejects.toMatchObject({ code: "bad_request" });
    await expect(
      store.createWorkspace(
        { ...base, actorUserId: OTHER, tenantRole: "member" },
        { key: "noauth", name: "No", environment: "production" },
      ),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      store.createWorkspace(
        { ...base, mfaVerifiedAt: Date.now() - 600_000 },
        { key: "nomfa", name: "No", environment: "production" },
      ),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      store.createWorkspace(
        { ...base, idempotencyKey: "" },
        { key: "noidem", name: "No", environment: "production" },
      ),
    ).rejects.toMatchObject({ code: "bad_request" });
    await expect(
      store.createWorkspace(
        { ...base, expectedRevision: 999 },
        { key: "stale", name: "No", environment: "production" },
      ),
    ).rejects.toMatchObject({ code: "revision_conflict" });
    const before = (await getDb().select().from(workspaces)).length;
    await expect(
      store.createWorkspace(
        {
          ...base,
          audit: async () => {
            throw new Error("audit unavailable");
          },
        },
        { key: "noaudit", name: "No", environment: "production" },
      ),
    ).rejects.toThrow("audit unavailable");
    expect((await getDb().select().from(workspaces)).length).toBe(before);
  });

  test("enforces matrix scope and non-enumerating cross-workspace/tenant behavior", async () => {
    await getDb()
      .insert(providerRoleBindings)
      .values([
        {
          tenantId: "tenant-main",
          workspaceId: WORKSPACE_A,
          principalType: "human",
          principalId: OTHER,
          roleKey: "workspace_admin",
          operationKeys: ["github.issue.list"],
          grantedByUserId: ADMIN,
          reason: "scoped",
        },
        {
          tenantId: "tenant-main",
          workspaceId: WORKSPACE_B,
          principalType: "human",
          principalId: OWNER,
          roleKey: "workspace_admin",
          operationKeys: ["github.issue.list"],
          environment: "staging",
          grantedByUserId: ADMIN,
          reason: "wrong environment",
        },
      ]);
    await expect(
      store.createProviderAccount(
        mutation({
          actorUserId: OTHER,
          tenantRole: "member",
          expectedRevision: 1,
        }),
        {
          workspaceId: WORKSPACE_B,
          adapterKey: "github",
          externalRef: "forbidden",
          displayName: "Forbidden",
        },
      ),
    ).rejects.toMatchObject({ code: "not_found", status: 404 });
    await expect(
      store.createProviderAccount(
        mutation({
          actorUserId: OWNER,
          tenantRole: "owner",
          expectedRevision: 1,
        }),
        {
          workspaceId: WORKSPACE_B,
          adapterKey: "github",
          externalRef: "wrong-environment",
          displayName: "Wrong Environment",
        },
      ),
    ).rejects.toMatchObject({ code: "not_found", status: 404 });
    await expect(
      store.createProviderAccount(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          tenantId: "tenant-main",
          expectedRevision: 1,
        }),
        {
          workspaceId: "90000000-0000-4000-8000-000000000001",
          adapterKey: "github",
          externalRef: "guessed",
          displayName: "Guessed",
        },
      ),
    ).rejects.toMatchObject({ code: "not_found", status: 404 });
    await expect(
      store.issueRoleBinding(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          expectedRevision: 1,
        }),
        {
          workspaceId: WORKSPACE_B,
          principalType: "human",
          principalId: OTHER,
          roleKey: "workspace_approver",
          operationKeys: [],
          notBefore: new Date("invalid"),
        },
      ),
    ).rejects.toMatchObject({ code: "bad_request" });
    expect(await store.listProviderAccounts("tenant-main", WORKSPACE_B)).toHaveLength(1);
    expect(
      await store.listProviderAccounts("tenant-main", "90000000-0000-4000-8000-000000000001"),
    ).toEqual([]);
  });

  test("protects the last tenant authority admin", async () => {
    const [adminBinding] = await getDb()
      .select()
      .from(providerRoleBindings)
      .where(eq(providerRoleBindings.roleKey, "tenant_authority_admin"));
    await expect(
      store.revokeRoleBinding(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          expectedRevision: adminBinding.revision,
        }),
        adminBinding.id,
      ),
    ).rejects.toMatchObject({ code: "last_admin" });
  });

  test("grant operation sets attenuate the administrator mandate and grants are non-delegable", async () => {
    const [workspace] = await getDb()
      .select()
      .from(workspaces)
      .where(eq(workspaces.id, WORKSPACE_A));
    await expect(
      store.issueGrant(
        mutation({
          actorUserId: OTHER,
          tenantRole: "member",
          expectedRevision: workspace.revision,
        }),
        {
          workspaceId: WORKSPACE_A,
          providerAccountId: ACCOUNT_A,
          agentId: "agent-x",
          operationKeys: ["github.pr.comment.create"],
          expiresAt: new Date(Date.now() + 60_000),
        },
      ),
    ).rejects.toMatchObject({ code: "forbidden" });
    const grant = await store.issueGrant(
      mutation({
        actorUserId: OTHER,
        tenantRole: "member",
        expectedRevision: workspace.revision,
      }),
      {
        workspaceId: WORKSPACE_A,
        providerAccountId: ACCOUNT_A,
        agentId: "agent-x",
        operationKeys: ["github.issue.list"],
        expiresAt: new Date(Date.now() + 60_000),
        environment: "production",
      },
    );
    expect(grant.operationKeys).toEqual(["github.issue.list"]);
    expect("parentGrantId" in grant).toBe(false);
    expect("delegateGrant" in store).toBe(false);
  });

  test("access checks enforce time bounds, environment, lifecycle, and no implicit admin invoke", async () => {
    const common = {
      tenantId: "tenant-main",
      workspaceId: WORKSPACE_A,
      actor: { type: "agent" as const, id: "agent-x" },
      providerAccountId: ACCOUNT_A,
      operationKey: "github.issue.list",
      environment: "production" as const,
    };
    expect(
      (
        await store.checkAccess({
          ...common,
          evaluatedAt: new Date().toISOString(),
        })
      ).effect,
    ).toBe("allow");
    await getDb()
      .insert(providerGrants)
      .values([
        {
          tenantId: "tenant-main",
          workspaceId: WORKSPACE_A,
          providerAccountId: ACCOUNT_A,
          agentId: "agent-y",
          operationKeys: ["github.issue.list"],
          environment: "staging",
          expiresAt: new Date(Date.now() + 60_000),
          grantedByUserId: ADMIN,
          reason: "wrong env",
        },
        {
          tenantId: "tenant-main",
          workspaceId: WORKSPACE_A,
          providerAccountId: ACCOUNT_A,
          agentId: "agent-y",
          operationKeys: ["github.issue.list"],
          notBefore: new Date(Date.now() + 60_000),
          expiresAt: new Date(Date.now() + 120_000),
          grantedByUserId: ADMIN,
          reason: "future",
        },
        {
          tenantId: "tenant-main",
          workspaceId: WORKSPACE_A,
          providerAccountId: ACCOUNT_A,
          agentId: "agent-y",
          operationKeys: ["github.issue.list"],
          expiresAt: new Date(Date.now() - 1_000),
          grantedByUserId: ADMIN,
          reason: "expired",
        },
      ]);
    expect(
      (
        await store.checkAccess({
          ...common,
          actor: { type: "agent", id: "agent-y" },
          evaluatedAt: new Date().toISOString(),
        })
      ).reasonCode,
    ).toBe("no_matching_authority");
    expect(
      (
        await store.checkAccess({
          ...common,
          actor: { type: "human", id: ADMIN },
          evaluatedAt: new Date().toISOString(),
        })
      ).effect,
    ).toBe("deny");
  });

  test("Client A allow cannot be replayed against Client B or mixed identifiers", async () => {
    const base = {
      tenantId: "tenant-main",
      actor: { type: "agent" as const, id: "agent-x" },
      operationKey: "github.issue.list",
      environment: "production" as const,
      evaluatedAt: new Date().toISOString(),
    };
    const allow = await store.checkAccess({
      ...base,
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_A,
    });
    const sibling = await store.checkAccess({
      ...base,
      workspaceId: WORKSPACE_B,
      providerAccountId: ACCOUNT_B,
    });
    const mixed = await store.checkAccess({
      ...base,
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_B,
    });
    const copied = await store.checkAccess({
      ...base,
      workspaceId: WORKSPACE_B,
      providerAccountId: ACCOUNT_A,
    });
    expect(allow.effect).toBe("allow");
    expect(sibling.effect).toBe("deny");
    expect(mixed.reasonCode).toBe("resource_not_found");
    expect(copied.reasonCode).toBe("resource_not_found");
    expect(mixed.matchedGrantIds).toEqual([]);
  });

  test("expired tenant-admin authority does not act or reopen owner bootstrap", async () => {
    const [adminBinding] = await getDb()
      .select()
      .from(providerRoleBindings)
      .where(eq(providerRoleBindings.roleKey, "tenant_authority_admin"));
    await getDb()
      .update(providerRoleBindings)
      .set({ expiresAt: new Date(Date.now() - 1_000) })
      .where(eq(providerRoleBindings.id, adminBinding.id));
    await expect(
      store.createWorkspace(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          expectedRevision: 2,
        }),
        { key: "expired-admin", name: "Denied", environment: "production" },
      ),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      store.createWorkspace(mutation({ expectedRevision: 2 }), {
        key: "bootstrap-cannot-reopen",
        name: "Denied",
        environment: "production",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
  });

  test("mandatory audit runs before each successful mutation", () => {
    expect(auditEvents.some((event) => event.action === "provider.role_binding.issue")).toBe(true);
    expect(auditEvents.some((event) => event.action === "provider.workspace.create")).toBe(true);
    expect(auditEvents.some((event) => event.action === "provider.grant.issue")).toBe(true);
  });

  test("operators can create, list, revise, and disable first-class agent budgets", async () => {
    await getDb()
      .update(providerRoleBindings)
      .set({ expiresAt: null })
      .where(eq(providerRoleBindings.roleKey, "tenant_authority_admin"));
    const admin = mutation({
      actorUserId: ADMIN,
      tenantRole: "admin",
      expectedRevision: 0,
    });
    const count = await store.createAgentBudget(admin, {
      agentId: "agent-x",
      dimension: "count",
      windowSeconds: 86_400,
      max: 500,
      autoFreeze: true,
    });
    expect(count).toMatchObject({
      agentId: "agent-x",
      workspaceId: null,
      dimension: "count",
      max: 500,
      revision: 1,
    });
    const notional = await store.createAgentBudget(
      mutation({
        actorUserId: ADMIN,
        tenantRole: "admin",
        expectedRevision: 0,
      }),
      {
        agentId: "agent-x",
        workspaceId: WORKSPACE_A,
        dimension: "notional",
        windowSeconds: 604_800,
        max: 10_000,
        currency: "USD",
      },
    );
    expect(await store.listAgentBudgets("tenant-main", "agent-x")).toHaveLength(2);

    const disabled = await store.updateAgentBudget(
      mutation({
        actorUserId: ADMIN,
        tenantRole: "admin",
        expectedRevision: notional.revision,
      }),
      notional.id,
      {
        dimension: "notional",
        windowSeconds: 604_800,
        max: 9_000,
        currency: "USD",
        enabled: false,
      },
    );
    expect(disabled).toMatchObject({ max: 9_000, enabled: false, revision: 2 });
    await expect(
      store.updateAgentBudget(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          expectedRevision: 1,
        }),
        notional.id,
        {
          dimension: "notional",
          windowSeconds: 604_800,
          max: 8_000,
          currency: "USD",
        },
      ),
    ).rejects.toMatchObject({ code: "revision_conflict" });
    expect(
      (
        await getDb()
          .select()
          .from(providerAgentBudgets)
          .where(eq(providerAgentBudgets.id, count.id))
      )[0]?.autoFreeze,
    ).toBe(true);
    const budgetAuditRows = await getDb()
      .select({
        action: persistedAuditEvents.action,
        resourceId: persistedAuditEvents.resourceId,
      })
      .from(persistedAuditEvents);
    expect(
      budgetAuditRows.some(
        (event) => event.action === "provider.agent_budget.create" && event.resourceId === count.id,
      ),
    ).toBe(true);
    expect(
      budgetAuditRows.some(
        (event) =>
          event.action === "provider.agent_budget.update" && event.resourceId === notional.id,
      ),
    ).toBe(true);
  });

  test("workspace admins cannot turn a workspace budget into a tenant-global freeze", async () => {
    await getDb()
      .insert(providerGrants)
      .values({
        tenantId: "tenant-main",
        workspaceId: WORKSPACE_A,
        providerAccountId: ACCOUNT_A,
        agentId: "agent-x",
        operationKeys: ["github.issue.list"],
        expiresAt: new Date(Date.now() + 60 * 60_000),
        status: "active",
        grantedByUserId: ADMIN,
        reason: "budget authority fixture",
      });
    const workspaceAdmin = mutation({
      actorUserId: OTHER,
      tenantRole: "member",
      expectedRevision: 0,
    });

    const ordinary = await store.createAgentBudget(workspaceAdmin, {
      agentId: "agent-x",
      workspaceId: WORKSPACE_A,
      dimension: "count",
      windowSeconds: 12_345,
      max: 5,
    });
    expect(ordinary).toMatchObject({ workspaceId: WORKSPACE_A, autoFreeze: false });

    await expect(
      store.createAgentBudget(
        mutation({
          actorUserId: OTHER,
          tenantRole: "member",
          expectedRevision: 0,
        }),
        {
          agentId: "agent-x",
          workspaceId: WORKSPACE_A,
          dimension: "count",
          windowSeconds: 12_346,
          max: 0,
          autoFreeze: true,
        },
      ),
    ).rejects.toMatchObject({ code: "forbidden" });

    const freezing = await store.createAgentBudget(
      mutation({
        actorUserId: ADMIN,
        tenantRole: "admin",
        expectedRevision: 0,
      }),
      {
        agentId: "agent-x",
        workspaceId: WORKSPACE_A,
        dimension: "count",
        windowSeconds: 12_346,
        max: 0,
        autoFreeze: true,
      },
    );
    await expect(
      store.updateAgentBudget(
        mutation({
          actorUserId: OTHER,
          tenantRole: "member",
          expectedRevision: freezing.revision,
        }),
        freezing.id,
        {
          dimension: "count",
          windowSeconds: 12_346,
          max: 1,
          autoFreeze: false,
        },
      ),
    ).rejects.toMatchObject({ code: "forbidden" });

    await expect(
      store.createAgentBudget(
        mutation({
          actorUserId: OTHER,
          tenantRole: "member",
          expectedRevision: 0,
        }),
        {
          agentId: "agent-y",
          workspaceId: WORKSPACE_A,
          dimension: "count",
          windowSeconds: 12_347,
          max: 5,
        },
      ),
    ).rejects.toMatchObject({ code: "not_found", status: 404 });
  });

  test("budget insert failure rolls back its required audit event", async () => {
    const context = mutation({
      actorUserId: ADMIN,
      tenantRole: "admin",
      expectedRevision: 0,
    });
    const definition = {
      agentId: "agent-x",
      dimension: "count" as const,
      windowSeconds: 3_600,
      max: 10,
    };
    await store.createAgentBudget(context, definition);
    const before = await getDb()
      .select({ id: persistedAuditEvents.id })
      .from(persistedAuditEvents)
      .where(eq(persistedAuditEvents.action, "provider.agent_budget.create"));

    await expect(
      store.createAgentBudget(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          expectedRevision: 0,
        }),
        definition,
      ),
    ).rejects.toThrow();

    const after = await getDb()
      .select({ id: persistedAuditEvents.id })
      .from(persistedAuditEvents)
      .where(eq(persistedAuditEvents.action, "provider.agent_budget.create"));
    expect(after).toHaveLength(before.length);
  });

  test("a concurrent budget revision race commits exactly one mutation and one audit", async () => {
    const created = await store.createAgentBudget(
      mutation({
        actorUserId: ADMIN,
        tenantRole: "admin",
        expectedRevision: 0,
      }),
      {
        agentId: "agent-y",
        dimension: "count",
        windowSeconds: 7_200,
        max: 20,
      },
    );
    const update = (max: number) =>
      store.updateAgentBudget(
        mutation({
          actorUserId: ADMIN,
          tenantRole: "admin",
          expectedRevision: created.revision,
        }),
        created.id,
        {
          dimension: "count",
          windowSeconds: 7_200,
          max,
        },
      );

    const outcomes = await Promise.allSettled([update(21), update(22)]);
    expect(outcomes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((result) => result.status === "rejected")).toHaveLength(1);
    const rows = await getDb()
      .select({ id: persistedAuditEvents.id })
      .from(persistedAuditEvents)
      .where(
        and(
          eq(persistedAuditEvents.action, "provider.agent_budget.update"),
          eq(persistedAuditEvents.resourceId, created.id),
        ),
      );
    expect(rows).toHaveLength(1);
  });
});
