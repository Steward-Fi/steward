import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  providerAccounts,
  providerOperations,
  secretRoutes,
  secrets,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { withTenantAuditedTransaction } from "../services/audit";
import {
  assertGovernedRouteUpdateIsSafe,
  assertNoOppositeAuthorityOverlap,
  lockSecretRouteNamespaces,
  type RouteAuthorityTx,
  SecretRouteAuthorityConflict,
  secretRouteAuthorityPatternsOverlap,
} from "../services/secret-route-authority";

const TENANT = "route-authority-tenant";
const AGENT = "route-authority-agent";
const SECRET = "72000000-0000-4000-8000-000000000000";
const GOVERNED = "72000000-0000-4000-8000-000000000001";
const RACE_TARGET = "72000000-0000-4000-8000-000000000003";
const WORKSPACE = "72000000-0000-4000-8000-000000000010";
const ACCOUNT = "72000000-0000-4000-8000-000000000011";
const GOVERNED_OPERATION = "72000000-0000-4000-8000-000000000012";
const RACE_OPERATION = "72000000-0000-4000-8000-000000000013";
const USER = "72000000-0000-4000-8000-000000000099";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function failRequiredAudit(
  appendAudit: Parameters<Parameters<typeof withTenantAuditedTransaction>[1]>[1],
) {
  await appendAudit({
    tenantId: `${TENANT}-wrong`,
    actorType: "user",
    actorId: USER,
    action: "secret_route.test",
    resourceType: "secret_route",
    metadata: {},
  });
}

describe("secret route authority exclusivity", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await db.insert(tenants).values({ id: TENANT, name: "route authority", apiKeyHash: "hash" });
    await db.insert(users).values({ id: USER, email: "route-authority@example.test" });
    await db.insert(agents).values({
      id: AGENT,
      tenantId: TENANT,
      name: "route authority agent",
      walletAddress: "0x1",
    });
    await db.insert(secrets).values({
      id: SECRET,
      tenantId: TENANT,
      name: "credential",
      ciphertext: "ciphertext",
      iv: "iv",
      authTag: "tag",
      salt: "salt",
      version: 1,
    });
    await db.insert(secretRoutes).values([
      {
        id: GOVERNED,
        tenantId: TENANT,
        agentId: AGENT,
        secretId: SECRET,
        hostPattern: "api.example.com",
        pathPattern: "/v1/items/*",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        enabled: true,
      },
      {
        id: RACE_TARGET,
        tenantId: TENANT,
        agentId: AGENT,
        secretId: SECRET,
        hostPattern: "race.example.com",
        pathPattern: "/v2/race/*",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        enabled: true,
      },
    ]);
    await db.insert(workspaces).values({
      id: WORKSPACE,
      tenantId: TENANT,
      key: "route-authority",
      name: "route authority",
      environment: "production",
      createdBy: USER,
    });
    await db.insert(providerAccounts).values({
      id: ACCOUNT,
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      adapterKey: "generic-http",
      externalRef: "route-authority",
      displayName: "route authority",
      credentialSecretId: SECRET,
      credentialVersion: 1,
    });
    await db.insert(providerOperations).values([
      {
        id: GOVERNED_OPERATION,
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        providerAccountId: ACCOUNT,
        operationKey: "route.authority.governed",
        riskClass: "write",
        secretRouteId: GOVERNED,
      },
      {
        id: RACE_OPERATION,
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        providerAccountId: ACCOUNT,
        operationKey: "route.authority.race",
        riskClass: "write",
        secretRouteId: RACE_TARGET,
      },
    ]);
    await db
      .update(secretRoutes)
      .set({ authorityMode: "governed_v2", providerOperationId: GOVERNED_OPERATION })
      .where(eq(secretRoutes.id, GOVERNED));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("uses one exact overlap predicate for wildcard host, path, and method", () => {
    expect(
      secretRouteAuthorityPatternsOverlap(
        { hostPattern: "*.example.com", pathPattern: "/v1/*", method: "*" },
        { hostPattern: "api.example.com", pathPattern: "/v1/items", method: "POST" },
      ),
    ).toBe(true);
    expect(
      secretRouteAuthorityPatternsOverlap(
        { hostPattern: "api.example.com", pathPattern: "/v2/*", method: "POST" },
        { hostPattern: "api.example.com", pathPattern: "/v1/items", method: "POST" },
      ),
    ).toBe(false);
  });

  test("rejects a legacy create bypass atomically and rolls it back", async () => {
    const legacyId = "72000000-0000-4000-8000-000000000002";
    await expect(
      getDb().transaction(async (tx) => {
        await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
        const [legacy] = await tx
          .insert(secretRoutes)
          .values({
            id: legacyId,
            tenantId: TENANT,
            agentId: AGENT,
            secretId: SECRET,
            hostPattern: "api.example.com",
            pathPattern: "/v1/items/one",
            method: "POST",
            injectAs: "header",
            injectKey: "authorization",
            authorityMode: "legacy",
            enabled: true,
          })
          .returning();
        await assertNoOppositeAuthorityOverlap(tx, legacy);
      }),
    ).rejects.toBeInstanceOf(SecretRouteAuthorityConflict);
    expect(
      await getDb().select().from(secretRoutes).where(eq(secretRoutes.id, legacyId)),
    ).toHaveLength(0);
  });

  test("a disabled governed route still reserves its namespace from legacy creation", async () => {
    const legacyId = "72000000-0000-4000-8000-000000000005";
    await getDb().update(secretRoutes).set({ enabled: false }).where(eq(secretRoutes.id, GOVERNED));
    await expect(
      getDb().transaction(async (tx) => {
        await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
        const [legacy] = await tx
          .insert(secretRoutes)
          .values({
            id: legacyId,
            tenantId: TENANT,
            agentId: AGENT,
            secretId: SECRET,
            hostPattern: "api.example.com",
            pathPattern: "/v1/items/one",
            method: "POST",
            injectAs: "header",
            injectKey: "authorization",
            authorityMode: "legacy",
            enabled: true,
          })
          .returning();
        await assertNoOppositeAuthorityOverlap(tx, { ...legacy, agentId: AGENT });
      }),
    ).rejects.toBeInstanceOf(SecretRouteAuthorityConflict);
    expect(
      await getDb().select().from(secretRoutes).where(eq(secretRoutes.id, legacyId)),
    ).toHaveLength(0);
    await getDb().update(secretRoutes).set({ enabled: true }).where(eq(secretRoutes.id, GOVERNED));
  });

  test("a disabled legacy route cannot be enabled over a governed reservation", async () => {
    const legacyId = "72000000-0000-4000-8000-000000000006";
    await getDb().insert(secretRoutes).values({
      id: legacyId,
      tenantId: TENANT,
      agentId: AGENT,
      secretId: SECRET,
      hostPattern: "api.example.com",
      pathPattern: "/v1/items/one",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      authorityMode: "legacy",
      enabled: false,
    });
    await expect(
      getDb().transaction(async (tx) => {
        await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
        const [enabled] = await tx
          .update(secretRoutes)
          .set({ enabled: true })
          .where(eq(secretRoutes.id, legacyId))
          .returning();
        await assertNoOppositeAuthorityOverlap(tx, { ...enabled, agentId: AGENT });
      }),
    ).rejects.toBeInstanceOf(SecretRouteAuthorityConflict);
    const [legacy] = await getDb().select().from(secretRoutes).where(eq(secretRoutes.id, legacyId));
    expect(legacy.enabled).toBe(false);
  });

  test("serializes a governed-promotion/legacy-create race so exactly one authority wins", async () => {
    const legacyId = "72000000-0000-4000-8000-000000000004";
    const promote = () =>
      getDb().transaction(async (tx) => {
        await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
        const [target] = await tx
          .select()
          .from(secretRoutes)
          .where(eq(secretRoutes.id, RACE_TARGET));
        await assertNoOppositeAuthorityOverlap(tx, {
          ...target,
          agentId: AGENT,
          authorityMode: "governed_v2",
        });
        await tx
          .update(secretRoutes)
          .set({ authorityMode: "governed_v2", providerOperationId: RACE_OPERATION })
          .where(eq(secretRoutes.id, RACE_TARGET));
      });
    const createLegacy = () =>
      getDb().transaction(async (tx) => {
        await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
        const [created] = await tx
          .insert(secretRoutes)
          .values({
            id: legacyId,
            tenantId: TENANT,
            agentId: AGENT,
            secretId: SECRET,
            hostPattern: "race.example.com",
            pathPattern: "/v2/race/*",
            method: "POST",
            injectAs: "header",
            injectKey: "authorization",
            authorityMode: "legacy",
            enabled: true,
          })
          .returning();
        await assertNoOppositeAuthorityOverlap(tx, created);
      });

    const results = await Promise.allSettled([promote(), createLegacy()]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected?.status === "rejected" ? rejected.reason : null).toBeInstanceOf(
      SecretRouteAuthorityConflict,
    );
    const survivors = await getDb().select().from(secretRoutes);
    const raceRoutes = survivors.filter(
      (route) => route.id === RACE_TARGET || route.id === legacyId,
    );
    expect(new Set(raceRoutes.map((route) => route.authorityMode)).size).toBe(1);
  });

  test("rejects descriptor-invalidating governed edits but permits fail-safe disable", async () => {
    const [governed] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, GOVERNED));
    expect(() => assertGovernedRouteUpdateIsSafe(governed, { pathPattern: "/v1/admin/*" })).toThrow(
      SecretRouteAuthorityConflict,
    );
    expect(() => assertGovernedRouteUpdateIsSafe(governed, { enabled: false })).not.toThrow();
  });

  test("update and required audit roll back atomically before a concurrent promotion", async () => {
    await getDb()
      .update(secretRoutes)
      .set({ authorityMode: "legacy", providerOperationId: null, pathPattern: "/v1/items/*" })
      .where(eq(secretRoutes.id, GOVERNED));
    const mutated = deferred();
    const failNow = deferred();
    const update = withTenantAuditedTransaction(TENANT, async (txRaw, appendAudit) => {
      const tx = txRaw as RouteAuthorityTx;
      await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
      await tx
        .update(secretRoutes)
        .set({ pathPattern: "/v1/changed/*" })
        .where(eq(secretRoutes.id, GOVERNED));
      mutated.resolve();
      await failNow.promise;
      await failRequiredAudit(appendAudit);
    });
    await mutated.promise;
    const promote = getDb().transaction(async (tx) => {
      await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
      const [route] = await tx.select().from(secretRoutes).where(eq(secretRoutes.id, GOVERNED));
      await assertNoOppositeAuthorityOverlap(tx, {
        ...route,
        agentId: AGENT,
        authorityMode: "governed_v2",
      });
      await tx
        .update(secretRoutes)
        .set({ authorityMode: "governed_v2", providerOperationId: GOVERNED_OPERATION })
        .where(eq(secretRoutes.id, GOVERNED));
    });
    failNow.resolve();
    await expect(update).rejects.toThrow("audit event tenant does not match");
    await promote;
    const [current] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, GOVERNED));
    expect(current).toMatchObject({
      authorityMode: "governed_v2",
      providerOperationId: GOVERNED_OPERATION,
      pathPattern: "/v1/items/*",
    });
  });

  test("create and required audit roll back atomically before a concurrent promotion", async () => {
    const createdId = "72000000-0000-4000-8000-000000000007";
    await getDb()
      .update(secretRoutes)
      .set({
        authorityMode: "legacy",
        providerOperationId: null,
        hostPattern: "create-race.example.com",
        pathPattern: "/v3/create/*",
      })
      .where(eq(secretRoutes.id, RACE_TARGET));
    const mutated = deferred();
    const failNow = deferred();
    const create = withTenantAuditedTransaction(TENANT, async (txRaw, appendAudit) => {
      const tx = txRaw as RouteAuthorityTx;
      await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
      const [created] = await tx
        .insert(secretRoutes)
        .values({
          id: createdId,
          tenantId: TENANT,
          agentId: AGENT,
          secretId: SECRET,
          hostPattern: "create-race.example.com",
          pathPattern: "/v3/create/item",
          method: "POST",
          injectAs: "header",
          injectKey: "authorization",
          enabled: true,
        })
        .returning();
      await assertNoOppositeAuthorityOverlap(tx, { ...created, agentId: AGENT });
      mutated.resolve();
      await failNow.promise;
      await failRequiredAudit(appendAudit);
    });
    await mutated.promise;
    const promote = getDb().transaction(async (tx) => {
      await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
      const [route] = await tx.select().from(secretRoutes).where(eq(secretRoutes.id, RACE_TARGET));
      await assertNoOppositeAuthorityOverlap(tx, {
        ...route,
        agentId: AGENT,
        authorityMode: "governed_v2",
      });
      await tx
        .update(secretRoutes)
        .set({ authorityMode: "governed_v2", providerOperationId: RACE_OPERATION })
        .where(eq(secretRoutes.id, RACE_TARGET));
    });
    failNow.resolve();
    await expect(create).rejects.toThrow("audit event tenant does not match");
    await promote;
    expect(
      await getDb().select().from(secretRoutes).where(eq(secretRoutes.id, createdId)),
    ).toHaveLength(0);
  });

  test("delete and required audit roll back atomically before promotion", async () => {
    const deleteId = "72000000-0000-4000-8000-000000000008";
    const deleteOperation = "72000000-0000-4000-8000-000000000018";
    await getDb().insert(secretRoutes).values({
      id: deleteId,
      tenantId: TENANT,
      agentId: AGENT,
      secretId: SECRET,
      hostPattern: "delete-race.example.com",
      pathPattern: "/v4/delete/*",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      enabled: true,
    });
    const mutated = deferred();
    const failNow = deferred();
    const remove = withTenantAuditedTransaction(TENANT, async (txRaw, appendAudit) => {
      const tx = txRaw as RouteAuthorityTx;
      await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
      await tx.delete(secretRoutes).where(eq(secretRoutes.id, deleteId));
      mutated.resolve();
      await failNow.promise;
      await failRequiredAudit(appendAudit);
    });
    await mutated.promise;
    const promote = getDb().transaction(async (tx) => {
      await lockSecretRouteNamespaces(tx, TENANT, [AGENT]);
      const [route] = await tx.select().from(secretRoutes).where(eq(secretRoutes.id, deleteId));
      await assertNoOppositeAuthorityOverlap(tx, {
        ...route,
        agentId: AGENT,
        authorityMode: "governed_v2",
      });
      await tx.insert(providerOperations).values({
        id: deleteOperation,
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        providerAccountId: ACCOUNT,
        operationKey: "route.authority.delete-race",
        riskClass: "write",
        secretRouteId: deleteId,
      });
      await tx
        .update(secretRoutes)
        .set({ authorityMode: "governed_v2", providerOperationId: deleteOperation })
        .where(eq(secretRoutes.id, deleteId));
    });
    failNow.resolve();
    await expect(remove).rejects.toThrow("audit event tenant does not match");
    await promote;
    const [current] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, deleteId));
    expect(current.authorityMode).toBe("governed_v2");
  });
});
