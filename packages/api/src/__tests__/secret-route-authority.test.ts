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
import {
  assertGovernedRouteUpdateIsSafe,
  assertNoOppositeAuthorityOverlap,
  compensateCreatedSecretRoute,
  compensateDeletedSecretRoute,
  compensateUpdatedSecretRoute,
  lockSecretRouteNamespaces,
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

  test("update compensation never rewrites a concurrently promoted route", async () => {
    await getDb()
      .update(secretRoutes)
      .set({ authorityMode: "legacy", providerOperationId: null, pathPattern: "/v1/items/*" })
      .where(eq(secretRoutes.id, GOVERNED));
    const [before] = await getDb().select().from(secretRoutes).where(eq(secretRoutes.id, GOVERNED));
    const [after] = await getDb()
      .update(secretRoutes)
      .set({ pathPattern: "/v1/changed/*" })
      .where(eq(secretRoutes.id, GOVERNED))
      .returning();

    await getDb()
      .update(secretRoutes)
      .set({ authorityMode: "governed_v2", providerOperationId: GOVERNED_OPERATION })
      .where(eq(secretRoutes.id, GOVERNED));
    expect(await compensateUpdatedSecretRoute(getDb(), before, after)).toBe(false);
    const [current] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, GOVERNED));
    expect(current).toMatchObject({
      authorityMode: "governed_v2",
      providerOperationId: GOVERNED_OPERATION,
      pathPattern: "/v1/changed/*",
    });
    await getDb()
      .update(secretRoutes)
      .set({ pathPattern: "/v1/items/*" })
      .where(eq(secretRoutes.id, GOVERNED));
  });

  test("create compensation never deletes a concurrently promoted route", async () => {
    await getDb()
      .update(secretRoutes)
      .set({ authorityMode: "legacy", providerOperationId: null })
      .where(eq(secretRoutes.id, GOVERNED));
    const [created] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, GOVERNED));
    await getDb()
      .update(secretRoutes)
      .set({ authorityMode: "governed_v2", providerOperationId: GOVERNED_OPERATION })
      .where(eq(secretRoutes.id, GOVERNED));

    expect(await compensateCreatedSecretRoute(getDb(), created)).toBe(false);
    const [current] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, GOVERNED));
    expect(current.authorityMode).toBe("governed_v2");
  });

  test("delete compensation refuses to recreate legacy overlap after concurrent promotion", async () => {
    const deletedId = "72000000-0000-4000-8000-000000000007";
    const [deleted] = await getDb()
      .insert(secretRoutes)
      .values({
        id: deletedId,
        tenantId: TENANT,
        agentId: AGENT,
        secretId: SECRET,
        hostPattern: "api.example.com",
        pathPattern: "/v1/delete-race/*",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        authorityMode: "legacy",
        enabled: true,
      })
      .returning();
    await getDb().delete(secretRoutes).where(eq(secretRoutes.id, deletedId));
    await getDb()
      .update(secretRoutes)
      .set({ pathPattern: "/v1/delete-race/*" })
      .where(eq(secretRoutes.id, GOVERNED));

    expect(await compensateDeletedSecretRoute(getDb(), deleted)).toBe(false);
    expect(
      await getDb().select().from(secretRoutes).where(eq(secretRoutes.id, deletedId)),
    ).toHaveLength(0);
    await getDb()
      .update(secretRoutes)
      .set({ pathPattern: "/v1/items/*" })
      .where(eq(secretRoutes.id, GOVERNED));
  });
});
