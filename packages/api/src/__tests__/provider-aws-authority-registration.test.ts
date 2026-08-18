import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  providerAccounts,
  providerOperations,
  secretRoutes,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { ProviderAuthorityStore } from "../services/provider-authority-store";

setDefaultTimeout(120_000);

const TENANT = "tenant-aws-authority";
const OWNER = "10000000-0000-4000-8000-000000000204";
const WORKSPACE = "20000000-0000-4000-8000-000000000204";
const AGENT = "agent-aws-authority";
const MASTER = "aws-authority-registration-test-master";

describe("AWS provider authority registration", () => {
  const store = new ProviderAuthorityStore();
  let secretId: string;
  let routeId: string;
  let headerRouteId: string;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = MASTER;
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await db.insert(tenants).values({ id: TENANT, name: TENANT, apiKeyHash: `hash-${TENANT}` });
    await db.insert(users).values({ id: OWNER, email: "aws-authority@example.test" });
    await db.insert(userTenants).values({ userId: OWNER, tenantId: TENANT, role: "owner" });
    await db.insert(agents).values({
      id: AGENT,
      tenantId: TENANT,
      name: "AWS authority agent",
      walletAddress: `0x${"2".repeat(40)}`,
    });
    await db.insert(workspaces).values({
      id: WORKSPACE,
      tenantId: TENANT,
      key: "aws-authority",
      name: "AWS Authority",
      environment: "production",
      createdBy: OWNER,
    });
    const vault = new SecretVault(MASTER);
    const secret = await vault.createSecret(
      TENANT,
      "aws-authority-credential",
      JSON.stringify({ accessKeyId: "AKIDEXAMPLE123456", secretAccessKey: "secret-key-material" }),
    );
    secretId = secret.id;
    routeId = (
      await vault.createRoute(TENANT, secret.id, {
        agentId: AGENT,
        hostPattern: "ec2.us-west-2.amazonaws.com",
        pathPattern: "/",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "{value}",
        injectionStrategy: "sigv4",
        injectionConfig: { service: "ec2", region: "us-west-2" },
      })
    ).id;
    headerRouteId = (
      await vault.createRoute(TENANT, secret.id, {
        agentId: AGENT,
        hostPattern: "api.openai.com",
        pathPattern: "/",
        method: "GET",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
      })
    ).id;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  test("requires exact EC2 SigV4 route and consequential StopInstances risk", async () => {
    const context = (expectedRevision: number) => ({
      tenantId: TENANT,
      actorUserId: OWNER,
      tenantRole: "owner",
      mfaVerifiedAt: Date.now(),
      idempotencyKey: `idem-${crypto.randomUUID()}`,
      expectedRevision,
      reason: "AWS authority regression",
      audit: async () => {},
    });
    const account = await store.createProviderAccount(context(1), {
      workspaceId: WORKSPACE,
      adapterKey: "aws",
      externalRef: "123456789012",
      displayName: "AWS production",
      credentialSecretId: secretId,
      credentialVersion: 1,
    });
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "aws.ec2.StopInstances",
        riskClass: "write",
        secretRouteId: routeId,
      }),
    ).rejects.toMatchObject({ code: "bad_request", status: 400 });
    await expect(
      store.registerOperation(context(1), account.id, {
        operationKey: "aws.ec2.DescribeInstances",
        riskClass: "read",
        secretRouteId: headerRouteId,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });
    const operation = await store.registerOperation(context(1), account.id, {
      operationKey: "aws.ec2.DescribeInstances",
      riskClass: "read",
      secretRouteId: routeId,
      requestProfile: { profile: "aws.provider-action.v1" },
    });
    expect(operation.operationKey).toBe("aws.ec2.DescribeInstances");
    const [route] = await getDb()
      .select({ mode: secretRoutes.authorityMode, operationId: secretRoutes.providerOperationId })
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(route).toEqual({ mode: "governed_v2", operationId: operation.id });
    expect(await getDb().select().from(providerOperations)).toHaveLength(1);
    expect(await getDb().select().from(providerAccounts)).toHaveLength(1);
  });
});
