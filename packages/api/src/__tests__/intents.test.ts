import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";

setDefaultTimeout(30000);

import {
  agentKeyQuorums,
  agentSigners,
  agents,
  closeDb,
  getDb,
  intents,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `intents-tenant-${Date.now()}`;
const OTHER_TENANT_ID = `intents-other-tenant-${Date.now()}`;
const AGENT_ID = `intents-agent-${Date.now()}`;
const SUCCESS_AGENT_ID = `intents-success-agent-${Date.now()}`;
const ADMIN_USER_ID = "00000000-0000-4000-8000-000000000101";
const OTHER_ADMIN_USER_ID = "00000000-0000-4000-8000-000000000102";
const REMOVED_REVIEWER_USER_ID = "00000000-0000-4000-8000-000000000103";
const DEACTIVATED_REVIEWER_USER_ID = "00000000-0000-4000-8000-000000000104";
const ABI_ALLOWED_RECIPIENT = "0x1111111111111111111111111111111111111111";
const ABI_BLOCKED_RECIPIENT = "0x2222222222222222222222222222222222222222";

function abiAddress(address: string): string {
  return address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

function abiUint(value: bigint | number | string): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

async function makeApp(
  options: {
    tenantId?: string;
    authMode?: "api-key" | "admin" | "admin-no-mfa";
    userId?: string;
  } = {},
) {
  const { intentRoutes } = await import("../routes/intents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", options.tenantId ?? TENANT_ID);
    if (options.authMode === "admin" || options.authMode === "admin-no-mfa") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", options.userId ?? ADMIN_USER_ID);
      if (options.authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    } else {
      c.set("authType", "api-key");
    }
    await next();
  });
  app.route("/intents", intentRoutes);
  return app;
}

describe("generic intents API", () => {
  let apiApp: Awaited<ReturnType<typeof makeApp>>;
  let adminApp: Awaited<ReturnType<typeof makeApp>>;
  let otherAdminApp: Awaited<ReturnType<typeof makeApp>>;
  let adminNoMfaApp: Awaited<ReturnType<typeof makeApp>>;
  let intentId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "intents-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "intents-test-audit-hmac-key-0123456789abcdef0123456789";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Intents Tenant", apiKeyHash: `hash-${TENANT_ID}` },
        {
          id: OTHER_TENANT_ID,
          name: "Other Intents Tenant",
          apiKeyHash: `hash-${OTHER_TENANT_ID}`,
        },
      ]);
    await getDb()
      .insert(users)
      .values([
        { id: ADMIN_USER_ID, email: "intent-admin@example.test" },
        { id: OTHER_ADMIN_USER_ID, email: "intent-other-admin@example.test" },
        { id: REMOVED_REVIEWER_USER_ID, email: "intent-removed-reviewer@example.test" },
        {
          id: DEACTIVATED_REVIEWER_USER_ID,
          email: "intent-deactivated-reviewer@example.test",
          deactivatedAt: new Date(),
        },
      ]);
    await getDb()
      .insert(userTenants)
      .values([
        { userId: ADMIN_USER_ID, tenantId: TENANT_ID, role: "owner" },
        { userId: OTHER_ADMIN_USER_ID, tenantId: TENANT_ID, role: "admin" },
        { userId: DEACTIVATED_REVIEWER_USER_ID, tenantId: TENANT_ID, role: "admin" },
      ]);
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Intents Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    const { vault } = await import("../services/context");
    await vault.createAgent(TENANT_ID, SUCCESS_AGENT_ID, "Intent Success Agent");
    apiApp = await makeApp();
    adminApp = await makeApp({ authMode: "admin" });
    otherAdminApp = await makeApp({ authMode: "admin", userId: OTHER_ADMIN_USER_ID });
    adminNoMfaApp = await makeApp({ authMode: "admin-no-mfa" });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  async function createReviewIntent(label: string): Promise<string> {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "wallet_update",
        agentId: AGENT_ID,
        payload: { displayName: `Review ${label}` },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as { data: { id: string } };
    return created.data.id;
  }

  async function expectStaleReviewerBlocked(
    app: Awaited<ReturnType<typeof makeApp>>,
    action: "authorize" | "approve" | "reject" | "cancel" | "execute" | "fail",
    label: string,
  ) {
    const id = await createReviewIntent(`${label}-${action}`);
    if (action === "execute") {
      const authorize = await otherAdminApp.request(`/intents/${id}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(authorize.status).toBe(200);
    }

    const response = await app.request(`/intents/${id}/${action}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body:
        action === "fail"
          ? JSON.stringify({ reason: "stale reviewer fail", executionResult: { ok: false } })
          : JSON.stringify({ reason: "stale reviewer" }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("active owner or admin tenant membership");

    const [stored] = await getDb().select().from(intents).where(eq(intents.id, id));
    expect(stored.status).toBe(action === "execute" ? "authorized" : "pending");
  }

  it("creates, lists, and retrieves generic wallet intents", async () => {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "wallet_update",
        agentId: AGENT_ID,
        resourceType: "agent_wallet",
        resourceId: AGENT_ID,
        payload: { displayName: "Treasury" },
        createdByDisplayName: "ops@example.com",
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      ok: boolean;
      data: {
        id: string;
        intent_id: string;
        intentType: string;
        intent_type: string;
        status: string;
        resource_id: string;
        authorization_details: Array<Record<string, unknown>>;
      };
    };
    expect(created.ok).toBe(true);
    expect(created.data.intent_id).toBe(created.data.id);
    expect(created.data.intentType).toBe("wallet_update");
    expect(created.data.intent_type).toBe("wallet_update");
    expect(created.data.status).toBe("pending");
    expect(created.data.resource_id).toBe(AGENT_ID);
    expect(created.data.authorization_details).toEqual([]);
    intentId = created.data.id;

    const listResponse = await apiApp.request(`/intents?status=pending&agentId=${AGENT_ID}`);
    expect(listResponse.status).toBe(200);
    const listed = (await listResponse.json()) as {
      ok: boolean;
      data: { intents: Array<{ id: string }>; limit: number; offset: number };
    };
    expect(listed.ok).toBe(true);
    expect(listed.data.intents.map((intent) => intent.id)).toContain(intentId);
    expect(listed.data.limit).toBe(50);

    const getResponse = await apiApp.request(`/intents/${intentId}`);
    expect(getResponse.status).toBe(200);
    const found = (await getResponse.json()) as { data: { id: string; payload: unknown } };
    expect(found.data.id).toBe(intentId);
    expect(found.data.payload).toEqual({ displayName: "Treasury" });
  });

  it("enforces tenant isolation and payload validation", async () => {
    const otherTenantApp = await makeApp({ tenantId: OTHER_TENANT_ID });
    const isolated = await otherTenantApp.request(`/intents/${intentId}`);
    expect(isolated.status).toBe(404);

    const invalidType = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intentType: "unknown", payload: {} }),
    });
    expect(invalidType.status).toBe(400);

    const missingAgent = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intentType: "rpc", agentId: "missing-agent" }),
    });
    expect(missingAgent.status).toBe(404);

    const noExpiry = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "rpc",
        agentId: AGENT_ID,
        payload: { method: "eth_chainId" },
      }),
    });
    expect(noExpiry.status).toBe(201);
    const noExpiryBody = (await noExpiry.json()) as { data: { expiresAt: string | null } };
    expect(noExpiryBody.data.expiresAt).toBeTruthy();
    const defaultExpiry = new Date(noExpiryBody.data.expiresAt as string).getTime();
    expect(defaultExpiry).toBeGreaterThan(Date.now());
    expect(defaultExpiry).toBeLessThanOrEqual(Date.now() + 24 * 60 * 60 * 1000 + 5_000);

    const overlongTtl = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "rpc",
        agentId: AGENT_ID,
        ttlSeconds: 604_801,
        payload: { method: "eth_chainId" },
      }),
    });
    expect(overlongTtl.status).toBe(400);
  });

  it("requires owner/admin MFA to authorize or reject intents", async () => {
    const apiAuthorize = await apiApp.request(`/intents/${intentId}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(apiAuthorize.status).toBe(403);

    const noMfaAuthorize = await adminNoMfaApp.request(`/intents/${intentId}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(noMfaAuthorize.status).toBe(403);

    const authorize = await otherAdminApp.request(`/intents/${intentId}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "reviewed" }),
    });
    expect(authorize.status).toBe(200);
    const authorized = (await authorize.json()) as {
      data: { status: string; authorizedAt: string };
    };
    expect(authorized.data.status).toBe("authorized");
    expect(authorized.data.authorizedAt).toBeTruthy();

    const rejectAfterAuthorize = await adminApp.request(`/intents/${intentId}/reject`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "too late" }),
    });
    expect(rejectAfterAuthorize.status).toBe(409);
  });

  it("accepts Privy-style intent type, wallet, and approve aliases", async () => {
    const existingIntentId = intentId;
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intent_type: "rpc",
        wallet_id: AGENT_ID,
        resource_type: "agent_rpc",
        resource_id: AGENT_ID,
        payload: { method: "eth_chainId" },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      data: { id: string; intent_type: string; wallet_id: string | null };
    };
    expect(created.data.intent_type).toBe("rpc");
    expect(created.data.wallet_id).toBe(AGENT_ID);

    const listResponse = await apiApp.request(`/intents?intent_type=rpc&wallet_id=${AGENT_ID}`);
    expect(listResponse.status).toBe(200);
    const listed = (await listResponse.json()) as {
      data: { intents: Array<{ id: string }> };
    };
    expect(listed.data.intents.map((intent) => intent.id)).toContain(created.data.id);

    const approveResponse = await otherAdminApp.request(`/intents/${created.data.id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "approved through alias" }),
    });
    expect(approveResponse.status).toBe(200);
    const approved = (await approveResponse.json()) as {
      data: { status: string; authorizedBy: string | null };
    };
    expect(approved.data.status).toBe("authorized");
    expect(approved.data.authorizedBy).toBe(OTHER_ADMIN_USER_ID);
    intentId = existingIntentId;
  });

  it("rejects self-authorization of user-created intents", async () => {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_update",
        agentId: AGENT_ID,
        payload: {
          policies: [],
          allowClearAllPolicies: true,
        },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as { data: { id: string } };

    const authorize = await adminApp.request(`/intents/${created.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "approved by creator" }),
    });
    expect(authorize.status).toBe(403);
    const body = (await authorize.json()) as { error: string };
    expect(body.error).toContain("different approver");

    const [stored] = await getDb().select().from(intents).where(eq(intents.id, created.data.id));
    expect(stored.status).toBe("pending");
    expect(stored.authorizedBy).toBeNull();
  });

  it("rejects malformed lifecycle JSON without changing intent state", async () => {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_update",
        agentId: AGENT_ID,
        payload: {
          policies: [],
          allowClearAllPolicies: true,
        },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as { data: { id: string } };

    const authorize = await otherAdminApp.request(`/intents/${created.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });
    expect(authorize.status).toBe(400);
    const body = (await authorize.json()) as { error: string };
    expect(body.error).toContain("Malformed JSON");

    const [stored] = await getDb().select().from(intents).where(eq(intents.id, created.data.id));
    expect(stored.status).toBe("pending");
    expect(stored.authorizedBy).toBeNull();
    expect(stored.authorizedAt).toBeNull();
  });

  it("rejects intent lifecycle actions when reviewer membership was removed after token issuance", async () => {
    const removedReviewerApp = await makeApp({
      authMode: "admin",
      userId: REMOVED_REVIEWER_USER_ID,
    });
    for (const action of ["authorize", "approve", "reject", "cancel", "execute", "fail"] as const) {
      await expectStaleReviewerBlocked(removedReviewerApp, action, "removed");
    }
  });

  it("rejects intent lifecycle actions when reviewer user was deactivated after token issuance", async () => {
    const deactivatedReviewerApp = await makeApp({
      authMode: "admin",
      userId: DEACTIVATED_REVIEWER_USER_ID,
    });
    for (const action of ["authorize", "approve", "reject", "cancel", "execute", "fail"] as const) {
      await expectStaleReviewerBlocked(deactivatedReviewerApp, action, "deactivated");
    }
  });

  it("rejects API-key creation of control-plane intents to prevent identity-split self approval", async () => {
    const createResponse = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_update",
        agentId: AGENT_ID,
        payload: {
          policies: [],
          allowClearAllPolicies: true,
        },
      }),
    });

    const body = (await createResponse.json()) as { ok: boolean; error?: string };
    expect(createResponse.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("human owner/admin session");
  });

  it("executes authorized intents and prevents double execution", async () => {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "wallet_update",
        agentId: AGENT_ID,
        payload: { displayName: "Treasury" },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as { data: { id: string } };
    const authorizeResponse = await otherAdminApp.request(`/intents/${created.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(authorizeResponse.status).toBe(200);

    const apiExecute = await apiApp.request(`/intents/${created.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ executionResult: { ok: true, txHash: "0xabc" } }),
    });
    expect(apiExecute.status).toBe(403);

    const noMfaExecute = await adminNoMfaApp.request(`/intents/${created.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ executionResult: { ok: true, txHash: "0xabc" } }),
    });
    expect(noMfaExecute.status).toBe(403);

    const execute = await otherAdminApp.request(`/intents/${created.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ executionResult: { ok: true, txHash: "0xabc" } }),
    });
    expect(execute.status).toBe(200);
    const executed = (await execute.json()) as {
      data: { status: string; executionResult: Record<string, unknown> };
    };
    expect(executed.data.status).toBe("executed");
    expect(executed.data.executionResult).toMatchObject({
      handler: "wallet_update",
      agentId: AGENT_ID,
      updatedFields: ["name"],
    });
    const [updatedAgent] = await getDb().select().from(agents).where(eq(agents.id, AGENT_ID));
    expect(updatedAgent.name).toBe("Treasury");

    const again = await otherAdminApp.request(`/intents/${created.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(again.status).toBe(409);
  });

  it("claims execution before side effects so concurrent execute requests cannot both win", async () => {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "wallet_update",
        agentId: AGENT_ID,
        payload: { displayName: "Concurrent Treasury" },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as { data: { id: string } };
    const authorize = await otherAdminApp.request(`/intents/${created.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(authorize.status).toBe(200);

    const results = await Promise.all(
      Array.from({ length: 2 }, () =>
        otherAdminApp.request(`/intents/${created.data.id}/execute`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }),
      ),
    );

    expect(results.map((result) => result.status).sort()).toEqual([200, 409]);
    const [stored] = await getDb().select().from(intents).where(eq(intents.id, created.data.id));
    expect(stored.status).toBe("executed");
    expect(stored.executedAt).toBeTruthy();
  });

  it("cancels pending intents with lifecycle metadata", async () => {
    const createResponse = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_update",
        agentId: AGENT_ID,
        ttlSeconds: 300,
        payload: { policyId: "daily-limit" },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      data: { id: string; expiresAt: string | null };
    };
    expect(created.data.expiresAt).toBeTruthy();

    const apiCancel = await apiApp.request(`/intents/${created.data.id}/cancel`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "caller withdrew request" }),
    });
    expect(apiCancel.status).toBe(403);

    const noMfaCancel = await adminNoMfaApp.request(`/intents/${created.data.id}/cancel`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "caller withdrew request" }),
    });
    expect(noMfaCancel.status).toBe(403);

    const cancelResponse = await adminApp.request(`/intents/${created.data.id}/cancel`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "caller withdrew request" }),
    });
    expect(cancelResponse.status).toBe(200);
    const canceled = (await cancelResponse.json()) as {
      data: {
        status: string;
        canceledAt: string | null;
        canceledBy: string | null;
        cancellationReason: string | null;
      };
    };
    expect(canceled.data.status).toBe("canceled");
    expect(canceled.data.canceledAt).toBeTruthy();
    expect(canceled.data.canceledBy).toBe(ADMIN_USER_ID);
    expect(canceled.data.cancellationReason).toBe("caller withdrew request");

    const executeCanceled = await adminApp.request(`/intents/${created.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(executeCanceled.status).toBe(409);
  });

  it("executes typed policy and quorum mutation intents", async () => {
    const policyIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_update",
        agentId: AGENT_ID,
        payload: {
          policies: [
            {
              id: "intent-spend",
              type: "spending-limit",
              enabled: true,
              config: { maxPerTx: "1000000000000000000" },
            },
          ],
        },
      }),
    });
    expect(policyIntent.status).toBe(201);
    const policyCreated = (await policyIntent.json()) as { data: { id: string } };
    const policyAuthorize = await otherAdminApp.request(
      `/intents/${policyCreated.data.id}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(policyAuthorize.status).toBe(200);
    const policyExecute = await otherAdminApp.request(`/intents/${policyCreated.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(policyExecute.status).toBe(200);
    const storedPolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    expect(storedPolicies.map((policy) => policy.id)).toEqual(["intent-spend"]);

    const ruleIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_rule_update",
        agentId: AGENT_ID,
        payload: {
          action: "update",
          ruleId: "intent-spend",
          patch: { enabled: false },
        },
      }),
    });
    expect(ruleIntent.status).toBe(201);
    const ruleCreated = (await ruleIntent.json()) as { data: { id: string } };
    await otherAdminApp.request(`/intents/${ruleCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const ruleExecute = await otherAdminApp.request(`/intents/${ruleCreated.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(ruleExecute.status).toBe(200);
    const [updatedPolicy] = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.id, "intent-spend"));
    expect(updatedPolicy.enabled).toBe(false);

    const createRuleIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_rule_create",
        agentId: AGENT_ID,
        payload: {
          rule: {
            id: "intent-approved-addresses",
            type: "approved-addresses",
            enabled: true,
            config: {
              mode: "whitelist",
              addresses: ["0x1111111111111111111111111111111111111111"],
            },
          },
        },
      }),
    });
    expect(createRuleIntent.status).toBe(201);
    const createRuleCreated = (await createRuleIntent.json()) as { data: { id: string } };
    await otherAdminApp.request(`/intents/${createRuleCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const createRuleExecute = await otherAdminApp.request(
      `/intents/${createRuleCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(createRuleExecute.status).toBe(200);
    const createRuleBody = (await createRuleExecute.json()) as {
      data: { executionResult: { handler: string; action: string; rule: { id: string } } };
    };
    expect(createRuleBody.data.executionResult.handler).toBe("policy_rule_create");
    expect(createRuleBody.data.executionResult.action).toBe("create");
    expect(createRuleBody.data.executionResult.rule.id).toBe("intent-approved-addresses");

    const createRuleAgain = await otherAdminApp.request(
      `/intents/${createRuleCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(createRuleAgain.status).toBe(409);

    const deleteRuleIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_rule_delete",
        agentId: AGENT_ID,
        payload: {
          ruleId: "intent-approved-addresses",
        },
      }),
    });
    expect(deleteRuleIntent.status).toBe(201);
    const deleteRuleCreated = (await deleteRuleIntent.json()) as { data: { id: string } };
    await otherAdminApp.request(`/intents/${deleteRuleCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const deleteRuleExecute = await otherAdminApp.request(
      `/intents/${deleteRuleCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(deleteRuleExecute.status).toBe(200);
    const deleteRuleBody = (await deleteRuleExecute.json()) as {
      data: { executionResult: { handler: string; action: string; rule: { id: string } } };
    };
    expect(deleteRuleBody.data.executionResult.handler).toBe("policy_rule_delete");
    expect(deleteRuleBody.data.executionResult.action).toBe("delete");
    expect(deleteRuleBody.data.executionResult.rule.id).toBe("intent-approved-addresses");
    const postTypedRulePolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    expect(postTypedRulePolicies.map((policy) => policy.id)).toEqual(["intent-spend"]);

    const deleteLastRuleIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_rule_update",
        agentId: AGENT_ID,
        payload: {
          action: "delete",
          ruleId: "intent-spend",
        },
      }),
    });
    expect(deleteLastRuleIntent.status).toBe(201);
    const deleteLastRuleCreated = (await deleteLastRuleIntent.json()) as { data: { id: string } };
    await otherAdminApp.request(`/intents/${deleteLastRuleCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const deleteLastRuleExecute = await otherAdminApp.request(
      `/intents/${deleteLastRuleCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(deleteLastRuleExecute.status).toBe(403);
    const [failedDeleteLastRule] = await getDb()
      .select()
      .from(intents)
      .where(eq(intents.id, deleteLastRuleCreated.data.id));
    expect(failedDeleteLastRule.status).toBe("failed");
    const preservedPolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    expect(preservedPolicies.map((policy) => policy.id)).toEqual(["intent-spend"]);

    const [signerA, signerB] = await getDb()
      .insert(agentSigners)
      .values([
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "owner",
          subjectType: "user",
          subjectId: "quorum-a",
          status: "active",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "owner",
          subjectType: "user",
          subjectId: "quorum-b",
          status: "active",
        },
      ])
      .returning();
    const quorumIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "quorum_update",
        agentId: AGENT_ID,
        payload: {
          action: "create",
          name: "Ops quorum",
          threshold: 2,
          memberSignerIds: [signerA.id, signerB.id],
          permissions: ["sign_transaction"],
        },
      }),
    });
    expect(quorumIntent.status).toBe(201);
    const quorumCreated = (await quorumIntent.json()) as { data: { id: string } };
    await otherAdminApp.request(`/intents/${quorumCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const quorumExecute = await otherAdminApp.request(`/intents/${quorumCreated.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(quorumExecute.status).toBe(200);
    const storedQuorums = await getDb()
      .select()
      .from(agentKeyQuorums)
      .where(eq(agentKeyQuorums.agentId, AGENT_ID));
    expect(storedQuorums).toHaveLength(1);
    expect(storedQuorums[0].threshold).toBe(2);

    const clearPoliciesIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_update",
        agentId: AGENT_ID,
        payload: { policies: [] },
      }),
    });
    expect(clearPoliciesIntent.status).toBe(201);
    const clearPoliciesCreated = (await clearPoliciesIntent.json()) as { data: { id: string } };
    await otherAdminApp.request(`/intents/${clearPoliciesCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const clearPoliciesExecute = await otherAdminApp.request(
      `/intents/${clearPoliciesCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(clearPoliciesExecute.status).toBe(403);
    const [failedClearPolicies] = await getDb()
      .select()
      .from(intents)
      .where(eq(intents.id, clearPoliciesCreated.data.id));
    expect(failedClearPolicies.status).toBe("failed");
  });

  it("rejects stale authorized control-plane mutation intents", async () => {
    await getDb()
      .insert(policies)
      .values({
        id: "stale-intent-spend",
        agentId: AGENT_ID,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "1000000000000000000" },
      });

    const stalePolicyIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "policy_rule_update",
        agentId: AGENT_ID,
        payload: {
          action: "update",
          ruleId: "stale-intent-spend",
          patch: { enabled: false },
        },
      }),
    });
    expect(stalePolicyIntent.status).toBe(201);
    const stalePolicyCreated = (await stalePolicyIntent.json()) as { data: { id: string } };
    const authorizePolicy = await otherAdminApp.request(
      `/intents/${stalePolicyCreated.data.id}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(authorizePolicy.status).toBe(200);

    await getDb()
      .update(policies)
      .set({
        enabled: true,
        config: { maxPerTx: "1" },
        updatedAt: new Date(),
      })
      .where(eq(policies.id, "stale-intent-spend"));

    const executePolicy = await otherAdminApp.request(
      `/intents/${stalePolicyCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(executePolicy.status).toBe(409);
    const [hardenedPolicy] = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.id, "stale-intent-spend"));
    expect(hardenedPolicy.enabled).toBe(true);
    expect(hardenedPolicy.config).toEqual({ maxPerTx: "1" });

    const staleTransferIntent = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "transfer",
        agentId: AGENT_ID,
        payload: {
          to: "0x1234567890123456789012345678901234567890",
          value: "1",
          chainId: 8453,
          broadcast: false,
        },
      }),
    });
    expect(staleTransferIntent.status).toBe(201);
    const staleTransferCreated = (await staleTransferIntent.json()) as { data: { id: string } };
    const authorizeTransfer = await adminApp.request(
      `/intents/${staleTransferCreated.data.id}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(authorizeTransfer.status).toBe(200);

    await getDb()
      .update(policies)
      .set({
        enabled: true,
        config: { maxPerTx: "2" },
        updatedAt: new Date(),
      })
      .where(eq(policies.id, "stale-intent-spend"));

    const executeTransfer = await adminApp.request(
      `/intents/${staleTransferCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(executeTransfer.status).toBe(409);
    const [staleTransferRow] = await getDb()
      .select()
      .from(intents)
      .where(eq(intents.id, staleTransferCreated.data.id));
    expect(staleTransferRow.status).toBe("authorized");

    const [signerA, signerB] = await getDb()
      .insert(agentSigners)
      .values([
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "owner",
          subjectType: "user",
          subjectId: "stale-quorum-a",
          status: "active",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "owner",
          subjectType: "user",
          subjectId: "stale-quorum-b",
          status: "active",
        },
      ])
      .returning();
    const [quorum] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: "Stale quorum",
        threshold: 2,
        memberSignerIds: [signerA.id, signerB.id],
        permissions: ["sign_transaction"],
        metadata: {},
        status: "paused",
      })
      .returning();

    const staleQuorumIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "quorum_update",
        agentId: AGENT_ID,
        payload: {
          action: "update",
          quorumId: quorum.id,
          status: "active",
        },
      }),
    });
    expect(staleQuorumIntent.status).toBe(201);
    const staleQuorumCreated = (await staleQuorumIntent.json()) as { data: { id: string } };
    const authorizeQuorum = await otherAdminApp.request(
      `/intents/${staleQuorumCreated.data.id}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(authorizeQuorum.status).toBe(200);

    await getDb()
      .update(agentKeyQuorums)
      .set({ status: "revoked", updatedAt: new Date() })
      .where(eq(agentKeyQuorums.id, quorum.id));

    const executeQuorum = await otherAdminApp.request(
      `/intents/${staleQuorumCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(executeQuorum.status).toBe(409);
    const [revokedQuorum] = await getDb()
      .select()
      .from(agentKeyQuorums)
      .where(eq(agentKeyQuorums.id, quorum.id));
    expect(revokedQuorum.status).toBe("revoked");

    const [signerC, signerD] = await getDb()
      .insert(agentSigners)
      .values([
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "owner",
          subjectType: "user",
          subjectId: "stale-quorum-c",
          address: "0x3333333333333333333333333333333333333333",
          status: "active",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "owner",
          subjectType: "user",
          subjectId: "stale-quorum-d",
          address: "0x4444444444444444444444444444444444444444",
          status: "active",
        },
      ])
      .returning();
    const staleSignerIntent = await adminApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "quorum_update",
        agentId: AGENT_ID,
        payload: {
          action: "create",
          name: "Signer baseline quorum",
          threshold: 2,
          memberSignerIds: [signerC.id, signerD.id],
          permissions: ["sign_transaction"],
        },
      }),
    });
    expect(staleSignerIntent.status).toBe(201);
    const staleSignerCreated = (await staleSignerIntent.json()) as { data: { id: string } };
    const authorizeSignerQuorum = await otherAdminApp.request(
      `/intents/${staleSignerCreated.data.id}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(authorizeSignerQuorum.status).toBe(200);

    await getDb()
      .update(agentSigners)
      .set({ address: "0x5555555555555555555555555555555555555555", updatedAt: new Date() })
      .where(eq(agentSigners.id, signerC.id));

    const executeSignerQuorum = await otherAdminApp.request(
      `/intents/${staleSignerCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(executeSignerQuorum.status).toBe(409);
  });

  it("bridges transfer, wallet_action, and RPC intents with fail-closed execution", async () => {
    await getDb()
      .insert(policies)
      .values({
        id: "intent-transfer-allowlist",
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: {
          mode: "whitelist",
          addresses: ["0x0000000000000000000000000000000000000001"],
        },
      })
      .onConflictDoNothing();

    const transferIntent = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "transfer",
        agentId: AGENT_ID,
        payload: {
          to: "0x0000000000000000000000000000000000000002",
          value: "1",
          chainId: 8453,
          broadcast: false,
        },
      }),
    });
    expect(transferIntent.status).toBe(201);
    const transferCreated = (await transferIntent.json()) as { data: { id: string } };
    const transferAuthorize = await adminApp.request(
      `/intents/${transferCreated.data.id}/authorize`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(transferAuthorize.status).toBe(200);
    const transferExecute = await adminApp.request(`/intents/${transferCreated.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(transferExecute.status).toBe(403);
    const transferBlocked = (await transferExecute.json()) as { error?: string };
    expect(transferBlocked.error).toContain("policy");

    const walletActionIntent = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "wallet_action",
        agentId: AGENT_ID,
        payload: {
          action: "send_calls",
          chainId: 8453,
          calls: [
            {
              to: "0x0000000000000000000000000000000000000001",
              value: "0",
              data: "0x1234",
            },
          ],
        },
      }),
    });
    expect(walletActionIntent.status).toBe(201);
    const walletActionCreated = (await walletActionIntent.json()) as { data: { id: string } };
    await adminApp.request(`/intents/${walletActionCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const walletActionExecute = await adminApp.request(
      `/intents/${walletActionCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(walletActionExecute.status).toBe(403);

    const rpcIntent = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "rpc",
        agentId: AGENT_ID,
        payload: {
          method: "eth_sendRawTransaction",
          params: [],
          chainId: 8453,
        },
      }),
    });
    expect(rpcIntent.status).toBe(201);
    const rpcCreated = (await rpcIntent.json()) as { data: { id: string } };
    await adminApp.request(`/intents/${rpcCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const rpcExecute = await adminApp.request(`/intents/${rpcCreated.data.id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(rpcExecute.status).toBe(403);
    const rpcBlocked = (await rpcExecute.json()) as { error?: string };
    expect(rpcBlocked.error).toContain("allowlisted");

    const malformedCalldataIntent = await apiApp.request("/intents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        intentType: "wallet_action",
        agentId: AGENT_ID,
        payload: {
          action: "send_calls",
          chainId: 8453,
          broadcast: false,
          calls: [
            {
              to: "0x0000000000000000000000000000000000000001",
              value: "0",
              data: "0xa9059cbb0",
            },
          ],
        },
      }),
    });
    expect(malformedCalldataIntent.status).toBe(201);
    const malformedCalldataCreated = (await malformedCalldataIntent.json()) as {
      data: { id: string };
    };
    await adminApp.request(`/intents/${malformedCalldataCreated.data.id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const malformedCalldataExecute = await adminApp.request(
      `/intents/${malformedCalldataCreated.data.id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );
    expect(malformedCalldataExecute.status).toBe(400);
  });

  it("executes successful generic transfer and send-calls intents through vault signing", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const request = JSON.parse(String(init?.body ?? "{}")) as { id?: number; method?: string };
      const result =
        request.method === "eth_getTransactionCount"
          ? "0x0"
          : request.method === "eth_gasPrice"
            ? "0x3b9aca00"
            : null;
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id ?? 1, result }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    try {
      await getDb()
        .insert(policies)
        .values({
          id: "intent-success-transfer-allowlist",
          agentId: SUCCESS_AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: {
            mode: "whitelist",
            addresses: [
              "0x0000000000000000000000000000000000000001",
              "0x0000000000000000000000000000000000000002",
              "0x0000000000000000000000000000000000000003",
            ],
          },
        })
        .onConflictDoNothing();

      const transferIntent = await apiApp.request("/intents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intentType: "transfer",
          agentId: SUCCESS_AGENT_ID,
          payload: {
            to: "0x0000000000000000000000000000000000000001",
            value: "123",
            chainId: 84532,
            broadcast: false,
            referenceId: "intent-e2e-transfer",
          },
        }),
      });
      expect(transferIntent.status).toBe(201);
      const created = (await transferIntent.json()) as { data: { id: string } };

      const authorize = await adminApp.request(`/intents/${created.data.id}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(authorize.status).toBe(200);

      const execute = await otherAdminApp.request(`/intents/${created.data.id}/execute`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(execute.status).toBe(200);
      const executed = (await execute.json()) as {
        data: { status: string; executionResult: Record<string, unknown> };
      };
      expect(executed.data.status).toBe("executed");
      expect(executed.data.executionResult).toMatchObject({
        handler: "transfer",
        status: "signed",
        actionId: created.data.id,
      });
      expect(String(executed.data.executionResult.signedTx)).toMatch(/^0x[0-9a-fA-F]+$/);
      const storedTransferIntent = await adminApp.request(`/intents/${created.data.id}`);
      const storedTransfer = (await storedTransferIntent.json()) as {
        data: { executionResult: Record<string, unknown> };
      };
      expect(storedTransfer.data.executionResult.signedTx).toBe("[redacted]");

      const [storedTx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, created.data.id));
      expect(storedTx.status).toBe("signed");
      expect(storedTx.actionType).toBe("transfer");
      expect(storedTx.actionPayload).toMatchObject({
        referenceId: "intent-e2e-transfer",
        sourceIntentId: created.data.id,
      });

      const sendCallsIntent = await apiApp.request("/intents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intentType: "wallet_action",
          agentId: SUCCESS_AGENT_ID,
          payload: {
            action: "send_calls",
            chainId: 84532,
            broadcast: false,
            referenceId: "intent-e2e-send-calls",
            calls: [
              { to: "0x0000000000000000000000000000000000000001", value: "1" },
              { to: "0x0000000000000000000000000000000000000002", value: "2" },
            ],
          },
        }),
      });
      expect(sendCallsIntent.status).toBe(201);
      const sendCallsCreated = (await sendCallsIntent.json()) as { data: { id: string } };
      const sendCallsAuthorize = await adminApp.request(
        `/intents/${sendCallsCreated.data.id}/authorize`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
      );
      expect(sendCallsAuthorize.status).toBe(200);
      const sendCallsExecute = await adminApp.request(
        `/intents/${sendCallsCreated.data.id}/execute`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
      );
      expect(sendCallsExecute.status).toBe(200);
      const sendCallsExecuted = (await sendCallsExecute.json()) as {
        data: { status: string; executionResult: { signedCalls?: Array<Record<string, unknown>> } };
      };
      expect(sendCallsExecuted.data.status).toBe("executed");
      expect(sendCallsExecuted.data.executionResult.signedCalls).toHaveLength(2);
      expect(sendCallsExecuted.data.executionResult.signedCalls?.[0]?.signedTx).toMatch(
        /^0x[0-9a-fA-F]+$/,
      );
      const childTxs = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.agentId, SUCCESS_AGENT_ID));
      expect(childTxs.map((tx) => tx.id)).toContain(`${sendCallsCreated.data.id}:0`);
      expect(childTxs.map((tx) => tx.id)).toContain(`${sendCallsCreated.data.id}:1`);

      await getDb()
        .insert(policies)
        .values({
          id: "intent-contract-allowlist",
          agentId: SUCCESS_AGENT_ID,
          type: "contract-allowlist",
          enabled: true,
          config: {
            contracts: [
              {
                address: "0x0000000000000000000000000000000000000003",
                selectors: ["0xa9059cbb"],
                constraints: {
                  "0xa9059cbb": {
                    recipientAllowlist: [ABI_ALLOWED_RECIPIENT],
                    maxAmount: "100",
                  },
                },
              },
            ],
          },
        });
      const calldata = `0xa9059cbb${abiAddress(ABI_ALLOWED_RECIPIENT)}${abiUint(100)}`;
      const contractCallsIntent = await apiApp.request("/intents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intentType: "wallet_action",
          agentId: SUCCESS_AGENT_ID,
          payload: {
            action: "send_calls",
            chainId: 84532,
            broadcast: false,
            calls: [
              {
                to: "0x0000000000000000000000000000000000000003",
                value: "0",
                data: calldata,
              },
            ],
          },
        }),
      });
      expect(contractCallsIntent.status).toBe(201);
      const contractCallsCreated = (await contractCallsIntent.json()) as { data: { id: string } };
      await adminApp.request(`/intents/${contractCallsCreated.data.id}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const contractCallsExecute = await adminApp.request(
        `/intents/${contractCallsCreated.data.id}/execute`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
      );
      expect(contractCallsExecute.status).toBe(200);
      const contractCallsExecuted = (await contractCallsExecute.json()) as {
        data: { executionResult: { signedCalls?: Array<Record<string, unknown>> } };
      };
      expect(contractCallsExecuted.data.executionResult.signedCalls).toHaveLength(1);
      expect(contractCallsExecuted.data.executionResult.signedCalls?.[0]?.signedTx).toMatch(
        /^0x[0-9a-fA-F]+$/,
      );
      const [contractChildTx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, `${contractCallsCreated.data.id}:0`));
      expect(contractChildTx.actionPayload).toMatchObject({
        type: "send_calls",
        calls: [{ data: calldata }],
      });

      const blockedCalldata = `0xa9059cbb${abiAddress(ABI_BLOCKED_RECIPIENT)}${abiUint(1)}`;
      const blockedContractCallsIntent = await apiApp.request("/intents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intentType: "wallet_action",
          agentId: SUCCESS_AGENT_ID,
          payload: {
            action: "send_calls",
            chainId: 84532,
            broadcast: false,
            calls: [
              {
                to: "0x0000000000000000000000000000000000000003",
                value: "0",
                data: blockedCalldata,
              },
            ],
          },
        }),
      });
      expect(blockedContractCallsIntent.status).toBe(201);
      const blockedContractCallsCreated = (await blockedContractCallsIntent.json()) as {
        data: { id: string };
      };
      await adminApp.request(`/intents/${blockedContractCallsCreated.data.id}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const blockedContractCallsExecute = await adminApp.request(
        `/intents/${blockedContractCallsCreated.data.id}/execute`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
      );
      expect(blockedContractCallsExecute.status).toBe(403);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("expires stale pending intents before authorization", async () => {
    const id = crypto.randomUUID();
    await getDb()
      .insert(intents)
      .values({
        id,
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        intentType: "quorum_update",
        status: "pending",
        resourceType: "agent_key_quorum",
        resourceId: "quorum-1",
        expiresAt: new Date(Date.now() - 1000),
      });

    const authorize = await adminApp.request(`/intents/${id}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(authorize.status).toBe(409);
    const body = (await authorize.json()) as {
      ok: boolean;
      error?: string;
      data?: { status: string; expiredAt: string | null; expiredBy: string | null };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("expired");
    expect(body.data?.status).toBe("expired");
    expect(body.data?.expiredAt).toBeTruthy();
    expect(body.data?.expiredBy).toBe("system:expires_at");
  });

  it("expires stale authorized intents before execution", async () => {
    const id = crypto.randomUUID();
    await getDb()
      .insert(intents)
      .values({
        id,
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        intentType: "wallet_action",
        status: "authorized",
        resourceType: "wallet_action",
        resourceId: "action-1",
        authorizedAt: new Date(Date.now() - 5000),
        authorizedBy: ADMIN_USER_ID,
        expiresAt: new Date(Date.now() - 1000),
      });

    const execute = await adminApp.request(`/intents/${id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ executionResult: { ok: true } }),
    });
    expect(execute.status).toBe(409);
    const body = (await execute.json()) as { data?: { status: string } };
    expect(body.data?.status).toBe("expired");
  });

  it("requires owner/admin MFA to manually expire authorized intents", async () => {
    const id = crypto.randomUUID();
    await getDb().insert(intents).values({
      id,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      intentType: "wallet_action",
      status: "authorized",
      resourceType: "wallet_action",
      resourceId: "action-manual-expire",
      authorizedAt: new Date(),
      authorizedBy: ADMIN_USER_ID,
    });

    const apiExpire = await apiApp.request(`/intents/${id}/expire`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(apiExpire.status).toBe(403);

    const noMfaExpire = await adminNoMfaApp.request(`/intents/${id}/expire`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(noMfaExpire.status).toBe(403);

    const expire = await adminApp.request(`/intents/${id}/expire`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    expect(expire.status).toBe(200);
    const body = (await expire.json()) as {
      data?: { status: string; expiredBy: string | null };
    };
    expect(body.data?.status).toBe("expired");
    expect(body.data?.expiredBy).toBe("system:manual");
  });
});
