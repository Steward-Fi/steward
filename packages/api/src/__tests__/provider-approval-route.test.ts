/**
 * PR3 approval + execute HTTP route tests (PGLite + fully composed app).
 * Proves the §9 route contract: human-session gating, MFA gating, unknown-field
 * + resume-actor-substitution rejection, and the exact happy-path status codes.
 */

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import { signAccessToken } from "@stwd/auth";
import { agents, closeDb, getDb, providerRoleBindings, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { Hono } from "hono";
import type { AppVariables } from "../services/context";
import {
  bindingRow,
  createApprovalRequired,
  F,
  freshMfa,
  seedFixture,
} from "./provider-approval-fixture";

setDefaultTimeout(120_000);

let app: Hono<{ Variables: AppVariables }>;

async function wipeAndSeed() {
  const {
    getDb,
    approvalQueue,
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
  } = await import("@stwd/db");
  const db = getDb();
  for (const t of [
    providerActionAuditOutbox,
    approvalQueue,
    providerActionBindings,
    intents,
    providerGrants,
    providerRoleBindings,
    providerOperations,
    providerAccounts,
    secretRoutes,
    secrets,
    workspaces,
    userTenants,
    users,
    tenants,
  ]) {
    await db.delete(t);
  }
  await seedFixture();
}

async function humanToken(
  userId: string,
  mfaVerifiedAt: number | null = freshMfa(),
  tenantId = F.TENANT,
) {
  const payload: Record<string, unknown> = {
    address: `0xuser-${userId.slice(0, 6)}`,
    tenantId,
    userId,
  };
  if (mfaVerifiedAt !== null) payload.mfaVerifiedAt = mfaVerifiedAt;
  return signAccessToken(payload as never, "10m");
}

async function agentToken(agentId = F.AGENT, tenantId = F.TENANT, userId?: string) {
  const { signAgentToken } = await import("@stwd/auth");
  return signAgentToken({ agentId, tenantId, scopes: [], ...(userId ? { userId } : {}) }, "10m");
}

async function expectExecuteErrorShapeMatchesGet(executeResponse: Response, getResponse: Response) {
  expect(executeResponse.status).toBe(getResponse.status);
  const executeBody = (await executeResponse.json()) as {
    ok: false;
    error: { code: string; message: string; requestId: unknown };
  };
  const getBody = (await getResponse.json()) as typeof executeBody;
  expect(Object.keys(executeBody).sort()).toEqual(Object.keys(getBody).sort());
  expect(Object.keys(executeBody.error).sort()).toEqual(Object.keys(getBody.error).sort());
  expect(executeBody.error.code).toBe(getBody.error.code);
  expect(executeBody.error.message).toBe(getBody.error.message);
  expect(typeof executeBody.error.requestId).toBe(typeof getBody.error.requestId);
  return executeBody;
}

function decideReq(intentId: string, token: string, body: unknown) {
  return app.request(`/v2/provider-actions/${intentId}/approval`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "x-steward-tenant": F.TENANT,
    },
    body: JSON.stringify(body),
  });
}

describe("PR3 approval + execute routes", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    const mod = await import("../app");
    app = mod.app as Hono<{ Variables: AppVariables }>;
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });
  beforeEach(async () => {
    await wipeAndSeed();
  });

  test("N01: agent token calls approval decision => 403 APPROVAL_HUMAN_SESSION_REQUIRED, pending unchanged", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const res = await decideReq(intentId, await agentToken(), {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: requestHash,
      expectedActionDigest: actionDigest,
      idempotencyKey: "route-agent-key",
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("APPROVAL_HUMAN_SESSION_REQUIRED");
    expect((await bindingRow(intentId)).status).toBe("pending_approval");
  });

  test("N15: body supplies an unknown field => 400 APPROVAL_UNKNOWN_FIELD, caller value never stored", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const res = await decideReq(intentId, await humanToken(F.APPROVER), {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: requestHash,
      expectedActionDigest: actionDigest,
      idempotencyKey: "route-unknown-key",
      approvedBy: "attacker",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("APPROVAL_UNKNOWN_FIELD");
    expect((await bindingRow(intentId)).status).toBe("pending_approval");
  });

  test("N16: execute rejects every body instead of silently ignoring retry or actor fields", async () => {
    const { intentId } = await createApprovalRequired();
    const res = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await humanToken(F.APPROVER)}`,
        "content-type": "application/json",
        "x-steward-tenant": F.TENANT,
      },
      body: JSON.stringify({ resumeActor: "attacker", account: "x" }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("RESUME_BODY_NOT_ALLOWED");

    const retryBody = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await humanToken(F.APPROVER)}`,
        "content-type": "application/json",
        "x-steward-tenant": F.TENANT,
      },
      body: JSON.stringify({ idempotencyKey: "ignored-retry-key" }),
    });
    expect(retryBody.status).toBe(400);
    expect(((await retryBody.json()) as { error: { code: string } }).error.code).toBe(
      "RESUME_BODY_NOT_ALLOWED",
    );
  });

  test("happy path: human approver approves (200), then execute resumes (200 execution_ready)", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const token = await humanToken(F.APPROVER);
    const approveRes = await decideReq(intentId, token, {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: requestHash,
      expectedActionDigest: actionDigest,
      idempotencyKey: "route-happy-approve",
    });
    expect(approveRes.status).toBe(200);
    const approveBody = (await approveRes.json()) as { status: string; version: number };
    expect(approveBody.status).toBe("approved");
    expect(approveBody.version).toBe(2);

    const execRes = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "x-steward-tenant": F.TENANT,
      },
    });
    expect(execRes.status).toBe(200);
    const execBody = (await execRes.json()) as { status: string; resumeAttemptId: string };
    expect(execBody.status).toBe("execution_ready");
    expect(execBody.resumeAttemptId).toBeTruthy();
  });

  test("execute permits the original requesting agent", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const approveRes = await decideReq(intentId, await humanToken(F.APPROVER), {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: requestHash,
      expectedActionDigest: actionDigest,
      idempotencyKey: "route-agent-execute",
    });
    expect(approveRes.status).toBe(200);

    const execRes = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await agentToken()}`,
        "x-steward-tenant": F.TENANT,
      },
    });
    expect(execRes.status).toBe(200);
    expect((await execRes.json()) as { status: string }).toMatchObject({
      status: "execution_ready",
    });
  });

  test("execute does not let an agent token borrow an embedded human approver claim", async () => {
    const unrelatedAgentId = "agent-unrelated";
    await getDb().insert(agents).values({
      id: unrelatedAgentId,
      tenantId: F.TENANT,
      name: "Unrelated",
      walletAddress: "0x2",
    });
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const approveRes = await decideReq(intentId, await humanToken(F.APPROVER), {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: requestHash,
      expectedActionDigest: actionDigest,
      idempotencyKey: "route-mixed-identity-execute",
    });
    expect(approveRes.status).toBe(200);

    const execRes = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await agentToken(unrelatedAgentId, F.TENANT, F.APPROVER)}`,
        "x-steward-tenant": F.TENANT,
      },
    });
    expect(execRes.status).toBe(404);
    expect(((await execRes.json()) as { error: { code: string } }).error.code).toBe(
      "SCOPE_RESOURCE_NOT_FOUND",
    );
    expect((await bindingRow(intentId)).status).toBe("approved");
  });

  test("execute permits a current workspace admin with matching environment scope", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const approveRes = await decideReq(intentId, await humanToken(F.APPROVER), {
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: requestHash,
      expectedActionDigest: actionDigest,
      idempotencyKey: "route-admin-execute",
    });
    expect(approveRes.status).toBe(200);
    await getDb().insert(providerRoleBindings).values({
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      principalType: "human",
      principalId: F.APPROVER_2,
      roleKey: "workspace_admin",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: F.GRANTOR,
      reason: "route-admin",
    });

    const execRes = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${await humanToken(F.APPROVER_2)}`,
        "x-steward-tenant": F.TENANT,
      },
    });
    expect(execRes.status).toBe(200);
    expect((await execRes.json()) as { status: string }).toMatchObject({
      status: "execution_ready",
    });
  });

  test("execute hides an existing action from an unrelated tenant principal with GET-shape parity", async () => {
    const { intentId } = await createApprovalRequired();
    const token = await humanToken(F.APPROVER_2);
    const executeResponse = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "x-steward-tenant": F.TENANT },
    });
    const getResponse = await app.request(`/v2/provider-actions/${intentId}/approval`, {
      method: "GET",
      headers: { authorization: `Bearer ${token}`, "x-steward-tenant": F.TENANT },
    });

    const body = await expectExecuteErrorShapeMatchesGet(executeResponse, getResponse);
    expect(executeResponse.status).toBe(404);
    expect(body.error.code).toBe("SCOPE_RESOURCE_NOT_FOUND");
    expect((await bindingRow(intentId)).status).toBe("pending_approval");
  });

  test("execute hides a cross-tenant action with GET-shape parity", async () => {
    const { intentId } = await createApprovalRequired();
    await getDb().insert(userTenants).values({
      userId: F.APPROVER_2,
      tenantId: F.TENANT_B,
      role: "member",
    });
    const token = await humanToken(F.APPROVER_2, freshMfa(), F.TENANT_B);
    const executeResponse = await app.request(`/v2/provider-actions/${intentId}/execute`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "x-steward-tenant": F.TENANT_B },
    });
    const getResponse = await app.request(`/v2/provider-actions/${intentId}/approval`, {
      method: "GET",
      headers: { authorization: `Bearer ${token}`, "x-steward-tenant": F.TENANT_B },
    });

    const body = await expectExecuteErrorShapeMatchesGet(executeResponse, getResponse);
    expect(executeResponse.status).toBe(404);
    expect(body.error.code).toBe("SCOPE_RESOURCE_NOT_FOUND");
    expect((await bindingRow(intentId)).status).toBe("pending_approval");
  });

  test("GET approval requires recent MFA => 403 APPROVAL_MFA_REQUIRED when MFA missing", async () => {
    const { intentId } = await createApprovalRequired();
    const res = await app.request(`/v2/provider-actions/${intentId}/approval`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${await humanToken(F.APPROVER, null)}`,
        "x-steward-tenant": F.TENANT,
      },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("APPROVAL_MFA_REQUIRED");
  });

  test("GET approval returns safe summary to an eligible approver", async () => {
    const { intentId } = await createApprovalRequired();
    const res = await app.request(`/v2/provider-actions/${intentId}/approval`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${await humanToken(F.APPROVER)}`,
        "x-steward-tenant": F.TENANT,
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { status: string; safeSummary: unknown } };
    expect(body.data.status).toBe("pending_approval");
    expect(body.data.safeSummary).toBeDefined();
  });
});
