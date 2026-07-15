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
import { closeDb } from "@stwd/db";
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

async function humanToken(userId: string, mfaVerifiedAt: number | null = freshMfa()) {
  const payload: Record<string, unknown> = {
    address: `0xuser-${userId.slice(0, 6)}`,
    tenantId: F.TENANT,
    userId,
  };
  if (mfaVerifiedAt !== null) payload.mfaVerifiedAt = mfaVerifiedAt;
  return signAccessToken(payload as never, "10m");
}

async function agentToken() {
  const { signAgentToken } = await import("@stwd/auth");
  return signAgentToken({ agentId: F.AGENT, tenantId: F.TENANT, scopes: [] }, "10m");
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

  test("N16: execute body supplies an actor/action field => 400 RESUME_ACTOR_SUBSTITUTION_FORBIDDEN", async () => {
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
    expect(body.error.code).toBe("RESUME_ACTOR_SUBSTITUTION_FORBIDDEN");
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
