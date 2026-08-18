import { afterAll, beforeAll, describe, expect, it } from "bun:test";

// Skip all DB-dependent tests when DATABASE_URL is not configured
const SKIP = !process.env.DATABASE_URL;

import { generateApiKey } from "@stwd/auth";
import {
  agents,
  approvalQueue,
  autoApprovalRules,
  getDb,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { eq, sql } from "drizzle-orm";
import { createSessionToken } from "../routes/auth";

const TEST_PORT = parseInt(process.env.PORT || "3200", 10);
const BASE_URL = `http://localhost:${TEST_PORT}`;
const RUN_ID = Date.now();
const TEST_TENANT = `test-approvals-tenant-${RUN_ID}`;
const TEST_AGENT = `test-approvals-agent-${RUN_ID}`;
const TEST_TX_APPROVE = `test-tx-approve-${RUN_ID}`;
const TEST_TX_DENY = `test-tx-deny-${RUN_ID}`;
const TEST_APPROVAL_APPROVE = `test-approval-approve-${RUN_ID}`;
const TEST_APPROVAL_DENY = `test-approval-deny-${RUN_ID}`;
const PAGINATION_OTHER_AGENT = `approval-page-other-${RUN_ID}`;
const PAGINATION_TARGET_TX = `approval-page-target-tx-${RUN_ID}`;
const PAGINATION_TARGET_APPROVAL = `approval-page-target-${RUN_ID}`;
const OWNER_USER_ID = crypto.randomUUID();

let validApiKey: string;
let adminToken: string;

// ─── Setup ────────────────────────────────────────────────────────────────

beforeAll(async () => {
  if (SKIP) return;
  const db = getDb();
  const apiKeyPair = generateApiKey();
  validApiKey = apiKeyPair.key;

  await db
    .insert(tenants)
    .values({
      id: TEST_TENANT,
      name: "Approvals Test Tenant",
      apiKeyHash: apiKeyPair.hash,
    })
    .onConflictDoNothing();

  await db.insert(users).values({
    id: OWNER_USER_ID,
    email: `approvals-${RUN_ID}@example.test`,
    emailVerified: true,
  });
  await db.insert(userTenants).values({
    userId: OWNER_USER_ID,
    tenantId: TEST_TENANT,
    role: "owner",
  });
  adminToken = await createSessionToken("0x0000000000000000000000000000000000000001", TEST_TENANT, {
    userId: OWNER_USER_ID,
    email: `approvals-${RUN_ID}@example.test`,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });

  await db
    .insert(agents)
    .values({
      id: TEST_AGENT,
      tenantId: TEST_TENANT,
      name: "Test Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    })
    .onConflictDoNothing();

  // Create test transactions
  for (const txId of [TEST_TX_APPROVE, TEST_TX_DENY]) {
    await db
      .insert(transactions)
      .values({
        id: txId,
        agentId: TEST_AGENT,
        status: "pending",
        toAddress: "0x0000000000000000000000000000000000000001",
        value: "1000000000000000000",
        chainId: 84532,
      })
      .onConflictDoNothing();
  }

  // Create approval queue entries
  await db
    .insert(approvalQueue)
    .values({
      id: TEST_APPROVAL_APPROVE,
      txId: TEST_TX_APPROVE,
      agentId: TEST_AGENT,
      status: "pending",
    })
    .onConflictDoNothing();

  await db
    .insert(approvalQueue)
    .values({
      id: TEST_APPROVAL_DENY,
      txId: TEST_TX_DENY,
      agentId: TEST_AGENT,
      status: "pending",
    })
    .onConflictDoNothing();

  await db.insert(agents).values({
    id: PAGINATION_OTHER_AGENT,
    tenantId: TEST_TENANT,
    name: "Pagination Noise Agent",
    walletAddress: "0x2234567890123456789012345678901234567890",
  });
  await db.insert(transactions).values({
    id: PAGINATION_TARGET_TX,
    agentId: TEST_AGENT,
    status: "pending",
    toAddress: "0x0000000000000000000000000000000000000001",
    value: "1",
    chainId: 84532,
    createdAt: new Date("2025-01-01T00:00:00.000Z"),
  });
  await db.insert(approvalQueue).values({
    id: PAGINATION_TARGET_APPROVAL,
    txId: PAGINATION_TARGET_TX,
    agentId: TEST_AGENT,
    status: "pending",
    requestedAt: new Date("2025-01-01T00:00:00.000Z"),
  });

  const noiseTransactions = Array.from({ length: 51 }, (_, index) => ({
    id: `approval-noise-tx-${RUN_ID}-${index}`,
    agentId: PAGINATION_OTHER_AGENT,
    status: "pending" as const,
    toAddress: "0x0000000000000000000000000000000000000002",
    value: "1",
    chainId: 84532,
    createdAt: new Date(`2026-01-01T00:${String(index).padStart(2, "0")}:00.000Z`),
  }));
  await db.insert(transactions).values(noiseTransactions);
  await db.insert(approvalQueue).values(
    noiseTransactions.map((transaction, index) => ({
      id: `approval-noise-${RUN_ID}-${index}`,
      txId: transaction.id,
      agentId: PAGINATION_OTHER_AGENT,
      status: "pending" as const,
      requestedAt: transaction.createdAt,
    })),
  );
});

afterAll(async () => {
  if (SKIP) return;
  const db = getDb();
  await db.delete(approvalQueue).where(eq(approvalQueue.agentId, PAGINATION_OTHER_AGENT));
  await db.delete(transactions).where(eq(transactions.agentId, PAGINATION_OTHER_AGENT));
  await db.delete(approvalQueue).where(eq(approvalQueue.agentId, TEST_AGENT));
  await db.delete(transactions).where(eq(transactions.agentId, TEST_AGENT));
  await db.delete(autoApprovalRules).where(eq(autoApprovalRules.tenantId, TEST_TENANT));
  await db.delete(agents).where(eq(agents.id, TEST_AGENT));
  await db.delete(agents).where(eq(agents.id, PAGINATION_OTHER_AGENT));
  await db.delete(userTenants).where(eq(userTenants.tenantId, TEST_TENANT));
  await db.delete(users).where(eq(users.id, OWNER_USER_ID));
  await db.delete(tenants).where(eq(tenants.id, TEST_TENANT));
});

function authHeaders() {
  return {
    "X-Steward-Tenant": TEST_TENANT,
    "X-Steward-Key": validApiKey,
    "Content-Type": "application/json",
  };
}

function adminHeaders() {
  return {
    Authorization: `Bearer ${adminToken}`,
    "X-Steward-Tenant": TEST_TENANT,
    "Content-Type": "application/json",
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe.skipIf(SKIP)("Approval Workflow API", () => {
  describe("GET /approvals", () => {
    it("rejects API-key access even when an agent filter is supplied", async () => {
      const res = await fetch(`${BASE_URL}/approvals?agentId=${encodeURIComponent(TEST_AGENT)}`, {
        headers: authHeaders(),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin user session");
    });

    it("lists pending approvals for tenant", async () => {
      const res = await fetch(`${BASE_URL}/approvals`, {
        headers: adminHeaders(),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.length).toBeGreaterThanOrEqual(2);
      expect(body.data[0].agentName).toBeDefined();
      expect(body.data[0].toAddress).toBeDefined();
    });

    it("filters by status", async () => {
      const res = await fetch(`${BASE_URL}/approvals?status=approved`, {
        headers: adminHeaders(),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      // No approvals should be approved yet
      expect(body.data.length).toBe(0);
    });

    it("filters by agent before pagination when 51 newer mixed-agent rows exist", async () => {
      const unfiltered = await fetch(`${BASE_URL}/approvals?status=pending&limit=50`, {
        headers: adminHeaders(),
      });
      expect(unfiltered.status).toBe(200);
      const unfilteredBody = await unfiltered.json();
      expect(unfilteredBody.data).toHaveLength(50);
      expect(
        unfilteredBody.data.some(
          (entry: { id: string }) => entry.id === PAGINATION_TARGET_APPROVAL,
        ),
      ).toBe(false);

      const filtered = await fetch(
        `${BASE_URL}/approvals?status=pending&agentId=${encodeURIComponent(TEST_AGENT)}&limit=50`,
        { headers: adminHeaders() },
      );
      expect(filtered.status).toBe(200);
      const filteredBody = await filtered.json();
      expect(filteredBody.data.length).toBeGreaterThanOrEqual(1);
      expect(
        filteredBody.data.every((entry: { agentId: string }) => entry.agentId === TEST_AGENT),
      ).toBe(true);
      expect(
        filteredBody.data.some((entry: { id: string }) => entry.id === PAGINATION_TARGET_APPROVAL),
      ).toBe(true);
    });

    it("rejects empty, padded, and overlong agent filters", async () => {
      for (const agentId of ["", ` ${TEST_AGENT}`, "x".repeat(65)]) {
        const res = await fetch(`${BASE_URL}/approvals?agentId=${encodeURIComponent(agentId)}`, {
          headers: adminHeaders(),
        });
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toContain("agentId must be a non-empty string of at most 64 characters");
      }
    });

    it("paginates by the stable requestedAt and id keyset", async () => {
      const first = await fetch(
        `${BASE_URL}/approvals?status=pending&agentId=${encodeURIComponent(TEST_AGENT)}&limit=1`,
        { headers: adminHeaders() },
      );
      expect(first.status).toBe(200);
      const firstBody = await first.json();
      expect(firstBody.data).toHaveLength(1);
      const boundary = firstBody.data[0] as { id: string; requestedAt: string };

      const second = await fetch(
        `${BASE_URL}/approvals?status=pending&agentId=${encodeURIComponent(TEST_AGENT)}&limit=50&cursorRequestedAt=${encodeURIComponent(boundary.requestedAt)}&cursorId=${encodeURIComponent(boundary.id)}`,
        { headers: adminHeaders() },
      );
      expect(second.status).toBe(200);
      const secondBody = await second.json();
      expect(secondBody.data.every((entry: { id: string }) => entry.id !== boundary.id)).toBe(true);
    });

    it("does not skip approvals whose database timestamps differ below JSON precision", async () => {
      const db = getDb();
      // Put the lexically smaller ID later at microsecond precision. The API
      // serializes both values as .123Z, so a correct keyset must deliberately
      // order and compare at that same precision and then use ID as its tie.
      await db.execute(sql`
        UPDATE approval_queue
        SET requested_at = CASE id
          WHEN ${TEST_APPROVAL_APPROVE} THEN TIMESTAMPTZ '2030-01-01 00:00:00.123900+00'
          WHEN ${TEST_APPROVAL_DENY} THEN TIMESTAMPTZ '2030-01-01 00:00:00.123100+00'
        END
        WHERE id IN (${TEST_APPROVAL_APPROVE}, ${TEST_APPROVAL_DENY})
      `);

      const first = await fetch(
        `${BASE_URL}/approvals?status=pending&agentId=${encodeURIComponent(TEST_AGENT)}&limit=1`,
        { headers: adminHeaders() },
      );
      expect(first.status).toBe(200);
      const firstBody = await first.json();
      const boundary = firstBody.data[0] as { id: string; requestedAt: string };

      const second = await fetch(
        `${BASE_URL}/approvals?status=pending&agentId=${encodeURIComponent(TEST_AGENT)}&limit=1&cursorRequestedAt=${encodeURIComponent(boundary.requestedAt)}&cursorId=${encodeURIComponent(boundary.id)}`,
        { headers: adminHeaders() },
      );
      expect(second.status).toBe(200);
      const secondBody = await second.json();
      expect(secondBody.data).toHaveLength(1);
      expect(new Set([boundary.id, secondBody.data[0]?.id])).toEqual(
        new Set([TEST_APPROVAL_APPROVE, TEST_APPROVAL_DENY]),
      );
    });

    it("rejects partial, malformed, and offset-combined cursors", async () => {
      for (const query of [
        "cursorId=approval-1",
        "cursorRequestedAt=not-a-date&cursorId=approval-1",
        "cursorRequestedAt=2026-01-01T00%3A00%3A00.000Z&cursorId=approval-1&offset=1",
      ]) {
        const res = await fetch(`${BASE_URL}/approvals?${query}`, { headers: adminHeaders() });
        expect(res.status).toBe(400);
      }
    });
  });

  describe("GET /approvals/stats", () => {
    it("returns approval statistics", async () => {
      const res = await fetch(`${BASE_URL}/approvals/stats`, {
        headers: adminHeaders(),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.pending).toBeGreaterThanOrEqual(2);
      expect(typeof body.data.approved).toBe("number");
      expect(typeof body.data.rejected).toBe("number");
      expect(typeof body.data.avgWaitSeconds).toBe("number");
    });
  });

  describe("POST /approvals/:txId/approve", () => {
    it("rejects API-key approval of a pending transaction", async () => {
      const res = await fetch(`${BASE_URL}/approvals/${TEST_TX_APPROVE}/approve`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ comment: "Looks good" }),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin user session");
    });

    it("rejects double-approval", async () => {
      const res = await fetch(`${BASE_URL}/approvals/${TEST_TX_APPROVE}/approve`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin user session");
    });
  });

  describe("POST /approvals/:txId/deny", () => {
    it("requires a reason", async () => {
      const res = await fetch(`${BASE_URL}/approvals/${TEST_TX_DENY}/deny`, {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toContain("reason is required");
    });

    it("denies a pending transaction with reason", async () => {
      const res = await fetch(`${BASE_URL}/approvals/${TEST_TX_DENY}/deny`, {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({ reason: "Suspicious destination address" }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data.status).toBe("rejected");
      expect(body.data.reason).toBe("Suspicious destination address");
    });

    it("returns 404 for non-existent transaction", async () => {
      const res = await fetch(`${BASE_URL}/approvals/nonexistent-tx/deny`, {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({ reason: "test" }),
      });

      expect(res.status).toBe(404);
    });
  });
});

describe.skipIf(SKIP)("Auto-Approval Rules API", () => {
  describe("GET /approvals/rules", () => {
    it("returns null when no rules configured", async () => {
      const res = await fetch(`${BASE_URL}/approvals/rules`, {
        headers: adminHeaders(),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.ok).toBe(true);
      expect(body.data).toBeNull();
    });
  });

  describe("PUT /approvals/rules", () => {
    it("rejects API-key creation of auto-approval rules", async () => {
      const res = await fetch(`${BASE_URL}/approvals/rules`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          maxAmountWei: "1000000000000000000",
          autoDenyAfterHours: 24,
          escalateAboveWei: "10000000000000000000",
        }),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin user session");
    });

    it("rejects API-key updates to existing rules", async () => {
      const res = await fetch(`${BASE_URL}/approvals/rules`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          autoDenyAfterHours: 48,
          enabled: false,
        }),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin user session");
    });

    it("rejects invalid maxAmountWei", async () => {
      const res = await fetch(`${BASE_URL}/approvals/rules`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ maxAmountWei: "not-a-number" }),
      });

      expect(res.status).toBe(403);
    });

    it("rejects invalid escalateAboveWei instead of persisting malformed rule state", async () => {
      const res = await fetch(`${BASE_URL}/approvals/rules`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ escalateAboveWei: "not-a-number" }),
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("owner or admin user session");
    });
  });
});
