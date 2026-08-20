/**
 * Mounted real-Postgres proof for provider-case KC06 snapshot consistency.
 *
 * The request reads its binding before approval_queue. Holding an ACCESS
 * EXCLUSIVE lock on approval_queue pauses the mounted handler after its first
 * snapshot read. A second connection then commits an operation change. The
 * manifest must retain the pre-change operation value; READ COMMITTED would
 * observe the concurrent value on the later provider_operations statement.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { signAccessToken } from "@stwd/auth";
import {
  agents,
  closeDb,
  createPostgresClient,
  getDb,
  providerOperations,
  tenants,
  transactions,
} from "@stwd/db";
import { eq } from "drizzle-orm";
import { F } from "./provider-approval-fixture";
import { createPendingCase, seedCaseFixture, wipeCase } from "./provider-case-fixture";

const DATABASE_URL = process.env.DATABASE_URL;
const SKIP = !DATABASE_URL;
const ORIGINAL_RISK_CLASS = "write";
const CONCURRENT_RISK_CLASS = "read";
const SENTINEL_TENANT = "tenant-provider-case-snapshot-sentinel";
const SENTINEL_AGENT = "agent-provider-case-snapshot-sentinel";
const SENTINEL_TRANSACTION = "tx-provider-case-snapshot-sentinel";

describe.skipIf(SKIP)("provider-case mounted repeatable-read snapshot (Postgres)", () => {
  let admin: ReturnType<typeof createPostgresClient>;
  let locker: ReturnType<typeof createPostgresClient>;
  let writer: ReturnType<typeof createPostgresClient>;
  let app: any;
  let caseId: string;
  let ownerToken: string;

  beforeAll(async () => {
    admin = createPostgresClient(DATABASE_URL!);
    locker = createPostgresClient(DATABASE_URL!);
    writer = createPostgresClient(DATABASE_URL!);
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD ??= "provider-case-snapshot-master-password";
    process.env.STEWARD_JWT_SECRET ??=
      "provider-case-snapshot-jwt-secret-0123456789abcdef0123456789";
    await getDb()
      .update(transactions)
      .set({ status: "failed" })
      .where(eq(transactions.id, SENTINEL_TRANSACTION));
    await getDb().delete(tenants).where(eq(tenants.id, SENTINEL_TENANT));
    await getDb().insert(tenants).values({
      id: SENTINEL_TENANT,
      name: "Provider case snapshot cleanup sentinel",
      apiKeyHash: "provider-case-snapshot-sentinel-hash",
    });
    await getDb().insert(agents).values({
      id: SENTINEL_AGENT,
      tenantId: SENTINEL_TENANT,
      name: "Provider case snapshot cleanup sentinel",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(transactions).values({
      id: SENTINEL_TRANSACTION,
      agentId: SENTINEL_AGENT,
      status: "signed",
      toAddress: "0x0000000000000000000000000000000000000002",
      value: "1",
      chainId: 1,
    });
    await wipeCase();
    expect(
      await getDb().query.transactions.findFirst({
        where: eq(transactions.id, SENTINEL_TRANSACTION),
      }),
    ).toMatchObject({ id: SENTINEL_TRANSACTION, agentId: SENTINEL_AGENT, status: "signed" });
    await seedCaseFixture();
    ({ intentId: caseId } = await createPendingCase("pgsnap01"));
    await getDb()
      .update(providerOperations)
      .set({ riskClass: ORIGINAL_RISK_CLASS })
      .where(eq(providerOperations.id, F.OP));
    ownerToken = await signAccessToken({
      address: "0xsnapshot-owner",
      tenantId: F.TENANT,
      userId: F.APPROVER_2,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const mod = await import("../app");
    app = mod.mountCoreIdempotencyAndRoutes(mod.createApp());
  }, 120_000);

  afterAll(async () => {
    await wipeCase();
    await getDb()
      .update(transactions)
      .set({ status: "failed" })
      .where(eq(transactions.id, SENTINEL_TRANSACTION));
    await getDb().delete(tenants).where(eq(tenants.id, SENTINEL_TENANT));
    await Promise.all([admin.end(), locker.end(), writer.end()]);
    await closeDb();
  });

  test("later reads ignore a concurrent committed operation change", async () => {
    let releaseLock!: () => void;
    let lockHeld!: () => void;
    const release = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });
    const locked = new Promise<void>((resolve) => {
      lockHeld = resolve;
    });
    const lockTask = locker.begin(async (tx) => {
      await tx.unsafe("LOCK TABLE approval_queue IN ACCESS EXCLUSIVE MODE");
      lockHeld();
      await release;
    });
    await locked;

    let response: Response;
    try {
      const responsePromise = app.request(`/v2/provider-actions/${caseId}/case`, {
        headers: {
          Authorization: `Bearer ${ownerToken}`,
          "X-Steward-Tenant": F.TENANT,
        },
      });

      const deadline = Date.now() + 10_000;
      let blocked = false;
      while (Date.now() < deadline) {
        const [row] = await admin<{ blocked: boolean }[]>`
          SELECT EXISTS (
            SELECT 1
            FROM pg_locks waiting
            WHERE waiting.relation = 'approval_queue'::regclass
              AND NOT waiting.granted
          ) AS blocked
        `;
        if (row?.blocked) {
          blocked = true;
          break;
        }
        await Bun.sleep(20);
      }
      expect(blocked).toBe(true);

      await writer`
        UPDATE provider_operations
        SET risk_class = ${CONCURRENT_RISK_CLASS}
        WHERE id = ${F.OP}
      `;
      releaseLock();
      await lockTask;
      response = await responsePromise;
    } finally {
      releaseLock();
      await lockTask;
    }

    expect(response.status).toBe(200);
    const manifest = (await response.json()) as { operation: { riskClass: string } };
    expect(manifest.operation.riskClass).toBe(ORIGINAL_RISK_CLASS);
    const [current] = await writer<{ risk_class: string }[]>`
      SELECT risk_class FROM provider_operations WHERE id = ${F.OP}
    `;
    expect(current?.risk_class).toBe(CONCURRENT_RISK_CLASS);
  }, 30_000);
});
