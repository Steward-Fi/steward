import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `signed-retirement-${crypto.randomUUID()}`;
const AGENT_ID = `signed-retirement-agent-${crypto.randomUUID()}`;
const SIGNATURE =
  "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
const BLOCKHASH = "11111111111111111111111111111111";
const AUDIT_KEY = "signed-artifact-retirement-audit-key-with-more-than-32-bytes";

let app: Hono<{ Variables: AppVariables }>;

async function insertSigned(input?: { chainId?: number; actionType?: string }): Promise<string> {
  const id = crypto.randomUUID();
  await getDb()
    .insert(transactions)
    .values({
      id,
      agentId: AGENT_ID,
      status: "signed",
      toAddress: "11111111111111111111111111111111",
      value: "0",
      chainId: input?.chainId ?? 101,
      txHash: SIGNATURE,
      actionType: input?.actionType ?? "solana_transaction",
      actionPayload: {
        artifactSignature: SIGNATURE,
        recentBlockhash: BLOCKHASH,
        blockhashKind: "recent",
      },
      signedAt: new Date(),
    });
  return id;
}

async function retire(id: string): Promise<Response> {
  return app.request(`/vault/${AGENT_ID}/transactions/${id}/retire-signed`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ reason: "operator verified artifact retirement" }),
  });
}

describe("mounted signed-artifact retirement", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "signed-artifact-retirement-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Signed artifact retirement",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Signed artifact retirement agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    const { vaultRoutes } = await import("../routes/vault");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("userId", "retirement-admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("requestId", crypto.randomUUID());
      await next();
    });
    app.route("/vault", vaultRoutes);
    app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
  });

  beforeEach(async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();
    await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    __resetAuditHmacKeyCacheForTests();
  });

  it("rejects generic failure relabeling and unsupported EVM abandonment", async () => {
    const solanaId = await insertSigned();
    const failure = await app.request(`/vault/${AGENT_ID}/transactions/${solanaId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "transaction.provider_error", error: "timeout" }),
    });
    expect(failure.status).toBe(409);
    expect(
      await getDb()
        .select({ status: transactions.status })
        .from(transactions)
        .where(eq(transactions.id, solanaId)),
    ).toEqual([{ status: "signed" }]);

    const broadcast = await app.request(`/vault/${AGENT_ID}/transactions/${solanaId}/lifecycle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "transaction.broadcasted", txHash: SIGNATURE }),
    });
    expect(broadcast.status).toBe(200);
    const indirectFailure = await app.request(
      `/vault/${AGENT_ID}/transactions/${solanaId}/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: "transaction.provider_error", error: "timeout" }),
      },
    );
    expect(indirectFailure.status).toBe(409);
    expect(
      await getDb()
        .select({ status: transactions.status })
        .from(transactions)
        .where(eq(transactions.id, solanaId)),
    ).toEqual([{ status: "broadcast" }]);

    await getDb().delete(transactions).where(eq(transactions.id, solanaId));
    const evmId = await insertSigned({ chainId: 1, actionType: "transaction" });
    const evm = await retire(evmId);
    expect(evm.status).toBe(409);
    expect(await evm.json()).toMatchObject({
      ok: false,
      error: expect.stringContaining("finalized nonce replacement or consumption"),
    });
  });

  it("fails closed while live, then retires absent expired evidence without signed bytes", async () => {
    const id = await insertSigned();
    const context = await import("../services/context");
    const original = context.vault.inspectSolanaSignedArtifact.bind(context.vault);
    try {
      context.vault.inspectSolanaSignedArtifact = async () => ({ result: "absent_live" });
      expect((await retire(id)).status).toBe(409);

      context.vault.inspectSolanaSignedArtifact = async () => ({ result: "absent_expired" });
      const response = await retire(id);
      expect(response.status).toBe(200);
      const [row] = await getDb().select().from(transactions).where(eq(transactions.id, id));
      expect(row?.status).toBe("retired");
      expect(JSON.stringify(row?.actionPayload)).not.toContain("signedTransaction");
      const events = await getDb()
        .select({ action: auditEvents.action, metadata: auditEvents.metadata })
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.resourceId, id)));
      expect(events).toContainEqual({
        action: "vault.signed_artifact.retired",
        metadata: expect.objectContaining({
          artifactSignature: SIGNATURE,
          recentBlockhash: BLOCKHASH,
          inspectionResult: "absent_expired",
        }),
      });
      expect(JSON.stringify(events)).not.toContain("signedTransaction");
    } finally {
      context.vault.inspectSolanaSignedArtifact = original;
    }
  });

  it("never treats durable-nonce or unclassified artifacts as ordinary expired blockhashes", async () => {
    const context = await import("../services/context");
    const original = context.vault.inspectSolanaSignedArtifact.bind(context.vault);
    let inspected = false;
    context.vault.inspectSolanaSignedArtifact = async () => {
      inspected = true;
      return { result: "absent_expired" };
    };
    try {
      for (const blockhashKind of ["durable_nonce", "unknown"] as const) {
        const id = await insertSigned();
        const [row] = await getDb().select().from(transactions).where(eq(transactions.id, id));
        await getDb()
          .update(transactions)
          .set({ actionPayload: { ...(row?.actionPayload ?? {}), blockhashKind } })
          .where(eq(transactions.id, id));
        const response = await retire(id);
        expect(response.status).toBe(409);
        expect(
          await getDb()
            .select({ status: transactions.status })
            .from(transactions)
            .where(eq(transactions.id, id)),
        ).toEqual([{ status: "signed" }]);
        await getDb().delete(transactions).where(eq(transactions.id, id));
      }
      expect(inspected).toBe(false);
    } finally {
      context.vault.inspectSolanaSignedArtifact = original;
    }
  });

  it("reconciles an exact landed artifact instead of retiring it", async () => {
    const id = await insertSigned();
    const context = await import("../services/context");
    const original = context.vault.inspectSolanaSignedArtifact.bind(context.vault);
    context.vault.inspectSolanaSignedArtifact = async () => ({ result: "landed_confirmed" });
    try {
      const response = await retire(id);
      expect(response.status).toBe(409);
      expect(
        await getDb()
          .select({ status: transactions.status })
          .from(transactions)
          .where(eq(transactions.id, id)),
      ).toEqual([{ status: "confirmed" }]);
    } finally {
      context.vault.inspectSolanaSignedArtifact = original;
    }
  });

  it("rolls retirement back when the required audit append fails", async () => {
    const id = await insertSigned();
    const context = await import("../services/context");
    const original = context.vault.inspectSolanaSignedArtifact.bind(context.vault);
    context.vault.inspectSolanaSignedArtifact = async () => ({ result: "absent_expired" });
    process.env.STEWARD_AUDIT_HMAC_KEY = "too-short";
    __resetAuditHmacKeyCacheForTests();
    try {
      expect((await retire(id)).status).toBe(500);
      expect(
        await getDb()
          .select({ status: transactions.status })
          .from(transactions)
          .where(eq(transactions.id, id)),
      ).toEqual([{ status: "signed" }]);
    } finally {
      context.vault.inspectSolanaSignedArtifact = original;
    }
  });

  it("allows only one broadcast or replacement CAS winner during retirement", async () => {
    const context = await import("../services/context");
    const original = context.vault.inspectSolanaSignedArtifact.bind(context.vault);
    try {
      for (const competitor of ["broadcast", "replace"] as const) {
        const id = await insertSigned();
        let releaseInspection: (() => void) | undefined;
        let inspectionStarted: (() => void) | undefined;
        const started = new Promise<void>((resolve) => {
          inspectionStarted = resolve;
        });
        context.vault.inspectSolanaSignedArtifact = async () => {
          inspectionStarted?.();
          await new Promise<void>((resolve) => {
            releaseInspection = resolve;
          });
          return { result: "absent_expired" };
        };

        const retirement = retire(id);
        await started;
        const competingResponse = await app.request(
          `/vault/${AGENT_ID}/transactions/${id}/${competitor === "replace" ? "replace" : "lifecycle"}`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(
              competitor === "replace"
                ? { replacementTxHash: `${SIGNATURE.slice(0, -1)}A`, reason: "replacement" }
                : { type: "transaction.broadcasted", txHash: SIGNATURE },
            ),
          },
        );
        expect(competingResponse.status).toBe(200);
        releaseInspection?.();
        expect((await retirement).status).toBe(409);
        expect(
          await getDb()
            .select({ status: transactions.status })
            .from(transactions)
            .where(eq(transactions.id, id)),
        ).toEqual([{ status: "broadcast" }]);
        await getDb().delete(transactions).where(eq(transactions.id, id));
      }
    } finally {
      context.vault.inspectSolanaSignedArtifact = original;
    }
  });
});
