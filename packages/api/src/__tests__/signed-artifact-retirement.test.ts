import { afterAll, beforeAll, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditEvents,
  closeDb,
  getDb,
  policies,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { canonicalJsonStringify } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `signed-retirement-${crypto.randomUUID()}`;
const AGENT_ID = `signed-retirement-agent-${crypto.randomUUID()}`;
const NATIVE_SOL_AGENT_ID = `retire-sol-${crypto.randomUUID()}`;
const EVM_AGENT_ID = `retire-evm-${crypto.randomUUID()}`;
const NATIVE_SOL_RECIPIENT = "6TcyBfPdBt1kjsvDZLzmBFnuMaLWiTaAt4RjUr9VA5YD";
const NATIVE_SOL_BLOCKHASH = "7gyGAp71YXQRoxmFBaHxofQXAipvgHyBKPyxmdSJxyvz";
const EVM_RECIPIENT = "0x9876543210987654321098765432109876543210";
const SIGNATURE =
  "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
const BLOCKHASH = "11111111111111111111111111111111";
const AUDIT_KEY = "signed-artifact-retirement-audit-key-with-more-than-32-bytes";

let app: Hono<{ Variables: AppVariables }>;

async function insertSigned(input?: { chainId?: number; actionType?: string }): Promise<string> {
  const id = crypto.randomUUID();
  const signedArtifactEvidence =
    input?.chainId === 1
      ? {
          version: 1 as const,
          chainFamily: "evm" as const,
          artifactHash: `0x${"ab".repeat(32)}`,
          signer: "0x1234567890123456789012345678901234567890",
          nonce: "7",
          rawIntentDigest: "c".repeat(64),
        }
      : {
          version: 1 as const,
          chainFamily: "solana" as const,
          artifactSignature: SIGNATURE,
          signer: "11111111111111111111111111111111",
          recentBlockhash: BLOCKHASH,
          blockhashKind: "recent" as const,
          lastValidBlockHeight: 123,
          rawIntentDigest: "d".repeat(64),
        };
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
      signedArtifactEvidence,
      signedArtifactEvidenceDigest: createHash("sha256")
        .update(canonicalJsonStringify(signedArtifactEvidence))
        .digest("hex"),
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
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "signed-artifact-retirement-execution-auth-secret";
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
    const context = await import("../services/context");
    await context.vault.createAgent(
      TENANT_ID,
      NATIVE_SOL_AGENT_ID,
      "Signed retirement native SOL agent",
    );
    await context.vault.createAgent(TENANT_ID, EVM_AGENT_ID, "Signed retirement EVM agent");
    await getDb()
      .insert(policies)
      .values({
        id: `signed-retirement-recipient-${crypto.randomUUID()}`,
        agentId: NATIVE_SOL_AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [NATIVE_SOL_RECIPIENT], mode: "whitelist" },
      });
    await getDb()
      .insert(policies)
      .values({
        id: `retire-evm-policy-${crypto.randomUUID()}`,
        agentId: EVM_AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [EVM_RECIPIENT], mode: "whitelist" },
      });
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
    delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    __resetAuditHmacKeyCacheForTests();
  });

  it("rejects generic failure relabeling and live EVM abandonment", async () => {
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
    const context = await import("../services/context");
    const original = context.vault.inspectEvmSignedArtifact.bind(context.vault);
    context.vault.inspectEvmSignedArtifact = async () => ({ result: "absent_live" });
    try {
      const evm = await retire(evmId);
      expect(evm.status).toBe(409);
      expect(await evm.json()).toMatchObject({
        ok: false,
        error: expect.stringContaining("still broadcastable"),
      });
    } finally {
      context.vault.inspectEvmSignedArtifact = original;
    }
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
          artifactId: SIGNATURE,
          chainFamily: "solana",
          inspectionResult: "absent_expired",
        }),
      });
      expect(JSON.stringify(events)).not.toContain("signedTransaction");
    } finally {
      context.vault.inspectSolanaSignedArtifact = original;
    }
  });

  it("creates native-SOL evidence through the mounted offline signing path", async () => {
    process.env.STEWARD_SOLANA_PRIORITY_FEES = "0";
    const requireFromVault = createRequire(new URL("../../../vault/package.json", import.meta.url));
    const { Connection } = requireFromVault("@solana/web3.js") as {
      Connection: { prototype: { getLatestBlockhash: () => Promise<unknown> } };
    };
    const getBlockhash = spyOn(Connection.prototype, "getLatestBlockhash").mockResolvedValue({
      blockhash: NATIVE_SOL_BLOCKHASH,
      lastValidBlockHeight: 4321,
    });
    try {
      const response = await app.request(`/vault/${NATIVE_SOL_AGENT_ID}/actions/transfer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: NATIVE_SOL_RECIPIENT,
          value: "1234",
          chainId: 101,
          broadcast: false,
        }),
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { data: { id: string; signedTx: string } };
      expect(body.data.signedTx.length).toBeGreaterThan(100);
      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.id));
      expect(row?.status).toBe("signed");
      expect(row?.signedArtifactEvidence).toMatchObject({
        chainFamily: "solana",
        signer: expect.any(String),
        recentBlockhash: NATIVE_SOL_BLOCKHASH,
        lastValidBlockHeight: 4321,
        rawIntentDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(row?.signedArtifactEvidenceDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.stringify(row?.signedArtifactEvidence)).not.toContain(body.data.signedTx);
      await getDb().delete(transactions).where(eq(transactions.id, body.data.id));
    } finally {
      getBlockhash.mockRestore();
      delete process.env.STEWARD_SOLANA_PRIORITY_FEES;
    }
  });

  it("creates EVM evidence through the mounted offline signing path", async () => {
    const calls: unknown[] = [];
    const rpc = spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body)) as { id: number; method: string };
      calls.push(request);
      const result =
        request.method === "eth_getCode"
          ? "0x"
          : request.method === "eth_getTransactionCount"
            ? "0x0"
            : request.method === "eth_gasPrice"
              ? "0x3b9aca00"
              : request.method === "eth_chainId"
                ? "0x2105"
                : null;
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }));
    });
    try {
      const response = await app.request(`/vault/${EVM_AGENT_ID}/sign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: EVM_RECIPIENT,
          value: "1234",
          chainId: 8453,
          nonce: 0,
          broadcast: false,
        }),
      });
      const body = (await response.json()) as {
        data: { txId: string; signedTx: string };
        error?: string;
      };
      expect(response.status, `${body.error}: ${JSON.stringify(calls)}`).toBe(200);
      expect(body.data.signedTx).toMatch(/^0x[0-9a-f]+$/);
      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.txId));
      expect(row?.status).toBe("signed");
      expect(row?.signedArtifactEvidence).toMatchObject({
        chainFamily: "evm",
        artifactHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        signer: expect.stringMatching(/^0x[0-9a-fA-F]{40}$/),
        nonce: "0",
        rawIntentDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(row?.signedArtifactEvidenceDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.stringify(row?.signedArtifactEvidence)).not.toContain(body.data.signedTx);
      await expect(
        getDb()
          .update(transactions)
          .set({
            signedArtifactEvidence: {
              version: 1,
              chainFamily: "evm",
              artifactHash: `0x${"11".repeat(32)}`,
              signer: "0x1111111111111111111111111111111111111111",
              nonce: "1",
              rawIntentDigest: "11".repeat(32),
            },
          })
          .where(eq(transactions.id, body.data.txId))
          .execute(),
      ).rejects.toThrow();
      const [preserved] = await getDb()
        .select({
          evidence: transactions.signedArtifactEvidence,
          digest: transactions.signedArtifactEvidenceDigest,
        })
        .from(transactions)
        .where(eq(transactions.id, body.data.txId));
      expect(preserved).toEqual({
        evidence: row?.signedArtifactEvidence,
        digest: row?.signedArtifactEvidenceDigest,
      });
      await getDb().delete(transactions).where(eq(transactions.id, body.data.txId));
    } finally {
      rpc.mockRestore();
    }
  });

  it("rejects missing or tampered digest-bound evidence before RPC", async () => {
    const id = crypto.randomUUID();
    await getDb()
      .insert(transactions)
      .values({
        id,
        agentId: AGENT_ID,
        status: "signed",
        toAddress: "11111111111111111111111111111111",
        value: "0",
        chainId: 101,
        txHash: SIGNATURE,
        signedArtifactEvidenceDigest: "0".repeat(64),
      });
    expect((await retire(id)).status).toBe(409);
    expect(
      await getDb()
        .select({ status: transactions.status })
        .from(transactions)
        .where(eq(transactions.id, id)),
    ).toEqual([{ status: "signed" }]);
  });

  it("rejects a matching digest over malformed lifetime evidence before RPC", async () => {
    const id = crypto.randomUUID();
    const malformedEvidence = {
      version: 1,
      chainFamily: "solana",
      artifactSignature: SIGNATURE,
      signer: "11111111111111111111111111111111",
      recentBlockhash: BLOCKHASH,
      blockhashKind: "recent",
      rawIntentDigest: "d".repeat(64),
    };
    await getDb()
      .insert(transactions)
      .values({
        id,
        agentId: AGENT_ID,
        status: "signed",
        toAddress: "11111111111111111111111111111111",
        value: "0",
        chainId: 101,
        txHash: SIGNATURE,
        signedArtifactEvidence: malformedEvidence as never,
        signedArtifactEvidenceDigest: createHash("sha256")
          .update(canonicalJsonStringify(malformedEvidence))
          .digest("hex"),
      });
    const context = await import("../services/context");
    const inspection = spyOn(context.vault, "inspectSolanaSignedArtifact");
    try {
      expect((await retire(id)).status).toBe(409);
      expect(inspection).not.toHaveBeenCalled();
    } finally {
      inspection.mockRestore();
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
