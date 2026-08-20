import { expect, it } from "bun:test";
import { createHash } from "node:crypto";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
  transactions,
} from "@stwd/db";
import { canonicalJsonStringify } from "@stwd/shared";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt(
  "gives a concurrent exact-chain transition one CAS winner over mounted retirement",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `retirement-race-${suffix}`;
    const agentId = `retirement-race-agent-${suffix}`;
    const txId = `retirement-race-tx-${suffix}`;
    const signature =
      "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";
    const evidence = {
      version: 1 as const,
      chainFamily: "solana" as const,
      artifactSignature: signature,
      signer: "11111111111111111111111111111111",
      recentBlockhash: "11111111111111111111111111111111",
      blockhashKind: "recent" as const,
      lastValidBlockHeight: 100,
      rawIntentDigest: "a".repeat(64),
    };
    const evidenceDigest = createHash("sha256")
      .update(canonicalJsonStringify(evidence))
      .digest("hex");
    process.env.STEWARD_AUDIT_HMAC_KEY = `retirement-race-audit-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `retirement-race-master-${suffix}`;
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    __resetAuditHmacKeyCacheForTests();
    const admin = createDb(databaseUrl!);
    const competitor = createDb(databaseUrl!);
    try {
      await admin.db.insert(tenants).values({
        id: tenantId,
        name: tenantId,
        apiKeyHash: `hash-${tenantId}`,
      });
      await admin.db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: "0x1234567890123456789012345678901234567890",
      });
      await admin.db.insert(transactions).values({
        id: txId,
        agentId,
        status: "signed",
        toAddress: "11111111111111111111111111111111",
        value: "0",
        chainId: 101,
        txHash: signature,
        signedArtifactEvidence: evidence,
        signedArtifactEvidenceDigest: evidenceDigest,
      });

      const context = await import("../services/context");
      const originalInspect = context.vault.inspectSolanaSignedArtifact.bind(context.vault);
      let releaseInspection!: () => void;
      const release = new Promise<void>((resolve) => {
        releaseInspection = resolve;
      });
      let signalInspection!: () => void;
      const inspecting = new Promise<void>((resolve) => {
        signalInspection = resolve;
      });
      context.vault.inspectSolanaSignedArtifact = async () => {
        signalInspection();
        await release;
        return { result: "absent_expired" };
      };
      try {
        const { vaultRoutes } = await import("../routes/vault");
        const app = new Hono<{ Variables: AppVariables }>();
        app.use("*", async (c, next) => {
          c.set("tenantId", tenantId);
          c.set("authType", "session-jwt");
          c.set("tenantRole", "admin");
          c.set("userId", `admin-${suffix}`);
          c.set("sessionMfaVerifiedAt", Date.now());
          await next();
        });
        app.route("/vault", vaultRoutes);
        const retirement = app.request(`/vault/${agentId}/transactions/${txId}/retire-signed`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ reason: "concurrent chain winner" }),
        });
        await inspecting;
        let releaseCompetitor!: () => void;
        const competitorRelease = new Promise<void>((resolve) => {
          releaseCompetitor = resolve;
        });
        let signalCompetitor!: () => void;
        const competitorLocked = new Promise<void>((resolve) => {
          signalCompetitor = resolve;
        });
        const competingTransition = competitor.client.begin(async (tx) => {
          const changed = await tx`
            update transactions
            set status = 'broadcast'
            where id = ${txId} and status = 'signed'
            returning id
          `;
          expect(changed).toHaveLength(1);
          signalCompetitor();
          await competitorRelease;
        });
        await competitorLocked;
        let retirementSettled = false;
        const observedRetirement = retirement.then((response) => {
          retirementSettled = true;
          return response;
        });
        releaseInspection();
        await Bun.sleep(50);
        expect(retirementSettled).toBe(false);
        releaseCompetitor();
        await competingTransition;
        expect((await observedRetirement).status).toBe(409);
        const [winner] = await admin.db
          .select({ status: transactions.status })
          .from(transactions)
          .where(eq(transactions.id, txId));
        expect(winner?.status).toBe("broadcast");
      } finally {
        context.vault.inspectSolanaSignedArtifact = originalInspect;
      }
    } finally {
      await admin.db.delete(transactions).where(eq(transactions.agentId, agentId));
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db.delete(agents).where(eq(agents.id, agentId));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await competitor.client.end();
      await admin.client.end();
      delete process.env.STEWARD_AUDIT_HMAC_KEY;
      delete process.env.STEWARD_MASTER_PASSWORD;
      delete process.env.STEWARD_ALLOW_DEV_SECRETS;
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);
