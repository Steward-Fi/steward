import { expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  createDb,
  tenantSsoDomains,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt(
  "allows exactly one tenant to verify the same DNS-proven domain under a deterministic race",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 16);
    const tenantIds = [`sso-race-a-${suffix}`, `sso-race-b-${suffix}`];
    const userIds = [crypto.randomUUID(), crypto.randomUUID()];
    const domain = `race-${suffix}.example.test`;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    process.env.STEWARD_AUDIT_HMAC_KEY = `sso-race-audit-${suffix}-at-least-32-bytes`;
    process.env.STEWARD_JWT_SECRET = `sso-race-jwt-${suffix}-at-least-32-bytes`;
    process.env.STEWARD_MASTER_PASSWORD = `sso-race-master-${suffix}-at-least-32-bytes`;
    __resetAuditHmacKeyCacheForTests();

    const admin = createDb(databaseUrl!);
    let resetTxtResolver: (() => void) | undefined;
    try {
      for (let index = 0; index < tenantIds.length; index++) {
        const pair = generateApiKey();
        await admin.db.insert(tenants).values({
          id: tenantIds[index],
          name: `SSO race ${index}`,
          apiKeyHash: pair.hash,
        });
        await admin.db.insert(users).values({
          id: userIds[index],
          email: `sso-race-${index}-${suffix}@example.test`,
        });
        await admin.db.insert(userTenants).values({
          userId: userIds[index],
          tenantId: tenantIds[index],
          role: "owner",
        });
        await admin.db.insert(tenantSsoDomains).values({
          tenantId: tenantIds[index],
          domain,
          verificationToken: `steward-sso-race-${suffix}`,
          status: "pending",
          ssoRequired: true,
        });
      }

      const authModule = await import("../routes/auth");
      const tenantModule = await import("../routes/tenant-config");
      resetTxtResolver = () => tenantModule.__setSsoDomainTxtResolverForTests();
      const tokens = await Promise.all(
        tenantIds.map((tenantId, index) =>
          authModule.createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
            userId: userIds[index],
            tenantId,
            mfaVerifiedAt: Date.now(),
            mfaMethod: "totp",
          }),
        ),
      );
      const app = new Hono().route("/tenants", tenantModule.tenantConfigRoutes);
      app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));

      let arrivals = 0;
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      tenantModule.__setSsoDomainTxtResolverForTests(async () => {
        arrivals++;
        if (arrivals === 2) release();
        await gate;
        return [[`steward-sso-race-${suffix}`]];
      });
      const requests = tenantIds.map((tenantId, index) =>
        app.request(`/tenants/${tenantId}/sso-domains/${domain}/verify`, {
          method: "POST",
          headers: { Authorization: `Bearer ${tokens[index]}` },
        }),
      );

      const responses = await Promise.all(requests);
      expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);

      const rows = await admin.db
        .select({ tenantId: tenantSsoDomains.tenantId, status: tenantSsoDomains.status })
        .from(tenantSsoDomains)
        .where(eq(tenantSsoDomains.domain, domain));
      expect(rows.filter((row) => row.status === "verified")).toHaveLength(1);
      expect(rows.filter((row) => row.status === "pending")).toHaveLength(1);

      const completions = await admin.db
        .select({ tenantId: auditEvents.tenantId })
        .from(auditEvents)
        .where(
          and(
            inArray(auditEvents.tenantId, tenantIds),
            eq(auditEvents.action, "tenant.sso_domain.verify"),
          ),
        );
      expect(completions).toHaveLength(1);
      expect(completions[0]?.tenantId).toBe(
        rows.find((row) => row.status === "verified")?.tenantId,
      );
    } finally {
      resetTxtResolver?.();
      await admin.db.delete(auditEvents).where(inArray(auditEvents.tenantId, tenantIds));
      await admin.db.delete(auditChainHeads).where(inArray(auditChainHeads.tenantId, tenantIds));
      await admin.db.delete(tenantSsoDomains).where(inArray(tenantSsoDomains.tenantId, tenantIds));
      await admin.db.delete(userTenants).where(inArray(userTenants.tenantId, tenantIds));
      await admin.db.delete(tenants).where(inArray(tenants.id, tenantIds));
      await admin.db.delete(users).where(inArray(users.id, userIds));
      await admin.client.end();
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);
