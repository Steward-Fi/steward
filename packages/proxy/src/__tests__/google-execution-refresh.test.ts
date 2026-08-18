import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  closeDb,
  getDb,
  providerAccounts,
  providerGoogleCredentialLifecycles,
  secrets,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import {
  __setGoogleExecutionTokenForwarderForTests,
  mintGoogleExecutionAccessToken,
} from "../handlers/google-execution-credential";

setDefaultTimeout(120_000);

const TENANT = "tenant-google-execution-refresh";
const USER = "10000000-0000-4000-8000-000000000093";
const WORKSPACE = "20000000-0000-4000-8000-000000000093";
const MASTER = "google-execution-refresh-test-master";
const vault = new SecretVault(MASTER);
const credential = JSON.stringify({
  schemaVersion: "steward.provider-google.credential.v1",
  accessToken: "persisted-stale-access-canary",
  refreshToken: "server-refresh-canary",
  scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
  googleUserId: "google-user-123",
  googleEmail: "user@example.test",
  obtainedAt: new Date(0).toISOString(),
  expiresAt: new Date(1).toISOString(),
});
let accountId = "";

describe("Google execution-time token mint", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await db.insert(tenants).values({ id: TENANT, name: TENANT, apiKeyHash: `hash-${TENANT}` });
    await db.insert(users).values({ id: USER, email: "google-refresh@example.test" });
    await db.insert(workspaces).values({
      id: WORKSPACE,
      tenantId: TENANT,
      key: "google-refresh",
      name: "Google Refresh",
      environment: "production",
      createdBy: USER,
    });
    const secret = await vault.createSecret(TENANT, "google-refresh", credential);
    const [account] = await db
      .insert(providerAccounts)
      .values({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        adapterKey: "google",
        externalRef: "google-user-123",
        displayName: "Google user",
        credentialSecretId: secret.id,
        credentialVersion: secret.version,
      })
      .returning();
    accountId = account.id;
  });

  afterAll(async () => {
    __setGoogleExecutionTokenForwarderForTests(null);
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  test("ignores persisted access token and injects a newly minted short-lived token", async () => {
    let requestBody = "";
    __setGoogleExecutionTokenForwarderForTests(async (body) => {
      requestBody = body;
      return Response.json({
        access_token: "ephemeral-access",
        token_type: "Bearer",
        scope: "openid email https://www.googleapis.com/auth/gmail.send",
        expires_in: 3600,
      });
    });
    await expect(
      mintGoogleExecutionAccessToken({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        accountRevision: 1,
        credential,
        vault,
        clientId: "provider-client",
        clientSecret: "provider-secret",
      }),
    ).resolves.toBe("ephemeral-access");
    expect(requestBody).toContain("refresh_token=server-refresh-canary");
    expect(requestBody).not.toContain("persisted-stale-access-canary");
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    expect(lifecycle.state).toBe("adopted");
    expect(lifecycle.credentialSecretId).toBeNull();
    expect(await getDb().select().from(secrets).where(eq(secrets.tenantId, TENANT))).toHaveLength(
      1,
    );
  });

  test("durably escrows an unexpectedly rotated refresh response", async () => {
    __setGoogleExecutionTokenForwarderForTests(async () =>
      Response.json({
        access_token: "ephemeral-rotated-access",
        refresh_token: "rotated-refresh-canary",
        token_type: "Bearer",
        scope: "openid email https://www.googleapis.com/auth/gmail.send",
        expires_in: 3600,
      }),
    );
    await expect(
      mintGoogleExecutionAccessToken({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        accountRevision: 1,
        credential,
        vault,
        clientId: "provider-client",
        clientSecret: "provider-secret",
      }),
    ).resolves.toBe("ephemeral-rotated-access");
    const rows = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    const lifecycle = rows.find((row) => row.state === "credential_staged");
    expect(lifecycle?.credentialSecretId).toBeTruthy();
    const [escrow] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, lifecycle?.credentialSecretId as string));
    expect(JSON.stringify(escrow)).not.toContain("rotated-refresh-canary");
    expect(await vault.decryptSecret(TENANT, escrow.id)).toContain("rotated-refresh-canary");
  });

  test("disables execution after an outcome-unknown token request", async () => {
    await getDb()
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "adopted", credentialSecretId: null })
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    const [account] = await getDb()
      .update(providerAccounts)
      .set({ status: "active", revision: 2 })
      .where(eq(providerAccounts.id, accountId))
      .returning();
    __setGoogleExecutionTokenForwarderForTests(async () => {
      throw new Error("connection reset after request body was sent");
    });
    await expect(
      mintGoogleExecutionAccessToken({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        accountRevision: account.revision,
        credential,
        vault,
        clientId: "provider-client",
        clientSecret: "provider-secret",
      }),
    ).rejects.toThrow("connection reset");
    const [disabled] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(disabled.status).toBe("disabled");
    const rows = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    expect(rows.some((row) => row.state === "needs_attention")).toBeTrue();
  });

  test("rejects a newly minted token that is still too close to expiry", async () => {
    await getDb()
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "adopted", credentialSecretId: null })
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    const [account] = await getDb()
      .update(providerAccounts)
      .set({ status: "active", revision: 4 })
      .where(eq(providerAccounts.id, accountId))
      .returning();
    __setGoogleExecutionTokenForwarderForTests(async () =>
      Response.json({
        access_token: "ephemeral-too-short",
        token_type: "Bearer",
        scope: "openid email https://www.googleapis.com/auth/gmail.send",
        expires_in: 299,
      }),
    );
    await expect(
      mintGoogleExecutionAccessToken({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        accountRevision: account.revision,
        credential,
        vault,
        clientId: "provider-client",
        clientSecret: "provider-secret",
      }),
    ).rejects.toThrow("invalid Google refresh response");
    const [disabled] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(disabled.status).toBe("disabled");
  });

  test("rejects scope widening and freezes the account before another mint", async () => {
    await getDb()
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "adopted", credentialSecretId: null })
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    const [account] = await getDb()
      .update(providerAccounts)
      .set({ status: "active", revision: 6 })
      .where(eq(providerAccounts.id, accountId))
      .returning();
    __setGoogleExecutionTokenForwarderForTests(async () =>
      Response.json({
        access_token: "ephemeral-widened",
        token_type: "Bearer",
        scope:
          "openid email https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/calendar.events",
        expires_in: 3600,
      }),
    );
    await expect(
      mintGoogleExecutionAccessToken({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        accountRevision: account.revision,
        credential,
        vault,
        clientId: "provider-client",
        clientSecret: "provider-secret",
      }),
    ).rejects.toThrow("Google refresh widened OAuth scope");
    const [disabled] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(disabled.status).toBe("disabled");
    const rows = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.providerAccountId, accountId));
    expect(rows.some((row) => row.state === "revocation_pending")).toBeTrue();
  });
});
