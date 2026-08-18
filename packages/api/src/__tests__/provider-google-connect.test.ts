/**
 * Google Workspace provider-account OAuth connect + token lifecycle tests
 * (issue #195).
 *
 * Covers: connect initiate/complete happy path, state mismatch, expired state,
 * reused state, PKCE failure, wrong-role caller (via canConnectProviderAccounts
 * gate), refresh rotation single-flight (concurrency: exactly one token call),
 * refresh revoked -> degraded, disconnect. The X network is fully faked through
 * the __setGoogleForwardForTests seam; no real network is ever hit.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import {
  agents,
  auditEvents as auditEventsTable,
  closeDb,
  getDb,
  providerAccounts,
  providerGoogleCredentialLifecycles,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  __setGoogleExecutionTokenForwarderForTests,
  mintGoogleExecutionAccessToken,
} from "@stwd/proxy/src/handlers/google-execution-credential";
import { SecretVault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { providerAuthorityStore } from "../services/provider-authority-store";
import {
  __runDefaultGoogleForwardForTests,
  __setGoogleConnectCommitHookForTests,
  __setGoogleCredentialStageHookForTests,
  __setGoogleDisconnectJournalHookForTests,
  __setGoogleDisconnectRevokeHookForTests,
  __setGoogleForwardForTests,
  __setGoogleRefreshIntentHookForTests,
  assertGoogleConnectStoreIsSafe,
  completeGoogleConnect,
  disconnectGoogleProviderCredential,
  GOOGLE_ADAPTER_KEY,
  GoogleConnectError,
  type GoogleCredentialPayload,
  type GoogleForwardRequest,
  type GoogleForwardResponse,
  googleCredentialSecretName,
  initiateGoogleConnect,
  type PendingConnectStore,
  reconcileGoogleCredentialRevocation,
  reconcileGoogleRefreshLifecycle,
  refreshGoogleProviderCredential,
  resolveGoogleConnectConfig,
  runGoogleCredentialLifecycleSweep,
} from "../services/provider-google-connect";

setDefaultTimeout(120_000);

// ── Fixture identifiers ───────────────────────────────────────────────────────
const TENANT = "tenant-x-connect";
const ADMIN = "10000000-0000-4000-8000-0000000000a1";
const APPROVER = "10000000-0000-4000-8000-0000000000a2";
const VIEWER = "10000000-0000-4000-8000-0000000000a3";
const OUTSIDER = "10000000-0000-4000-8000-0000000000a4";
const WORKSPACE = "20000000-0000-4000-8000-0000000000b1";
const WORKSPACE_OTHER = "20000000-0000-4000-8000-0000000000b2";
const AGENT = "agent-google-connect-test";
const ADMIN_BINDING = "30000000-0000-4000-8000-0000000000c1";
const APPROVER_BINDING = "30000000-0000-4000-8000-0000000000c2";
const VIEWER_BINDING = "30000000-0000-4000-8000-0000000000c3";

const REDIRECT = "https://app.steward.test/connect/x/callback";
const CONFIG = { clientId: "x-client-id", clientSecret: "x-client-secret" };

const MASTER = process.env.STEWARD_MASTER_PASSWORD ?? "steward-api-test-suite-master-password";
const vault = new SecretVault(MASTER);

async function readAuditActions(tenantId: string): Promise<string[]> {
  const db = getDb();
  const rows = await db
    .select({ action: auditEventsTable.action })
    .from(auditEventsTable)
    .where(eq(auditEventsTable.tenantId, tenantId));
  return rows.map((r) => r.action);
}

/** base64url encode without the narrow bun-types Buffer encoding union. */
function toB64url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── In-memory pending-connect store (single-use, TTL-aware) ───────────────────
class MemoryConnectStore implements PendingConnectStore {
  private map = new Map<string, { value: string; expiresAt: number }>();
  now = Date.now();

  async set(key: string, value: string, ttlMs: number): Promise<void> {
    this.map.set(key, { value, expiresAt: this.now + ttlMs });
  }
  async get(key: string): Promise<string | null> {
    const rec = this.map.get(key);
    if (!rec) return null;
    if (rec.expiresAt <= this.now) {
      this.map.delete(key);
      return null;
    }
    return rec.value;
  }
  async consume(key: string): Promise<string | null> {
    // Keep the read+delete synchronous so this fake preserves the production
    // store's atomic GETDEL semantics under concurrent callbacks.
    const rec = this.map.get(key);
    if (!rec) return null;
    this.map.delete(key);
    return rec.expiresAt <= this.now ? null : rec.value;
  }
}

// ── Fake X network ────────────────────────────────────────────────────────────
interface FakeXOptions {
  exchangeToken?: Partial<{
    access_token: string;
    refresh_token: string;
    scope: string;
    expires_in: number;
  }>;
  exchangeStatus?: number;
  identity?: { sub: string; email: string; email_verified?: boolean; name: string };
  identityStatus?: number;
  revokeStatus?: number;
  refreshResponses?: Array<{
    status: number;
    body: Record<string, unknown>;
    delayMs?: number;
  }>;
}

interface FakeXCounters {
  exchange: number;
  identity: number;
  refresh: number;
  revoke: number;
}

function installFakeX(opts: FakeXOptions = {}): {
  counters: FakeXCounters;
  restore: () => void;
} {
  const counters: FakeXCounters = { exchange: 0, identity: 0, refresh: 0, revoke: 0 };
  let refreshIdx = 0;
  const fn = async (req: GoogleForwardRequest): Promise<GoogleForwardResponse> => {
    // Token endpoint: distinguish exchange vs refresh by grant_type.
    if (req.url.endsWith("/token")) {
      const body = req.body ?? "";
      if (body.includes("grant_type=refresh_token")) {
        counters.refresh += 1;
        const resp = opts.refreshResponses?.[refreshIdx] ?? {
          status: 200,
          body: {
            access_token: `access-refreshed-${counters.refresh}`,
            refresh_token: `refresh-rotated-${counters.refresh}`,
            scope: "openid email https://www.googleapis.com/auth/gmail.send",
            expires_in: 7200,
          },
        };
        refreshIdx += 1;
        if (resp.delayMs) await new Promise((r) => setTimeout(r, resp.delayMs));
        return jsonResponse(resp.status, resp.body);
      }
      counters.exchange += 1;
      const status = opts.exchangeStatus ?? 200;
      if (status !== 200) return jsonResponse(status, { error: "invalid_request" });
      return jsonResponse(200, {
        access_token: "access-initial",
        refresh_token: "refresh-initial",
        scope: "openid email https://www.googleapis.com/auth/gmail.send",
        expires_in: 7200,
        ...opts.exchangeToken,
      });
    }
    if (req.url.includes("/userinfo")) {
      counters.identity += 1;
      const status = opts.identityStatus ?? 200;
      if (status !== 200) return jsonResponse(status, {});
      const identity = opts.identity ?? {
        sub: "google-user-123",
        email: "solsundial@example.com",
        email_verified: true,
        name: "Sol",
      };
      identity.email_verified ??= true;
      return jsonResponse(200, identity);
    }
    if (req.url.endsWith("/revoke")) {
      counters.revoke += 1;
      return jsonResponse(opts.revokeStatus ?? 200, {});
    }
    throw new Error(`unexpected Google call: ${req.url}`);
  };
  const restore = __setGoogleForwardForTests(fn);
  return { counters, restore };
}

function jsonResponse(status: number, body: unknown): GoogleForwardResponse {
  const text = JSON.stringify(body);
  return { status, ok: status >= 200 && status < 300, json: body, text };
}

// ── Schema bootstrap ──────────────────────────────────────────────────────────
async function seed() {
  const db = getDb();
  await db.insert(tenants).values([{ id: TENANT, name: "X Connect", apiKeyHash: "h" }]);
  await db.insert(users).values([
    { id: ADMIN, email: "admin@x.test" },
    { id: APPROVER, email: "approver@x.test" },
    { id: VIEWER, email: "viewer@x.test" },
    { id: OUTSIDER, email: "outsider@x.test" },
  ]);
  await db.insert(userTenants).values([
    { userId: ADMIN, tenantId: TENANT, role: "member" },
    { userId: APPROVER, tenantId: TENANT, role: "member" },
    { userId: VIEWER, tenantId: TENANT, role: "member" },
    // OUTSIDER is deliberately NOT a tenant member.
  ]);
  await db.insert(agents).values({
    id: AGENT,
    tenantId: TENANT,
    name: "Google connect test agent",
    walletAddress: `0x${"7".repeat(40)}`,
  });
  await db.insert(workspaces).values([
    {
      id: WORKSPACE,
      tenantId: TENANT,
      key: "client-x",
      name: "Client X",
      environment: "production",
      createdBy: ADMIN,
    },
    {
      id: WORKSPACE_OTHER,
      tenantId: TENANT,
      key: "client-x-other",
      name: "Client X Other",
      environment: "production",
      createdBy: ADMIN,
    },
  ]);
  await db.insert(providerRoleBindings).values([
    {
      id: ADMIN_BINDING,
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      principalType: "human",
      principalId: ADMIN,
      roleKey: "workspace_admin",
      status: "active",
      grantedByUserId: ADMIN,
      reason: "seed",
    },
    {
      id: APPROVER_BINDING,
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      principalType: "human",
      principalId: APPROVER,
      roleKey: "workspace_approver",
      status: "active",
      grantedByUserId: ADMIN,
      reason: "seed",
    },
    {
      id: VIEWER_BINDING,
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      principalType: "human",
      principalId: VIEWER,
      roleKey: "workspace_viewer",
      status: "active",
      grantedByUserId: ADMIN,
      reason: "seed",
    },
  ]);
}

beforeAll(async () => {
  process.env.STEWARD_MASTER_PASSWORD ??= MASTER;
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);
  process.env.STEWARD_PGLITE_MEMORY ??= "true";
  process.env.STEWARD_DB_MODE ??= "pglite";
  // Fresh, isolated schema for this file (matches the per-file convention). The
  // override's teardown closes the client exactly once via closeDb() in afterAll.
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  await seed();
});

afterAll(async () => {
  __setGoogleForwardForTests(null);
  __setGoogleConnectCommitHookForTests(null);
  __setGoogleCredentialStageHookForTests(null);
  __setGoogleDisconnectJournalHookForTests(null);
  __setGoogleDisconnectRevokeHookForTests(null);
  __setGoogleRefreshIntentHookForTests(null);
  __setGoogleExecutionTokenForwarderForTests(null);
  await closeDb();
});

afterEach(async () => {
  __setGoogleForwardForTests(null);
  __setGoogleConnectCommitHookForTests(null);
  __setGoogleCredentialStageHookForTests(null);
  __setGoogleDisconnectJournalHookForTests(null);
  __setGoogleDisconnectRevokeHookForTests(null);
  __setGoogleRefreshIntentHookForTests(null);
  __setGoogleExecutionTokenForwarderForTests(null);
  // Reset connected accounts + credential secrets between tests.
  const db = getDb();
  await db
    .delete(providerGoogleCredentialLifecycles)
    .where(eq(providerGoogleCredentialLifecycles.tenantId, TENANT));
  await db.delete(providerAccounts).where(eq(providerAccounts.tenantId, TENANT));
  await db.delete(secrets).where(eq(secrets.tenantId, TENANT));
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function connectHappy(
  store: MemoryConnectStore,
  overrides: {
    userId?: string;
    identity?: { sub: string; email: string; email_verified?: boolean; name: string };
    exchangeToken?: FakeXOptions["exchangeToken"];
  } = {},
) {
  const fake = installFakeX({
    identity: overrides.identity,
    exchangeToken: overrides.exchangeToken,
  });
  const initiated = await initiateGoogleConnect({
    tenantId: TENANT,
    workspaceId: WORKSPACE,
    initiatedByUserId: overrides.userId ?? ADMIN,
    redirectUri: REDIRECT,
    config: CONFIG,
    store,
  });
  const completed = await completeGoogleConnect({
    tenantId: TENANT,
    workspaceId: WORKSPACE,
    callerUserId: overrides.userId ?? ADMIN,
    code: "auth-code",
    state: initiated.state,
    connectToken: initiated.connectToken,
    redirectUri: REDIRECT,
    config: CONFIG,
    store,
    vault,
  });
  fake.restore();
  return { initiated, completed, fake };
}

async function decryptCredential(accountId: string): Promise<GoogleCredentialPayload> {
  const db = getDb();
  const [acct] = await db
    .select()
    .from(providerAccounts)
    .where(and(eq(providerAccounts.tenantId, TENANT), eq(providerAccounts.id, accountId)))
    .limit(1);
  const decrypted = await vault.decryptSecret(TENANT, acct.credentialSecretId as string);
  return JSON.parse(decrypted) as GoogleCredentialPayload;
}

// ── Authority gate (wrong-role caller) ────────────────────────────────────────
describe("connect authority gate", () => {
  test("workspace_admin is authorized", async () => {
    expect(
      await providerAuthorityStore.canConnectProviderAccounts(TENANT, WORKSPACE, ADMIN, "member"),
    ).toBe(true);
  });
  test("workspace_approver is authorized", async () => {
    expect(
      await providerAuthorityStore.canConnectProviderAccounts(
        TENANT,
        WORKSPACE,
        APPROVER,
        "member",
      ),
    ).toBe(true);
  });
  test("workspace_viewer is NOT authorized", async () => {
    expect(
      await providerAuthorityStore.canConnectProviderAccounts(TENANT, WORKSPACE, VIEWER, "member"),
    ).toBe(false);
  });
  test("non-member outsider is NOT authorized", async () => {
    expect(
      await providerAuthorityStore.canConnectProviderAccounts(
        TENANT,
        WORKSPACE,
        OUTSIDER,
        "member",
      ),
    ).toBe(false);
  });
});

// ── Connect happy path + idempotent reconnect ─────────────────────────────────
describe("connect", () => {
  test("authorize request never enables incremental previously granted scopes", async () => {
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store: new MemoryConnectStore(),
    });
    const authorizeUrl = new URL(initiated.authorizeUrl);
    expect(authorizeUrl.searchParams.has("include_granted_scopes")).toBe(false);
  });

  test("happy path: creates account, versioned credential, audit event", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    expect(completed.reconnected).toBe(false);
    expect(completed.googleUserId).toBe("google-user-123");
    expect(completed.googleEmail).toBe("solsundial@example.com");
    expect(completed.credentialVersion).toBe(1);

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.adapterKey).toBe(GOOGLE_ADAPTER_KEY);
    expect(acct.externalRef).toBe("google-user-123");
    expect(acct.displayName).toBe("solsundial@example.com");
    expect(acct.status).toBe("active");
    expect(acct.credentialSecretId).toBeTruthy();
    expect(acct.credentialVersion).toBe(1);

    const cred = await decryptCredential(completed.providerAccountId);
    expect(cred.accessToken).toBe("access-initial");
    expect(cred.refreshToken).toBe("refresh-initial");
    expect(cred.googleUserId).toBe("google-user-123");

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.google.connect.completed")).toBe(true);
  });

  test("reconnect same Google user id updates version + bumps revision, never duplicates", async () => {
    const store = new MemoryConnectStore();
    const first = await connectHappy(store);
    const firstId = first.completed.providerAccountId;

    const store2 = new MemoryConnectStore();
    const second = await connectHappy(store2);

    expect(second.completed.reconnected).toBe(true);
    expect(second.completed.providerAccountId).toBe(firstId);
    expect(second.completed.credentialVersion).toBe(2);

    const db = getDb();
    const rows = await db
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, TENANT),
          eq(providerAccounts.adapterKey, GOOGLE_ADAPTER_KEY),
          eq(providerAccounts.externalRef, "google-user-123"),
        ),
      );
    expect(rows.length).toBe(1);
    expect(rows[0].revision).toBe(2);
    expect(rows[0].credentialVersion).toBe(2);
  });

  test("reconnect supersedes only a null-handle unknown refresh and restores minting without replay", async () => {
    const first = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [beforeAccount] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, first.completed.providerAccountId));
    const lifecycleId = crypto.randomUUID();
    await db.insert(providerGoogleCredentialLifecycles).values({
      id: lifecycleId,
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      providerAccountId: beforeAccount.id,
      kind: "refresh_rotation",
      state: "needs_attention",
      credentialSecretId: null,
      expectedAccountRevision: beforeAccount.revision,
      lastErrorCode: "REFRESH_OUTCOME_UNKNOWN",
    });

    let tokenRequests = 0;
    __setGoogleExecutionTokenForwarderForTests(async () => {
      tokenRequests += 1;
      return Response.json({
        access_token: "execution-access-after-reconnect",
        token_type: "Bearer",
        expires_in: 3600,
      });
    });
    try {
      const blockedRefresh = installFakeX();
      try {
        await expect(
          refreshGoogleProviderCredential({
            tenantId: TENANT,
            workspaceId: WORKSPACE,
            accountId: beforeAccount.id,
            vault,
            config: CONFIG,
            force: true,
          }),
        ).rejects.toMatchObject({ code: "GOOGLE_CREDENTIAL_NEEDS_ATTENTION" });
        expect(blockedRefresh.counters.refresh).toBe(0);
      } finally {
        blockedRefresh.restore();
      }

      await expect(
        mintGoogleExecutionAccessToken({
          tenantId: TENANT,
          workspaceId: WORKSPACE,
          accountId: beforeAccount.id,
          accountRevision: beforeAccount.revision,
          credential: JSON.stringify(await decryptCredential(beforeAccount.id)),
          vault,
          clientId: CONFIG.clientId,
          clientSecret: CONFIG.clientSecret,
        }),
      ).rejects.toThrow("Google credential refresh lifecycle must be reconciled before token mint");
      expect(tokenRequests).toBe(0);

      const second = await connectHappy(new MemoryConnectStore());
      expect(second.completed.reconnected).toBe(true);
      const [afterAccount] = await db
        .select()
        .from(providerAccounts)
        .where(eq(providerAccounts.id, beforeAccount.id));
      const [superseded] = await db
        .select()
        .from(providerGoogleCredentialLifecycles)
        .where(eq(providerGoogleCredentialLifecycles.id, lifecycleId));
      expect(superseded.state).toBe("superseded");
      expect(superseded.credentialSecretId).toBeNull();
      expect(superseded.lastErrorCode).toBe("SUPERSEDED_BY_RECONNECT");

      const minted = await mintGoogleExecutionAccessToken({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: afterAccount.id,
        accountRevision: afterAccount.revision,
        credential: JSON.stringify(await decryptCredential(afterAccount.id)),
        vault,
        clientId: CONFIG.clientId,
        clientSecret: CONFIG.clientSecret,
      });
      expect(minted).toBe("execution-access-after-reconnect");
      expect(tokenRequests).toBe(1);
      expect(await readAuditActions(TENANT)).toContain(
        "provider.google.refresh.superseded_by_reconnect",
      );
    } finally {
      __setGoogleExecutionTokenForwarderForTests(null);
    }
  });

  test("reconnect preserves and rejects every unresolved staged refresh credential handle", async () => {
    const first = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [beforeAccount] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, first.completed.providerAccountId));
    const strandedHandle = await vault.createSecret(
      TENANT,
      `provider-google-lifecycle:${crypto.randomUUID()}`,
      JSON.stringify({
        schemaVersion: "steward.provider-google.lifecycle.v1",
        token: { access_token: "stranded-access", refresh_token: "stranded-refresh" },
      }),
    );
    const lifecycleId = crypto.randomUUID();
    await db.insert(providerGoogleCredentialLifecycles).values({
      id: lifecycleId,
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      providerAccountId: beforeAccount.id,
      kind: "refresh_rotation",
      state: "needs_attention",
      credentialSecretId: strandedHandle.id,
      expectedAccountRevision: beforeAccount.revision,
      lastErrorCode: "REFRESH_OUTCOME_UNKNOWN",
    });

    await expect(connectHappy(new MemoryConnectStore())).rejects.toMatchObject({
      code: "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
    });

    const [unchangedLifecycle] = await db
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.id, lifecycleId));
    const [unchangedAccount] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, beforeAccount.id));
    expect(unchangedLifecycle.state).toBe("needs_attention");
    expect(unchangedLifecycle.credentialSecretId).toBe(strandedHandle.id);
    expect(unchangedAccount.revision).toBe(beforeAccount.revision);
    expect(await vault.decryptSecret(TENANT, strandedHandle.id)).toContain("stranded-refresh");
  });

  test("injected initial persistence failure rolls back secret/account and revokes issued grant", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const restoreHook = __setGoogleConnectCommitHookForTests(() => {
      throw new Error("injected commit failure");
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toThrow("injected commit failure");
    restoreHook();

    const db = getDb();
    expect(
      await db.select().from(providerAccounts).where(eq(providerAccounts.tenantId, TENANT)),
    ).toHaveLength(0);
    expect(await db.select().from(secrets).where(eq(secrets.tenantId, TENANT))).toHaveLength(0);
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
  });

  test("scope widening is rejected and the issued grant is revoked", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX({
      exchangeToken: {
        scope: "openid email https://www.googleapis.com/auth/drive",
      },
    });
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_SCOPE_WIDENED" });
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
  });

  test("post-exchange crash leaves an encrypted single-use revocation handle", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const restoreHook = __setGoogleCredentialStageHookForTests(() => {
      throw new Error("crash after durable stage");
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toThrow("crash after durable stage");
    restoreHook();
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.tenantId, TENANT));
    expect(lifecycle.state).toBe("credential_staged");
    expect(lifecycle.credentialSecretId).toBeTruthy();
    const [encryptedHandle] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, lifecycle.credentialSecretId as string));
    expect(JSON.stringify(encryptedHandle)).not.toContain("access-initial");
    expect(JSON.stringify(encryptedHandle)).not.toContain("refresh-initial");
    expect(await vault.decryptSecret(TENANT, encryptedHandle.id)).toContain("refresh-initial");
    const concurrentRecovery = await Promise.all([
      runGoogleCredentialLifecycleSweep({
        vault,
        config: CONFIG,
        now: new Date(Date.now() + 20_000),
      }),
      runGoogleCredentialLifecycleSweep({
        vault,
        config: CONFIG,
        now: new Date(Date.now() + 20_000),
      }),
    ]);
    expect(concurrentRecovery.reduce((sum, result) => sum + result.processed, 0)).toBe(1);
    expect(concurrentRecovery.reduce((sum, result) => sum + result.revoked, 0)).toBe(1);
    expect(concurrentRecovery.reduce((sum, result) => sum + result.attention, 0)).toBe(0);
    await expect(
      reconcileGoogleCredentialRevocation({
        tenantId: TENANT,
        lifecycleId: lifecycle.id,
        vault,
        config: CONFIG,
      }),
    ).resolves.toBe("already_terminal");
    expect(fake.counters.revoke).toBe(1);
    const [terminalLifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.id, lifecycle.id));
    expect(terminalLifecycle.state).toBe("revoked");
    expect(terminalLifecycle.credentialSecretId).toBeNull();
    expect(
      await getDb().select().from(secrets).where(eq(secrets.id, encryptedHandle.id)),
    ).toHaveLength(0);
    fake.restore();
  });

  test("revoker failure is durably classified needs_attention without leaking the handle", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX({
      revokeStatus: 503,
      exchangeToken: { scope: "openid https://www.googleapis.com/auth/drive" },
    });
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_SCOPE_WIDENED" });
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.tenantId, TENANT));
    expect(lifecycle.state).toBe("needs_attention");
    expect(JSON.stringify(lifecycle)).not.toContain("access-initial");
    expect(JSON.stringify(lifecycle)).not.toContain("refresh-initial");
    fake.restore();
  });

  test("injected reconnect failure preserves old account/credential and revokes only new grant", async () => {
    const firstStore = new MemoryConnectStore();
    const first = await connectHappy(firstStore);
    const before = await decryptCredential(first.completed.providerAccountId);
    const db = getDb();
    const [beforeAccount] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, first.completed.providerAccountId));

    const store = new MemoryConnectStore();
    const fake = installFakeX({
      exchangeToken: { access_token: "access-new", refresh_token: "refresh-new" },
    });
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const restoreHook = __setGoogleConnectCommitHookForTests(() => {
      throw new Error("injected reconnect failure");
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code-new",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toThrow("injected reconnect failure");
    restoreHook();

    const [afterAccount] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, first.completed.providerAccountId));
    expect(afterAccount.credentialSecretId).toBe(beforeAccount.credentialSecretId);
    expect(afterAccount.credentialVersion).toBe(beforeAccount.credentialVersion);
    expect(afterAccount.revision).toBe(beforeAccount.revision);
    expect(await decryptCredential(first.completed.providerAccountId)).toEqual(before);
    const activeSecrets = await db
      .select()
      .from(secrets)
      .where(
        and(
          eq(secrets.tenantId, TENANT),
          eq(secrets.name, googleCredentialSecretName(WORKSPACE, "google-user-123")),
        ),
      );
    expect(activeSecrets).toHaveLength(1);
    expect(activeSecrets[0].deletedAt).toBeNull();
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
  });

  test("concurrent duplicate callback has one winner and revokes the loser's issued grant", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const args = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      callerUserId: ADMIN,
      code: "auth-code",
      state: initiated.state,
      connectToken: initiated.connectToken,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
      vault,
    };
    const outcomes = await Promise.allSettled([
      completeGoogleConnect(args),
      completeGoogleConnect(args),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const rejected = outcomes.find((outcome) => outcome.status === "rejected");
    expect(rejected).toMatchObject({ reason: { code: "GOOGLE_STATE_REUSED" } });
    expect(fake.counters.revoke).toBe(1);
    const db = getDb();
    expect(
      await db.select().from(providerAccounts).where(eq(providerAccounts.tenantId, TENANT)),
    ).toHaveLength(1);
    expect(await db.select().from(secrets).where(eq(secrets.tenantId, TENANT))).toHaveLength(1);
    fake.restore();
  });
});

// ── State + PKCE negative cases ───────────────────────────────────────────────
describe("connect state validation", () => {
  test("state mismatch (unknown state) => GOOGLE_STATE_INVALID", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: "never-issued",
        connectToken: toB64url(JSON.stringify({ state: "never-issued", verifier: "v" })),
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_STATE_INVALID" });
    fake.restore();
  });

  test("expired state => GOOGLE_STATE_INVALID (store returns null)", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    // Advance the store clock beyond the TTL so get() evicts the entry.
    store.now += 60 * 60 * 1000;
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_STATE_INVALID" });
    fake.restore();
  });

  test("reused state => GOOGLE_STATE_REUSED on the second completion", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const args = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      callerUserId: ADMIN,
      code: "auth-code",
      state: initiated.state,
      connectToken: initiated.connectToken,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
      vault,
    };
    await completeGoogleConnect(args);
    await expect(completeGoogleConnect(args)).rejects.toMatchObject({
      code: "GOOGLE_STATE_INVALID",
    });
    fake.restore();
  });

  test("PKCE verifier mismatch => GOOGLE_PKCE_MISMATCH", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    // Forge a connectToken with the right state but a WRONG verifier.
    const forged = toB64url(JSON.stringify({ state: initiated.state, verifier: "wrong-verifier" }));
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: forged,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_PKCE_MISMATCH" });
    fake.restore();
  });

  test("scope mismatch: caller from a different workspace/user cannot complete", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: APPROVER, // different user than initiated
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_STATE_INVALID" });
    fake.restore();
  });

  test("token exchange failure does NOT consume the state (retryable)", async () => {
    const store = new MemoryConnectStore();
    const failing = installFakeX({ exchangeStatus: 400 });
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const args = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      callerUserId: ADMIN,
      code: "auth-code",
      state: initiated.state,
      connectToken: initiated.connectToken,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
      vault,
    };
    await expect(completeGoogleConnect(args)).rejects.toMatchObject({
      code: "GOOGLE_TOKEN_EXCHANGE_FAILED",
    });
    failing.restore();
    // The state must still be present for a retry.
    const ok = installFakeX();
    const retried = await completeGoogleConnect(args);
    expect(retried.googleUserId).toBe("google-user-123");
    ok.restore();
  });

  test("missing offline refresh token revokes the issued access token without consuming state", async () => {
    const store = new MemoryConnectStore();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const fake = installFakeX({ exchangeToken: { refresh_token: undefined } });
    const args = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      callerUserId: ADMIN,
      code: "auth-code",
      state: initiated.state,
      connectToken: initiated.connectToken,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
      vault,
    };
    await expect(completeGoogleConnect(args)).rejects.toMatchObject({
      code: "GOOGLE_REFRESH_TOKEN_MISSING",
    });
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
    const ok = installFakeX();
    await expect(completeGoogleConnect(args)).resolves.toMatchObject({
      googleUserId: "google-user-123",
    });
    expect(ok.counters.exchange).toBe(1);
    ok.restore();
  });

  test("malformed successful token exchange revokes credentials without consuming state", async () => {
    const store = new MemoryConnectStore();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const fake = installFakeX({
      exchangeToken: { access_token: "", refresh_token: "refresh-issued" },
    });
    const args = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      callerUserId: ADMIN,
      code: "auth-code",
      state: initiated.state,
      connectToken: initiated.connectToken,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
      vault,
    };
    await expect(completeGoogleConnect(args)).rejects.toMatchObject({
      code: "GOOGLE_TOKEN_EXCHANGE_FAILED",
    });
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
    const ok = installFakeX();
    await expect(completeGoogleConnect(args)).resolves.toMatchObject({
      googleUserId: "google-user-123",
    });
    ok.restore();
    expect(fake.counters.exchange).toBe(1);
    fake.restore();
  });

  test("overbroad exchange scopes are rejected and the issued grant is revoked", async () => {
    const store = new MemoryConnectStore();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      scopes: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      config: CONFIG,
      store,
    });
    const fake = installFakeX({
      exchangeToken: {
        scope:
          "openid email https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/drive",
      },
    });
    await expect(
      completeGoogleConnect({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_SCOPE_WIDENED" });
    expect(fake.counters.revoke).toBe(1);
    expect(fake.counters.identity).toBe(0);
    expect(
      await getDb().select().from(providerAccounts).where(eq(providerAccounts.tenantId, TENANT)),
    ).toHaveLength(0);
    fake.restore();
  });

  test("identity failure revokes the issued grant without consuming state", async () => {
    const store = new MemoryConnectStore();
    const initiated = await initiateGoogleConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    const fake = installFakeX({ identityStatus: 503 });
    const args = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      callerUserId: ADMIN,
      code: "auth-code",
      state: initiated.state,
      connectToken: initiated.connectToken,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
      vault,
    };
    await expect(completeGoogleConnect(args)).rejects.toMatchObject({
      code: "GOOGLE_IDENTITY_FAILED",
    });
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
    const ok = installFakeX();
    await expect(completeGoogleConnect(args)).resolves.toMatchObject({
      googleUserId: "google-user-123",
    });
    expect(ok.counters.exchange).toBe(1);
    ok.restore();
  });
});

// ── Refresh: rotation, single-flight, revoke ──────────────────────────────────
describe("refresh", () => {
  test("force refresh rotates token to a new credential version + audit", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const [beforeAccount] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const route = await vault.createRoute(TENANT, beforeAccount.credentialSecretId as string, {
      agentId: AGENT,
      hostPattern: "gmail.googleapis.com",
      pathPattern: "/gmail/v1/users/me/messages/send",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const fake = installFakeX();
    const result = await refreshGoogleProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    });
    expect(result.refreshed).toBe(true);
    expect(result.credentialVersion).toBe(2);
    expect(fake.counters.refresh).toBe(1);

    const cred = await decryptCredential(completed.providerAccountId);
    expect(cred.accessToken).toBe("access-refreshed-1");
    expect(cred.refreshToken).toBe("refresh-rotated-1");
    const [afterAccount] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const [updatedRoute] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, route.id));
    expect(updatedRoute.secretId).toBe(afterAccount.credentialSecretId);
    expect(updatedRoute.authorityRevision).toBeGreaterThan(1);
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.google.refresh.completed")).toBe(true);
  });

  test("malformed refresh success revokes the account without rotating the stored credential", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const before = await decryptCredential(completed.providerAccountId);
    const fake = installFakeX({
      refreshResponses: [
        {
          status: 200,
          body: {
            access_token: "",
            refresh_token: "refresh-attacker-controlled",
            expires_in: Number.POSITIVE_INFINITY,
          },
        },
      ],
    });
    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_REFRESH_FAILED" });
    expect(await decryptCredential(completed.providerAccountId)).toEqual(before);
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("disabled");
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
  });

  test("crash after rotated response staging reconciles without a second refresh call", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreHook = __setGoogleCredentialStageHookForTests(() => {
      throw new Error("crash after rotated credential stage");
    });
    const refreshInput = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    };
    await expect(refreshGoogleProviderCredential(refreshInput)).rejects.toThrow(
      "crash after rotated credential stage",
    );
    restoreHook();
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"));
    expect(lifecycle.state).toBe("credential_staged");
    await expect(
      reconcileGoogleRefreshLifecycle({ ...refreshInput, lifecycleId: lifecycle.id }),
    ).resolves.toMatchObject({ refreshed: true, credentialVersion: 2 });
    expect(fake.counters.refresh).toBe(1);
    expect((await decryptCredential(completed.providerAccountId)).refreshToken).toBe(
      "refresh-rotated-1",
    );
    const [adoptedLifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.id, lifecycle.id));
    expect(adoptedLifecycle.state).toBe("adopted");
    expect(adoptedLifecycle.credentialSecretId).toBeNull();
    expect(
      await getDb()
        .select()
        .from(secrets)
        .where(eq(secrets.id, lifecycle.credentialSecretId as string)),
    ).toHaveLength(0);
    fake.restore();
  });

  test("staged refresh lifecycle cannot be adopted into a different account", async () => {
    const first = await connectHappy(new MemoryConnectStore());
    const second = await connectHappy(new MemoryConnectStore(), {
      identity: {
        sub: "google-user-456",
        email: "other@example.com",
        email_verified: true,
        name: "Other",
      },
    });
    const fake = installFakeX();
    const restoreHook = __setGoogleCredentialStageHookForTests(() => {
      throw new Error("crash after rotated credential stage");
    });
    const firstRefresh = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: first.completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    };
    await expect(refreshGoogleProviderCredential(firstRefresh)).rejects.toThrow(
      "crash after rotated credential stage",
    );
    restoreHook();
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"));
    const beforeSecond = await decryptCredential(second.completed.providerAccountId);

    await expect(
      reconcileGoogleRefreshLifecycle({
        ...firstRefresh,
        accountId: second.completed.providerAccountId,
        lifecycleId: lifecycle.id,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_CREDENTIAL_NEEDS_ATTENTION" });

    const [secondAccount] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, second.completed.providerAccountId));
    expect(secondAccount.status).toBe("active");
    expect(await decryptCredential(second.completed.providerAccountId)).toEqual(beforeSecond);
    expect(fake.counters.revoke).toBe(0);
    fake.restore();
  });

  test("crash after durable refresh intent never spends the token during reconciliation", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreHook = __setGoogleRefreshIntentHookForTests(() => {
      throw new Error("crash after refresh intent");
    });
    const refreshInput = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    };
    await expect(refreshGoogleProviderCredential(refreshInput)).rejects.toThrow(
      "crash after refresh intent",
    );
    restoreHook();
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"));
    expect(lifecycle.state).toBe("inflight");
    await expect(
      runGoogleCredentialLifecycleSweep({
        vault,
        config: CONFIG,
        now: new Date(Date.now() + 20_000),
      }),
    ).resolves.toMatchObject({ processed: 1, attention: 1 });
    expect(fake.counters.refresh).toBe(0);
  });

  test("a rotated response that cannot be staged disables the unchanged account", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const stagingFailureVault = new SecretVault(MASTER);
    const createSecretWithinTx = stagingFailureVault.createSecretWithinTx.bind(stagingFailureVault);
    stagingFailureVault.createSecretWithinTx = async (...args) => {
      if (args[2].startsWith("provider-google-lifecycle:")) {
        throw new Error("durable staging unavailable");
      }
      return createSecretWithinTx(...args);
    };

    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault: stagingFailureVault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toThrow("durable staging unavailable");

    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"));
    expect(account.status).toBe("disabled");
    expect(lifecycle.state).toBe("needs_attention");
    expect(lifecycle.lastErrorCode).toBe("REFRESH_RESPONSE_STAGING_FAILED");
    expect(fake.counters.refresh).toBe(1);
    fake.restore();
  });

  test("a stale invalid_grant cannot revoke a credential installed after refresh intent", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX({
      refreshResponses: [{ status: 400, body: { error: "invalid_grant" } }],
    });
    const restoreHook = __setGoogleRefreshIntentHookForTests(async () => {
      const [account] = await getDb()
        .select({ revision: providerAccounts.revision })
        .from(providerAccounts)
        .where(eq(providerAccounts.id, completed.providerAccountId));
      await getDb()
        .update(providerAccounts)
        .set({ revision: account.revision + 1, status: "active" })
        .where(eq(providerAccounts.id, completed.providerAccountId));
    });

    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_REFRESH_REVOKED" });
    restoreHook();

    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const [lifecycle] = await getDb()
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"));
    expect(account.status).toBe("active");
    expect(lifecycle.state).toBe("revoked");
    expect(fake.counters.refresh).toBe(1);
    fake.restore();
  });

  test("refresh scope widening is revoked and freezes the local account", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX({
      refreshResponses: [
        {
          status: 200,
          body: {
            access_token: "widened-access",
            refresh_token: "widened-refresh",
            scope: "openid email https://www.googleapis.com/auth/drive",
            expires_in: 7200,
          },
        },
      ],
    });
    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_SCOPE_WIDENED" });
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("disabled");
    expect(fake.counters.refresh).toBe(1);
    expect(fake.counters.revoke).toBe(1);
    fake.restore();
  });

  test("SINGLE-FLIGHT: two concurrent refreshes of a near-expiry token make exactly ONE token call", async () => {
    const store = new MemoryConnectStore();
    // Seed a token that is ALREADY near expiry (expires_in=1s) so BOTH non-forced
    // concurrent callers independently decide a refresh is needed. That is the
    // real rotating-refresh hazard: without the per-account row lock + post-lock
    // near-expiry re-check, both would call the token endpoint and both would try
    // to spend the SAME single-use refresh token. Single-flight collapses this to
    // exactly one token call; the loser observes the freshly rotated (far-expiry)
    // token after acquiring the lock and short-circuits.
    //
    // Mutation check: weaken the guard (drop `.for("update")` or the post-lock
    // near-expiry re-check) and the refresh counter becomes 2 => this fails.
    const { completed } = await connectHappy(store, { exchangeToken: { expires_in: 1 } });
    const fake = installFakeX({
      refreshResponses: [
        {
          status: 200,
          delayMs: 40,
          body: {
            access_token: "access-refreshed-1",
            refresh_token: "refresh-rotated-1",
            scope: "openid email https://www.googleapis.com/auth/gmail.send",
            expires_in: 7200,
          },
        },
        {
          status: 200,
          body: {
            access_token: "access-refreshed-2",
            refresh_token: "refresh-rotated-2",
            scope: "openid email https://www.googleapis.com/auth/gmail.send",
            expires_in: 7200,
          },
        },
      ],
    });

    const [r1, r2] = await Promise.all([
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
      }),
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
      }),
    ]);

    // Exactly one performed the network refresh; the other observed the freshly
    // rotated (not-near-expiry) token and short-circuited.
    expect(fake.counters.refresh).toBe(1);
    const refreshedCount = [r1, r2].filter((r) => r.refreshed).length;
    expect(refreshedCount).toBe(1);

    const cred = await decryptCredential(completed.providerAccountId);
    expect(cred.accessToken).toBe("access-refreshed-1");
    fake.restore();
  });

  test("refresh with fresh token + not forced short-circuits (no token call)", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const result = await refreshGoogleProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
    });
    expect(result.refreshed).toBe(false);
    expect(fake.counters.refresh).toBe(0);
    fake.restore();
  });

  test("upstream failure preserves credential and redacts provider/token canaries", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const before = await decryptCredential(completed.providerAccountId);
    const fake = installFakeX({
      refreshResponses: [
        {
          status: 503,
          body: { error: "upstream-canary", error_description: "refresh-initial access-initial" },
        },
      ],
    });
    let thrown: unknown;
    try {
      await refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: "GOOGLE_REFRESH_FAILED" });
    expect(String(thrown)).not.toContain("upstream-canary");
    expect(String(thrown)).not.toContain("refresh-initial");
    const after = await decryptCredential(completed.providerAccountId);
    expect(after).toEqual(before);
    fake.restore();
  });

  test("revoked upstream (invalid_grant) => account degraded + audit + GOOGLE_REFRESH_REVOKED", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX({
      refreshResponses: [{ status: 400, body: { error: "invalid_grant" } }],
    });
    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_REFRESH_REVOKED" });

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.status).toBe("revoked");
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.google.refresh.revoked")).toBe(true);
  });

  test("refresh of a non-Google account is rejected", async () => {
    const db = getDb();
    const [row] = await db
      .insert(providerAccounts)
      .values({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        adapterKey: "github",
        externalRef: "gh-1",
        displayName: "gh",
      })
      .returning();
    const fake = installFakeX();
    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: row.id,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_ACCOUNT_NOT_GOOGLE" });
    fake.restore();
  });

  test("cross-workspace IDOR: refreshing an account from another workspace => GOOGLE_ACCOUNT_NOT_FOUND", async () => {
    // Connect an Google account in WORKSPACE, then attempt to refresh it while
    // claiming authority over WORKSPACE_OTHER. The account does not belong to
    // WORKSPACE_OTHER, so the workspace-binding guard must reject it (404).
    //
    // Mutation check: drop the `account.workspaceId !== input.workspaceId` guard
    // and this refresh succeeds against another workspace's credential.
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE_OTHER,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_ACCOUNT_NOT_FOUND" });
    expect(fake.counters.refresh).toBe(0);
    fake.restore();
  });

  test("refresh does NOT resurrect a locally revoked account (reconnect required)", async () => {
    // Connect, then disconnect (status -> revoked), then a forced refresh must
    // fail closed instead of reactivating the account.
    //
    // Mutation check: drop the `account.status !== "active"` guard and the
    // refresh reactivates a disconnected account without a fresh OAuth connect.
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const disc = installFakeX();
    await disconnectGoogleProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      callerUserId: ADMIN,
      vault,
      config: CONFIG,
    });
    disc.restore();

    const fake = installFakeX();
    await expect(
      refreshGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_REFRESH_REVOKED" });
    expect(fake.counters.refresh).toBe(0);

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.status).toBe("revoked");
    fake.restore();
  });
});

// ── Disconnect ────────────────────────────────────────────────────────────────
describe("disconnect", () => {
  test("degrades account, best-effort revokes at Google, audits", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX();
    const result = await disconnectGoogleProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      callerUserId: ADMIN,
      vault,
      config: CONFIG,
    });
    expect(result.revoked).toBe(true);
    expect(fake.counters.revoke).toBe(1);

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.status).toBe("revoked");
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.google.disconnect.completed")).toBe(true);
  });

  test("journal crash revokes local authority before scheduled upstream recovery", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreHook = __setGoogleDisconnectJournalHookForTests(() => {
      throw new Error("crash after disconnect journal");
    });
    await expect(
      disconnectGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toThrow("crash after disconnect journal");
    restoreHook();
    const db = getDb();
    const [account] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("revoked");
    expect(fake.counters.revoke).toBe(0);
    const [pending] = await db
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "disconnect_revoke"));
    expect(pending.state).toBe("revocation_pending");
    expect(JSON.stringify(pending)).not.toContain("refresh-initial");
    await db
      .update(providerGoogleCredentialLifecycles)
      .set({ updatedAt: new Date(Date.now() - 60_000) })
      .where(eq(providerGoogleCredentialLifecycles.id, pending.id));
    const result = await runGoogleCredentialLifecycleSweep({ vault, config: CONFIG });
    expect(result.revoked).toBe(1);
    expect(fake.counters.revoke).toBe(1);
    const [recovered] = await db
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.id, pending.id));
    expect(recovered.state).toBe("revoked");
    expect(recovered.credentialSecretId).toBeNull();
    fake.restore();
  });

  test("post-revoke crash stays locally revoked and retries without terminal rollback", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreHook = __setGoogleDisconnectRevokeHookForTests(() => {
      throw new Error("crash after upstream revoke");
    });
    await expect(
      disconnectGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toThrow("crash after upstream revoke");
    restoreHook();
    const db = getDb();
    const [account] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("revoked");
    expect(fake.counters.revoke).toBe(1);
    const [pending] = await db
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.kind, "disconnect_revoke"));
    await db
      .update(providerGoogleCredentialLifecycles)
      .set({ updatedAt: new Date(Date.now() - 60_000) })
      .where(eq(providerGoogleCredentialLifecycles.id, pending.id));
    const result = await runGoogleCredentialLifecycleSweep({ vault, config: CONFIG });
    expect(result.revoked).toBe(1);
    expect(fake.counters.revoke).toBe(2);
    const [terminal] = await db
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(eq(providerGoogleCredentialLifecycles.id, pending.id));
    expect(terminal.state).toBe("revoked");
    fake.restore();
  });

  test("reconnect cannot race a pending disconnect revoker", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreHook = __setGoogleDisconnectJournalHookForTests(() => {
      throw new Error("crash after disconnect journal");
    });
    await expect(
      disconnectGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toThrow("crash after disconnect journal");
    restoreHook();
    fake.restore();
    await expect(connectHappy(new MemoryConnectStore())).rejects.toMatchObject({
      code: "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
    });
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("revoked");
  });

  test("disconnect of a missing account => GOOGLE_ACCOUNT_NOT_FOUND", async () => {
    const fake = installFakeX();
    await expect(
      disconnectGoogleProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: "40000000-0000-4000-8000-0000000000ff",
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toMatchObject({ code: "GOOGLE_ACCOUNT_NOT_FOUND" });
    fake.restore();
  });
});

// ── Sanity: secret lineage name is deterministic per (workspace, x user) ──────
test("credential secret name is stable per workspace+Google user (reconnect lineage)", () => {
  expect(googleCredentialSecretName(WORKSPACE, "google-user-123")).toBe(
    `provider-google/${WORKSPACE}/google-user-123`,
  );
});

test("GoogleConnectError carries code + http status", () => {
  const e = new GoogleConnectError("GOOGLE_STATE_INVALID", 401);
  expect(e.code).toBe("GOOGLE_STATE_INVALID");
  expect(e.httpStatus).toBe(401);
});

test("provider connect uses OAuth credentials isolated from human login", () => {
  expect(
    resolveGoogleConnectConfig({
      GOOGLE_CLIENT_ID: "human-login-client",
      GOOGLE_CLIENT_SECRET: "human-login-secret",
      GOOGLE_PROVIDER_CLIENT_ID: "provider-client",
      GOOGLE_PROVIDER_CLIENT_SECRET: "provider-secret",
    }),
  ).toEqual({ clientId: "provider-client", clientSecret: "provider-secret" });
  expect(() =>
    resolveGoogleConnectConfig({
      GOOGLE_CLIENT_ID: "human-login-client",
      GOOGLE_CLIENT_SECRET: "human-login-secret",
    }),
  ).toThrow("GOOGLE_PROVIDER_CLIENT_ID and GOOGLE_PROVIDER_CLIENT_SECRET");
});

test("provider connect rejects process-local state in multi-instance runtimes", () => {
  expect(() => assertGoogleConnectStoreIsSafe("memory", { NODE_ENV: "production" })).toThrow(
    "Durable storage is required for Google provider-connect state",
  );
  expect(() => assertGoogleConnectStoreIsSafe("memory", { STEWARD_RUNTIME: "workers" })).toThrow();
  expect(() =>
    assertGoogleConnectStoreIsSafe("postgres", { NODE_ENV: "production" }),
  ).not.toThrow();
});

test("real Google transport rejects oversized provider responses before parsing", async () => {
  const originalFetch = globalThis.fetch;
  let requestInit: RequestInit | undefined;
  globalThis.fetch = (async (_input, init) => {
    requestInit = init;
    return new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "1048577" },
    });
  }) as typeof fetch;
  try {
    await expect(
      __runDefaultGoogleForwardForTests({
        url: "https://openidconnect.googleapis.com/v1/userinfo",
        method: "GET",
        headers: { accept: "application/json" },
      }),
    ).rejects.toThrow("Google provider response exceeded maximum size");
    expect(requestInit?.redirect).toBe("error");
    expect(requestInit?.signal).toBeInstanceOf(AbortSignal);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
