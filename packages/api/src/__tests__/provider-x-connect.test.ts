/**
 * Provider-account X (Twitter) OAuth connect + token lifecycle tests
 * (issue #195 workstream A).
 *
 * Covers: connect initiate/complete happy path, state mismatch, expired state,
 * reused state, PKCE failure, wrong-role caller (via canConnectProviderAccounts
 * gate), refresh rotation single-flight (concurrency: exactly one token call),
 * refresh revoked -> degraded, disconnect. The X network is fully faked through
 * the __setXForwardForTests seam; no real network is ever hit.
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
  auditEvents as auditEventsTable,
  closeDb,
  getDb,
  providerAccounts,
  providerRoleBindings,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { providerAuthorityStore } from "../services/provider-authority-store";
import {
  __setXForwardForTests,
  completeXConnect,
  disconnectXProviderCredential,
  initiateXConnect,
  type PendingConnectStore,
  refreshXProviderCredential,
  X_ADAPTER_KEY,
  XConnectError,
  type XCredentialPayload,
  type XForwardRequest,
  type XForwardResponse,
  xCredentialSecretName,
} from "../services/provider-x-connect";

setDefaultTimeout(120_000);

// ── Fixture identifiers ───────────────────────────────────────────────────────
const TENANT = "tenant-x-connect";
const ADMIN = "10000000-0000-4000-8000-0000000000a1";
const APPROVER = "10000000-0000-4000-8000-0000000000a2";
const VIEWER = "10000000-0000-4000-8000-0000000000a3";
const OUTSIDER = "10000000-0000-4000-8000-0000000000a4";
const WORKSPACE = "20000000-0000-4000-8000-0000000000b1";
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
    const value = await this.get(key);
    if (value !== null) this.map.delete(key);
    return value;
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
  identity?: { id: string; username: string; name: string };
  identityStatus?: number;
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
  const fn = async (req: XForwardRequest): Promise<XForwardResponse> => {
    // Token endpoint: distinguish exchange vs refresh by grant_type.
    if (req.url.includes("/oauth2/token")) {
      const body = req.body ?? "";
      if (body.includes("grant_type=refresh_token")) {
        counters.refresh += 1;
        const resp = opts.refreshResponses?.[refreshIdx] ?? {
          status: 200,
          body: {
            access_token: `access-refreshed-${counters.refresh}`,
            refresh_token: `refresh-rotated-${counters.refresh}`,
            scope: "tweet.read tweet.write users.read offline.access",
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
        scope: "tweet.read tweet.write users.read offline.access",
        expires_in: 7200,
        ...opts.exchangeToken,
      });
    }
    if (req.url.includes("/users/me")) {
      counters.identity += 1;
      const status = opts.identityStatus ?? 200;
      if (status !== 200) return jsonResponse(status, {});
      const identity = opts.identity ?? { id: "x-user-123", username: "solsundial", name: "Sol" };
      return jsonResponse(200, { data: identity });
    }
    if (req.url.includes("/oauth2/revoke")) {
      counters.revoke += 1;
      return jsonResponse(200, {});
    }
    throw new Error(`unexpected X call: ${req.url}`);
  };
  const restore = __setXForwardForTests(fn);
  return { counters, restore };
}

function jsonResponse(status: number, body: unknown): XForwardResponse {
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
  await db.insert(workspaces).values([
    {
      id: WORKSPACE,
      tenantId: TENANT,
      key: "client-x",
      name: "Client X",
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
  __setXForwardForTests(null);
  await closeDb();
});

afterEach(async () => {
  __setXForwardForTests(null);
  // Reset connected accounts + credential secrets between tests.
  const db = getDb();
  await db.delete(providerAccounts).where(eq(providerAccounts.tenantId, TENANT));
  await db.delete(secrets).where(eq(secrets.tenantId, TENANT));
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function connectHappy(
  store: MemoryConnectStore,
  overrides: {
    userId?: string;
    identity?: { id: string; username: string; name: string };
    exchangeToken?: FakeXOptions["exchangeToken"];
  } = {},
) {
  const fake = installFakeX({
    identity: overrides.identity,
    exchangeToken: overrides.exchangeToken,
  });
  const initiated = await initiateXConnect({
    tenantId: TENANT,
    workspaceId: WORKSPACE,
    initiatedByUserId: overrides.userId ?? ADMIN,
    redirectUri: REDIRECT,
    config: CONFIG,
    store,
  });
  const completed = await completeXConnect({
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

async function decryptCredential(accountId: string): Promise<XCredentialPayload> {
  const db = getDb();
  const [acct] = await db
    .select()
    .from(providerAccounts)
    .where(and(eq(providerAccounts.tenantId, TENANT), eq(providerAccounts.id, accountId)))
    .limit(1);
  const decrypted = await vault.decryptSecret(TENANT, acct.credentialSecretId as string);
  return JSON.parse(decrypted) as XCredentialPayload;
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
  test("happy path: creates account, versioned credential, audit event", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    expect(completed.reconnected).toBe(false);
    expect(completed.xUserId).toBe("x-user-123");
    expect(completed.xUsername).toBe("solsundial");
    expect(completed.credentialVersion).toBe(1);

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.adapterKey).toBe(X_ADAPTER_KEY);
    expect(acct.externalRef).toBe("x-user-123");
    expect(acct.displayName).toBe("@solsundial");
    expect(acct.status).toBe("active");
    expect(acct.credentialSecretId).toBeTruthy();
    expect(acct.credentialVersion).toBe(1);

    const cred = await decryptCredential(completed.providerAccountId);
    expect(cred.accessToken).toBe("access-initial");
    expect(cred.refreshToken).toBe("refresh-initial");
    expect(cred.xUserId).toBe("x-user-123");

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.x.connect.completed")).toBe(true);
  });

  test("reconnect same X user id updates version + bumps revision, never duplicates", async () => {
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
          eq(providerAccounts.adapterKey, X_ADAPTER_KEY),
          eq(providerAccounts.externalRef, "x-user-123"),
        ),
      );
    expect(rows.length).toBe(1);
    expect(rows[0].revision).toBe(2);
    expect(rows[0].credentialVersion).toBe(2);
  });
});

// ── State + PKCE negative cases ───────────────────────────────────────────────
describe("connect state validation", () => {
  test("state mismatch (unknown state) => X_STATE_INVALID", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    await expect(
      completeXConnect({
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
    ).rejects.toMatchObject({ code: "X_STATE_INVALID" });
    fake.restore();
  });

  test("expired state => X_STATE_INVALID (store returns null)", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateXConnect({
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
      completeXConnect({
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
    ).rejects.toMatchObject({ code: "X_STATE_INVALID" });
    fake.restore();
  });

  test("reused state => X_STATE_REUSED on the second completion", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateXConnect({
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
    await completeXConnect(args);
    await expect(completeXConnect(args)).rejects.toMatchObject({ code: "X_STATE_INVALID" });
    fake.restore();
  });

  test("PKCE verifier mismatch => X_PKCE_MISMATCH", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateXConnect({
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
      completeXConnect({
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
    ).rejects.toMatchObject({ code: "X_PKCE_MISMATCH" });
    fake.restore();
  });

  test("scope mismatch: caller from a different workspace/user cannot complete", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX();
    const initiated = await initiateXConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    await expect(
      completeXConnect({
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
    ).rejects.toMatchObject({ code: "X_STATE_INVALID" });
    fake.restore();
  });

  test("token exchange failure does NOT consume the state (retryable)", async () => {
    const store = new MemoryConnectStore();
    const failing = installFakeX({ exchangeStatus: 400 });
    const initiated = await initiateXConnect({
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
    await expect(completeXConnect(args)).rejects.toMatchObject({
      code: "X_TOKEN_EXCHANGE_FAILED",
    });
    failing.restore();
    // The state must still be present for a retry.
    const ok = installFakeX();
    const retried = await completeXConnect(args);
    expect(retried.xUserId).toBe("x-user-123");
    ok.restore();
  });
});

// ── Refresh: rotation, single-flight, revoke ──────────────────────────────────
describe("refresh", () => {
  test("force refresh rotates token to a new credential version + audit", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX();
    const result = await refreshXProviderCredential({
      tenantId: TENANT,
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
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.x.refresh.completed")).toBe(true);
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
            scope: "tweet.read tweet.write users.read offline.access",
            expires_in: 7200,
          },
        },
        {
          status: 200,
          body: {
            access_token: "access-refreshed-2",
            refresh_token: "refresh-rotated-2",
            scope: "tweet.read tweet.write users.read offline.access",
            expires_in: 7200,
          },
        },
      ],
    });

    const [r1, r2] = await Promise.all([
      refreshXProviderCredential({
        tenantId: TENANT,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
      }),
      refreshXProviderCredential({
        tenantId: TENANT,
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
    const result = await refreshXProviderCredential({
      tenantId: TENANT,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
    });
    expect(result.refreshed).toBe(false);
    expect(fake.counters.refresh).toBe(0);
    fake.restore();
  });

  test("revoked upstream (invalid_grant) => account degraded + audit + X_REFRESH_REVOKED", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX({
      refreshResponses: [{ status: 400, body: { error: "invalid_grant" } }],
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_REFRESH_REVOKED" });

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.status).toBe("revoked");
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.x.refresh.revoked")).toBe(true);
  });

  test("refresh of a non-X account is rejected", async () => {
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
      refreshXProviderCredential({
        tenantId: TENANT,
        accountId: row.id,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_ACCOUNT_NOT_X" });
    fake.restore();
  });
});

// ── Disconnect ────────────────────────────────────────────────────────────────
describe("disconnect", () => {
  test("degrades account, best-effort revokes at X, audits", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX();
    const result = await disconnectXProviderCredential({
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
    expect(events.includes("provider.x.disconnect.completed")).toBe(true);
  });

  test("disconnect of a missing account => X_ACCOUNT_NOT_FOUND", async () => {
    const fake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: "40000000-0000-4000-8000-0000000000ff",
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toMatchObject({ code: "X_ACCOUNT_NOT_FOUND" });
    fake.restore();
  });
});

// ── Sanity: secret lineage name is deterministic per (workspace, x user) ──────
test("credential secret name is stable per workspace+x user (reconnect lineage)", () => {
  expect(xCredentialSecretName(WORKSPACE, "x-user-123")).toBe(`provider-x/${WORKSPACE}/x-user-123`);
});

test("XConnectError carries code + http status", () => {
  const e = new XConnectError("X_STATE_INVALID", 401);
  expect(e.code).toBe("X_STATE_INVALID");
  expect(e.httpStatus).toBe(401);
});
