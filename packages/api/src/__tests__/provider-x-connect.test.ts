/**
 * Provider-account X (Twitter) OAuth connect and token lifecycle tests.
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
  providerXCredentialLifecycles,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
  writeAuditEvent,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { and, eq, inArray, sql } from "drizzle-orm";
import { providerAuthorityStore } from "../services/provider-authority-store";
import {
  __runDefaultXForwardForTests,
  __setAfterXCredentialStageForTests,
  __setAfterXDisconnectJournalForTests,
  __setAfterXRefreshIntentForTests,
  __setAfterXRevocationClaimForTests,
  __setXForwardForTests,
  completeXConnect,
  disconnectXProviderCredential,
  initiateXConnect,
  type PendingConnectStore,
  refreshXProviderCredential,
  runXCredentialLifecycleSweep,
  X_ADAPTER_KEY,
  X_DEFAULT_SCOPES,
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
const WORKSPACE_OTHER = "20000000-0000-4000-8000-0000000000b2";
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
    token_type: string;
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
  revokeStatuses?: number[];
}

interface FakeXCounters {
  exchange: number;
  identity: number;
  refresh: number;
  revoke: number;
  revokeBodies: string[];
}

function installFakeX(opts: FakeXOptions = {}): {
  counters: FakeXCounters;
  restore: () => void;
} {
  const counters: FakeXCounters = {
    exchange: 0,
    identity: 0,
    refresh: 0,
    revoke: 0,
    revokeBodies: [],
  };
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
      const identity = opts.identity ?? { id: "1234567890", username: "solsundial", name: "Sol" };
      return jsonResponse(200, { data: identity });
    }
    if (req.url.includes("/oauth2/revoke")) {
      counters.revoke += 1;
      counters.revokeBodies.push(req.body ?? "");
      const status = opts.revokeStatuses?.[counters.revoke - 1] ?? 200;
      return jsonResponse(status, status === 200 ? {} : { error: "temporarily_unavailable" });
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
  __setXForwardForTests(null);
  await closeDb();
});

afterEach(async () => {
  __setXForwardForTests(null);
  __setAfterXCredentialStageForTests(null);
  __setAfterXDisconnectJournalForTests(null);
  __setAfterXRefreshIntentForTests(null);
  __setAfterXRevocationClaimForTests(null);
  // Reset connected accounts + credential secrets between tests.
  const db = getDb();
  await db
    .delete(providerXCredentialLifecycles)
    .where(eq(providerXCredentialLifecycles.tenantId, TENANT));
  await db.delete(providerAccounts).where(eq(providerAccounts.tenantId, TENANT));
  await db.delete(secretRoutes).where(eq(secretRoutes.tenantId, TENANT));
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
    expect(completed.xUserId).toBe("1234567890");
    expect(completed.xUsername).toBe("solsundial");
    expect(completed.credentialVersion).toBe(1);

    const db = getDb();
    const [acct] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(acct.adapterKey).toBe(X_ADAPTER_KEY);
    expect(acct.externalRef).toBe("1234567890");
    expect(acct.displayName).toBe("@solsundial");
    expect(acct.status).toBe("active");
    expect(acct.credentialSecretId).toBeTruthy();
    expect(acct.credentialVersion).toBe(1);

    const cred = await decryptCredential(completed.providerAccountId);
    expect(cred.accessToken).toBe("access-initial");
    expect(cred.refreshToken).toBe("refresh-initial");
    expect(cred.xUserId).toBe("1234567890");

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
          eq(providerAccounts.externalRef, "1234567890"),
        ),
      );
    expect(rows.length).toBe(1);
    expect(rows[0].revision).toBe(2);
    expect(rows[0].credentialVersion).toBe(2);
  });

  test("a fresh connect can re-enable an account disabled before its intent", async () => {
    const first = await connectHappy(new MemoryConnectStore());
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, first.completed.providerAccountId));
    await providerAuthorityStore.disableProviderAccount(
      {
        tenantId: TENANT,
        actorUserId: ADMIN,
        tenantRole: "admin",
        mfaVerifiedAt: Date.now(),
        idempotencyKey: `disable-before-connect-${crypto.randomUUID()}`,
        expectedRevision: account.revision,
        reason: "test valid reconnect after generic disable",
        audit: async (event) => {
          await writeAuditEvent({
            tenantId: TENANT,
            actorType: "user",
            actorId: ADMIN,
            action: event.action,
            resourceType: event.resourceType,
            resourceId: event.resourceId,
            metadata: event.metadata,
          });
        },
      },
      account.id,
    );

    const second = await connectHappy(new MemoryConnectStore(), {
      exchangeToken: {
        access_token: "access-after-generic-disable",
        refresh_token: "refresh-after-generic-disable",
      },
    });
    expect(second.completed).toMatchObject({
      providerAccountId: account.id,
      credentialVersion: 2,
      reconnected: true,
    });
    const [reconnected] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, account.id));
    expect(reconnected).toMatchObject({ status: "active", revision: account.revision + 2 });
    expect(await decryptCredential(account.id)).toMatchObject({
      accessToken: "access-after-generic-disable",
      refreshToken: "refresh-after-generic-disable",
    });
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

  test("claims state before token exchange so a failed callback cannot be replayed", async () => {
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
    expect(failing.counters.exchange).toBe(1);
    failing.restore();
    // Security-fail-closed: retrying requires a fresh connect attempt. Keeping
    // the state live would let two replicas exchange one code and orphan the
    // losing callback's newly issued grant.
    const ok = installFakeX();
    await expect(completeXConnect(args)).rejects.toMatchObject({ code: "X_STATE_INVALID" });
    expect(ok.counters.exchange).toBe(0);
    ok.restore();
  });

  test("rejects malformed or oversized connect tokens before decoding", async () => {
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
    for (const connectToken of ["A".repeat(1025), `${initiated.connectToken}=`, "***"]) {
      await expect(
        completeXConnect({
          tenantId: TENANT,
          workspaceId: WORKSPACE,
          callerUserId: ADMIN,
          code: "auth-code",
          state: initiated.state,
          connectToken,
          redirectUri: REDIRECT,
          config: CONFIG,
          store,
          vault,
        }),
      ).rejects.toMatchObject({ code: "X_PKCE_MISMATCH" });
    }
    expect(fake.counters.exchange).toBe(0);
    fake.restore();
  });

  test("rejects malformed provider identities before persistence", async () => {
    for (const identity of [
      { id: "not-numeric", username: "valid_name", name: "Name" },
      { id: "1".repeat(33), username: "valid_name", name: "Name" },
      { id: "123", username: "bad-name", name: "Name" },
      { id: "123", username: "valid_name", name: "Name\nInjected" },
    ]) {
      const store = new MemoryConnectStore();
      const fake = installFakeX({ identity });
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
          callerUserId: ADMIN,
          code: "auth-code",
          state: initiated.state,
          connectToken: initiated.connectToken,
          redirectUri: REDIRECT,
          config: CONFIG,
          store,
          vault,
        }),
      ).rejects.toMatchObject({ code: "X_IDENTITY_FAILED" });
      expect(fake.counters.identity).toBe(1);
      expect(fake.counters.revoke).toBe(1);
      fake.restore();
    }
  });

  test("revokes the new grant when reconnect persistence fails", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    await getDb().insert(providerXCredentialLifecycles).values({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      providerAccountId: completed.providerAccountId,
      state: "inflight",
      expectedAccountRevision: 1,
    });

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
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "X_CREDENTIAL_NEEDS_ATTENTION" });
    expect(fake.counters).toMatchObject({ exchange: 1, identity: 1, revoke: 1 });
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.credentialVersion).toBe(1);
    fake.restore();
  });

  test("rejects malformed token endpoint credentials before identity fetch or persistence", async () => {
    for (const exchangeToken of [
      { access_token: "" },
      { access_token: "access\ncontrol" },
      { access_token: "x".repeat(16_385) },
      { refresh_token: "" },
      { refresh_token: "refresh\rcontrol" },
      { refresh_token: "r".repeat(16_385) },
      { token_type: "mac" },
      { expires_in: Number.NaN },
      { scope: "tweet.read admin.write" },
    ]) {
      const store = new MemoryConnectStore();
      const fake = installFakeX({ exchangeToken });
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
          callerUserId: ADMIN,
          code: "auth-code",
          state: initiated.state,
          connectToken: initiated.connectToken,
          redirectUri: REDIRECT,
          config: CONFIG,
          store,
          vault,
        }),
      ).rejects.toMatchObject({ code: "X_TOKEN_EXCHANGE_FAILED" });
      expect(fake.counters.identity).toBe(0);
      expect(fake.counters.revoke).toBe(1);
      fake.restore();
    }
  });
});

describe("connect exchange recovery", () => {
  test("a crash after encrypted staging is adopted by the sweep without another code exchange", async () => {
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
    __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated process crash after connect staging");
    });
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
    ).rejects.toThrow("simulated process crash");
    __setAfterXCredentialStageForTests(null);

    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, adopted: 1, attention: 0 });
    expect(fake.counters).toMatchObject({ exchange: 1, identity: 1 });
    const [lifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "connect_exchange"));
    expect(lifecycle.state).toBe("adopted");
    expect(lifecycle.credentialSecretId).toBeNull();
    fake.restore();
  });

  test("a stale staged connect grant is revoked instead of overwriting a newer reconnect", async () => {
    const firstStore = new MemoryConnectStore();
    const firstFake = installFakeX({
      exchangeToken: {
        access_token: "access-stale-first",
        refresh_token: "refresh-stale-first",
      },
    });
    const initiated = await initiateXConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store: firstStore,
    });
    __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated process crash after first connect staging");
    });
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
        store: firstStore,
        vault,
      }),
    ).rejects.toThrow("simulated process crash after first connect staging");
    __setAfterXCredentialStageForTests(null);
    firstFake.restore();

    const newer = await connectHappy(new MemoryConnectStore(), {
      exchangeToken: {
        access_token: "access-current-second",
        refresh_token: "refresh-current-second",
      },
    });
    const newerAccountId = newer.completed.providerAccountId;
    const beforeSweep = await decryptCredential(newerAccountId);
    expect(beforeSweep.accessToken).toBe("access-current-second");

    // The guard must be database-lineage based, not a comparison against an
    // application-supplied account timestamp that can move backwards under
    // replica clock skew.
    await getDb()
      .update(providerAccounts)
      .set({ updatedAt: new Date(0) })
      .where(eq(providerAccounts.id, newerAccountId));

    const [staleLifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "credential_staged"),
        ),
      );
    expect(staleLifecycle.providerAccountId).toBeNull();

    const [newerLifecycle] = await getDb()
      .select({ createdAt: providerXCredentialLifecycles.createdAt })
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, newerAccountId),
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "adopted"),
        ),
      );
    if (!newerLifecycle) throw new Error("newer adopted connect lifecycle missing");
    // A timestamp-only lineage check cannot distinguish this valid ordering.
    // The audit sequence must remain authoritative even when timestamps tie.
    await getDb()
      .update(providerXCredentialLifecycles)
      .set({ createdAt: newerLifecycle.createdAt })
      .where(eq(providerXCredentialLifecycles.id, staleLifecycle.id));

    const recovery = installFakeX({ revokeStatuses: [200] });
    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, adopted: 0, attention: 0 });
    expect(recovery.counters).toMatchObject({ exchange: 0, identity: 1, revoke: 1 });

    const afterSweep = await decryptCredential(newerAccountId);
    expect(afterSweep.accessToken).toBe("access-current-second");
    expect(afterSweep.refreshToken).toBe("refresh-current-second");

    const [revokedLifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, staleLifecycle.id));
    expect(revokedLifecycle.state).toBe("revoked");
    expect(revokedLifecycle.credentialSecretId).toBeNull();
    recovery.restore();
  });

  test("a staged connect cannot overwrite a newer generic X account without an X adoption anchor", async () => {
    const store = new MemoryConnectStore();
    const stagedFake = installFakeX({
      exchangeToken: {
        access_token: "access-staged-before-generic",
        refresh_token: "refresh-staged-before-generic",
      },
    });
    const initiated = await initiateXConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store,
    });
    __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated crash before generic account creation");
    });
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
    ).rejects.toThrow("simulated crash before generic account creation");
    __setAfterXCredentialStageForTests(null);
    stagedFake.restore();

    const currentPayload: XCredentialPayload = {
      schemaVersion: "steward.provider-x.credential.v1",
      accessToken: "access-current-generic",
      refreshToken: "refresh-current-generic",
      scopesGranted: [...X_DEFAULT_SCOPES],
      xUserId: "1234567890",
      xUsername: "steward_test",
      obtainedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7_200_000).toISOString(),
    };
    const currentSecret = await vault.createSecret(
      TENANT,
      "provider-x/generic-current-account",
      JSON.stringify(currentPayload),
    );
    const [workspace] = await getDb()
      .select({ revision: workspaces.revision })
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, TENANT), eq(workspaces.id, WORKSPACE)))
      .limit(1);
    const genericAccount = await providerAuthorityStore.createProviderAccount(
      {
        tenantId: TENANT,
        actorUserId: ADMIN,
        tenantRole: "admin",
        mfaVerifiedAt: Date.now(),
        idempotencyKey: `generic-x-${crypto.randomUUID()}`,
        expectedRevision: workspace.revision,
        reason: "test generic X account interleaving",
        audit: async (event) => {
          await writeAuditEvent({
            tenantId: TENANT,
            actorType: "user",
            actorId: ADMIN,
            action: event.action,
            resourceType: event.resourceType,
            resourceId: event.resourceId,
            metadata: event.metadata,
          });
        },
      },
      {
        workspaceId: WORKSPACE,
        adapterKey: X_ADAPTER_KEY,
        externalRef: currentPayload.xUserId,
        displayName: `@${currentPayload.xUsername}`,
        credentialSecretId: currentSecret.id,
        credentialVersion: currentSecret.version,
      },
    );
    expect((await readAuditActions(TENANT)).includes("provider.account.create")).toBe(true);

    const recovery = installFakeX({ revokeStatuses: [200] });
    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, adopted: 0, attention: 0 });
    expect(recovery.counters).toMatchObject({ exchange: 0, identity: 1, revoke: 1 });

    const [accountAfter] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, genericAccount.id));
    expect(accountAfter).toMatchObject({
      credentialSecretId: currentSecret.id,
      credentialVersion: currentSecret.version,
      revision: genericAccount.revision,
      status: "active",
    });
    expect(await decryptCredential(genericAccount.id)).toEqual(currentPayload);
    const [stagedLifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "connect_exchange"));
    expect(stagedLifecycle).toMatchObject({ state: "revoked", credentialSecretId: null });
    recovery.restore();
  });

  test("a staged connect cannot overwrite a credential rotated by a later refresh", async () => {
    const initial = await connectHappy(new MemoryConnectStore(), {
      exchangeToken: {
        access_token: "access-before-staged-connect",
        refresh_token: "refresh-before-staged-connect",
      },
    });
    const accountId = initial.completed.providerAccountId;

    const staleStore = new MemoryConnectStore();
    const stagedFake = installFakeX({
      exchangeToken: {
        access_token: "access-staged-before-refresh",
        refresh_token: "refresh-staged-before-refresh",
      },
    });
    const initiated = await initiateXConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store: staleStore,
    });
    __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated crash before the newer refresh");
    });
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
        store: staleStore,
        vault,
      }),
    ).rejects.toThrow("simulated crash before the newer refresh");
    __setAfterXCredentialStageForTests(null);
    stagedFake.restore();

    const refreshFake = installFakeX({
      refreshResponses: [
        {
          status: 200,
          body: {
            access_token: "access-current-after-refresh",
            refresh_token: "refresh-current-after-refresh",
            scope: "tweet.read tweet.write users.read offline.access",
            expires_in: 7200,
          },
        },
      ],
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        vault,
        config: CONFIG,
        actorId: ADMIN,
        force: true,
      }),
    ).resolves.toMatchObject({ refreshed: true, credentialVersion: 2 });
    expect(refreshFake.counters.refresh).toBe(1);
    refreshFake.restore();

    const [accountBeforeRecovery] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    const credentialBeforeRecovery = await decryptCredential(accountId);
    expect(credentialBeforeRecovery).toMatchObject({
      accessToken: "access-current-after-refresh",
      refreshToken: "refresh-current-after-refresh",
    });

    const recovery = installFakeX({ revokeStatuses: [200] });
    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, adopted: 0, attention: 0 });
    expect(recovery.counters).toMatchObject({ exchange: 0, identity: 1, refresh: 0, revoke: 1 });

    const [accountAfterRecovery] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(accountAfterRecovery).toMatchObject({
      credentialSecretId: accountBeforeRecovery.credentialSecretId,
      credentialVersion: accountBeforeRecovery.credentialVersion,
      revision: accountBeforeRecovery.revision,
      status: accountBeforeRecovery.status,
    });
    expect(await decryptCredential(accountId)).toEqual(credentialBeforeRecovery);
    const [stagedLifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "revoked"),
        ),
      );
    expect(stagedLifecycle).toMatchObject({ providerAccountId: null, credentialSecretId: null });
    recovery.restore();
  });

  test("a staged connect cannot resurrect an account disconnected later", async () => {
    const initial = await connectHappy(new MemoryConnectStore());
    const accountId = initial.completed.providerAccountId;
    const [connectedAccount] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    const routeId = crypto.randomUUID();
    await getDb()
      .insert(secretRoutes)
      .values({
        id: routeId,
        tenantId: TENANT,
        secretId: connectedAccount.credentialSecretId as string,
        hostPattern: "api.x.com",
        pathPattern: "/2/tweets",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      });

    const staleStore = new MemoryConnectStore();
    const stagedFake = installFakeX({
      exchangeToken: {
        access_token: "access-staged-before-disconnect",
        refresh_token: "refresh-staged-before-disconnect",
      },
    });
    const initiated = await initiateXConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store: staleStore,
    });
    __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated crash before the newer disconnect");
    });
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
        store: staleStore,
        vault,
      }),
    ).rejects.toThrow("simulated crash before the newer disconnect");
    __setAfterXCredentialStageForTests(null);
    stagedFake.restore();

    const disconnectFake = installFakeX({ revokeStatuses: [200] });
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).resolves.toMatchObject({ providerAccountId: accountId, revoked: true });
    expect(disconnectFake.counters.revoke).toBe(1);
    disconnectFake.restore();

    const [accountBeforeRecovery] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(accountBeforeRecovery).toMatchObject({
      credentialSecretId: null,
      credentialVersion: null,
      status: "revoked",
    });
    const [secretBeforeRecovery] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, connectedAccount.credentialSecretId as string));
    const [routeBeforeRecovery] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(secretBeforeRecovery.deletedAt).not.toBeNull();
    expect(routeBeforeRecovery).toMatchObject({
      enabled: false,
      secretId: connectedAccount.credentialSecretId,
    });

    const recovery = installFakeX({ revokeStatuses: [200] });
    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, adopted: 0, attention: 0 });
    expect(recovery.counters).toMatchObject({ exchange: 0, identity: 1, refresh: 0, revoke: 1 });

    const [accountAfterRecovery] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(accountAfterRecovery).toMatchObject({
      credentialSecretId: accountBeforeRecovery.credentialSecretId,
      credentialVersion: accountBeforeRecovery.credentialVersion,
      revision: accountBeforeRecovery.revision,
      status: accountBeforeRecovery.status,
    });
    const [secretAfterRecovery] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, connectedAccount.credentialSecretId as string));
    const [routeAfterRecovery] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(secretAfterRecovery).toEqual(secretBeforeRecovery);
    expect(routeAfterRecovery).toEqual(routeBeforeRecovery);
    const liveCredentialLineage = await getDb()
      .select({ id: secrets.id })
      .from(secrets)
      .where(
        and(
          eq(secrets.tenantId, TENANT),
          eq(secrets.name, xCredentialSecretName(WORKSPACE, "1234567890")),
          sql`${secrets.deletedAt} IS NULL`,
        ),
      );
    expect(liveCredentialLineage).toEqual([]);
    const [stagedLifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "revoked"),
        ),
      );
    expect(stagedLifecycle).toMatchObject({ providerAccountId: null, credentialSecretId: null });
    recovery.restore();
  });

  test("a staged connect cannot re-enable an account disabled by the generic authority path", async () => {
    const initial = await connectHappy(new MemoryConnectStore());
    const accountId = initial.completed.providerAccountId;
    const [connectedAccount] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    const routeId = crypto.randomUUID();
    await getDb()
      .insert(secretRoutes)
      .values({
        id: routeId,
        tenantId: TENANT,
        secretId: connectedAccount.credentialSecretId as string,
        hostPattern: "api.x.com",
        pathPattern: "/2/tweets",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      });

    const staleStore = new MemoryConnectStore();
    const stagedFake = installFakeX({
      exchangeToken: {
        access_token: "access-staged-before-disable",
        refresh_token: "refresh-staged-before-disable",
      },
    });
    const initiated = await initiateXConnect({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      initiatedByUserId: ADMIN,
      redirectUri: REDIRECT,
      config: CONFIG,
      store: staleStore,
    });
    __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated crash before the generic disable");
    });
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
        store: staleStore,
        vault,
      }),
    ).rejects.toThrow("simulated crash before the generic disable");
    __setAfterXCredentialStageForTests(null);
    stagedFake.restore();

    const [accountBeforeDisable] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    await providerAuthorityStore.disableProviderAccount(
      {
        tenantId: TENANT,
        actorUserId: ADMIN,
        tenantRole: "admin",
        mfaVerifiedAt: Date.now(),
        idempotencyKey: `disable-x-${crypto.randomUUID()}`,
        expectedRevision: accountBeforeDisable.revision,
        reason: "test staged connect and generic disable interleaving",
        audit: async (event) => {
          await writeAuditEvent({
            tenantId: TENANT,
            actorType: "user",
            actorId: ADMIN,
            action: event.action,
            resourceType: event.resourceType,
            resourceId: event.resourceId,
            metadata: event.metadata,
          });
        },
      },
      accountId,
    );

    const [accountBeforeRecovery] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    const credentialBeforeRecovery = await decryptCredential(accountId);
    const [secretBeforeRecovery] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, connectedAccount.credentialSecretId as string));
    const [routeBeforeRecovery] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(accountBeforeRecovery).toMatchObject({
      credentialSecretId: accountBeforeDisable.credentialSecretId,
      credentialVersion: accountBeforeDisable.credentialVersion,
      revision: accountBeforeDisable.revision + 1,
      status: "disabled",
    });

    const recovery = installFakeX({ revokeStatuses: [200] });
    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, adopted: 0, attention: 0 });
    expect(recovery.counters).toMatchObject({ exchange: 0, identity: 1, refresh: 0, revoke: 1 });

    const [accountAfterRecovery] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, accountId));
    expect(accountAfterRecovery).toMatchObject({
      credentialSecretId: accountBeforeRecovery.credentialSecretId,
      credentialVersion: accountBeforeRecovery.credentialVersion,
      revision: accountBeforeRecovery.revision,
      status: accountBeforeRecovery.status,
    });
    expect(await decryptCredential(accountId)).toEqual(credentialBeforeRecovery);
    const [secretAfterRecovery] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, connectedAccount.credentialSecretId as string));
    const [routeAfterRecovery] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, routeId));
    expect(secretAfterRecovery).toEqual(secretBeforeRecovery);
    expect(routeAfterRecovery).toEqual(routeBeforeRecovery);
    const [stagedLifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "revoked"),
        ),
      );
    expect(stagedLifecycle).toMatchObject({ providerAccountId: null, credentialSecretId: null });
    recovery.restore();
  });

  test("failed identity revocation is durably retried with backoff and a hard ceiling", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX({ identityStatus: 503, revokeStatuses: [503, 503, 503, 503, 503] });
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
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "X_IDENTITY_FAILED" });

    let [row] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "connect_exchange"));
    const handleId = row.credentialSecretId;
    expect(row).toMatchObject({ state: "revocation_pending", attempts: 1 });
    for (let expectedAttempts = 2; expectedAttempts <= 5; expectedAttempts += 1) {
      const retryAt = row.nextRetryAt as Date;
      const sweepAt = new Date(retryAt.getTime() + 1_000);
      await runXCredentialLifecycleSweep({ vault, config: CONFIG, now: sweepAt });
      [row] = await getDb()
        .select()
        .from(providerXCredentialLifecycles)
        .where(eq(providerXCredentialLifecycles.id, row.id));
      expect(row.attempts).toBe(expectedAttempts);
      if (expectedAttempts < 5) {
        expect((row.nextRetryAt as Date).getTime() - sweepAt.getTime()).toBe(
          60_000 * 2 ** (expectedAttempts - 1),
        );
      }
    }
    expect(row.state).toBe("needs_attention");
    expect(row.nextRetryAt).toBeNull();
    expect(row.credentialSecretId).toBe(handleId);
    expect(fake.counters).toMatchObject({ exchange: 1, identity: 1, revoke: 5 });
    const afterCeiling = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 24 * 60 * 60_000),
    });
    expect(afterCeiling.processed).toBe(0);
    fake.restore();
  });

  test("a crashed revocation claimant is reclaimed only after its durable lease", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX({ identityStatus: 503, revokeStatuses: [503, 200] });
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
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "X_IDENTITY_FAILED" });
    let [row] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "connect_exchange"));
    const firstRetry = row.nextRetryAt as Date;
    __setAfterXRevocationClaimForTests(async () => {
      throw new Error("simulated crash after claim");
    });
    await expect(
      runXCredentialLifecycleSweep({
        vault,
        config: CONFIG,
        now: new Date(firstRetry.getTime() + 1_000),
      }),
    ).resolves.toMatchObject({ processed: 1, attention: 1 });
    __setAfterXRevocationClaimForTests(null);
    [row] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, row.id));
    expect(row.attempts).toBe(2);
    expect(fake.counters.revoke).toBe(1);
    expect(
      (
        await runXCredentialLifecycleSweep({
          vault,
          config: CONFIG,
          now: new Date((row.nextRetryAt as Date).getTime() - 1),
        })
      ).processed,
    ).toBe(0);
    await runXCredentialLifecycleSweep({ vault, config: CONFIG, now: row.nextRetryAt as Date });
    [row] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, row.id));
    expect(row.state).toBe("revoked");
    expect(fake.counters.revoke).toBe(2);
    fake.restore();
  });

  test("an expired fifth crash lease terminalizes with its encrypted handle retained", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX({ identityStatus: 503, revokeStatuses: Array(20).fill(503) });
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
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "X_IDENTITY_FAILED" });
    let [row] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "connect_exchange"));
    const handleId = row.credentialSecretId;
    __setAfterXRevocationClaimForTests(async () => {
      throw new Error("simulated repeated crash after claim");
    });
    for (let attempts = 2; attempts <= 5; attempts += 1) {
      await runXCredentialLifecycleSweep({
        vault,
        config: CONFIG,
        now: new Date((row.nextRetryAt as Date).getTime() + 1_000),
      });
      [row] = await getDb()
        .select()
        .from(providerXCredentialLifecycles)
        .where(eq(providerXCredentialLifecycles.id, row.id));
      expect(row).toMatchObject({ state: "revocation_pending", attempts });
    }
    __setAfterXRevocationClaimForTests(null);
    await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date((row.nextRetryAt as Date).getTime() + 1_000),
    });
    [row] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, row.id));
    expect(row).toMatchObject({
      state: "needs_attention",
      attempts: 5,
      nextRetryAt: null,
      credentialSecretId: handleId,
    });
    fake.restore();
  });

  test("scope-widened responses revoke the exact bounded refresh handle", async () => {
    const store = new MemoryConnectStore();
    const fake = installFakeX({
      exchangeToken: {
        access_token: "access-valid",
        refresh_token: "exact-refresh-handle",
        scope: "tweet.read admin.write",
      },
    });
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
        callerUserId: ADMIN,
        code: "auth-code",
        state: initiated.state,
        connectToken: initiated.connectToken,
        redirectUri: REDIRECT,
        config: CONFIG,
        store,
        vault,
      }),
    ).rejects.toMatchObject({ code: "X_TOKEN_EXCHANGE_FAILED" });
    expect(fake.counters.revoke).toBe(1);
    expect(new URLSearchParams(fake.counters.revokeBodies[0]).get("token")).toBe(
      "exact-refresh-handle",
    );
    fake.restore();
  });
});

// ── Refresh: rotation, single-flight, revoke ──────────────────────────────────
describe("refresh", () => {
  test("rejects a credential secret whose X identity does not match the account", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const current = await decryptCredential(completed.providerAccountId);
    const wrong = await vault.createSecret(
      TENANT,
      "provider-x/wrong-account-binding",
      JSON.stringify({ ...current, xUserId: "999999999" }),
    );
    await getDb()
      .update(providerAccounts)
      .set({ credentialSecretId: wrong.id, credentialVersion: wrong.version })
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const fake = installFakeX();
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toThrow("credential account binding mismatch");
    expect(fake.counters.refresh).toBe(0);
    fake.restore();
  });

  test("database constraints reject invalid lifecycle revision and secret-state shapes", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const base = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      providerAccountId: completed.providerAccountId,
    };
    await expect(
      Promise.resolve(
        getDb()
          .insert(providerXCredentialLifecycles)
          .values({
            ...base,
            state: "inflight",
            expectedAccountRevision: 0,
          })
          .returning(),
      ),
    ).rejects.toThrow();
    await expect(
      Promise.resolve(
        getDb()
          .insert(providerXCredentialLifecycles)
          .values({
            ...base,
            state: "credential_staged",
            expectedAccountRevision: 1,
            credentialSecretId: null,
          })
          .returning(),
      ),
    ).rejects.toThrow();
    await expect(
      Promise.resolve(
        getDb()
          .insert(providerXCredentialLifecycles)
          .values({
            ...base,
            kind: "unknown" as "refresh_rotation",
            state: "inflight",
            expectedAccountRevision: 1,
          })
          .returning(),
      ),
    ).rejects.toThrow();
    await expect(
      Promise.resolve(
        getDb()
          .insert(providerXCredentialLifecycles)
          .values({
            ...base,
            state: "inflight",
            expectedAccountRevision: 1,
            attempts: 6,
          })
          .returning(),
      ),
    ).rejects.toThrow();
  });

  test("force refresh rotates token to a new credential version + audit", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX();
    const result = await refreshXProviderCredential({
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
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.x.refresh.completed")).toBe(true);
  });

  test("malformed rotating responses disable the account, retain an encrypted handle, and never replay", async () => {
    for (const body of [
      { access_token: "bad token", refresh_token: "refresh-valid" },
      { access_token: "access-valid", refresh_token: "r".repeat(16_385) },
      {
        access_token: "access-valid",
        refresh_token: "refresh-valid",
        scope: "tweet.read offline.access admin.write",
      },
      {
        access_token: "access-valid",
        refresh_token: "refresh-valid",
        expires_in: "7200",
      },
      {
        access_token: "access-valid",
        refresh_token: "refresh-valid",
        token_type: "mac",
      },
    ]) {
      const store = new MemoryConnectStore();
      const { completed } = await connectHappy(store);
      const fake = installFakeX({ refreshResponses: [{ status: 200, body }] });
      await expect(
        refreshXProviderCredential({
          tenantId: TENANT,
          workspaceId: WORKSPACE,
          accountId: completed.providerAccountId,
          vault,
          config: CONFIG,
          force: true,
        }),
      ).rejects.toMatchObject({ code: "X_REFRESH_FAILED" });
      expect(fake.counters.refresh).toBe(1);
      const db = getDb();
      const [account] = await db
        .select()
        .from(providerAccounts)
        .where(eq(providerAccounts.id, completed.providerAccountId));
      expect(account.status).toBe("disabled");
      const [lifecycle] = await db
        .select()
        .from(providerXCredentialLifecycles)
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, TENANT),
            eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
            eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
          ),
        );
      expect(lifecycle.state).toBe("revocation_pending");
      expect(lifecycle.credentialSecretId).toBeTruthy();
      expect(JSON.stringify(lifecycle)).not.toContain("refresh-valid");
      expect(await vault.decryptSecret(TENANT, lifecycle.credentialSecretId as string)).toContain(
        '"schemaVersion":"steward.provider-x.lifecycle.v1"',
      );
      await expect(
        refreshXProviderCredential({
          tenantId: TENANT,
          workspaceId: WORKSPACE,
          accountId: completed.providerAccountId,
          vault,
          config: CONFIG,
          force: true,
        }),
      ).rejects.toMatchObject({ code: "X_REFRESH_REVOKED" });
      expect(fake.counters.refresh).toBe(1);
      fake.restore();
      await db.delete(providerAccounts).where(eq(providerAccounts.tenantId, TENANT));
      await db.delete(secrets).where(eq(secrets.tenantId, TENANT));
    }
  });

  test("reconnect preserves a staged credential until autonomous exact-token revocation", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const invalid = installFakeX({
      refreshResponses: [
        {
          status: 200,
          body: {
            access_token: "bad token",
            refresh_token: "rotated-one-time-refresh",
            scope: "tweet.read tweet.write users.read offline.access",
            expires_in: 7200,
          },
        },
      ],
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_REFRESH_FAILED" });
    expect(invalid.counters.refresh).toBe(1);

    const db = getDb();
    const [pending] = await db
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(pending.state).toBe("revocation_pending");
    const stagedSecretId = pending.credentialSecretId as string;
    const [accountBefore] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));

    const reconnectStore = new MemoryConnectStore();
    await expect(connectHappy(reconnectStore)).rejects.toMatchObject({
      code: "X_CREDENTIAL_NEEDS_ATTENTION",
    });
    const [preserved] = await db
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(preserved.state).toBe("revocation_pending");
    expect(preserved.credentialSecretId).toBe(stagedSecretId);
    const [retainedHandle] = await db
      .select({ id: secrets.id })
      .from(secrets)
      .where(eq(secrets.id, stagedSecretId));
    expect(retainedHandle.id).toBe(stagedSecretId);
    const [accountAfter] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(accountAfter.credentialSecretId).toBe(accountBefore.credentialSecretId);
    expect(accountAfter.credentialVersion).toBe(accountBefore.credentialVersion);
    expect(accountAfter.revision).toBe(accountBefore.revision);
    expect(invalid.counters.refresh).toBe(1);
    invalid.restore();
    const revoker = installFakeX();

    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, attention: 0 });
    expect(revoker.counters.revoke).toBe(1);
    expect(invalid.counters.refresh).toBe(1);
    const [revoked] = await db
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(revoked.state).toBe("revoked");
    expect(revoked.credentialSecretId).toBeNull();
    const [deletedHandle] = await db
      .select({ id: secrets.id })
      .from(secrets)
      .where(eq(secrets.id, stagedSecretId));
    expect(deletedHandle).toBeUndefined();
    revoker.restore();

    const reconnected = await connectHappy(new MemoryConnectStore());
    expect(reconnected.completed.providerAccountId).toBe(completed.providerAccountId);
    expect(reconnected.completed.reconnected).toBe(true);
  });

  test("non-200 2xx revocation retains the exact handle and retries without refresh", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const invalid = installFakeX({
      refreshResponses: [
        {
          status: 200,
          body: {
            access_token: "access-valid",
            refresh_token: "rotated-one-time-refresh",
            scope: "tweet.read offline.access admin.write",
          },
        },
      ],
      revokeStatuses: [202, 200],
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_REFRESH_FAILED" });
    const [pending] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    const handleId = pending.credentialSecretId as string;

    const first = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(first).toMatchObject({ processed: 1, revoked: 0, attention: 1 });
    const [retained] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(retained.state).toBe("revocation_pending");
    expect(retained.credentialSecretId).toBe(handleId);

    const second = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 140_000),
    });
    expect(second).toMatchObject({ processed: 1, revoked: 1, attention: 0 });
    expect(invalid.counters).toMatchObject({ refresh: 1, revoke: 2 });
    const [revoked] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(revoked.state).toBe("revoked");
    expect(revoked.credentialSecretId).toBeNull();
    invalid.restore();
  });

  test("revokes the exact bounded rotated refresh token even when adoption rejects its grammar", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const invalidRefresh = "rotated refresh with spaces";
    const fake = installFakeX({
      refreshResponses: [
        {
          status: 200,
          body: {
            access_token: "access-valid",
            refresh_token: invalidRefresh,
            scope: "tweet.read tweet.write users.read offline.access",
          },
        },
      ],
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_REFRESH_FAILED" });

    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, attention: 0 });
    expect(fake.counters.refresh).toBe(1);
    expect(fake.counters.revoke).toBe(1);
    expect(new URLSearchParams(fake.counters.revokeBodies[0]).get("token")).toBe(invalidRefresh);
    expect(new URLSearchParams(fake.counters.revokeBodies[0]).get("token_type_hint")).toBe(
      "refresh_token",
    );
    fake.restore();
  });

  test("a crash after encrypted staging adopts on retry without a second provider call", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreCrash = __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated process exit after durable stage");
    });
    const input = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    } as const;
    await expect(refreshXProviderCredential(input)).rejects.toThrow("simulated process exit");
    expect(fake.counters.refresh).toBe(1);
    restoreCrash();

    const recovered = await refreshXProviderCredential(input);
    expect(recovered.credentialVersion).toBe(2);
    expect(fake.counters.refresh).toBe(1);
    const credential = await decryptCredential(completed.providerAccountId);
    expect(credential.refreshToken).toBe("refresh-rotated-1");
    const [lifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(lifecycle.state).toBe("adopted");
    expect(lifecycle.credentialSecretId).toBeNull();
    fake.restore();
  });

  test("an ambiguous provider outcome disables the account and cannot replay the old token", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    let refreshCalls = 0;
    const restore = __setXForwardForTests(async (request) => {
      if (request.url === "https://api.x.com/2/oauth2/token") {
        refreshCalls += 1;
        throw new Error("connection lost after provider accepted rotation");
      }
      throw new Error("unexpected request");
    });
    const input = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    } as const;
    await expect(refreshXProviderCredential(input)).rejects.toThrow("connection lost");
    expect(refreshCalls).toBe(1);
    await expect(refreshXProviderCredential(input)).rejects.toMatchObject({
      code: "X_REFRESH_REVOKED",
    });
    expect(refreshCalls).toBe(1);

    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("disabled");
    const [lifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(lifecycle.state).toBe("needs_attention");
    expect(lifecycle.credentialSecretId).toBeNull();
    expect(lifecycle.lastErrorCode).toBe("REFRESH_OUTCOME_UNKNOWN");
    restore();

    const reconnectStore = new MemoryConnectStore();
    const reconnected = await connectHappy(reconnectStore);
    expect(reconnected.completed.providerAccountId).toBe(completed.providerAccountId);
    const [superseded] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, lifecycle.id));
    expect(superseded.state).toBe("superseded");
    expect(superseded.credentialSecretId).toBeNull();
    const events = await readAuditActions(TENANT);
    expect(events).toContain("provider.x.lifecycle.superseded_by_reconnect");
  });

  test("revokes a rotated grant held in memory when encrypted staging fails", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const fake = installFakeX({ revokeStatuses: [200] });
    const originalCreate = vault.createSecretWithinTx;
    Object.defineProperty(vault, "createSecretWithinTx", {
      configurable: true,
      value: async (...args: Parameters<typeof originalCreate>) => {
        if (String(args[2]).startsWith("provider-x-lifecycle:")) {
          throw new Error("simulated encrypted staging failure");
        }
        return originalCreate.apply(vault, args);
      },
    });
    try {
      await expect(
        refreshXProviderCredential({
          tenantId: TENANT,
          workspaceId: WORKSPACE,
          accountId: completed.providerAccountId,
          vault,
          config: CONFIG,
          force: true,
        }),
      ).rejects.toThrow("simulated encrypted staging failure");
    } finally {
      Object.defineProperty(vault, "createSecretWithinTx", {
        configurable: true,
        value: originalCreate,
      });
    }
    expect(fake.counters).toMatchObject({ refresh: 1, revoke: 1 });
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("revoked");
    const [lifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(lifecycle).toMatchObject({
      state: "revoked",
      credentialSecretId: null,
      lastErrorCode: "ROTATED_GRANT_REVOKED_AFTER_STAGING_FAILURE",
    });
    fake.restore();

    const reconnected = await connectHappy(new MemoryConnectStore());
    expect(reconnected.completed.providerAccountId).toBe(completed.providerAccountId);
  });

  test("blocks reconnect when a rotated grant cannot be staged or confirmed revoked", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const fake = installFakeX({ revokeStatuses: [503] });
    const originalCreate = vault.createSecretWithinTx;
    Object.defineProperty(vault, "createSecretWithinTx", {
      configurable: true,
      value: async (...args: Parameters<typeof originalCreate>) => {
        if (String(args[2]).startsWith("provider-x-lifecycle:")) {
          throw new Error("simulated encrypted staging failure");
        }
        return originalCreate.apply(vault, args);
      },
    });
    try {
      await expect(
        refreshXProviderCredential({
          tenantId: TENANT,
          workspaceId: WORKSPACE,
          accountId: completed.providerAccountId,
          vault,
          config: CONFIG,
          force: true,
        }),
      ).rejects.toThrow("simulated encrypted staging failure");
    } finally {
      Object.defineProperty(vault, "createSecretWithinTx", {
        configurable: true,
        value: originalCreate,
      });
    }
    expect(fake.counters).toMatchObject({ refresh: 1, revoke: 1 });
    const [lifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(lifecycle).toMatchObject({
      state: "needs_attention",
      credentialSecretId: null,
      lastErrorCode: "REFRESH_RESPONSE_STAGING_FAILED",
    });
    fake.restore();

    await expect(connectHappy(new MemoryConnectStore())).rejects.toMatchObject({
      code: "X_CREDENTIAL_NEEDS_ATTENTION",
    });
  });

  test("the autonomous sweep fails closed a crashed pre-provider intent", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const restoreCrash = __setAfterXRefreshIntentForTests(async () => {
      throw new Error("simulated exit after durable intent");
    });
    const input = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    } as const;
    await expect(refreshXProviderCredential(input)).rejects.toThrow("simulated exit");
    expect(fake.counters.refresh).toBe(0);
    restoreCrash();

    await expect(connectHappy(new MemoryConnectStore())).rejects.toMatchObject({
      code: "X_CREDENTIAL_NEEDS_ATTENTION",
    });
    const [stillInflight] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(stillInflight.state).toBe("inflight");

    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 70_000),
    });
    expect(swept).toMatchObject({ processed: 1, adopted: 0, attention: 1 });
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("disabled");
    const [lifecycle] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(lifecycle.state).toBe("needs_attention");
    expect(lifecycle.lastErrorCode).toBe("REFRESH_OUTCOME_UNKNOWN");
    await expect(refreshXProviderCredential(input)).rejects.toMatchObject({
      code: "X_REFRESH_REVOKED",
    });
    expect(fake.counters.refresh).toBe(0);
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
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
      }),
      refreshXProviderCredential({
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

  test("a slow healthy refresh is not disabled by a concurrent waiter timeout", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore(), {
      exchangeToken: { expires_in: 1 },
    });
    const fake = installFakeX({
      refreshResponses: [
        {
          status: 200,
          delayMs: 2_500,
          body: {
            access_token: "access-slow-winner",
            refresh_token: "refresh-slow-winner",
            scope: "tweet.read tweet.write users.read offline.access",
            expires_in: 7200,
          },
        },
      ],
    });
    const input = {
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
    } as const;
    const results = await Promise.allSettled([
      refreshXProviderCredential(input),
      refreshXProviderCredential(input),
    ]);
    expect(fake.counters.refresh).toBe(1);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({
      status: "rejected",
      reason: { code: "X_REFRESH_FAILED", httpStatus: 409 },
    });
    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("active");
    expect((await decryptCredential(completed.providerAccountId)).refreshToken).toBe(
      "refresh-slow-winner",
    );
    fake.restore();
  });

  test("refresh with fresh token + not forced short-circuits (no token call)", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    const result = await refreshXProviderCredential({
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

  test("revoked upstream (invalid_grant) => account degraded + audit + X_REFRESH_REVOKED", async () => {
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);

    const fake = installFakeX({
      refreshResponses: [{ status: 400, body: { error: "invalid_grant" } }],
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
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
        workspaceId: WORKSPACE,
        accountId: row.id,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_ACCOUNT_NOT_X" });
    fake.restore();
  });

  test("cross-workspace IDOR: refreshing an account from another workspace => X_ACCOUNT_NOT_FOUND", async () => {
    // Connect an X account in WORKSPACE, then attempt to refresh it while
    // claiming authority over WORKSPACE_OTHER. The account does not belong to
    // WORKSPACE_OTHER, so the workspace-binding guard must reject it (404).
    //
    // Mutation check: drop the `account.workspaceId !== input.workspaceId` guard
    // and this refresh succeeds against another workspace's credential.
    const store = new MemoryConnectStore();
    const { completed } = await connectHappy(store);
    const fake = installFakeX();
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE_OTHER,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_ACCOUNT_NOT_FOUND" });
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
    await disconnectXProviderCredential({
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
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toMatchObject({ code: "X_REFRESH_REVOKED" });
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
    expect(acct.credentialSecretId).toBeNull();
    expect(acct.credentialVersion).toBeNull();
    fake.restore();

    const events = await readAuditActions(TENANT);
    expect(events.includes("provider.x.disconnect.completed")).toBe(true);
  });

  test("removes local credential authority and restores only unchanged routes on reconnect", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [before] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const restoredRouteId = "50000000-0000-4000-8000-0000000000d1";
    const operatorDisabledRouteId = "50000000-0000-4000-8000-0000000000d2";
    const adminMutatedRouteId = "50000000-0000-4000-8000-0000000000d3";
    await db.insert(secretRoutes).values([
      {
        id: restoredRouteId,
        tenantId: TENANT,
        secretId: before.credentialSecretId as string,
        hostPattern: "api.x.com",
        pathPattern: "/2/tweets",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
      {
        id: operatorDisabledRouteId,
        tenantId: TENANT,
        secretId: before.credentialSecretId as string,
        hostPattern: "api.x.com",
        pathPattern: "/2/users/me",
        method: "GET",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
        enabled: false,
      },
      {
        id: adminMutatedRouteId,
        tenantId: TENANT,
        secretId: before.credentialSecretId as string,
        hostPattern: "api.x.com",
        pathPattern: "/2/users/by",
        method: "GET",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
    ]);

    const fake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).resolves.toMatchObject({ revoked: true });
    fake.restore();

    const [disconnected] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(disconnected).toMatchObject({
      status: "revoked",
      credentialSecretId: null,
      credentialVersion: null,
    });
    const [disabledRoute] = await db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, restoredRouteId));
    expect(disabledRoute).toMatchObject({ enabled: false, authorityRevision: 2 });
    const [oldSecret] = await db
      .select()
      .from(secrets)
      .where(eq(secrets.id, before.credentialSecretId as string));
    expect(oldSecret.deletedAt).not.toBeNull();
    await db
      .update(secretRoutes)
      .set({ pathPattern: "/2/users/by/changed" })
      .where(eq(secretRoutes.id, adminMutatedRouteId));

    const reconnect = await connectHappy(new MemoryConnectStore());
    expect(reconnect.completed).toMatchObject({
      providerAccountId: completed.providerAccountId,
      reconnected: true,
    });
    const [reconnected] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const [restoredRoute] = await db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, restoredRouteId));
    expect(restoredRoute).toMatchObject({
      enabled: true,
      secretId: reconnected.credentialSecretId,
      authorityRevision: 4,
    });
    const [stillOperatorDisabled] = await db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, operatorDisabledRouteId));
    expect(stillOperatorDisabled).toMatchObject({
      enabled: false,
      secretId: reconnected.credentialSecretId,
      authorityRevision: 2,
    });
    const [stillAdminDisabled] = await db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, adminMutatedRouteId));
    expect(stillAdminDisabled).toMatchObject({
      enabled: false,
      pathPattern: "/2/users/by/changed",
      secretId: reconnected.credentialSecretId,
      authorityRevision: 4,
    });
  });

  test("malformed deterministic lineage fails closed without destructive action", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const malformed = await vault.rotateSecret(
      TENANT,
      xCredentialSecretName(WORKSPACE, "1234567890"),
      "{",
    );
    await getDb()
      .update(providerAccounts)
      .set({ credentialSecretId: malformed.id, credentialVersion: malformed.version })
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const malformedFake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toMatchObject({ code: "X_CREDENTIAL_NEEDS_ATTENTION" });
    expect(malformedFake.counters.revoke).toBe(0);
    malformedFake.restore();
    const [unchangedAccount] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(unchangedAccount).toMatchObject({
      status: "active",
      credentialSecretId: malformed.id,
      credentialVersion: malformed.version,
    });
    const [unchangedSecret] = await getDb()
      .select()
      .from(secrets)
      .where(eq(secrets.id, malformed.id));
    expect(unchangedSecret.deletedAt).toBeNull();
    const disconnectLifecycles = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "disconnect_revoke"));
    expect(disconnectLifecycles).toEqual([]);
  });

  test("a wrong secret pointer cannot revoke, delete, or disable unrelated authority", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [before] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const correctRouteId = "50000000-0000-4000-8000-0000000000e1";
    const unrelatedRouteId = "50000000-0000-4000-8000-0000000000e2";
    const unrelated = await vault.createSecret(
      TENANT,
      "unrelated/provider-credential",
      JSON.stringify({
        schemaVersion: "steward.provider-x.credential.v1",
        accessToken: "unrelated-access-handle",
        refreshToken: "unrelated-refresh-handle",
        tokenType: "bearer",
        scopesGranted: [...X_DEFAULT_SCOPES],
        xUserId: "999999999",
        xUsername: "unrelated",
        obtainedAt: new Date().toISOString(),
        expiresAt: null,
      }),
    );
    await db.insert(secretRoutes).values([
      {
        id: correctRouteId,
        tenantId: TENANT,
        secretId: before.credentialSecretId as string,
        hostPattern: "api.x.com",
        pathPattern: "/2/tweets",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
      {
        id: unrelatedRouteId,
        tenantId: TENANT,
        secretId: unrelated.id,
        hostPattern: "api.unrelated.test",
        pathPattern: "/live",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
    ]);
    await db
      .update(providerAccounts)
      .set({ credentialSecretId: unrelated.id, credentialVersion: unrelated.version })
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const fake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).resolves.toMatchObject({ revoked: true });
    expect(new URLSearchParams(fake.counters.revokeBodies[0]).get("token")).toBe("refresh-initial");
    fake.restore();

    const [correctSecret] = await db
      .select()
      .from(secrets)
      .where(eq(secrets.id, before.credentialSecretId as string));
    expect(correctSecret.deletedAt).not.toBeNull();
    const [unrelatedSecret] = await db.select().from(secrets).where(eq(secrets.id, unrelated.id));
    expect(unrelatedSecret.deletedAt).toBeNull();
    const [correctRoute] = await db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, correctRouteId));
    expect(correctRoute).toMatchObject({ enabled: false, authorityRevision: 2 });
    const [unrelatedRoute] = await db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, unrelatedRouteId));
    expect(unrelatedRoute).toMatchObject({
      secretId: unrelated.id,
      enabled: true,
      authorityRevision: 1,
    });
  });

  test("a null pointer discovers and revokes the deterministic live X lineage", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [before] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const routeId = "50000000-0000-4000-8000-0000000000e3";
    await db.insert(secretRoutes).values({
      id: routeId,
      tenantId: TENANT,
      secretId: before.credentialSecretId as string,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "Authorization",
      injectFormat: "Bearer {value}",
    });
    await db
      .update(providerAccounts)
      .set({ credentialSecretId: null, credentialVersion: null })
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const fake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).resolves.toMatchObject({ revoked: true });
    expect(fake.counters.revoke).toBe(1);
    expect(new URLSearchParams(fake.counters.revokeBodies[0]).get("token")).toBe("refresh-initial");
    const [account] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account).toMatchObject({
      status: "revoked",
      credentialSecretId: null,
      credentialVersion: null,
    });
    const [lineageSecret] = await db
      .select()
      .from(secrets)
      .where(eq(secrets.id, before.credentialSecretId as string));
    expect(lineageSecret.deletedAt).not.toBeNull();
    const [route] = await db.select().from(secretRoutes).where(eq(secretRoutes.id, routeId));
    expect(route).toMatchObject({ enabled: false, authorityRevision: 2 });
    fake.restore();
  });

  test("a null pointer revokes every live owned lineage version and route", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [accountBefore] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const firstSecretId = accountBefore.credentialSecretId as string;
    const firstPayload = await decryptCredential(completed.providerAccountId);
    const secondSecret = await vault.rotateSecret(
      TENANT,
      xCredentialSecretName(WORKSPACE, firstPayload.xUserId),
      JSON.stringify({
        ...firstPayload,
        accessToken: "access-second-live-version",
        refreshToken: "refresh-second-live-version",
        obtainedAt: new Date().toISOString(),
      } satisfies XCredentialPayload),
    );
    // Simulate a committed legacy/corrupt state that the real schema permits:
    // uniqueness is per version, not per live deterministic name.
    await db.update(secrets).set({ deletedAt: null }).where(eq(secrets.id, firstSecretId));
    const routeIds = [
      "50000000-0000-4000-8000-0000000000e4",
      "50000000-0000-4000-8000-0000000000e5",
    ];
    await db.insert(secretRoutes).values([
      {
        id: routeIds[0],
        tenantId: TENANT,
        secretId: firstSecretId,
        hostPattern: "api.x.com",
        pathPattern: "/2/tweets",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
      {
        id: routeIds[1],
        tenantId: TENANT,
        secretId: secondSecret.id,
        hostPattern: "api.x.com",
        pathPattern: "/2/users/me",
        method: "GET",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
    ]);
    await db
      .update(providerAccounts)
      .set({ credentialSecretId: null, credentialVersion: null })
      .where(eq(providerAccounts.id, completed.providerAccountId));

    const fake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).resolves.toMatchObject({ revoked: true });
    expect(fake.counters.revoke).toBe(2);
    expect(
      fake.counters.revokeBodies.map((body) => new URLSearchParams(body).get("token")).sort(),
    ).toEqual(["refresh-initial", "refresh-second-live-version"].sort());
    fake.restore();

    const lineage = await db
      .select()
      .from(secrets)
      .where(inArray(secrets.id, [firstSecretId, secondSecret.id]));
    expect(lineage).toHaveLength(2);
    expect(lineage.every((secret) => secret.deletedAt !== null)).toBe(true);
    const routes = await db.select().from(secretRoutes).where(inArray(secretRoutes.id, routeIds));
    expect(routes).toHaveLength(2);
    expect(routes.every((route) => !route.enabled && route.authorityRevision === 2)).toBe(true);
    const lifecycles = await db
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "disconnect_revoke"));
    expect(lifecycles).toHaveLength(2);
    expect(
      lifecycles.every(
        (lifecycle) => lifecycle.state === "revoked" && lifecycle.credentialSecretId === null,
      ),
    ).toBe(true);
  });

  test("same-name mismatched binding aborts without touching owned or unrelated authority", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const db = getDb();
    const [accountBefore] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    const ownedSecretId = accountBefore.credentialSecretId as string;
    const ownedPayload = await decryptCredential(completed.providerAccountId);
    const unrelatedSecret = await vault.rotateSecret(
      TENANT,
      xCredentialSecretName(WORKSPACE, ownedPayload.xUserId),
      JSON.stringify({
        ...ownedPayload,
        accessToken: "unrelated-access-handle",
        refreshToken: "unrelated-refresh-handle",
        xUserId: "999999999",
        xUsername: "unrelated",
        obtainedAt: new Date().toISOString(),
      } satisfies XCredentialPayload),
    );
    await db.update(secrets).set({ deletedAt: null }).where(eq(secrets.id, ownedSecretId));
    const routeIds = [
      "50000000-0000-4000-8000-0000000000e6",
      "50000000-0000-4000-8000-0000000000e7",
    ];
    await db.insert(secretRoutes).values([
      {
        id: routeIds[0],
        tenantId: TENANT,
        secretId: ownedSecretId,
        hostPattern: "api.x.com",
        pathPattern: "/2/tweets",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
      {
        id: routeIds[1],
        tenantId: TENANT,
        secretId: unrelatedSecret.id,
        hostPattern: "api.unrelated.test",
        pathPattern: "/live",
        method: "POST",
        injectAs: "header",
        injectKey: "Authorization",
        injectFormat: "Bearer {value}",
      },
    ]);

    const fake = installFakeX();
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toMatchObject({ code: "X_CREDENTIAL_NEEDS_ATTENTION" });
    expect(fake.counters.revoke).toBe(0);
    fake.restore();

    const [accountAfter] = await db
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(accountAfter).toMatchObject({
      status: "active",
      credentialSecretId: ownedSecretId,
      credentialVersion: accountBefore.credentialVersion,
      revision: accountBefore.revision,
    });
    const lineage = await db
      .select()
      .from(secrets)
      .where(inArray(secrets.id, [ownedSecretId, unrelatedSecret.id]));
    expect(lineage.every((secret) => secret.deletedAt === null)).toBe(true);
    const routes = await db.select().from(secretRoutes).where(inArray(secretRoutes.id, routeIds));
    expect(routes.every((route) => route.enabled && route.authorityRevision === 1)).toBe(true);
    const disconnectLifecycles = await db
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "disconnect_revoke"));
    expect(disconnectLifecycles).toEqual([]);
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

  test("crash after local revoke retains an encrypted handle for bounded recovery", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const fake = installFakeX();
    const restoreCrash = __setAfterXDisconnectJournalForTests(async () => {
      throw new Error("simulated disconnect crash");
    });
    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).rejects.toThrow("simulated disconnect crash");
    restoreCrash();

    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("revoked");
    expect(account.credentialSecretId).toBeNull();
    expect(account.credentialVersion).toBeNull();
    expect(fake.counters.revoke).toBe(0);
    const [pending] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "disconnect_revoke"),
        ),
      );
    expect(pending.kind).toBe("disconnect_revoke");
    expect(pending.state).toBe("revocation_pending");
    expect(pending.credentialSecretId).not.toBeNull();

    await getDb()
      .update(providerXCredentialLifecycles)
      .set({ attempts: 5 })
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    const exhausted = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 120_000),
    });
    expect(exhausted).toMatchObject({ processed: 1, attention: 1, revoked: 0 });
    expect(fake.counters.revoke).toBe(0);
    const [terminal] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(terminal).toMatchObject({
      state: "needs_attention",
      attempts: 5,
      nextRetryAt: null,
    });
    expect(terminal.credentialSecretId).toBe(pending.credentialSecretId);
    await getDb()
      .update(providerXCredentialLifecycles)
      .set({ attempts: 0, state: "revocation_pending", nextRetryAt: new Date() })
      .where(eq(providerXCredentialLifecycles.id, pending.id));

    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(Date.now() + 120_000),
    });
    expect(swept.revoked).toBe(1);
    expect(fake.counters.revoke).toBe(1);
    const [recovered] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(recovered.state).toBe("revoked");
    expect(recovered.credentialSecretId).toBeNull();
    fake.restore();
  });

  test("retains the disconnect handle until X confirms RFC 7009 status 200", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const fake = installFakeX({ revokeStatuses: [202, 200] });
    const disconnected = await disconnectXProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      callerUserId: ADMIN,
      vault,
      config: CONFIG,
    });
    expect(disconnected.revoked).toBe(false);
    expect(fake.counters.revoke).toBe(1);

    const [pending] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "disconnect_revoke"),
        ),
      );
    expect(pending).toMatchObject({
      kind: "disconnect_revoke",
      state: "revocation_pending",
      attempts: 1,
    });
    expect(pending.credentialSecretId).not.toBeNull();
    expect(pending.nextRetryAt).not.toBeNull();

    const swept = await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: pending.nextRetryAt as Date,
    });
    expect(swept).toMatchObject({ processed: 1, revoked: 1, attention: 0 });
    expect(fake.counters.revoke).toBe(2);
    const [revoked] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, pending.id));
    expect(revoked).toMatchObject({ state: "revoked", attempts: 2 });
    expect(revoked.credentialSecretId).toBeNull();
    fake.restore();
  });

  test("preserves a staged rotated grant while disconnect revokes the stored grant separately", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const fake = installFakeX();
    const restoreStageCrash = __setAfterXCredentialStageForTests(async () => {
      throw new Error("simulated crash after rotated grant staging");
    });
    await expect(
      refreshXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        vault,
        config: CONFIG,
        force: true,
      }),
    ).rejects.toThrow("simulated crash after rotated grant staging");
    restoreStageCrash();
    const [stagedBefore] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.kind, "refresh_rotation"));
    expect(stagedBefore.state).toBe("credential_staged");
    expect(stagedBefore.credentialSecretId).not.toBeNull();

    await expect(
      disconnectXProviderCredential({
        tenantId: TENANT,
        workspaceId: WORKSPACE,
        accountId: completed.providerAccountId,
        callerUserId: ADMIN,
        vault,
        config: CONFIG,
      }),
    ).resolves.toMatchObject({ revoked: true });
    const rows = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId));
    const stagedAfter = rows.find((row) => row.kind === "refresh_rotation");
    const disconnect = rows.find((row) => row.kind === "disconnect_revoke");
    expect(stagedAfter).toMatchObject({
      id: stagedBefore.id,
      state: "credential_staged",
      credentialSecretId: stagedBefore.credentialSecretId,
    });
    expect(disconnect).toMatchObject({ state: "revoked", credentialSecretId: null });
    expect(fake.counters.revoke).toBe(1);
    expect(new URLSearchParams(fake.counters.revokeBodies[0]).get("token")).toBe("refresh-initial");

    await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: new Date(stagedBefore.updatedAt.getTime() + 60_000),
    });
    const [pendingRotated] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, stagedBefore.id));
    expect(pendingRotated).toMatchObject({
      state: "revocation_pending",
      credentialSecretId: stagedBefore.credentialSecretId,
    });
    await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: pendingRotated.nextRetryAt as Date,
    });
    expect(fake.counters.revoke).toBe(2);
    expect(new URLSearchParams(fake.counters.revokeBodies[1]).get("token")).toBe(
      "refresh-rotated-1",
    );
    const [rotatedRevoked] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(eq(providerXCredentialLifecycles.id, stagedBefore.id));
    expect(rotatedRevoked).toMatchObject({ state: "revoked", credentialSecretId: null });
    fake.restore();
  });

  test("disconnect serializes with an in-flight rotating refresh without losing revocation", async () => {
    const { completed } = await connectHappy(new MemoryConnectStore());
    const fake = installFakeX();
    let releaseRefresh!: () => void;
    let refreshIntentReached!: () => void;
    const intentReached = new Promise<void>((resolve) => {
      refreshIntentReached = resolve;
    });
    const holdRefresh = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    const restoreHook = __setAfterXRefreshIntentForTests(async () => {
      refreshIntentReached();
      await holdRefresh;
    });
    const refreshing = refreshXProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      vault,
      config: CONFIG,
      force: true,
    });
    await intentReached;

    const disconnected = await disconnectXProviderCredential({
      tenantId: TENANT,
      workspaceId: WORKSPACE,
      accountId: completed.providerAccountId,
      callerUserId: ADMIN,
      vault,
      config: CONFIG,
    });
    expect(disconnected.revoked).toBe(true);
    releaseRefresh();
    await expect(refreshing).rejects.toThrow();
    restoreHook();

    const [account] = await getDb()
      .select()
      .from(providerAccounts)
      .where(eq(providerAccounts.id, completed.providerAccountId));
    expect(account.status).toBe("revoked");
    expect(fake.counters.refresh).toBe(1);
    expect(fake.counters.revoke).toBe(1);
    const [rotated] = await getDb()
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.providerAccountId, completed.providerAccountId),
          eq(providerXCredentialLifecycles.kind, "refresh_rotation"),
        ),
      );
    expect(rotated).toMatchObject({ state: "revocation_pending" });
    await runXCredentialLifecycleSweep({
      vault,
      config: CONFIG,
      now: rotated.nextRetryAt as Date,
    });
    expect(fake.counters.revoke).toBe(2);
    expect(new URLSearchParams(fake.counters.revokeBodies[1]).get("token")).toBe(
      "refresh-rotated-1",
    );
    fake.restore();
  });
});

// ── Sanity: secret lineage name is deterministic per (workspace, x user) ──────
test("credential secret name is stable per workspace+x user (reconnect lineage)", () => {
  expect(xCredentialSecretName(WORKSPACE, "1234567890")).toBe(`provider-x/${WORKSPACE}/1234567890`);
});

test("XConnectError carries code + http status", () => {
  const e = new XConnectError("X_STATE_INVALID", 401);
  expect(e.code).toBe("X_STATE_INVALID");
  expect(e.httpStatus).toBe(401);
});

test("real X transport rejects oversized provider responses before parsing", async () => {
  const originalFetch = globalThis.fetch;
  let redirect: RequestRedirect | undefined;
  globalThis.fetch = (async (_input, init) => {
    redirect = init?.redirect;
    return new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "1048577" },
    });
  }) as typeof fetch;
  try {
    await expect(
      __runDefaultXForwardForTests({
        url: "https://api.x.com/2/users/me",
        method: "GET",
        headers: { accept: "application/json" },
      }),
    ).rejects.toThrow("X provider response exceeded maximum size");
    expect(redirect).toBe("error");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("real X transport refuses redirects before credentials can be replayed", async () => {
  const originalFetch = globalThis.fetch;
  let redirectMode: RequestRedirect | undefined;
  globalThis.fetch = (async (_input, init) => {
    redirectMode = init?.redirect;
    throw new TypeError("redirect blocked");
  }) as typeof fetch;
  try {
    await expect(
      __runDefaultXForwardForTests({
        url: "https://api.x.com/2/oauth2/token",
        method: "POST",
        headers: { authorization: "Basic secret-canary" },
        body: "refresh_token=refresh-secret-canary",
      }),
    ).rejects.toThrow("redirect blocked");
    expect(redirectMode).toBe("error");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
