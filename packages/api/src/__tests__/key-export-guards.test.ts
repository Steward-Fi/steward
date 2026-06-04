import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAccessToken } from "@stwd/auth";
import { getDb, policies, tenants, users, userTenants } from "@stwd/db";
import { provisionUserWallet, Vault } from "@stwd/vault";
import { inArray, sql } from "drizzle-orm";

setDefaultTimeout(30000);

const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

process.env.STEWARD_MASTER_PASSWORD ??= "key-export-guard-master-password";
process.env.STEWARD_JWT_SECRET ??= "key-export-guard-jwt-secret-with-enough-bytes";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "key-export-guard-audit-hmac-key-with-enough-bytes";

const RUN_ID = crypto.randomUUID().slice(0, 8);
const TENANT_ID = `kx-${RUN_ID}`;
const AGENT_ID = `agent-${RUN_ID}`;
const ADMIN_USER_ID = crypto.randomUUID();
const WALLET_USER_ID = crypto.randomUUID();
const PERSONAL_TENANT_ID = `personal-${WALLET_USER_ID}`;

let app: typeof import("../app")["app"];
let previousAllowKeyExport: string | undefined;

function freshMfa() {
  return new Date().toISOString();
}

async function tenantToken(mfaVerifiedAt?: string) {
  return signAccessToken(
    {
      address: `0x${"1".repeat(40)}`,
      tenantId: TENANT_ID,
      userId: ADMIN_USER_ID,
      ...(mfaVerifiedAt ? { sessionMfaVerifiedAt: mfaVerifiedAt } : {}),
    },
    "1h",
  );
}

async function userToken(mfaVerifiedAt?: string) {
  return signAccessToken(
    {
      address: `0x${"2".repeat(40)}`,
      tenantId: PERSONAL_TENANT_ID,
      userId: WALLET_USER_ID,
      ...(mfaVerifiedAt ? { sessionMfaVerifiedAt: mfaVerifiedAt } : {}),
    },
    "1h",
  );
}

async function auditCount(tenantId: string, action: string) {
  const rows = (await getDb().execute(
    sql`SELECT count(*)::int AS count FROM audit_events WHERE tenant_id = ${tenantId} AND action = ${action}`,
  )) as Array<{ count: number }>;
  return Number(rows[0]?.count ?? 0);
}

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  previousAllowKeyExport = process.env.STEWARD_ALLOW_KEY_EXPORT;
  process.env.STEWARD_ALLOW_KEY_EXPORT = "true";

  ({ app } = await import("../app"));

  const db = getDb();
  const { hash } = generateApiKey();
  await db.insert(tenants).values([
    { id: TENANT_ID, name: "Key Export Guard Tenant", apiKeyHash: hash },
    { id: PERSONAL_TENANT_ID, name: "Key Export Personal Tenant", apiKeyHash: hash },
  ]);
  await db.insert(users).values([
    { id: ADMIN_USER_ID, email: `admin-${RUN_ID}@example.test` },
    { id: WALLET_USER_ID, email: `wallet-${RUN_ID}@example.test` },
  ]);
  await db.insert(userTenants).values([
    { userId: ADMIN_USER_ID, tenantId: TENANT_ID, role: "admin" },
    { userId: WALLET_USER_ID, tenantId: PERSONAL_TENANT_ID, role: "owner" },
  ]);

  const vault = new Vault({
    masterPassword: process.env.STEWARD_MASTER_PASSWORD!,
    rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
    chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
  });
  await vault.createAgent(TENANT_ID, AGENT_ID, "Key Export Guard Agent");
  await provisionUserWallet(vault, WALLET_USER_ID, "Key Export Wallet User", PERSONAL_TENANT_ID);
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;

  if (previousAllowKeyExport === undefined) {
    delete process.env.STEWARD_ALLOW_KEY_EXPORT;
  } else {
    process.env.STEWARD_ALLOW_KEY_EXPORT = previousAllowKeyExport;
  }

  const db = getDb();
  await db.execute(
    sql`DELETE FROM audit_events WHERE tenant_id IN (${TENANT_ID}, ${PERSONAL_TENANT_ID})`,
  );
  await db
    .delete(policies)
    .where(inArray(policies.agentId, [AGENT_ID, `user-wallet-${WALLET_USER_ID}`]));
  await db.delete(tenants).where(inArray(tenants.id, [TENANT_ID, PERSONAL_TENANT_ID]));
  await db.delete(users).where(inArray(users.id, [ADMIN_USER_ID, WALLET_USER_ID]));
});

describeWithDatabase("key export guards", () => {
  it("rejects tenant vault export without recent MFA", async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
    const token = await tenantToken();

    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "operator recovery drill" }),
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA");
  });

  it("allows tenant vault export with recent MFA and writes a blocking HIGH audit event", async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
    const token = await tenantToken(freshMfa());
    const before = await auditCount(TENANT_ID, "vault.key_export");

    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "operator recovery drill" }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data?: { evm?: { privateKey: string } } };
    expect(body.ok).toBe(true);
    expect(body.data?.evm?.privateKey).toStartWith("0x");
    expect(await auditCount(TENANT_ID, "vault.key_export")).toBe(before + 1);
  });

  it("rejects tenant vault export when the env kill switch is disabled", async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "false";
    const token = await tenantToken(freshMfa());

    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "operator recovery drill" }),
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("STEWARD_ALLOW_KEY_EXPORT");
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
  });

  it("rejects user wallet export without recent MFA", async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
    const token = await userToken();

    const res = await app.request("/user/me/wallet/export", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "user recovery" }),
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA");
  });

  it("allows user wallet export with recent MFA and writes a blocking HIGH audit event", async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
    const token = await userToken(freshMfa());
    const before = await auditCount(PERSONAL_TENANT_ID, "user.wallet_key_export");

    const res = await app.request("/user/me/wallet/export", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "user recovery" }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data?: { evm?: { privateKey: string } } };
    expect(body.ok).toBe(true);
    expect(body.data?.evm?.privateKey).toStartWith("0x");
    expect(await auditCount(PERSONAL_TENANT_ID, "user.wallet_key_export")).toBe(before + 1);
  });

  it("rejects user wallet export when the env kill switch is disabled", async () => {
    process.env.STEWARD_ALLOW_KEY_EXPORT = "false";
    const token = await userToken(freshMfa());

    const res = await app.request("/user/me/wallet/export", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ reason: "user recovery" }),
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("STEWARD_ALLOW_KEY_EXPORT");
    process.env.STEWARD_ALLOW_KEY_EXPORT = "true";
  });
});
