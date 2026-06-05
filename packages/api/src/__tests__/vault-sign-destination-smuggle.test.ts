/**
 * Regression: the vault /:agentId/sign route must not let a caller smuggle a
 * whitelisted `destination` past the approved-addresses allowlist while `to`
 * points at an arbitrary address.
 *
 * The approved-addresses evaluator treats an envelope `destination` (and
 * `action.destination` / `withdraw.destination`) as authoritative over `to` —
 * this is intentional for the server-built operator-withdraw flow. The /sign
 * route, however, used to spread the raw request body into the SignRequest, so a
 * body { to: <attacker>, destination: <whitelisted> } was evaluated against the
 * whitelisted destination (PASS) while the vault signed/broadcast to the
 * attacker `to`. The fix builds the SignRequest from its declared fields only,
 * so `to` is authoritative on /sign. This drives the REAL route.
 */
import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `sign-smuggle-tenant-${Date.now()}`;
const AGENT_ID = `sign-smuggle-agent-${Date.now()}`;
const ALLOWED = "0x1111111111111111111111111111111111111111";
const ATTACKER = "0x2222222222222222222222222222222222222222";

setDefaultTimeout(30000);

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "sign-smuggle-owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

type PolicyResult = { type?: string; passed?: boolean };
type SignBody = { ok: boolean; error?: string; data?: { results?: PolicyResult[] } };

describe("approved-addresses /sign destination-smuggle guard (real route)", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "sign-smuggle-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "sign-smuggle-test-audit-hmac-key-0123456789abcdef0123";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Smuggle Tenant", apiKeyHash: `hash-${TENANT_ID}` });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Smuggle Agent",
      walletAddress: "0x0000000000000000000000000000000000000abc",
    });
    // Allowlist ONLY the ALLOWED address.
    await getDb()
      .insert(policies)
      .values({
        id: `${AGENT_ID}-approved`,
        agentId: AGENT_ID,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [ALLOWED], mode: "whitelist" },
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  function postSign(body: Record<string, unknown>) {
    return app.request(`/vault/${AGENT_ID}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: "1000", chainId: 8453, broadcast: false, ...body }),
    });
  }

  it("does not let a smuggled `destination` satisfy the allowlist — `to` is authoritative", async () => {
    const res = await postSign({ to: ATTACKER, destination: ALLOWED });
    const body = (await res.json()) as SignBody;

    // Must NOT be authorized. (403 hard-deny or 202 pending-approval — either way
    // the smuggle did not pass; pre-fix this returned an authorized/sign path.)
    expect(body.ok).toBe(false);
    // The approved-addresses policy must have FAILED, evaluated against `to`.
    const results = body.data?.results ?? [];
    expect(results.some((r) => r.type === "approved-addresses" && r.passed === false)).toBe(true);
  });

  it("a smuggled `destination` behaves identically to no destination at all", async () => {
    const smuggled = await postSign({ to: ATTACKER, destination: ALLOWED });
    const body = (await smuggled.json()) as SignBody;
    expect(smuggled.status).toBe(403);
    expect(body.error).toBe("Transaction rejected by policy");
    expect(
      (body.data?.results ?? []).some((r) => r.type === "approved-addresses" && r.passed === false),
    ).toBe(true);
  });

  it("a genuinely whitelisted `to` is NOT rejected by the allowlist (positive control)", async () => {
    const res = await postSign({ to: ALLOWED });
    const body = (await res.json()) as SignBody;
    // It passes the allowlist (it may fail later for unrelated reasons — no key is
    // provisioned — but it is NOT a policy rejection).
    expect(body.error).not.toBe("Transaction rejected by policy");
  });
});
