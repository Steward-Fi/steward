/**
 * REAL behavioral coverage for the step-up / fail-closed gates on the vault
 * signing + transaction-lifecycle routes.
 *
 * The deleted vault-trade-audit-gates.test.ts asserted (via source grep) that
 * reject / lifecycle / replace / sign-message / sign-user-operation /
 * sign-authorization all *contain* `hasTenantAdminSession` + `hasRecentSessionMfa`.
 * A grep cannot tell whether the gate actually FIRES, or whether a refactor moved
 * it below the money-moving logic. This drives each route for real and proves the
 * outermost gate refuses the request:
 *
 *   - reject: an api-key principal → 403 (no owner/admin session); an owner
 *     session WITHOUT recent MFA → 403 (step-up required).
 *   - lifecycle + replace: same two postures → 403 on the combined session+MFA gate.
 *   - sign-message / sign-user-operation / sign-authorization: DISABLED by default
 *     (fail-closed) — even a fully-authenticated owner-with-MFA session is refused
 *     403 unless the explicit unsafe-signing opt-in env flags are set. This is the
 *     stronger invariant the grep never checked: arbitrary/AA signing cannot
 *     happen at all without a deliberate break-glass opt-in.
 *
 * Each gate returns BEFORE any DB mutation or key access, so no signing material
 * or seeded transaction is needed — the refusal itself is the invariant.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `signing-gate-tenant-${Date.now()}`;
const AGENT_ID = `signing-gate-agent-${Date.now()}`;

type Posture = "api-key" | "session-no-mfa" | "session-with-mfa";

async function makeApp(posture: Posture) {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("userId", "signing-gate-owner");
    c.set("tenantRole", "owner");
    if (posture === "api-key") {
      c.set("authType", "api-key");
    } else {
      c.set("authType", "session-jwt");
      if (posture === "session-with-mfa") c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

function post(app: Awaited<ReturnType<typeof makeApp>>, path: string, body: unknown) {
  return app.request(`/vault/${AGENT_ID}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function errorOf(res: Response): Promise<string> {
  const body = (await res.json()) as { ok: boolean; error?: string };
  expect(body.ok).toBe(false);
  return body.error ?? "";
}

describe("vault signing/lifecycle gates (real routes)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "signing-gate-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "signing-gate-test-audit-hmac-key-0123456789abcdef0123456789";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Signing Gate Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Signing Gate Agent",
      walletAddress: "0x0000000000000000000000000000000000000abc",
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("reject route: refuses api-key (no owner/admin session)", async () => {
    const res = await post(await makeApp("api-key"), "/reject/tx-gate", {});
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("Transaction rejection requires owner or admin session");
  });

  it("reject route: refuses an owner session without recent MFA", async () => {
    const res = await post(await makeApp("session-no-mfa"), "/reject/tx-gate", {});
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe("Transaction rejection requires recent MFA verification");
  });

  it("lifecycle route: refuses api-key and session-without-MFA on the combined gate", async () => {
    const apiKeyRes = await post(await makeApp("api-key"), "/transactions/tx-gate/lifecycle", {
      status: "confirmed",
    });
    expect(apiKeyRes.status).toBe(403);
    expect(await errorOf(apiKeyRes)).toBe(
      "Transaction lifecycle updates require owner or admin session with recent MFA",
    );

    const noMfaRes = await post(
      await makeApp("session-no-mfa"),
      "/transactions/tx-gate/lifecycle",
      {
        status: "confirmed",
      },
    );
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe(
      "Transaction lifecycle updates require owner or admin session with recent MFA",
    );
  });

  it("replace route: refuses api-key and session-without-MFA on the combined gate", async () => {
    const apiKeyRes = await post(await makeApp("api-key"), "/transactions/tx-gate/replace", {
      replacementTxHash: "0xdead",
    });
    expect(apiKeyRes.status).toBe(403);
    expect(await errorOf(apiKeyRes)).toBe(
      "Transaction replacement requires owner or admin session with recent MFA",
    );

    const noMfaRes = await post(await makeApp("session-no-mfa"), "/transactions/tx-gate/replace", {
      replacementTxHash: "0xdead",
    });
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe(
      "Transaction replacement requires owner or admin session with recent MFA",
    );
  });

  it("sign-message: fail-closed (disabled) even for a fully-authenticated owner+MFA session", async () => {
    const res = await post(await makeApp("session-with-mfa"), "/sign-message", {
      message: "hello world",
    });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toContain("Message signing is disabled");
  });

  it("sign-user-operation: fail-closed (disabled) even for a fully-authenticated owner+MFA session", async () => {
    const res = await post(await makeApp("session-with-mfa"), "/sign-user-operation", {
      userOperation: {},
    });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toContain("User operation signing is disabled");
  });

  it("sign-authorization: fail-closed (disabled) even for a fully-authenticated owner+MFA session", async () => {
    const res = await post(await makeApp("session-with-mfa"), "/sign-authorization", {
      authorization: {},
    });
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toContain("authorization signing is disabled");
  });
});
