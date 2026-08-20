import { describe, expect, it } from "bun:test";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

type RouteRequest = {
  body?: unknown;
  method: "DELETE" | "GET" | "PATCH" | "POST" | "PUT";
  path: string;
};

async function makeApp() {
  const [{ agentRoutes }, { conditionSetRoutes }, { policiesStandaloneRoutes }, { secretsRoutes }] =
    await Promise.all([
      import("../routes/agents"),
      import("../routes/condition-sets"),
      import("../routes/policies-standalone"),
      import("../routes/secrets"),
    ]);
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", "api-key-boundary-tenant");
    c.set(
      "authType",
      c.req.header("x-test-auth-type") === "agent-token" ? "agent-token" : "api-key",
    );
    await next();
  });
  app.route("/secrets", secretsRoutes);
  app.route("/policies", policiesStandaloneRoutes);
  app.route("/condition-sets", conditionSetRoutes);
  app.route("/agents", agentRoutes);
  return app;
}

// The package preload owns the process-wide test database. These requests
// reject at the mounted route guards before any database access, so this file
// must not replace or close that shared override and break later files.
const app = await makeApp();

async function expectMachinePrincipalRejected(
  app: Awaited<ReturnType<typeof makeApp>>,
  requests: RouteRequest[],
  authType: "agent-token" | "api-key" = "api-key",
): Promise<void> {
  for (const request of requests) {
    const response = await app.request(request.path, {
      method: request.method,
      headers: {
        "content-type": "application/json",
        "x-test-auth-type": authType,
      },
      body: request.method === "GET" ? undefined : JSON.stringify(request.body ?? {}),
    });
    expect(response.status, `${request.method} ${request.path}`).toBe(403);
    await expect(response.json(), `${request.method} ${request.path}`).resolves.toMatchObject({
      ok: false,
      error: expect.stringMatching(/admin|MFA|owner|session/i),
    });
  }
}

describe("API key control-plane boundary", () => {
  it("rejects API keys at every secret vault and injection route", async () => {
    await expectMachinePrincipalRejected(app, [
      { method: "GET", path: "/secrets" },
      { method: "POST", path: "/secrets" },
      { method: "GET", path: "/secrets/routes" },
      { method: "POST", path: "/secrets/routes" },
      { method: "PUT", path: "/secrets/routes/route-id" },
      { method: "DELETE", path: "/secrets/routes/route-id" },
      { method: "GET", path: "/secrets/secret-id" },
      { method: "PUT", path: "/secrets/secret-id" },
      { method: "DELETE", path: "/secrets/secret-id" },
      { method: "POST", path: "/secrets/secret-id/rotate" },
    ]);
  });

  it("rejects API keys at every policy-template route", async () => {
    const policyId = "00000000-0000-4000-8000-000000000001";
    await expectMachinePrincipalRejected(app, [
      { method: "GET", path: "/policies" },
      { method: "POST", path: "/policies" },
      { method: "GET", path: `/policies/${policyId}` },
      { method: "PUT", path: `/policies/${policyId}` },
      { method: "DELETE", path: `/policies/${policyId}` },
      { method: "POST", path: `/policies/${policyId}/assign` },
      {
        body: {
          policyId,
          request: {
            to: "0x1234567890abcdef1234567890abcdef12345678",
            value: "0",
          },
        },
        method: "POST",
        path: "/policies/simulate",
      },
      {
        body: {
          agentId: "agent-id",
          request: {
            to: "0x1234567890abcdef1234567890abcdef12345678",
            value: "0",
          },
        },
        method: "POST",
        path: "/policies/simulate",
      },
    ]);
  });

  it("rejects API keys at every condition-set route", async () => {
    await expectMachinePrincipalRejected(app, [
      { method: "GET", path: "/condition-sets" },
      { method: "POST", path: "/condition-sets" },
      { method: "GET", path: "/condition-sets/set-id" },
      { method: "PATCH", path: "/condition-sets/set-id" },
      { method: "DELETE", path: "/condition-sets/set-id" },
      { method: "GET", path: "/condition-sets/set-id/items" },
      { method: "POST", path: "/condition-sets/set-id/items" },
      { method: "PUT", path: "/condition-sets/set-id/items" },
      { method: "GET", path: "/condition-sets/set-id/items/item-id" },
      {
        body: { value: "updated" },
        method: "PATCH",
        path: "/condition-sets/set-id/items/item-id",
      },
      { method: "DELETE", path: "/condition-sets/set-id/items/item-id" },
    ]);
  });

  it("rejects agent tokens at every agent-administration route", async () => {
    await expectMachinePrincipalRejected(
      app,
      [
        { method: "POST", path: "/agents" },
        { method: "POST", path: "/agents/agent-id/token" },
        { method: "POST", path: "/agents/agent-id/wallets" },
        { method: "DELETE", path: "/agents/agent-id" },
        { method: "POST", path: "/agents/batch" },
        { method: "PUT", path: "/agents/agent-id/policies" },
      ],
      "agent-token",
    );
  });
});
