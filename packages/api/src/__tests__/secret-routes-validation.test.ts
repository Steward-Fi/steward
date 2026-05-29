import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Hono } from "hono";
import { secretsRoutes } from "../routes/secrets";
import type { AppVariables } from "../services/context";

const secretsRouteSource = readFileSync(
  join(import.meta.dir, "..", "routes", "secrets.ts"),
  "utf8",
);

function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", "tenant-secret-route-validation");
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "secret-route-validation-owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/secrets", secretsRoutes);
  return app;
}

describe("secret route validation", () => {
  it("rejects oversized credential injection formats before persistence", async () => {
    const res = await makeApp().request("/secrets/routes", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secretId: "secret-1",
        agentId: "agent-1",
        hostPattern: "api.openai.com",
        pathPattern: "/v1/*",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: `Bearer ${"x".repeat(2_000)}{value}`,
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("injectFormat cannot exceed");
  });

  it("rejects query credential injection because upstream bodies can reflect secrets", async () => {
    const res = await makeApp().request("/secrets/routes", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secretId: "secret-1",
        agentId: "agent-1",
        hostPattern: "api.openai.com",
        pathPattern: "/v1/*",
        method: "POST",
        injectAs: "query",
        injectKey: "api_key",
        injectFormat: "{value}",
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("'injectAs' must be one of: header");
  });

  it("rejects body credential injection until the proxy implements it", () => {
    expect(secretsRouteSource).toContain('const validInjectAs = ["header"]');
    expect(secretsRouteSource).toContain("'injectAs' must be one of:");
    expect(secretsRouteSource).not.toContain("STEWARD_ALLOW_QUERY_SECRET_INJECTION");
    expect(secretsRouteSource).not.toContain('const validInjectAs = ["header", "query"]');
  });

  it("type-checks route creation priority and enabled before persistence", () => {
    expect(secretsRouteSource).toContain("function parseSecretRouteCreate");
    expect(secretsRouteSource).toContain("'priority' must be an integer");
    expect(secretsRouteSource).toContain("'enabled' must be a boolean");
    expect(secretsRouteSource).toContain("const routeInput = parsedCreate.value");
    expect(secretsRouteSource).toContain("const MAX_SECRET_INJECT_FORMAT_LENGTH = 255");
  });

  it("rejects line breaks in secret values before header injection can use them", () => {
    expect(secretsRouteSource).toContain("function validateSecretValue");
    expect(secretsRouteSource).toContain("secret value must not contain line breaks");
    expect(secretsRouteSource).toContain(
      "const secretValueError = validateSecretValue(body.value)",
    );
  });
});
