import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { randomUUID } from "node:crypto";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const userId = randomUUID();

let app: Hono<{ Variables: AppVariables }>;
let priorDatabaseUrl: string | undefined;
let priorMasterPassword: string | undefined;

beforeAll(async () => {
  priorDatabaseUrl = process.env.DATABASE_URL;
  priorMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
  process.env.DATABASE_URL ||= "postgres://127.0.0.1:1/steward-webhook-policy-test";
  process.env.STEWARD_MASTER_PASSWORD ||= "mounted-webhook-policy-master-password";
  const { webhookRoutes } = await import("../routes/webhooks");
  app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    // The production route skips the tenant policy lookup only for this focused
    // boundary harness; the mounted handler and URL/event validation are real.
    c.set("tenantId", "");
    c.set("userId", userId);
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("requestId", randomUUID());
    await next();
  });
  app.route("/webhooks", webhookRoutes);
});

afterAll(() => {
  if (priorDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = priorDatabaseUrl;
  if (priorMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
  else process.env.STEWARD_MASTER_PASSWORD = priorMasterPassword;
});

function createWebhook(
  url: string,
  bindings: Record<string, string>,
  events: string[] = ["tx.signed"],
) {
  return withRuntimeEnvironment(bindings, () =>
    app.request("/webhooks", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url, events }),
    }),
  );
}

describe("mounted webhook request-local policy", () => {
  it("observes an enabled binding and then its removal without remounting the route", async () => {
    const enabled = await createWebhook(
      "http://127.0.0.1:38080/enabled",
      {
        STEWARD_ALLOW_INSECURE_WEBHOOK_URLS: "true",
        STEWARD_ALLOW_PRIVATE_WEBHOOK_NETWORKS: "true",
      },
      ["invalid-after-url-validation"],
    );
    expect(enabled.status).toBe(400);
    await expect(enabled.json()).resolves.toMatchObject({
      error: expect.stringContaining("Invalid events"),
    });

    const insecureRemoved = await createWebhook("http://127.0.0.1:38080/insecure-removed", {});
    expect(insecureRemoved.status).toBe(400);
    await expect(insecureRemoved.json()).resolves.toMatchObject({ error: "url must use https" });

    const privateRemoved = await createWebhook("https://127.0.0.1:38080/private-removed", {});
    expect(privateRemoved.status).toBe(400);
    await expect(privateRemoved.json()).resolves.toMatchObject({
      error: "url host must be public",
    });
  });
});
