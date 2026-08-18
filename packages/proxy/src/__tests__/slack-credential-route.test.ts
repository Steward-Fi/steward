import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, proxyAuditLog, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

const MASTER_PASSWORD = "proxy-slack-route-master";
setDefaultTimeout(30_000);
const SLACK_TOKEN = "xoxb-CANARY-never-agent-audit-log";
let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handleProxy: typeof import("../handlers/proxy")["handleProxy"];
let proxyMod: typeof import("../handlers/proxy");
let capturedAuthorization = "";

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-slack-route-jwt-secret-with-enough-bytes";
  // The production proxy deliberately requires request signing and Redis. This
  // integration test exercises the credential seam in the explicit local-test
  // posture; setting the flag before importing the handler is intentional.
  process.env.STEWARD_PROXY_DEV_MODE = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  ({ authMiddleware } = await import("../middleware/auth"));
  proxyMod = await import("../handlers/proxy");
  proxyMod.__resetSecretVaultForTests();
  ({ handleProxy } = proxyMod);
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "13.107.42.16", family: 4 }]);
});

afterAll(async () => {
  await closeDb().catch(() => {});
  proxyMod.__resetSecretVaultForTests();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_DEV_MODE;
});

async function fixture(secretValue = SLACK_TOKEN) {
  const tenantId = `tenant-slack-${crypto.randomUUID()}`;
  const agentId = `agent-slack-${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `h-${tenantId}` });
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"1".repeat(40)}` });
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "slack-bot", secretValue);
  await vault.createRoute(tenantId, secret.id, {
    agentId,
    hostPattern: "slack.com",
    pathPattern: "/api/chat.postMessage",
    method: "POST",
    injectAs: "header",
    injectKey: "authorization",
    injectFormat: "Bearer {value}",
  });
  return { tenantId, agentId };
}

async function invoke(tenantId: string, agentId: string) {
  const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
  const app = new Hono();
  app.use("*", authMiddleware);
  app.all("*", handleProxy);
  return app.request("/slack/api/chat.postMessage", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "idempotency-key": crypto.randomUUID(),
    },
    body: JSON.stringify({ channel: "C12345678", text: "hello" }),
  });
}

describe("Slack narrow credential route", () => {
  test("injects bot token only upstream and keeps it out of response and audit", async () => {
    const { tenantId, agentId } = await fixture();
    capturedAuthorization = "";
    proxyMod.__setForwardProxyRequestForTests(async (_url, _method, headers) => {
      capturedAuthorization = headers.get("authorization") ?? "";
      return new Response('{"ok":true,"ts":"1712345678.123456"}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const response = await invoke(tenantId, agentId);
    expect(response.status).toBe(200);
    expect(capturedAuthorization).toBe(`Bearer ${SLACK_TOKEN}`);
    expect(await response.text()).not.toContain(SLACK_TOKEN);
    const audit = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(eq(proxyAuditLog.tenantId, tenantId));
    expect(JSON.stringify(audit)).not.toContain(SLACK_TOKEN);
  });

  test("maps Slack HTTP 200 ok:false to a failed dispatch without leaking token", async () => {
    const { tenantId, agentId } = await fixture();
    proxyMod.__setForwardProxyRequestForTests(async (_url, _method, headers) => {
      capturedAuthorization = headers.get("authorization") ?? "";
      return new Response('{"ok":false,"error":"channel_not_found"}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const response = await invoke(tenantId, agentId);
    expect(capturedAuthorization).toBe(`Bearer ${SLACK_TOKEN}`);
    expect(response.status).toBe(502);
    const body = await response.text();
    expect(body).toContain("channel_not_found");
    expect(body).not.toContain(SLACK_TOKEN);
    const audit = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(eq(proxyAuditLog.tenantId, tenantId));
    expect(audit.map((row) => row.statusCode)).toEqual([102, 502]);
    expect(audit.some((row) => row.statusCode === 200)).toBe(false);
    expect(audit.at(-1)?.reason).toBe("slack-api-error:channel_not_found");
  });

  for (const [label, invalidCredential] of [
    ["user token", "xoxp-CANARY-user-token-must-not-forward"],
    ["arbitrary plaintext", "CANARY-not-a-slack-token"],
    ["truncated bot token", "xoxb-short"],
    ["line-terminated bot token", "xoxb-CANARY-valid-looking\n"],
  ] as const) {
    test(`rejects ${label} at use time without forwarding or leaking it`, async () => {
      const { tenantId, agentId } = await fixture(invalidCredential);
      let forwarded = false;
      proxyMod.__setForwardProxyRequestForTests(async () => {
        forwarded = true;
        return new Response('{"ok":true}', {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      });

      const response = await invoke(tenantId, agentId);
      const body = await response.text();
      const audit = await getDb()
        .select()
        .from(proxyAuditLog)
        .where(eq(proxyAuditLog.tenantId, tenantId));

      expect(response.status).toBe(403);
      expect(forwarded).toBe(false);
      expect(body).not.toContain(invalidCredential);
      expect(JSON.stringify(audit)).not.toContain(invalidCredential);
      expect(audit.at(-1)?.reason).toBe("slack-bot-credential-required");
    });
  }
});
