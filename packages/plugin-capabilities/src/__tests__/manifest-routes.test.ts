/**
 * manifest-routes.test.ts — E2E for the agent-facing manifest + issuance/renewal
 * routes (lane A1, scope 2-5). Mounts createManifestRoutes on a bare hono app
 * with an agent-token stub + real pglite store. Proves:
 *   - GET /manifest lists the agent's manifest entries,
 *   - broker-mode GitHub and Discord issuance return delegations (no token),
 *   - renew hits the same path,
 *   - revoked/absent manifest entry → 403,
 *   - audit events are emitted for each outcome,
 *   - agent auth is required (401 without agentScope).
 */

import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import type { AppVariables } from "@stwd/shared";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";
import type { CapabilityAuditEvent } from "../issuance";
import { createManifestRoutes } from "../manifest-routes";
import { CapabilityStore } from "../store";
import { validateCapabilitySpec } from "../validate";
import { ensureAgent, ensureSecret, ensureTenant, type Harness, makeHarness } from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
let tenantId: string;
const agentId = "agent-soliza";
let secretId: string;
let auditLog: CapabilityAuditEvent[] = [];

const GH_SPEC = {
  host: "api.github.com",
  pathPattern: "/repos/acme/app/issues/1/comments",
  method: "POST",
  injectKey: "authorization",
  injectFormat: "Bearer {value}",
};

function buildCtx(db: unknown): StewardAppContext {
  return {
    db,
    getRedisClient: () => null,
    async writeAuditEvent(ev: Record<string, unknown>) {
      // Reconstruct the structured event from the core-audit shape for assertion.
      const md = (ev.metadata ?? {}) as Record<string, unknown>;
      auditLog.push({
        action: ev.action as CapabilityAuditEvent["action"],
        tenantId: ev.tenantId as string,
        agentId: ev.actorId as string,
        manifest: md.manifest as string,
        mode: md.mode as CapabilityAuditEvent["mode"],
        decision: md.decision as CapabilityAuditEvent["decision"],
        reason: md.reason as string | undefined,
        jti: md.jti as string | undefined,
        ttlSeconds: md.ttlSeconds as number | undefined,
        at: Date.now(),
      });
    },
  } as unknown as StewardAppContext;
}

function buildApp(db: unknown, opts: { agent: boolean }): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    if (opts.agent) {
      c.set("tenantId", tenantId);
      c.set("agentScope", agentId);
    }
    await next();
  });
  app.route("/capabilities", createManifestRoutes(buildCtx(db)));
  return app;
}

async function seedManifestCapability(name: string, manifest: string) {
  const store = new CapabilityStore(harness!.db);
  const v = validateCapabilitySpec({ secretId, ...GH_SPEC });
  if (!v.ok) throw new Error(`spec invalid: ${v.error}`);
  const cap = await store.createCapability({
    tenantId,
    name,
    spec: v.spec,
    constraints: { manifest },
    enabled: true,
  });
  await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });
  return cap;
}

beforeEach(async () => {
  process.env.STEWARD_JWT_SECRET = "manifest-routes-jwt-secret-32chars-minimum!!";
  harness = await makeHarness();
  tenantId = `tenant-${crypto.randomUUID()}`;
  auditLog = [];
  await ensureTenant(harness.db, tenantId);
  await ensureAgent(harness.db, tenantId, agentId);
  secretId = await ensureSecret(harness.db, tenantId, "provider-secret");
});

afterEach(async () => {
  await harness?.close();
  harness = null;
});

describe("manifest routes", () => {
  test("401 without agent auth", async () => {
    const app = buildApp(harness!.db, { agent: false });
    const res = await app.request("/capabilities/manifest");
    expect(res.status).toBe(401);
  });

  test("GET /manifest lists the agent's manifest", async () => {
    await seedManifestCapability("gh-comment", "github:app:org");
    await seedManifestCapability("discord-send", "discord:bot-token:soliza");
    const app = buildApp(harness!.db, { agent: true });

    const res = await app.request("/capabilities/manifest");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { manifest: Array<{ manifest: string }> };
    };
    const ids = body.data.manifest.map((m) => m.manifest).sort();
    expect(ids).toEqual(["discord:bot-token:soliza", "github:app:org"]);
  });

  test("github stays brokered until a provider-native installation token minter exists", async () => {
    await seedManifestCapability("gh-comment", "github:app:org");
    const app = buildApp(harness!.db, { agent: true });

    const res = await app.request("/capabilities/manifest/github:app:org/issue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ttlSeconds: 90 }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { mode: string; token?: string; delegation: { capabilityName: string } };
    };
    expect(body.data.mode).toBe("broker");
    expect(body.data.token).toBeUndefined();
    expect(body.data.delegation.capabilityName).toBe("gh-comment");

    // audit: exactly one issue/allow/token event.
    expect(
      auditLog.some(
        (e) => e.action === "capability.issue" && e.decision === "allow" && e.mode === "broker",
      ),
    ).toBe(true);
  });

  test("broker mode: discord issue returns a delegation, no token", async () => {
    await seedManifestCapability("discord-send", "discord:bot-token:soliza");
    const app = buildApp(harness!.db, { agent: true });

    const res = await app.request("/capabilities/manifest/discord:bot-token:soliza/issue", {
      method: "POST",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { mode: string; token?: string; delegation: { capabilityName: string } };
    };
    expect(body.data.mode).toBe("broker");
    expect(body.data.token).toBeUndefined();
    expect(body.data.delegation.capabilityName).toBe("discord-send");
    expect(auditLog.some((e) => e.mode === "broker" && e.decision === "allow")).toBe(true);
  });

  test("renew hits the same path (audit action = renew)", async () => {
    await seedManifestCapability("gh-comment", "github:app:org");
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/manifest/github:app:org/renew", {
      method: "POST",
    });
    expect(res.status).toBe(200);
    expect(auditLog.some((e) => e.action === "capability.renew")).toBe(true);
  });

  test("revocation: revoked grant → 403 not_granted at next issue", async () => {
    const store = new CapabilityStore(harness!.db);
    const cap = await seedManifestCapability("gh-comment", "github:app:org");
    // find + revoke the grant
    const grants = await store.listGrantsForCapability(tenantId, cap.id);
    await store.revokeGrant(tenantId, grants[0].id);

    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/manifest/github:app:org/issue", {
      method: "POST",
    });
    expect(res.status).toBe(403);
    expect(auditLog.some((e) => e.decision === "deny")).toBe(true);
  });

  test("brokered GitHub issuance ignores token-only TTL parameters", async () => {
    await seedManifestCapability("gh-comment", "github:app:org");
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/manifest/github:app:org/issue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ttlSeconds: 99999 }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      data: { mode: string; token?: string };
    };
    expect(body.data.mode).toBe("broker");
    expect(body.data.token).toBeUndefined();
  });
});
