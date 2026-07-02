/**
 * store-lifecycle.test.ts - the paired secret_route lifecycle + validation matrix.
 *
 * proves the KEY invariant: NO orphaned enabled routes in any path (create ->
 * route exists+enabled; disable/revoke/expire -> route disabled/gone; delete ->
 * gone), grant-expiry semantics, and the validation matrix (strict-host github
 * rejections, off-allowlist host rejected) via the shared validator.
 */

import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { CapabilityStore } from "../store";
import { validateCapabilitySpec } from "../validate";
import {
  enabledRouteCount,
  ensureAgent,
  ensureSecret,
  ensureTenant,
  getRoute,
  type Harness,
  makeHarness,
  totalRouteCount,
} from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
let store: CapabilityStore;
let tenantId: string;
let secretId: string;

const GH_SPEC = {
  host: "api.github.com",
  pathPattern: "/repos/acme/widgets/issues/1/comments",
  method: "POST",
  injectKey: "authorization",
  injectFormat: "Bearer {value}",
};

beforeEach(async () => {
  harness = await makeHarness();
  store = new CapabilityStore(harness.db);
  tenantId = `tenant-${crypto.randomUUID()}`;
  await ensureTenant(harness.db, tenantId);
  secretId = await ensureSecret(harness.db, tenantId, "github-pat");
});

afterEach(async () => {
  await harness?.close();
  harness = null;
});

async function createGithubCapability(name = "github.pr.comment", enabled = true) {
  const v = validateCapabilitySpec({ secretId, ...GH_SPEC });
  if (!v.ok) throw new Error(`spec invalid: ${v.error}`);
  return store.createCapability({ tenantId, name, spec: v.spec, constraints: {}, enabled });
}

describe("validation matrix (shared secret-route validator, strict hosts)", () => {
  test("accepts a narrow github capability", () => {
    const v = validateCapabilitySpec({ secretId, ...GH_SPEC });
    expect(v.ok).toBe(true);
  });

  test("rejects github with a wildcard method (broad-method + strict host)", () => {
    const v = validateCapabilitySpec({ secretId, ...GH_SPEC, method: "*" });
    expect(v.ok).toBe(false);
    // rejected by the broad-method guard (evaluated before strict-host); either
    // way a wildcard method never reaches a github capability.
    if (!v.ok) expect(v.error).toMatch(/broad method|explicit HTTP method/i);
  });

  test("rejects github with a valid-but-non-github method omitted via GET narrowness still needs 2 segments", () => {
    // a concrete method that is NOT the broad wildcard still must satisfy the
    // strict-host path-depth rule; a shallow path is rejected with the strict msg.
    const v = validateCapabilitySpec({
      secretId,
      ...GH_SPEC,
      pathPattern: "/repos",
      method: "GET",
    });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toMatch(/at least 2 segments/i);
  });

  test("rejects github with < 2 path segments (strict host)", () => {
    const v = validateCapabilitySpec({ secretId, ...GH_SPEC, pathPattern: "/repos" });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toMatch(/at least 2 segments/i);
  });

  test("rejects github with a path wildcard (strict host)", () => {
    const v = validateCapabilitySpec({ secretId, ...GH_SPEC, pathPattern: "/repos/acme/*" });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toMatch(/exact path.*no.*wildcard/i);
  });

  test("rejects an off-allowlist host", () => {
    const v = validateCapabilitySpec({
      secretId,
      host: "evil.example.com",
      pathPattern: "/v1/x",
      method: "POST",
      injectKey: "authorization",
    });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toMatch(/allowlist/i);
  });

  test("rejects localhost / internal host", () => {
    const v = validateCapabilitySpec({
      secretId,
      host: "localhost",
      pathPattern: "/v1/x",
      method: "POST",
      injectKey: "authorization",
    });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toMatch(/localhost|internal|allowlist/i);
  });

  test("rejects a blocked inject header (host framing)", () => {
    const v = validateCapabilitySpec({
      secretId,
      host: "api.openai.com",
      pathPattern: "/v1/chat/completions",
      method: "POST",
      injectKey: "host",
    });
    expect(v.ok).toBe(false);
  });
});

describe("capability create: no grants -> no routes (fail-closed by construction)", () => {
  test("creating a capability materializes zero routes", async () => {
    const cap = await createGithubCapability();
    expect(cap.enabled).toBe(true);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
  });
});

describe("grant create -> paired route exists + enabled", () => {
  test("a grant to an enabled capability creates one enabled route", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");

    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    expect(res).not.toBeNull();
    expect(res?.route).not.toBeNull();
    expect(res?.grant.secretRouteId).toBe(res?.route?.id ?? null);

    const route = await getRoute(harness!.db, res!.route!.id);
    expect(route.enabled).toBe(true);
    expect(route.agentId).toBe("agent-a");
    expect(route.hostPattern).toBe("api.github.com");
    expect(route.method).toBe("POST");
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(1);
  });

  test("two agents granted -> two routes (per-GRANT pairing)", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    await ensureAgent(harness!.db, tenantId, "agent-b");
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-b",
      expiresAt: null,
    });
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(2);
  });

  test("grant to an unknown agent throws and creates no route", async () => {
    const cap = await createGithubCapability();
    await expect(
      store.createGrant({ tenantId, capabilityId: cap.id, agentId: "ghost", expiresAt: null }),
    ).rejects.toThrow(/not found/i);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
  });

  test("grant to a missing capability returns null, no route", async () => {
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const res = await store.createGrant({
      tenantId,
      capabilityId: crypto.randomUUID(),
      agentId: "agent-a",
      expiresAt: null,
    });
    expect(res).toBeNull();
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
  });

  test("granting an expired-at-creation grant creates a DISABLED route", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const past = new Date(Date.now() - 60_000);
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: past,
      now: new Date(),
    });
    const route = await getRoute(harness!.db, res!.route!.id);
    expect(route.enabled).toBe(false);
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
  });
});

describe("capability disable/enable -> paired routes track fail-closed", () => {
  test("disable disables every paired route; enable re-enables active grants", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    await ensureAgent(harness!.db, tenantId, "agent-b");
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-b",
      expiresAt: null,
    });
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(2);

    // disable -> both routes off (no orphaned enabled route)
    await store.updateCapability(tenantId, cap.id, { enabled: false });
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(2); // rows kept, disabled

    // re-enable -> both active grants' routes back on
    await store.updateCapability(tenantId, cap.id, { enabled: true });
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(2);
  });

  test("enabling does NOT re-enable a revoked grant's route (there is none)", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.revokeGrant(tenantId, res!.grant.id);
    await store.updateCapability(tenantId, cap.id, { enabled: false });
    await store.updateCapability(tenantId, cap.id, { enabled: true });
    // revoked grant's route was deleted; nothing to re-enable.
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
  });

  test("enabling a capability with an expired grant leaves that route disabled", async () => {
    const cap = await createGithubCapability("github.pr.comment", false);
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const future = new Date(Date.now() + 3_600_000);
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: future,
    });
    // capability was created disabled, so route starts disabled
    expect((await getRoute(harness!.db, res!.route!.id)).enabled).toBe(false);
    // enable the capability but evaluate expiry as if we are PAST the expiry
    await store.updateCapability(
      tenantId,
      cap.id,
      { enabled: true },
      new Date(future.getTime() + 1000),
    );
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
  });
});

describe("capability update: routing narrows the live route (no widen-by-patch)", () => {
  test("patching the path rewrites the paired route's path", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    const newPath = "/repos/acme/widgets/issues/2/comments";
    const v = validateCapabilitySpec({ secretId, ...GH_SPEC, pathPattern: newPath });
    if (!v.ok) throw new Error(v.error);
    await store.updateCapability(tenantId, cap.id, { spec: v.spec });
    const route = await getRoute(harness!.db, res!.route!.id);
    expect(route.pathPattern).toBe(newPath);
    expect(route.enabled).toBe(true);
  });
});

describe("grant revoke -> paired route deleted", () => {
  test("revoke deletes the route and marks the grant revoked", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    const ok = await store.revokeGrant(tenantId, res!.grant.id);
    expect(ok).toBe(true);
    expect(await getRoute(harness!.db, res!.route!.id)).toBeNull();
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
    const grant = await store.getGrantById(tenantId, res!.grant.id);
    expect(grant?.status).toBe("revoked");
    expect(grant?.secretRouteId).toBeNull();
  });

  test("revoke is idempotent and never leaves an orphaned enabled route", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.revokeGrant(tenantId, res!.grant.id);
    await store.revokeGrant(tenantId, res!.grant.id); // second time: no-op
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
  });

  test("revoke of a nonexistent grant returns false", async () => {
    const ok = await store.revokeGrant(tenantId, crypto.randomUUID());
    expect(ok).toBe(false);
  });
});

describe("capability delete -> all paired routes gone (no orphans)", () => {
  test("delete removes every route + grant + the capability", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    await ensureAgent(harness!.db, tenantId, "agent-b");
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-b",
      expiresAt: null,
    });
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(2);

    const removed = await store.deleteCapability(tenantId, cap.id);
    expect(removed).toBe(true);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
    expect(await store.getCapabilityById(tenantId, cap.id)).toBeNull();
    expect(await store.listGrantsForCapability(tenantId, cap.id)).toHaveLength(0);
  });

  test("delete of a nonexistent capability returns false", async () => {
    const removed = await store.deleteCapability(tenantId, crypto.randomUUID());
    expect(removed).toBe(false);
  });
});

describe("grant expiry semantics (usable-by-agent listing)", () => {
  test("expired grant is not listed as usable; unexpired is", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    await ensureAgent(harness!.db, tenantId, "agent-b");
    const future = new Date(Date.now() + 3_600_000);
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: future,
    });
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-b",
      expiresAt: future,
    });

    // as of now: both usable
    const now = new Date();
    expect(await store.listUsableCapabilitiesForAgent(tenantId, "agent-a", now)).toHaveLength(1);
    // as of after expiry: none usable
    const later = new Date(future.getTime() + 1000);
    expect(await store.listUsableCapabilitiesForAgent(tenantId, "agent-a", later)).toHaveLength(0);
  });

  test("revoked grant is not listed as usable", async () => {
    const cap = await createGithubCapability();
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const res = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.revokeGrant(tenantId, res!.grant.id);
    expect(await store.listUsableCapabilitiesForAgent(tenantId, "agent-a")).toHaveLength(0);
  });

  test("disabled capability is not listed as usable", async () => {
    const cap = await createGithubCapability("github.pr.comment", true);
    await ensureAgent(harness!.db, tenantId, "agent-a");
    await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId: "agent-a",
      expiresAt: null,
    });
    await store.updateCapability(tenantId, cap.id, { enabled: false });
    expect(await store.listUsableCapabilitiesForAgent(tenantId, "agent-a")).toHaveLength(0);
  });
});
