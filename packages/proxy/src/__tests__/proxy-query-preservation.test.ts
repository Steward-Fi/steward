/**
 * Governed-request query-preservation integration tests.
 *
 * The proxy handler resolves the upstream target from `c.req.path`, which Hono
 * strips of any query string. Before the fix this meant a governed request such
 * as `GET /github/search/issues?q=foo&page=2` was forwarded upstream as
 * `/search/issues` with the query silently dropped — a correctness bug that
 * breaks paginated / filtered APIs and can change request semantics.
 *
 * These tests drive the real `handleProxy` end-to-end (auth middleware + PGLite
 * DB + vault, network stubbed) and assert that:
 *   - the exact raw query string is forwarded to the upstream,
 *   - duplicate keys keep their ordered pair semantics (no Object collapse),
 *   - blank values, absent query, and percent-encoding are preserved verbatim,
 *   - a query value that looks like an absolute URL stays inert data and never
 *     rewrites the pinned scheme/host/port/path,
 *   - the query cannot influence route matching, and
 *   - userinfo / fragment cannot ride in through the query.
 *
 * Security invariant: preserving the query must not enable authority bypass or
 * target confusion. scheme/host/port/path remain pinned to the configured
 * upstream regardless of query contents.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-query-preservation-master";
const FINE_GRAINED_PAT = "github_pat_11QUERYCASE_examplefinegrainedtokenvalue";

let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handleProxy: typeof import("../handlers/proxy")["handleProxy"];
let proxyMod: typeof import("../handlers/proxy");

// Captures the outbound URL the proxy would have shipped upstream.
let captured: { url: URL; method: string; path: string } | null = null;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-query-preservation-jwt-secret-with-enough-bytes";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ authMiddleware } = await import("../middleware/auth"));
  proxyMod = await import("../handlers/proxy");
  ({ handleProxy } = proxyMod);

  // Pin DNS to a public address so the SSRF guard passes without a real lookup.
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "140.82.112.6", family: 4 }]);
  // Stub the final forward so nothing hits the network; capture the target URL.
  proxyMod.__setForwardProxyRequestForTests(async (url, method) => {
    captured = {
      url: new URL(url.toString()),
      method,
      path: `${url.pathname}${url.search}`,
    };
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
});

function buildApp() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.all("*", handleProxy);
  return app;
}

async function ensureTenant(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
}

async function ensureAgent(tenantId: string, agentId: string) {
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"1".repeat(40)}` })
    .onConflictDoNothing();
}

/**
 * Provision a fresh tenant/agent/secret/route and return a signed agent token.
 * The route governs a single exact path on api.github.com for the given method.
 */
async function provisionRoute(
  pathPattern: string,
  method: string,
  opts: { requiresApproval?: boolean } = {},
): Promise<string> {
  const tenantId = `tenant-q-${crypto.randomUUID()}`;
  const agentId = `agent-q-${crypto.randomUUID()}`;
  await ensureTenant(tenantId);
  await ensureAgent(tenantId, agentId);

  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, `pat-${crypto.randomUUID()}`, FINE_GRAINED_PAT);
  await vault.createRoute(tenantId, secret.id, {
    agentId,
    hostPattern: "api.github.com",
    pathPattern,
    method,
    injectAs: "header",
    injectKey: "authorization",
    injectFormat: "Bearer {value}",
    requiresApproval: opts.requiresApproval ?? false,
  });

  return signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
}

function proxyHeaders(token: string): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    "idempotency-key": crypto.randomUUID(),
  };
}

describe("proxy governed-request query preservation", () => {
  it("forwards a single query key/value upstream", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    const res = await buildApp().request("/github/repos/acme/widgets/issues?state=open", {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    expect(res.status).toBe(200);
    expect(captured?.url.origin).toBe("https://api.github.com");
    expect(captured?.url.pathname).toBe("/repos/acme/widgets/issues");
    expect(captured?.url.search).toBe("?state=open");
  });

  it("preserves ordered duplicate keys without collapsing pairs", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    const res = await buildApp().request(
      "/github/repos/acme/widgets/issues?label=bug&label=urgent&label=p0",
      {
        method: "POST",
        headers: proxyHeaders(token),
        body: JSON.stringify({ hi: 1 }),
      },
    );
    expect(res.status).toBe(200);
    // Exact raw string, in order — a naive Object/fromEntries would drop dupes.
    expect(captured?.url.search).toBe("?label=bug&label=urgent&label=p0");
    expect(captured?.url.searchParams.getAll("label")).toEqual(["bug", "urgent", "p0"]);
  });

  it("preserves a blank query value", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    const res = await buildApp().request("/github/repos/acme/widgets/issues?q=&page=2", {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    expect(res.status).toBe(200);
    expect(captured?.url.search).toBe("?q=&page=2");
  });

  it("does not decode/re-encode a percent-encoded query value", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    // %2F must stay %2F (not become a literal slash), space stays %20.
    const res = await buildApp().request(
      "/github/repos/acme/widgets/issues?q=a%2Fb%20c&sig=%2B%3D",
      {
        method: "POST",
        headers: proxyHeaders(token),
        body: JSON.stringify({ hi: 1 }),
      },
    );
    expect(res.status).toBe(200);
    expect(captured?.url.search).toBe("?q=a%2Fb%20c&sig=%2B%3D");
    // The pinned path is unaffected by an encoded slash in the query.
    expect(captured?.url.pathname).toBe("/repos/acme/widgets/issues");
  });

  it("forwards no query string when the request has none", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    const res = await buildApp().request("/github/repos/acme/widgets/issues", {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    expect(res.status).toBe(200);
    expect(captured?.url.search).toBe("");
    expect(captured?.path).toBe("/repos/acme/widgets/issues");
  });

  it("keeps an absolute-URL-looking query value inert (no authority bypass)", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    // A malicious query value that looks like a full URL to another host must
    // remain data on the pinned upstream, never redirect scheme/host/port/path.
    const evil = encodeURIComponent("https://evil.example.com/steal");
    const res = await buildApp().request(`/github/repos/acme/widgets/issues?next=${evil}`, {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    expect(res.status).toBe(200);
    expect(captured?.url.protocol).toBe("https:");
    expect(captured?.url.host).toBe("api.github.com");
    expect(captured?.url.hostname).toBe("api.github.com");
    expect(captured?.url.port).toBe("");
    expect(captured?.url.pathname).toBe("/repos/acme/widgets/issues");
    expect(captured?.url.username).toBe("");
    expect(captured?.url.password).toBe("");
    expect(captured?.url.hash).toBe("");
    expect(captured?.url.searchParams.get("next")).toBe("https://evil.example.com/steal");
  });

  it("does not let the query influence route matching", async () => {
    captured = null;
    // Route governs ONLY the exact path. A request that adds a query which,
    // if folded into path matching, might match a broader/other route must
    // still resolve against the exact configured path.
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    const res = await buildApp().request(
      "/github/repos/acme/widgets/issues?path=/repos/acme/other",
      {
        method: "POST",
        headers: proxyHeaders(token),
        body: JSON.stringify({ hi: 1 }),
      },
    );
    expect(res.status).toBe(200);
    expect(captured?.url.pathname).toBe("/repos/acme/widgets/issues");
    expect(captured?.url.searchParams.get("path")).toBe("/repos/acme/other");
  });

  it("rejects a query on an approval-gated route (fail closed, not silently dropped)", async () => {
    captured = null;
    // The approval hold/replay path cannot yet round-trip the query, so a
    // query-bearing request on an approval route must be rejected rather than
    // held-and-later-forwarded with the query stripped.
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST", {
      requiresApproval: true,
    });
    const res = await buildApp().request("/github/repos/acme/widgets/issues?state=open", {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    expect(res.status).toBe(400);
    // Nothing was forwarded upstream.
    expect(captured).toBeNull();
    const json = (await res.json()) as { ok: boolean; error: string };
    expect(json.ok).toBe(false);
    expect(json.error).toContain("approval");
  });

  it("still holds an approval-gated request that has no query", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST", {
      requiresApproval: true,
    });
    const res = await buildApp().request("/github/repos/acme/widgets/issues", {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    // Held for approval, not forwarded.
    expect(res.status).toBe(202);
    expect(captured).toBeNull();
    const json = (await res.json()) as { status: string };
    expect(json.status).toBe("pending_approval");
  });

  it("treats requests differing only by query as distinct for idempotency", async () => {
    // Same tenant/agent/route/method/body + same Idempotency-Key but different
    // query must NOT collide: the query is part of the forwarded request and
    // therefore part of the replay identity.
    const tenantId = `tenant-idem-${crypto.randomUUID()}`;
    const agentId = `agent-idem-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(
      tenantId,
      `pat-${crypto.randomUUID()}`,
      FINE_GRAINED_PAT,
    );
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/widgets/issues",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });
    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
    const body = JSON.stringify({ hi: 1 });
    const headersWith = (idem: string) => ({
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "idempotency-key": idem,
    });

    // Two distinct operations (different query) with distinct keys both succeed —
    // the query is faithfully forwarded and neither is mistaken for the other.
    captured = null;
    const first = await buildApp().request("/github/repos/acme/widgets/issues?id=1", {
      method: "POST",
      headers: headersWith(crypto.randomUUID()),
      body,
    });
    expect(first.status).toBe(200);
    expect(captured?.url.search).toBe("?id=1");

    captured = null;
    const second = await buildApp().request("/github/repos/acme/widgets/issues?id=2", {
      method: "POST",
      headers: headersWith(crypto.randomUUID()),
      body,
    });
    expect(second.status).toBe(200);
    expect(captured?.url.search).toBe("?id=2");

    // Reusing ONE key for two different queries must be detected as a DIFFERENT
    // request (409 "different"), not silently swallowed as a replay of the first.
    const sharedKey = crypto.randomUUID();
    const a = await buildApp().request("/github/repos/acme/widgets/issues?id=1", {
      method: "POST",
      headers: headersWith(sharedKey),
      body,
    });
    expect(a.status).toBe(200);
    const b = await buildApp().request("/github/repos/acme/widgets/issues?id=2", {
      method: "POST",
      headers: headersWith(sharedKey),
      body,
    });
    expect(b.status).toBe(409);
    const bJson = (await b.json()) as { error: string };
    // The fix makes the fingerprint query-aware: same key + different query is a
    // "different request" conflict, not an "already forwarded" replay hit.
    expect(bJson.error).toContain("different");

    // Same key + SAME query + SAME body => a genuine replay (409 "forwarded").
    const replayKey = crypto.randomUUID();
    const r1 = await buildApp().request("/github/repos/acme/widgets/issues?id=9", {
      method: "POST",
      headers: headersWith(replayKey),
      body,
    });
    expect(r1.status).toBe(200);
    const r2 = await buildApp().request("/github/repos/acme/widgets/issues?id=9", {
      method: "POST",
      headers: headersWith(replayKey),
      body,
    });
    expect(r2.status).toBe(409);
    const r2Json = (await r2.json()) as { error: string };
    expect(r2Json.error).toContain("forwarded");
  });

  it("rejects a fragment smuggled in the request target (no fragment forwarded)", async () => {
    captured = null;
    const token = await provisionRoute("/repos/acme/widgets/issues", "POST");
    // A fragment is not part of the request-target sent over the wire; even if a
    // client encodes one, it must never appear on the outbound URL.
    const res = await buildApp().request("/github/repos/acme/widgets/issues?a=1#frag", {
      method: "POST",
      headers: proxyHeaders(token),
      body: JSON.stringify({ hi: 1 }),
    });
    expect(res.status).toBe(200);
    expect(captured?.url.hash).toBe("");
    expect(captured?.url.search).toBe("?a=1");
  });
});
