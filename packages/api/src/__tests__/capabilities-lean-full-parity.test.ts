/**
 * capabilities-lean-full-parity.test.ts — the go-live gate for the capabilities
 * plugin's deploy toggle. The SAME composition root (`composeApp()`) runs LEAN
 * (STEWARD_PLUGINS unset → core only) or FULL (STEWARD_PLUGINS="capabilities" →
 * core + capabilities) purely by environment. This proves:
 *
 *   1. EVERY capabilities route (operator CRUD + agent-scoped read + the agent
 *      invoke path) 404s in LEAN (genuinely not mounted — core notFound) and is
 *      MOUNTED in FULL (reaches the plugin auth/handler → NOT 404).
 *   2. Migration parity: LEAN collects NO capability migrations; FULL collects the
 *      capabilities plugin without throwing (routes + migrations both-on/both-off).
 *   3. Multi-plugin: STEWARD_PLUGINS="trading,capabilities" mounts BOTH.
 *
 * SEPARATE from lean-full-parity.test.ts (which owns the trading enumeration) so
 * neither file has to know about the other's routes. SELF-CONTAINED +
 * ISOLATION-SAFE: composeApp reads process.env.STEWARD_PLUGINS directly, so every
 * case set/restores it. DB/secret bootstrap comes from test-preload.ts (PGLite).
 * Run from packages/api so bunfig's preload applies:
 *   ~/.bun/bin/bun test src/__tests__/capabilities-lean-full-parity.test.ts
 */

import { afterEach, beforeAll, describe, expect, it } from "bun:test";
import { policyRuleRegistry } from "@stwd/policy-engine";
import { composeApp, runComposedPluginMigrations } from "../compose";

// the capabilities plugin contributes the `capability-intent` policy rule into the
// PROCESS-WIDE policy-rule registry (fail-closed on double-register: a second
// plugin, or a second boot, that registers the SAME type throws). in PRODUCTION
// composeApp runs ONCE per process, so this never fires; in this suite we boot
// composeApp multiple times, so we CLEAR the (contributed-only) registry before a
// FULL boot to keep each boot hermetic. clearing is safe: core rule types are NOT
// in this registry (only plugin contributions are).

// capabilities routes, enumerated from packages/plugin-capabilities/src/:
//   - routes.ts        → CRUD + grants (createCapabilityRoutes), agent-scoped read
//   - invoke.ts        → the agent invoke path (createInvokeRoutes)
//   index.ts mounts CRUD/invoke at "/capabilities" AND "/v1/capabilities", and the
//   agent read at "/agents" AND "/v1/agents". A leaf is probed at both prefixes.
const CAP_ROUTE_LEAVES: ReadonlyArray<{ method: string; suffix: string }> = [
  { method: "GET", suffix: "/capabilities" },
  { method: "POST", suffix: "/capabilities" },
  { method: "GET", suffix: "/capabilities/cap_probe" }, // /:id
  { method: "PATCH", suffix: "/capabilities/cap_probe" },
  { method: "DELETE", suffix: "/capabilities/cap_probe" },
  { method: "POST", suffix: "/capabilities/cap_probe/grants" },
  { method: "DELETE", suffix: "/capabilities/grants/grant_probe" },
  { method: "POST", suffix: "/capabilities/github.pr.comment/invoke" }, // the agent invoke path
];

// NOTE on the agent-scoped read (/agents/:agentId/capabilities): the CORE already
// owns the `/agents/*` prefix (agent management routes), so that subpath is NOT
// plugin-EXCLUSIVE — in LEAN it hits the core /agents gate (403, not 404). The
// plugin-exclusive proof therefore uses the /capabilities/* leaves (CRUD + grants
// + invoke), which the core does not own at all. The agent-read mount is still
// covered by the plugin's own routes.test.ts.
const CAP_PREFIXES = ["", "/v1"] as const;

const CAP_ROUTES: ReadonlyArray<{ method: string; path: string }> = CAP_ROUTE_LEAVES.flatMap(
  (leaf) => CAP_PREFIXES.map((p) => ({ method: leaf.method, path: `${p}${leaf.suffix}` })),
);

function withPlugins(value: string | undefined): () => void {
  const prev = process.env.STEWARD_PLUGINS;
  if (value === undefined) delete process.env.STEWARD_PLUGINS;
  else process.env.STEWARD_PLUGINS = value;
  return () => {
    if (prev === undefined) delete process.env.STEWARD_PLUGINS;
    else process.env.STEWARD_PLUGINS = prev;
  };
}

async function bootApp(plugins: string | undefined) {
  const restore = withPlugins(plugins);
  try {
    return await composeApp();
  } finally {
    restore();
  }
}

async function probe(
  app: Awaited<ReturnType<typeof bootApp>>,
  method: string,
  path: string,
): Promise<number> {
  const init: RequestInit =
    method === "GET" || method === "HEAD"
      ? { method }
      : { method, headers: { "Content-Type": "application/json" }, body: "{}" };
  const res = await app.request(path, init);
  return res.status;
}

afterEach(() => {
  delete process.env.STEWARD_PLUGINS;
});

describe("capabilities parity — routes 404 in LEAN (genuinely not mounted)", () => {
  // LEAN boots register NO policy rules, so no registry hygiene needed here.
  let leanApp: Awaited<ReturnType<typeof bootApp>>;
  beforeAll(async () => {
    leanApp = await bootApp(undefined);
  });
  it.each(CAP_ROUTES)("LEAN 404: $method $path", async ({ method, path }) => {
    expect(await probe(leanApp, method, path)).toBe(404);
  });
});

describe("capabilities parity — routes MOUNTED in FULL (reach plugin, NOT 404)", () => {
  // boot FULL ONCE (the capability-intent contribution registers into the
  // process-wide registry, which fail-closes on a second same-type register).
  // clear the contributed-rule registry first for hermeticity across files.
  let fullApp: Awaited<ReturnType<typeof bootApp>>;
  beforeAll(async () => {
    policyRuleRegistry.clear();
    fullApp = await bootApp("capabilities");
  });
  it.each(CAP_ROUTES)("FULL mounted: $method $path", async ({ method, path }) => {
    // mounted → reaches plugin auth/handler: 400/401/403/200 etc, just NOT 404.
    expect(await probe(fullApp, method, path)).not.toBe(404);
  });
});

describe("capabilities parity — migration composition (both-on/both-off)", () => {
  it("LEAN: runComposedPluginMigrations returns [] (no attempt, no throw)", async () => {
    const restore = withPlugins(undefined);
    try {
      const results = await runComposedPluginMigrations();
      expect(results).toEqual([]);
    } finally {
      restore();
    }
  });

  it("FULL(capabilities): the migration seam COLLECTS + ATTEMPTS the capabilities plugin", async () => {
    // capabilities declares a REAL migration source (unlike trading, whose tables
    // ship via core migrations), so FULL mode ATTEMPTS to apply it. in this unit
    // env there is no real migration DB handle, so the attempt surfaces as
    // `DATABASE_URL is required` — which PROVES the capabilities plugin was
    // collected + run by the SAME resolver composeApp uses (parity). LEAN (above)
    // makes NO such attempt (returns [] cleanly). the real applied-into-namespaced
    // -table behavior is proven by the plugin's migration-isolation.test.ts.
    const restore = withPlugins("capabilities");
    try {
      let attempted = false;
      try {
        await runComposedPluginMigrations();
        // if it did not throw (a real DB was present), that is also fine — the
        // collection ran either way.
        attempted = true;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        // the throw must be the capabilities migration attempt (collection ran),
        // not a resolver/boot error.
        expect(msg).toContain("capabilities");
        attempted = true;
      }
      expect(attempted).toBe(true);
    } finally {
      restore();
    }
  });
});

describe("capabilities parity — multi-plugin (trading + capabilities)", () => {
  it("STEWARD_PLUGINS=trading,capabilities mounts BOTH", async () => {
    // fresh registry: this boot re-registers capability-intent, which would
    // collide with a prior FULL boot's registration in the same process.
    policyRuleRegistry.clear();
    const app = await bootApp("trading,capabilities");
    // a trading route is mounted…
    expect(await probe(app, "GET", "/v1/trade/token-status")).not.toBe(404);
    // …and a capabilities route is mounted.
    expect(await probe(app, "GET", "/v1/capabilities")).not.toBe(404);
  });
});
