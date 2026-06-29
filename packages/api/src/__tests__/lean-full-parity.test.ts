/**
 * lean-full-parity.test.ts — the machine-checkable GO-LIVE GATE for the
 * deploy-time plugin toggle (`STEWARD_PLUGINS`). The SAME composition root
 * (`composeApp()`) runs LEAN (core only) or FULL (core + trading) purely by
 * environment, and this suite proves "clean separation" exhaustively:
 *
 *   1. EVERY trading route 404s in LEAN (genuinely not mounted — core notFound)
 *      and is MOUNTED in FULL (reaches the plugin auth/handler → NOT 404).
 *   2. EVERY core route group is present + behaves IDENTICALLY (same status /
 *      auth-gate) in BOTH modes — the toggle is additive, the core is untouched.
 *   3. Migration parity: lean collects NO trading migrations; full collects the
 *      trading plugin without throwing (routes + migrations always both-on /
 *      both-off, never orphaned).
 *   4. Resolver edge matrix (boot-level smoke over composeApp; the exhaustive
 *      pure-resolver matrix lives in plugin-config.test.ts).
 *   5. Middleware ordering: the LEAN compose path preserves global mw → core auth
 *      → idempotency → core routes.
 *
 * The route lists are ENUMERATED from the trade plugin's actual mounts so the
 * assertions are DATA-DRIVEN: adding a trade route later is automatically
 * covered (LEAN-404 + FULL-mounted), and a core route added to app.ts is covered
 * once its prefix is listed here.
 *
 * SELF-CONTAINED + ISOLATION-SAFE: composeApp() reads process.env.STEWARD_PLUGINS
 * directly, so every case set/restores it around the call (and afterEach scrubs
 * it defensively). The DB/secret bootstrap comes from test-preload.ts (PGLite
 * in-memory). This file passes on its own, run FROM packages/api so bunfig's
 * preload applies:
 *   ~/.bun/bin/bun test src/__tests__/lean-full-parity.test.ts
 */

import { afterEach, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
// STATIC imports (not dynamic): test-preload.ts (bunfig preload) runs first and
// sets up the PGLite runtime + secrets, so evaluating compose.ts -> app.ts ->
// route modules -> context.ts at import time is safe. A static import also forces
// the FULL module graph to initialize in dependency order ONCE, before any test
// runs — which is what makes this file pass in ISOLATION (a per-case dynamic
// import re-enters a half-initialized circular graph and trips a TDZ
// "cannot access X before initialization"; the static import does not).
// NOTE: run from packages/api so bunfig.toml's preload applies.
import { isOperatorRecoveryPath } from "@stwd/plugin-trading";
import { composeApp, runComposedPluginMigrations } from "../compose";

// ─────────────────────────────────────────────────────────────────────────────
// ENUMERATED TRADING ROUTES
//
// Source of truth: packages/plugin-trading/src/
//   - routes/trade.ts            → createTradeRoutes()           (tradeRoutes.*)
//   - routes/operator-recovery.ts → createOperatorRecoveryRoutes() (operatorRecoveryRoutes.*)
//   - index.ts mounts BOTH routers at BOTH "/trade" AND "/v1/trade".
//
// So each leaf below is probed at both prefixes (TRADE_PREFIXES). A leaf is the
// (method, suffix) the router registers; operator-recovery leaves use the real
// venue segment ("hyperliquid") in place of ":venue".
// ─────────────────────────────────────────────────────────────────────────────

const TRADE_PREFIXES = ["/trade", "/v1/trade"] as const;

/** createTradeRoutes() leaves (trade.ts). */
const TRADE_ROUTE_LEAVES: ReadonlyArray<{ method: string; suffix: string }> = [
  { method: "GET", suffix: "/token-status" },
  { method: "POST", suffix: "/sessions" },
  { method: "GET", suffix: "/sessions/sess_probe" }, // /sessions/:id
  { method: "POST", suffix: "/sessions/sess_probe/revoke" }, // /sessions/:id/revoke
  { method: "POST", suffix: "/hyperliquid/order" },
  { method: "POST", suffix: "/polymarket/order" },
];

/**
 * createOperatorRecoveryRoutes() leaves (operator-recovery.ts), all POST
 * "/:venue/<action>". Probed with venue=hyperliquid (the only supported venue;
 * an unsupported venue still REACHES the handler → non-404, so this is a valid
 * "is it mounted" probe). These suffixes are exactly isOperatorRecoveryPath()'s
 * set, which is asserted below to keep the two in lockstep.
 */
const OPERATOR_RECOVERY_ACTIONS = [
  "deposit",
  "leverage",
  "add-margin",
  "usd-send",
  "approve-builder",
  "transfer",
  "close-all",
  "withdraw",
] as const;

const OPERATOR_ROUTE_LEAVES: ReadonlyArray<{ method: string; suffix: string }> =
  OPERATOR_RECOVERY_ACTIONS.map((action) => ({
    method: "POST",
    suffix: `/hyperliquid/${action}`,
  }));

/** Fully-expanded trading route list: every leaf × every mount prefix. */
const TRADE_ROUTES: ReadonlyArray<{ method: string; path: string }> = [
  ...TRADE_ROUTE_LEAVES,
  ...OPERATOR_ROUTE_LEAVES,
].flatMap((leaf) =>
  TRADE_PREFIXES.map((prefix) => ({ method: leaf.method, path: `${prefix}${leaf.suffix}` })),
);

// ─────────────────────────────────────────────────────────────────────────────
// ENUMERATED CORE ROUTES
//
// Source of truth: packages/api/src/app.ts (mountCoreIdempotencyAndRoutes).
// These MUST be present + behave identically regardless of the toggle. For each
// we probe a representative path that, with NO auth headers, returns a STABLE
// status (a non-404 if mounted). Paths are chosen to hit a concrete handler/gate
// (not just the router prefix, which can itself 404 inside a router with no
// "/" handler).
// ─────────────────────────────────────────────────────────────────────────────

/** Always-open core endpoints (no auth) — must be 200 in both modes. */
const CORE_OPEN: ReadonlyArray<{ method: string; path: string; status: number }> = [
  { method: "GET", path: "/", status: 200 },
  { method: "GET", path: "/health", status: 200 },
  { method: "GET", path: "/openapi.json", status: 200 },
];

/**
 * Core route-group probes. Each resolves to a concrete handler or auth gate in
 * the core, so it is NON-404 in both modes and returns the SAME status both
 * sides. Paths are chosen to hit a real handler (not just the router prefix),
 * driving the "core is identical under the toggle" guarantee.
 */
const CORE_GATED: ReadonlyArray<{ method: string; path: string }> = [
  { method: "GET", path: "/agents" }, // agentRoutes — tenant-gated
  { method: "GET", path: "/v1/agents" }, // versioned alias
  { method: "GET", path: "/accounts" }, // accountRoutes — tenant-gated
  { method: "GET", path: "/v1/accounts" },
  { method: "POST", path: "/auth/refresh" }, // authRoutes — present, validates
  { method: "GET", path: "/vault" }, // vaultRoutes
  { method: "GET", path: "/secrets" }, // secretsRoutes
  { method: "GET", path: "/tenants/config" }, // tenantConfigRoutes literal /config handler
  { method: "GET", path: "/dashboard" }, // dashboardRoutes
  { method: "GET", path: "/webhooks" }, // webhookRoutes
  { method: "GET", path: "/approvals" }, // approvalRoutes
  { method: "GET", path: "/intents" }, // intentRoutes
  { method: "GET", path: "/audit" }, // auditRoutes
  { method: "GET", path: "/adapters" }, // adapterRoutes
  { method: "GET", path: "/v1/adapters" },
  { method: "GET", path: "/policies" }, // policiesStandaloneRoutes
  { method: "GET", path: "/platform" }, // platformRoutes
  { method: "GET", path: "/user" }, // userRoutes
  { method: "GET", path: "/global-wallet" }, // globalWalletRoutes
  { method: "POST", path: "/wallets/batch" }, // createAgentBatch (direct mount)
  { method: "POST", path: "/v1/wallets/batch" },
  { method: "GET", path: "/discovery/agents" }, // discoveryRoutes (erc8004) GET /agents handler
];

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Set STEWARD_PLUGINS for one case, returning a restore fn. */
function withPlugins(value: string | undefined): () => void {
  const prev = process.env.STEWARD_PLUGINS;
  if (value === undefined) delete process.env.STEWARD_PLUGINS;
  else process.env.STEWARD_PLUGINS = value;
  return () => {
    if (prev === undefined) delete process.env.STEWARD_PLUGINS;
    else process.env.STEWARD_PLUGINS = prev;
  };
}

/** Boot a fresh composed app under a given STEWARD_PLUGINS value. */
async function bootApp(plugins: string | undefined) {
  const restore = withPlugins(plugins);
  try {
    return await composeApp();
  } finally {
    restore();
  }
}

/** Probe a path with its real method (no body needed to detect mount vs 404). */
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
  // Defensive: never leak STEWARD_PLUGINS into the shared single-process suite.
  delete process.env.STEWARD_PLUGINS;
});

// ─────────────────────────────────────────────────────────────────────────────
// 0) enumeration sanity — the trade list is non-trivial and the operator-recovery
//    probe set is in lockstep with isOperatorRecoveryPath().
// ─────────────────────────────────────────────────────────────────────────────

describe("parity — enumeration sanity", () => {
  it("enumerates a non-trivial set of trading routes (every leaf × both prefixes)", () => {
    // 6 trade leaves + 8 operator leaves = 14 leaves, × 2 prefixes = 28.
    expect(TRADE_ROUTE_LEAVES.length + OPERATOR_ROUTE_LEAVES.length).toBe(14);
    expect(TRADE_ROUTES.length).toBe(28);
    // no duplicate (method,path) probes
    const keys = new Set(TRADE_ROUTES.map((r) => `${r.method} ${r.path}`));
    expect(keys.size).toBe(TRADE_ROUTES.length);
  });

  it("operator-recovery probe actions match isOperatorRecoveryPath() exactly", () => {
    // every action we probe is recognized as an operator-recovery path
    for (const action of OPERATOR_RECOVERY_ACTIONS) {
      expect(isOperatorRecoveryPath(`/v1/trade/hyperliquid/${action}`)).toBe(true);
    }
    // a non-operator trade path is NOT (guards against drift the other way)
    expect(isOperatorRecoveryPath("/v1/trade/token-status")).toBe(false);
    expect(isOperatorRecoveryPath("/v1/trade/sessions")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 1) TRADING ROUTES: 404 in LEAN, MOUNTED in FULL — data-driven over TRADE_ROUTES.
// ─────────────────────────────────────────────────────────────────────────────

describe("parity — trading routes 404 in LEAN (genuinely not mounted)", () => {
  it.each(TRADE_ROUTES)("LEAN 404: $method $path", async ({ method, path }) => {
    const app = await bootApp(undefined);
    const status = await probe(app, method, path);
    // 404 (not 401/500): the route is NOT mounted → core notFound handler.
    expect(status).toBe(404);
  });

  it("LEAN: the core notFound shape is returned for an absent trade route", async () => {
    const app = await bootApp(undefined);
    const res = await app.request("/v1/trade/token-status");
    expect(res.status).toBe(404);
    await expect(res.json()).resolves.toMatchObject({ ok: false });
  });
});

describe("parity — trading routes MOUNTED in FULL (reach plugin, NOT 404)", () => {
  it.each(TRADE_ROUTES)("FULL mounted: $method $path", async ({ method, path }) => {
    const app = await bootApp("trading");
    const status = await probe(app, method, path);
    // mounted → reaches plugin auth/handler: 400/401/403/200 etc, just NOT 404.
    expect(status).not.toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) CORE ROUTES: present + identical status in BOTH modes (additive toggle).
// ─────────────────────────────────────────────────────────────────────────────

describe("parity — core OPEN routes identical + open in BOTH modes", () => {
  it.each(CORE_OPEN)("OPEN parity: $method $path → $status both modes", async ({
    method,
    path,
    status,
  }) => {
    const lean = await probe(await bootApp(undefined), method, path);
    const full = await probe(await bootApp("trading"), method, path);
    expect(lean).toBe(status);
    expect(full).toBe(status);
  });
});

describe("parity — core GATED routes mounted + identical status in BOTH modes", () => {
  it.each(CORE_GATED)("GATED parity: $method $path identical + mounted", async ({
    method,
    path,
  }) => {
    const lean = await probe(await bootApp(undefined), method, path);
    const full = await probe(await bootApp("trading"), method, path);
    // identical regardless of the toggle (core unchanged)
    expect(lean).toBe(full);
    // present in both (the toggle never removes a core route)
    expect(lean).not.toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) MIGRATION PARITY: lean collects NO trading migration; full collects trading
//    (no throw). Routes + migrations are always both-on / both-off.
// ─────────────────────────────────────────────────────────────────────────────

describe("parity — migration composition mirrors route composition", () => {
  it("LEAN: runComposedPluginMigrations() returns NO trading entry (exactly [])", async () => {
    const restore = withPlugins(undefined);
    try {
      const results = await runComposedPluginMigrations();
      expect(results).toEqual([]);
      expect(results.find((r) => r.pluginName === "trading")).toBeUndefined();
    } finally {
      restore();
    }
  });

  it("FULL: runComposedPluginMigrations() collects trading without throwing", async () => {
    // The trading plugin declares NO migration source today (its tables ship via
    // core migrations), so the APPLIED list is still empty in full mode — what
    // this proves is the COLLECTION seam ran with trading enabled (no throw).
    // If/when trading declares a migration source, full-mode applies it into the
    // namespaced table and lean-mode skips it (asserted above).
    const restore = withPlugins("trading");
    try {
      const results = await runComposedPluginMigrations();
      expect(Array.isArray(results)).toBe(true);
      // no trading-applied entry today (no declared source), but the path ran.
      expect(results.find((r) => r.pluginName === "trading")).toBeUndefined();
    } finally {
      restore();
    }
  });

  it("the namespaced plugin-migration table convention is locked to per-plugin isolation", () => {
    // Lock the documented isolation contract at the source level: plugin
    // migrations are written to a per-plugin NAMESPACED bookkeeping table,
    // isolated from the core journal `__drizzle_migrations`. This is the
    // table-name guarantee that pairs with the both-on/both-off collection
    // parity above (compose.ts documents the same).
    const pluginSrc = readFileSync(join(import.meta.dir, "..", "plugin.ts"), "utf8");
    expect(pluginSrc).toContain("__drizzle_migrations_plugin_");
    const composeSrc = readFileSync(join(import.meta.dir, "..", "compose.ts"), "utf8");
    expect(composeSrc).toContain("__drizzle_migrations_plugin_");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4) RESOLVER EDGE MATRIX — boot-level smoke over composeApp (the exhaustive
//    pure-resolver matrix lives in plugin-config.test.ts; here we prove the
//    matrix actually drives compose's lean/full decision).
// ─────────────────────────────────────────────────────────────────────────────

describe("parity — resolver matrix drives compose lean/full", () => {
  const LEAN_VALUES: Array<string | undefined> = [undefined, "", "   ", ",, ,"];
  const FULL_VALUES: string[] = ["trading", "TRADING", "  trading  ", "trading,trading"];

  it.each(
    LEAN_VALUES.map((v) => ({ v })),
  )("LEAN boot for STEWARD_PLUGINS=%o → trade route 404", async ({ v }) => {
    const app = await bootApp(v);
    expect(await probe(app, "GET", "/v1/trade/token-status")).toBe(404);
    // core still healthy
    expect(await probe(app, "GET", "/health")).toBe(200);
  });

  it.each(
    FULL_VALUES.map((v) => ({ v })),
  )("FULL boot for STEWARD_PLUGINS=%o → trade route mounted", async ({ v }) => {
    const app = await bootApp(v);
    expect(await probe(app, "GET", "/v1/trade/token-status")).not.toBe(404);
    expect(await probe(app, "GET", "/health")).toBe(200);
  });

  it("legacy STEWARD_ENABLE_TRADING=true boots FULL", async () => {
    const prevList = process.env.STEWARD_PLUGINS;
    const prevBool = process.env.STEWARD_ENABLE_TRADING;
    delete process.env.STEWARD_PLUGINS;
    process.env.STEWARD_ENABLE_TRADING = "true";
    try {
      const app = await composeApp();
      expect(await probe(app, "GET", "/v1/trade/token-status")).not.toBe(404);
    } finally {
      if (prevList === undefined) delete process.env.STEWARD_PLUGINS;
      else process.env.STEWARD_PLUGINS = prevList;
      if (prevBool === undefined) delete process.env.STEWARD_ENABLE_TRADING;
      else process.env.STEWARD_ENABLE_TRADING = prevBool;
    }
  });

  it("legacy bool + list union still boots FULL (no double-mount, routes work)", async () => {
    const prevList = process.env.STEWARD_PLUGINS;
    const prevBool = process.env.STEWARD_ENABLE_TRADING;
    process.env.STEWARD_PLUGINS = "trading";
    process.env.STEWARD_ENABLE_TRADING = "true";
    try {
      const app = await composeApp();
      expect(await probe(app, "GET", "/v1/trade/token-status")).not.toBe(404);
      expect(await probe(app, "GET", "/health")).toBe(200);
    } finally {
      if (prevList === undefined) delete process.env.STEWARD_PLUGINS;
      else process.env.STEWARD_PLUGINS = prevList;
      if (prevBool === undefined) delete process.env.STEWARD_ENABLE_TRADING;
      else process.env.STEWARD_ENABLE_TRADING = prevBool;
    }
  });

  it("unknown plugin name FAILS CLOSED — composeApp rejects (no silent lean boot)", async () => {
    const restore = withPlugins("bogus-plugin");
    try {
      await expect(composeApp()).rejects.toThrow(/unknown plugin/i);
    } finally {
      restore();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5) MIDDLEWARE ORDERING — the LEAN compose path must preserve the canonical
//    money-rail order: global mw → core auth mw → idempotency → core routes.
//
//    HONESTY NOTE: a true END-TO-END idempotency *replay* needs a SAFE auth
//    context (the middleware deliberately skips unverified requests via
//    isSafeIdempotencyContext — api-key / agent-token / platform-key / MFA'd
//    session), which a test-only suite can't forge without standing up real
//    credentials. So the FULL behavioral replay is owned by
//    idempotency-middleware.test.ts (which builds a minimal safe-context app).
//    Here we prove the part this suite is responsible for: that the LEAN compose
//    path (composeApp with no plugins) wires idempotency AFTER all core auth mw
//    and BEFORE routes — the same ordering FULL uses minus the absent plugin
//    contributions. This is asserted at the SOURCE level (the proven pattern from
//    idempotency-middleware.test.ts) plus a behavioral cross-check that the lean
//    app still RUNS core auth before any handler (a protected core route rejects
//    pre-handler, identically to full).
// ─────────────────────────────────────────────────────────────────────────────

describe("parity — LEAN preserves global mw → core auth → idempotency → routes", () => {
  const appSource = readFileSync(join(import.meta.dir, "..", "app.ts"), "utf8");
  const composeSource = readFileSync(join(import.meta.dir, "..", "compose.ts"), "utf8");

  it("createApp registers GLOBAL mw before CORE auth mw (source order)", () => {
    // global mw (security/cors/logger/correlation) lands before any per-route
    // auth mw, so auth runs with the global context already established.
    const globalIdx = appSource.indexOf('app.use("*", securityHeaders)');
    const firstAuthIdx = appSource.indexOf('app.use("/agents"');
    expect(globalIdx).toBeGreaterThanOrEqual(0);
    expect(firstAuthIdx).toBeGreaterThanOrEqual(0);
    expect(globalIdx).toBeLessThan(firstAuthIdx);
  });

  it("idempotency is installed AFTER all core auth mw and BEFORE core routes", () => {
    // mountCoreIdempotencyAndRoutes installs idempotency, THEN mounts routes.
    const idempotencyIdx = appSource.indexOf('app.use("*", idempotencyMiddleware())');
    const firstRouteIdx = appSource.indexOf('app.route("/", identityDiscoveryRoutes)');
    expect(idempotencyIdx).toBeGreaterThanOrEqual(0);
    expect(firstRouteIdx).toBeGreaterThanOrEqual(0);
    // idempotency before the first route mount
    expect(idempotencyIdx).toBeLessThan(firstRouteIdx);
    // every core auth mw declared in createApp() lands BEFORE idempotency (which
    // is in the later mountCoreIdempotencyAndRoutes section of the same file).
    for (const marker of [
      'app.use("/agents"',
      'app.use("/vault/*"',
      'app.use("/tenants/:id"',
      'app.use("/dashboard/*"',
      'app.use("/webhooks"',
      'app.use("/intents"',
      'app.use("/platform"',
      'app.use("/user"',
    ]) {
      const authIdx = appSource.indexOf(marker);
      expect(authIdx).toBeGreaterThanOrEqual(0);
      expect(authIdx).toBeLessThan(idempotencyIdx);
    }
  });

  it("the LEAN compose branch routes through mountCoreIdempotencyAndRoutes (no plugin defer)", () => {
    // compose.ts's lean branch calls mountCoreIdempotencyAndRoutes(app) directly
    // (the deferred-route machinery only exists to slot a plugin's auth mw before
    // idempotency + its routes after; with no plugin there is nothing to defer),
    // so the lean order is exactly createApp()'s [global mw + core auth] ->
    // idempotency -> core routes.
    expect(composeSource).toContain("mountCoreIdempotencyAndRoutes(app)");
    // the lean early-return happens before any trading import/registration
    const leanReturnIdx = composeSource.indexOf('if (!enabled.has("trading"))');
    const tradingImportIdx = composeSource.indexOf('import("@stwd/plugin-trading")');
    expect(leanReturnIdx).toBeGreaterThanOrEqual(0);
    expect(tradingImportIdx).toBeGreaterThanOrEqual(0);
    expect(leanReturnIdx).toBeLessThan(tradingImportIdx);
  });

  it("BEHAVIORAL: LEAN runs core auth BEFORE the handler (protected route rejects pre-handler)", async () => {
    // A core protected route with NO auth headers must be rejected by the auth mw
    // (which runs before idempotency + before the handler) — never reaching a
    // handler, never 404 (the route IS mounted), identical to full mode. This
    // proves the auth phase is intact in the lean composition.
    const lean = await probe(await bootApp(undefined), "GET", "/agents");
    const full = await probe(await bootApp("trading"), "GET", "/agents");
    expect(lean).toBe(full);
    expect(lean).not.toBe(404); // mounted
    expect(lean).not.toBe(200); // rejected by auth before the handler
  });

  it("BEHAVIORAL: LEAN responds to a known core mutation route (idempotency layer present, not 404)", async () => {
    // /wallets/batch is a core mutating POST mounted AFTER idempotency. Without a
    // safe auth context the idempotency layer correctly SKIPS replay and auth
    // rejects pre-handler — but the route is MOUNTED (not 404), so the request
    // traversed the global mw + auth + idempotency chain rather than falling
    // through to core notFound. (True replay is covered in
    // idempotency-middleware.test.ts with a forged safe context.)
    const a = await probe(await bootApp(undefined), "POST", "/wallets/batch");
    expect(a).not.toBe(404);
  });
});
