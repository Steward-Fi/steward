# steward plugins

steward is a lean open core plus opt-in plugins. there are two doors.

- door 1: you want a turnkey core (auth + embedded wallet + policy). run it, point your app at it, done.
- door 2: you want to extend it. write a plugin that contributes routes, policy rules, webhook events, db migrations, or provider adapters, and register it at the composition root.

the core never imports a plugin, and a plugin never imports the core. everything a plugin needs is injected. that keeps the dependency one-directional (no cycle), and an install that only wants the core never pulls a plugin's transitive deps (smaller install, smaller supply-chain + audit surface).

---

## door 1 - use the turnkey core (operator)

the lean core gives you, out of the box:

- auth (sessions, jwts, the login methods you enable)
- an embedded wallet / vault (key custody + signing, fail-closed)
- a policy engine (spending limits, address allow/blocklists, rate limits, time windows, and more)
- a proxy + webhooks surface

you compose the deployable app from the core and any plugins you want. the entrypoint calls `composeApp()`, which builds the lean core and registers this repo's opt-in plugins:

```ts
// the deployable server entrypoint (already wired in @stwd/api).
import { composeApp } from "@stwd/api/compose";

const app = await composeApp(); // lean core + opt-in plugins
// serve `app` with your runtime (Bun.serve, Workers, ...).
```

minimum env to boot the core:

- `DATABASE_URL` - your Postgres connection string (or run the bundled PGLite for local/dev).
- `STEWARD_MASTER_PASSWORD` - the vault master secret. required; the hardened guard rejects dev-weak values.
- `STEWARD_JWT_SECRET` - the jwt signing secret (full entropy).
- `STEWARD_AUDIT_HMAC_KEY` - the audit-log hmac key.

migrations run at boot before the server accepts traffic. that's it - the core is up.

---

## door 2 - write a plugin (author)

a plugin is one object. you import everything from a single package:

```ts
import type { StewardApiPlugin } from "@stwd/plugin-sdk";
```

`@stwd/plugin-sdk` is the one import for writing a plugin. it re-exports the plugin contract + the host runtime. a plugin contributes any of five things, each optional, each fail-closed:

### the plugin object

```ts
import type { StewardApiPlugin } from "@stwd/plugin-sdk";

export const myPlugin: StewardApiPlugin = {
  name: "my-plugin",
  version: "0.1.0",
  // dependsOn: ["other-plugin"], // optional: ordered + fail-closed on missing/cyclic
  // ...contributions below
};
```

### 1. route - `register(app, ctx)`

mount hono routes/middleware onto the core app. `ctx` is injected: it carries the shared service singletons (db, vault, policy engine, ...) and the auth middleware to gate your routes (`requireAgentJwt`, `operatorAuth`, `tenantAuth`).

```ts
register(app, ctx) {
  app.get("/example/ping", (c) => c.json({ ok: true }));
  // gate a route: app.post("/example/do", ctx.requireAgentJwt, handler);
}
```

### 2. policy rule

contribute a custom rule `type` the core's closed policy union does not enumerate. the engine consults your evaluator for that type and uses the verdict.

```ts
policyRules: [
  {
    type: "example-business-hours",
    description: "passes only inside a configured UTC hour window.",
    evaluate(rule, ctx) {
      const passed = new Date().getUTCHours() < 17;
      return { policyId: rule.id, type: rule.type, passed };
    },
  },
],
```

### 3. webhook event

declare event-type names your plugin emits. the host merges them into the runtime registry (core union ∪ plugin-declared) so the webhook config/dispatch path accepts them.

```ts
webhookEvents: ["example.pinged"],
```

### 4. migration

point at your plugin's OWN drizzle migrations folder (with its own `meta/_journal.json`). the host applies it after the core migrator, into a per-plugin namespaced bookkeeping table - never the core journal.

```ts
import { fileURLToPath } from "node:url";

migrations: {
  id: "example",
  migrationsFolder: fileURLToPath(new URL("../drizzle", import.meta.url)),
},
```

### 5. adapter

contribute a real provider integration under a known adapter category (swap, earn, onramp, offramp, kyc, tos, custodial, push, bridge, spark, exchange).

```ts
adapters: [
  {
    category: "push",
    provider: "example-push",
    adapter: myPushAdapter, // implements the category's interface
  },
],
```

### register it (composition root)

an operator enables your plugin where the app is composed - not inside the core:

```ts
import { buildPluginContext, registerPlugin } from "@stwd/plugin-sdk";
import { myPlugin } from "my-plugin";

await registerPlugin(app, myPlugin, buildPluginContext());
```

compose several plugins with `PluginHost` for dependency ordering + diagnostics:

```ts
import { PluginHost, buildPluginContext } from "@stwd/plugin-sdk";

const host = new PluginHost();
await host.register(app, buildPluginContext(), pluginA, pluginB);
console.log(host.describe()); // loaded plugins + every contribution
```

### fail-closed guarantees

the host refuses to compose an ambiguous or unsafe surface. a plugin:

- cannot shadow a core policy rule type, and cannot reuse a rule type another plugin already registered.
- cannot write into or read from the core migration journal - its migration ledger lives in its own namespaced table (`drizzle.__drizzle_migrations_plugin_<id>`).
- cannot silently overwrite a registered adapter - a `(category, provider)` collision throws, as does an unknown category, an empty provider, or a missing adapter instance.
- cannot register against a half-built dependency - a missing or cyclic `dependsOn`, or a duplicate plugin name, throws before anything registers.

### runnable reference

`@stwd/plugin-example` is the smallest honest plugin: it exercises all five contribution points and imports only from `@stwd/plugin-sdk`. read `packages/plugin-example/src/index.ts` and its end-to-end test for a working template.
