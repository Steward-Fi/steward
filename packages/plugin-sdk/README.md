# @stwd/plugin-sdk

the one import for writing a Steward plugin.

a plugin contributes any of: routes (the `register` hook), policy rules, webhook events, db migrations, provider adapters. each is fail-closed.

this package is a thin facade. it re-exports:

- the framework-agnostic contract from `@stwd/shared` (`StewardPlugin`, `PolicyRuleContribution`, `ContributedPolicyRule`, `ContributedPolicyResult`, `PluginMigrationSource`, `AdapterContribution`).
- the concrete, app-bound types + host runtime from `@stwd/api` (`StewardApiPlugin`, `StewardApp`, `StewardAppContext`, `PluginHostDiagnostics`, `LoadedPluginInfo`, plus `buildPluginContext`, `registerPlugin`, `PluginHost`, `PluginHostError`).

```ts
import type { StewardApiPlugin } from "@stwd/plugin-sdk";

export const myPlugin: StewardApiPlugin = {
  name: "my-plugin",
  register(app, ctx) {
    app.get("/my-plugin/ping", (c) => c.json({ ok: true }));
  },
};
```

register it at the composition root:

```ts
import { buildPluginContext, registerPlugin } from "@stwd/plugin-sdk";
import { myPlugin } from "my-plugin";

await registerPlugin(app, myPlugin, buildPluginContext());
```

see `@stwd/plugin-example` for a runnable hello-world, and `docs/plugins/README.md` for the full two-door quickstart.
