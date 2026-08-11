# @stwd/plugin-example

the smallest honest Steward plugin. the runnable reference for writing one.

it exercises all of the plugin contract's contribution points in the minimal way, importing ONLY from `@stwd/plugin-sdk`:

1. route - `register(app, ctx)` mounts `GET /example/ping` -> `{ ok: true }`.
2. policy rule - a custom `example-business-hours` rule the engine evaluates.
3. webhook event - declares `example.pinged`.
4. migration - points at this package's own `drizzle/` folder (one `CREATE TABLE example_log`), applied into a per-plugin namespaced bookkeeping table, isolated from the core journal.
5. adapter - a trivial `push` provider (`example-push`).

enable it at the composition root:

```ts
import { buildPluginContext, registerPlugin } from "@stwd/plugin-sdk";
import { examplePlugin } from "@stwd/plugin-example";

await registerPlugin(app, examplePlugin, buildPluginContext());
```

the end-to-end test (`src/__tests__/example-plugin.test.ts`) registers the plugin through the public sdk surface and asserts every contribution point landed: the route responds, the policy rule is consulted, the webhook event is in the registry, the adapter resolves, and the migration source is collected. that test is the proof an end-to-end plugin works through `@stwd/plugin-sdk` alone.

see `docs/plugins/README.md` for the full quickstart.
