/**
 * plugin-config.ts — deploy-time plugin enablement resolver.
 *
 * WHY THIS EXISTS
 * ---------------
 * the composition root (`compose.ts`) assembles the deployable server: the lean
 * core (`createApp()`) plus this deploy's opt-in plugins. historically that set
 * was HARDCODED — `composeApp()` always registered the trading plugin and
 * `runComposedPluginMigrations()` always collected its migrations. that coupled
 * the SHIPPED IMAGE to a single feature profile: every deploy ran trading,
 * whether or not it was wanted.
 *
 * this resolver makes the same image run LEAN (core only) or FULL (core + opt-in
 * plugins) purely by ENVIRONMENT, with NO change to what any plugin does. it only
 * answers ONE question: "which opt-in plugins should the composition root
 * register?" the actual registration, ordering, and migration logic is untouched
 * (see compose.ts) — this only gates WHETHER trading is composed in, never HOW.
 *
 * THE CONTRACT
 * ------------
 *   - `STEWARD_PLUGINS` — comma-separated plugin names, e.g. "trading". each name
 *     is trimmed + lowercased. empty/unset → LEAN (no opt-in plugins).
 *   - `STEWARD_ENABLE_TRADING=true` — legacy boolean that ALSO enables trading
 *     (union with STEWARD_PLUGINS), so an older deploy config keeps working.
 *   - an UNKNOWN plugin name in `STEWARD_PLUGINS` → THROW at boot. fail-closed +
 *     loud: a typo'd / unsupported plugin name never silently disables a feature
 *     a deploy expected, it refuses to boot with a clear error.
 *
 * PARITY (load-bearing)
 * ---------------------
 * BOTH the app-composition path (`composeApp`) and the migration-composition path
 * (`runComposedPluginMigrations`) call THIS resolver, so a plugin's routes and
 * its migrations are always BOTH-on or BOTH-off. they can never drift into an
 * orphaned state (routes mounted with no schema, or schema migrated with no
 * routes). the single source of truth is here.
 */

/**
 * The closed set of opt-in plugin names this composition root knows how to
 * register. An entry in `STEWARD_PLUGINS` that is NOT in this set is a
 * fail-closed boot error (see {@link resolveEnabledPlugins}). Kept as the single
 * authority for "what can be enabled" so adding a plugin is a one-line change
 * here plus its registration in compose.ts.
 */
export const KNOWN_PLUGIN_NAMES = new Set<string>(["trading", "capabilities"]);

/**
 * Error thrown when `STEWARD_PLUGINS` names a plugin this composition root does
 * not know how to register. The boot path surfaces it and refuses to start
 * (fail-closed + loud) rather than silently dropping the unknown name — a typo or
 * an unsupported plugin must never look like a successful lean boot.
 */
export class UnknownPluginError extends Error {
  constructor(name: string, known: readonly string[]) {
    super(
      `unknown plugin "${name}" in STEWARD_PLUGINS. ` +
        `known plugins: ${known.length > 0 ? known.join(", ") : "(none)"}.`,
    );
    this.name = "UnknownPluginError";
  }
}

/**
 * Resolve which opt-in plugins this deploy should register, from the environment.
 *
 * Reads:
 *   - `STEWARD_PLUGINS` — comma-separated names (trimmed, lowercased, empties
 *     dropped). unset/empty → no plugins (LEAN).
 *   - `STEWARD_ENABLE_TRADING` — legacy boolean; `"true"` (case-insensitive,
 *     trimmed) ALSO adds "trading" to the set.
 *
 * FAILS CLOSED: any name in `STEWARD_PLUGINS` not in {@link KNOWN_PLUGIN_NAMES}
 * throws {@link UnknownPluginError}. The legacy boolean only ever adds a KNOWN
 * name, so it cannot trip the unknown-name guard.
 *
 * @param env the environment to read. defaults to `process.env`; injectable so
 *   tests can drive it hermetically without mutating the real process env.
 * @returns the set of enabled plugin names (lowercased). empty in LEAN mode.
 */
export function resolveEnabledPlugins(
  env: Record<string, string | undefined> = process.env,
): Set<string> {
  const enabled = new Set<string>();

  const raw = env.STEWARD_PLUGINS;
  if (typeof raw === "string" && raw.trim() !== "") {
    for (const part of raw.split(",")) {
      const name = part.trim().toLowerCase();
      if (name === "") continue;
      if (!KNOWN_PLUGIN_NAMES.has(name)) {
        throw new UnknownPluginError(name, [...KNOWN_PLUGIN_NAMES]);
      }
      enabled.add(name);
    }
  }

  // Legacy boolean: STEWARD_ENABLE_TRADING=true unions "trading" into the set, so
  // an older deploy config that predates STEWARD_PLUGINS keeps enabling trading.
  const legacyTrading = env.STEWARD_ENABLE_TRADING;
  if (typeof legacyTrading === "string" && legacyTrading.trim().toLowerCase() === "true") {
    enabled.add("trading");
  }

  return enabled;
}
