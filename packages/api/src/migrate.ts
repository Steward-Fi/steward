import { runMigrations } from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { runComposedPluginMigrations } from "./compose";
import { runReleaseMigrations } from "./release-migrations";

/**
 * Apply the complete database release in load-bearing order. Production API
 * containers set SKIP_MIGRATIONS and invoke this entrypoint out of band with
 * the dedicated migration identity.
 */
export async function runConfiguredReleaseMigrations() {
  return runReleaseMigrations({
    runCore: runMigrations,
    runPlugins: runComposedPluginMigrations,
  });
}

if (import.meta.main) {
  try {
    const { applied, plugins } = await runConfiguredReleaseMigrations();
    console.log(`[migrate] Core migrations applied: ${applied.length}`);
    console.log(`[migrate] Plugin migration ledgers reconciled: ${plugins.length}`);
    // Plugin discovery imports the API composition graph, whose Bun server
    // compatibility modules own bounded housekeeping timers. The release
    // command has closed every migration client at this point; terminate
    // explicitly so those unrelated timers cannot keep a successful release
    // job alive forever.
    process.exit(0);
  } catch (error) {
    console.error("[migrate] Release migration failed", redactedThrownDiagnostics(error));
    process.exit(1);
  }
}
