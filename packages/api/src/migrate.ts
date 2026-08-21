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
  runConfiguredReleaseMigrations()
    .then(({ applied, plugins }) => {
      console.log(`[migrate] Core migrations applied: ${applied.length}`);
      console.log(`[migrate] Plugin migration ledgers reconciled: ${plugins.length}`);
    })
    .catch((error) => {
      console.error("[migrate] Release migration failed", redactedThrownDiagnostics(error));
      process.exitCode = 1;
    });
}
