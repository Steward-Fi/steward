import { redactedThrownDiagnostics } from "@stwd/shared";

const phase = process.argv[2];
if (
  phase !== "core" &&
  phase !== "core-through-0112" &&
  phase !== "core-through-0113" &&
  phase !== "plugins"
) {
  throw new Error(
    "usage: bun migrate-production.ts <core|core-through-0112|core-through-0113|plugins>",
  );
}

const migrationDatabaseUrl = process.env.MIGRATION_DATABASE_URL?.trim();
if (!migrationDatabaseUrl) throw new Error("MIGRATION_DATABASE_URL is required");
if (process.env.DATABASE_URL && process.env.DATABASE_URL !== migrationDatabaseUrl) {
  throw new Error("DATABASE_URL must be unset or equal MIGRATION_DATABASE_URL");
}

process.env.DATABASE_URL = migrationDatabaseUrl;
process.env.SKIP_MIGRATIONS = "1";

try {
  if (phase === "core" || phase === "core-through-0112" || phase === "core-through-0113") {
    const { runMigrations } = await import("@stwd/db");
    const result = await runMigrations(
      phase === "core-through-0112"
        ? { throughTag: "0112_rls_activation_release_gates" }
        : phase === "core-through-0113"
          ? { throughTag: "0113_personal_tenant_account_lifecycle" }
          : undefined,
    );
    console.log(JSON.stringify({ phase, applied: result.applied }));
  } else {
    const { runComposedPluginMigrations } = await import("../src/compose");
    const result = await runComposedPluginMigrations();
    console.log(JSON.stringify({ phase, plugins: result }));
  }
} catch (error) {
  console.error("[steward:migrate-production] failed", redactedThrownDiagnostics(error));
  process.exitCode = 1;
} finally {
  const { closeDb } = await import("@stwd/db");
  await closeDb();
}

process.exit(process.exitCode ?? 0);
