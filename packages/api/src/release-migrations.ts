export interface ReleaseMigrationResult {
  applied: string[];
  plugins: Array<{ pluginName: string; id: string; migrationsTable: string }>;
}

export interface ReleaseMigrationRunners {
  runCore: () => Promise<{ applied: string[] }>;
  runPlugins: () => Promise<ReleaseMigrationResult["plugins"]>;
}

/** Apply the complete release in load-bearing core-then-plugin order. */
export async function runReleaseMigrations(
  runners: ReleaseMigrationRunners,
): Promise<ReleaseMigrationResult> {
  const { applied } = await runners.runCore();
  const plugins = await runners.runPlugins();
  return { applied, plugins };
}
