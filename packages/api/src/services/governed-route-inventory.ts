import { getDb, sql } from "@stwd/db";

export type GovernedRouteInventory = {
  governedRoutes: number;
  nullOperationRoutes: number;
  dualModeRoutes: number;
  ok: boolean;
};

function rowsFromExecute<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object" && "rows" in result) {
    const rows = (result as { rows?: unknown }).rows;
    if (Array.isArray(rows)) return rows as T[];
  }
  return [];
}

/**
 * Single source for the runtime doctor and PR7's static/runtime route guard.
 * A dual-mode match is the same tenant/agent/host/path/method credential route
 * exposed once through legacy authority and once through governed authority.
 */
export async function inspectGovernedRoutes(): Promise<GovernedRouteInventory> {
  const db = getDb();
  const [row = { governed: 0, null_operations: 0, dual_mode: 0 }] = rowsFromExecute<{
    governed: number;
    null_operations: number;
    dual_mode: number;
  }>(
    await db.execute(sql`
      WITH route_counts AS (
        SELECT
          tenant_id,
          COALESCE(agent_id, '') AS agent_id,
          host_pattern,
          COALESCE(path_pattern, '/*') AS path_pattern,
          COALESCE(method, '*') AS method,
          BOOL_OR(authority_mode = 'legacy') AS has_legacy,
          BOOL_OR(authority_mode = 'governed_v2') AS has_governed
        FROM secret_routes
        WHERE enabled = TRUE
        GROUP BY tenant_id, COALESCE(agent_id, ''), host_pattern,
          COALESCE(path_pattern, '/*'), COALESCE(method, '*')
      )
      SELECT
        (SELECT COUNT(*)::int FROM secret_routes
          WHERE enabled = TRUE AND authority_mode = 'governed_v2') AS governed,
        (SELECT COUNT(*)::int FROM secret_routes
          WHERE enabled = TRUE AND authority_mode = 'governed_v2'
            AND provider_operation_id IS NULL) AS null_operations,
        (SELECT COUNT(*)::int FROM route_counts
          WHERE has_legacy AND has_governed) AS dual_mode
    `),
  );
  const governedRoutes = Number(row.governed);
  const nullOperationRoutes = Number(row.null_operations);
  const dualModeRoutes = Number(row.dual_mode);
  return {
    governedRoutes,
    nullOperationRoutes,
    dualModeRoutes,
    ok: nullOperationRoutes === 0 && dualModeRoutes === 0,
  };
}
