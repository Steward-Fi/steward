import { getDb, sql } from "@stwd/db";
import {
  secretRouteHostPatternsOverlap,
  secretRouteMethodPatternsOverlap,
  secretRoutePathPatternsOverlap,
} from "@stwd/shared";

export type GovernedRouteInventory = {
  governedRoutes: number;
  nullOperationRoutes: number;
  dualModeRoutes: number;
  ok: boolean;
};

type InventoryRoute = {
  tenant_id: string;
  agent_id: string | null;
  authority_mode: string;
  provider_operation_id: string | null;
  host_pattern: string;
  path_pattern: string | null;
  method: string | null;
};

function rowsFromExecute<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object" && "rows" in result) {
    const rows = (result as { rows?: unknown }).rows;
    if (Array.isArray(rows)) return rows as T[];
  }
  return [];
}

function authorityRoutesOverlap(a: InventoryRoute, b: InventoryRoute): boolean {
  return (
    a.tenant_id === b.tenant_id &&
    a.agent_id === b.agent_id &&
    secretRouteHostPatternsOverlap(a.host_pattern, b.host_pattern) &&
    secretRoutePathPatternsOverlap(a.path_pattern ?? "/*", b.path_pattern ?? "/*") &&
    secretRouteMethodPatternsOverlap(a.method, b.method)
  );
}

/** Runtime doctor using the same wildcard semantics as proxy matching. */
export async function inspectGovernedRoutes(): Promise<GovernedRouteInventory> {
  const routes = rowsFromExecute<InventoryRoute>(
    await getDb().execute(sql`
      SELECT tenant_id, agent_id, authority_mode, provider_operation_id,
             host_pattern, path_pattern, method
      FROM secret_routes WHERE enabled = TRUE
    `),
  );
  const governed = routes.filter((route) => route.authority_mode === "governed_v2");
  const legacy = routes.filter((route) => route.authority_mode === "legacy");
  let dualModeRoutes = 0;
  for (const route of governed) {
    if (legacy.some((candidate) => authorityRoutesOverlap(route, candidate))) dualModeRoutes++;
  }
  const governedRoutes = governed.length;
  const nullOperationRoutes = governed.filter((route) => !route.provider_operation_id).length;
  return {
    governedRoutes,
    nullOperationRoutes,
    dualModeRoutes,
    ok: nullOperationRoutes === 0 && dualModeRoutes === 0,
  };
}
