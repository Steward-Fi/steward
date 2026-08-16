import { getDb, sql } from "@stwd/db";

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

function wildcardSuffix(pattern: string): string | null {
  return pattern.startsWith("*.") ? pattern.slice(1).toLowerCase() : null;
}

export function hostPatternsOverlap(a: string, b: string): boolean {
  const left = a.toLowerCase();
  const right = b.toLowerCase();
  if (left === "*" || right === "*") return true;
  if (left === right) return true;
  const leftSuffix = wildcardSuffix(left);
  const rightSuffix = wildcardSuffix(right);
  if (leftSuffix && rightSuffix) {
    return leftSuffix.endsWith(rightSuffix) || rightSuffix.endsWith(leftSuffix);
  }
  if (leftSuffix) return right.endsWith(leftSuffix) && right.length > leftSuffix.length;
  if (rightSuffix) return left.endsWith(rightSuffix) && left.length > rightSuffix.length;
  return false;
}

function pathPrefix(pattern: string): string | null {
  if (pattern === "*" || pattern === "/*") return "/";
  return pattern.endsWith("/*") ? pattern.slice(0, -1) : null;
}

export function pathPatternsOverlap(a: string | null, b: string | null): boolean {
  const left = a ?? "/*";
  const right = b ?? "/*";
  if (left === right) return true;
  const leftPrefix = pathPrefix(left);
  const rightPrefix = pathPrefix(right);
  if (leftPrefix && rightPrefix) {
    return leftPrefix.startsWith(rightPrefix) || rightPrefix.startsWith(leftPrefix);
  }
  if (leftPrefix) return right.startsWith(leftPrefix);
  if (rightPrefix) return left.startsWith(rightPrefix);
  return false;
}

export function methodPatternsOverlap(a: string | null, b: string | null): boolean {
  const left = (a ?? "*").toUpperCase();
  const right = (b ?? "*").toUpperCase();
  return left === "*" || right === "*" || left === right;
}

function authorityRoutesOverlap(a: InventoryRoute, b: InventoryRoute): boolean {
  return (
    a.tenant_id === b.tenant_id &&
    a.agent_id === b.agent_id &&
    hostPatternsOverlap(a.host_pattern, b.host_pattern) &&
    pathPatternsOverlap(a.path_pattern, b.path_pattern) &&
    methodPatternsOverlap(a.method, b.method)
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
