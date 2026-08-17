import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "secrets.ts"), "utf8");

function expectBefore(first: string, second: string) {
  const firstIndex = routeSource.indexOf(first);
  const secondIndex = routeSource.indexOf(second, firstIndex);
  expect(firstIndex).toBeGreaterThanOrEqual(0);
  expect(secondIndex).toBeGreaterThanOrEqual(0);
  expect(firstIndex).toBeLessThan(secondIndex);
}

function routeBody(start: string, end: string): string {
  const startIndex = routeSource.indexOf(start);
  expect(startIndex).toBeGreaterThanOrEqual(0);
  const endIndex = routeSource.indexOf(end, startIndex + start.length);
  expect(endIndex).toBeGreaterThan(startIndex);
  return routeSource.slice(startIndex, endIndex);
}

describe("secret route audit ordering", () => {
  it("writes authorization audit events before sensitive secret mutations", () => {
    expectBefore('action: "secret.create.authorized"', "sv.createSecret");
    expectBefore('action: "secret_route.create.authorized"', "sv.createRouteWithinTx");
    expectBefore('action: "secret_route.update.authorized"', "sv.updateRouteWithinTx");
    expectBefore('action: "secret_route.delete.authorized"', ".delete(secretRouteRows)");
    expectBefore('action: "secret.rotate.authorized"', "sv.rotateSecret");
    expectBefore('action: "secret.delete.authorized"', "sv.deleteSecret");
  });

  it("allowlists secret route update fields before persistence", () => {
    const updateRoute = routeBody(
      'secretsRoutes.put("/routes/:id"',
      "/** DELETE /secrets/routes/:id",
    );

    expect(routeSource).toContain("SECRET_ROUTE_UPDATE_KEYS");
    expect(routeSource).toContain("Unknown secret route field");
    expect(updateRoute).toContain("const parsedUpdate = parseSecretRouteUpdate(body)");
    expect(updateRoute).toContain("const update = parsedUpdate.value");
    expect(updateRoute).toContain("sv.updateRouteWithinTx(tx, tenantId, routeId, update)");
    expect(updateRoute).not.toContain("sv.updateRouteWithinTx(tx, tenantId, routeId, body)");
  });

  it("atomically commits secret route mutations with their final audit events", () => {
    const createSecretRoute = routeBody('secretsRoutes.post("/",', "/** GET /secrets");
    expect(createSecretRoute).toContain('action: "secret.create"');
    expect(createSecretRoute).toContain(".update(secretRows)");
    expect(createSecretRoute).toContain("deletedAt: now");
    expect(createSecretRoute).toContain("eq(secretRows.id, secret.id)");

    const createRoute = routeBody('secretsRoutes.post("/routes"', "/** GET /secrets/routes");
    expect(createRoute).toContain("withTenantAuditedTransaction(tenantId");
    expect(createRoute).toContain("await appendAudit(");
    expect(createRoute).toContain('action: "secret_route.create"');
    expect(createRoute).not.toContain("sv.deleteRoute(tenantId, route.id)");

    const updateRoute = routeBody(
      'secretsRoutes.put("/routes/:id"',
      "/** DELETE /secrets/routes/:id",
    );
    expect(updateRoute).toContain("withTenantAuditedTransaction(tenantId");
    expect(updateRoute).toContain("await appendAudit(");
    expect(updateRoute).toContain('action: "secret_route.update"');
    expect(updateRoute).not.toContain("hostPattern: existing.hostPattern");
    expect(updateRoute).not.toContain("injectFormat: existing.injectFormat");

    const deleteRoute = routeBody(
      'secretsRoutes.delete("/routes/:id"',
      "// ─── Secret CRUD (by ID)",
    );
    expect(deleteRoute).toContain("withTenantAuditedTransaction(tenantId");
    expect(deleteRoute).toContain("await appendAudit(");
    expect(deleteRoute).toContain('action: "secret_route.delete"');
    expect(deleteRoute).not.toContain(".insert(secretRouteRows).values");
    expect(deleteRoute).not.toContain("id: existing.id");
    expect(deleteRoute).not.toContain("secretId: existing.secretId");

    for (const body of [createRoute, updateRoute, deleteRoute]) {
      expect(body).toContain("lockSecretRouteNamespaces(");
    }

    // Secret CRUD still uses explicit compensating transactions where its
    // vault abstraction does not expose within-transaction mutation helpers.

    for (const marker of ['secretsRoutes.put("/:id"', 'secretsRoutes.post("/:id/rotate"']) {
      const rotateRoute = routeSource.slice(routeSource.indexOf(marker));
      expect(rotateRoute).toContain('action: "secret.rotate"');
      expect(rotateRoute).toContain(".set({ secretId: existing.id })");
      expect(rotateRoute).toContain("eq(secretRouteRows.secretId, rotated.id)");
      expect(rotateRoute).toContain("eq(secretRows.id, rotated.id)");
      expect(rotateRoute).toContain("eq(secretRows.id, existing.id)");
    }

    const deleteSecretRoute = routeBody(
      'secretsRoutes.delete("/:id"',
      "/** POST /secrets/:id/rotate",
    );
    expect(deleteSecretRoute).toContain('action: "secret.delete"');
    expect(deleteSecretRoute).toContain("const secretVersions = await getVaultDb()");
    expect(deleteSecretRoute).toContain("const routeSnapshot =");
    expect(deleteSecretRoute).toContain("deletedAt: row.deletedAt");
    expect(deleteSecretRoute).toContain("tx.insert(secretRouteRows).values");
  });
});
