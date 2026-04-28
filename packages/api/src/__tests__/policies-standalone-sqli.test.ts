import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sql } from "drizzle-orm";
import { PgDialect } from "drizzle-orm/pg-core";

const routeSourcePath = join(import.meta.dir, "..", "routes", "policies-standalone.ts");
const routeSource = readFileSync(routeSourcePath, "utf8");
const dialect = new PgDialect();

const maliciousId = "00000000-0000-0000-0000-000000000000'; DROP TABLE policy_templates; --";
const maliciousTenant = "tenant'; DROP TABLE tenants; --";
const maliciousName = "template', rules = '[]'::jsonb; DROP TABLE policy_templates; --";
const maliciousDescription = "desc'; DELETE FROM policy_templates; --";
const maliciousRules = [{ type: "spend_limit", config: { note: "'; DROP TABLE policies; --" } }];

function expectParameterized(query: ReturnType<typeof dialect.sqlToQuery>, values: string[]) {
  for (const value of values) {
    expect(query.sql).not.toContain(value);
    expect(query.params).toContain(value);
  }
}

describe("policies-standalone SQL construction", () => {
  it("does not call sql.raw in the route", () => {
    expect(routeSource).not.toMatch(/\bsql\.raw\s*\(/);
  });

  it("keeps SQL metacharacters in path, tenant, and body values parameterized", () => {
    const getQuery = dialect.sqlToQuery(
      sql`SELECT id, tenant_id, name, description, rules, is_default, created_at, updated_at
        FROM policy_templates
        WHERE id = ${maliciousId}::uuid AND tenant_id = ${maliciousTenant}`,
    );
    expect(getQuery.sql).toBe(
      "SELECT id, tenant_id, name, description, rules, is_default, created_at, updated_at\n        FROM policy_templates\n        WHERE id = $1::uuid AND tenant_id = $2",
    );
    expectParameterized(getQuery, [maliciousId, maliciousTenant]);

    const insertQuery = dialect.sqlToQuery(
      sql`INSERT INTO policy_templates (tenant_id, name, description, rules, is_default)
        VALUES (${maliciousTenant}, ${maliciousName}, ${maliciousDescription}, ${JSON.stringify(maliciousRules)}::jsonb, ${false})
        RETURNING id, tenant_id, name, description, rules, is_default, created_at, updated_at`,
    );
    expect(insertQuery.sql).toContain("VALUES ($1, $2, $3, $4::jsonb, $5)");
    expectParameterized(insertQuery, [
      maliciousTenant,
      maliciousName,
      maliciousDescription,
      JSON.stringify(maliciousRules),
    ]);

    const updateQuery = dialect.sqlToQuery(
      sql`UPDATE policy_templates SET
      name = CASE WHEN ${true} THEN ${maliciousName} ELSE name END,
      description = CASE WHEN ${true} THEN ${maliciousDescription} ELSE description END,
      rules = CASE WHEN ${true} THEN ${JSON.stringify(maliciousRules)}::jsonb ELSE rules END,
      is_default = CASE WHEN ${true} THEN ${false} ELSE is_default END,
      updated_at = now()
    WHERE id = ${maliciousId}::uuid AND tenant_id = ${maliciousTenant}
    RETURNING id, tenant_id, name, description, rules, is_default, created_at, updated_at`,
    );
    expect(updateQuery.sql).toContain("name = CASE WHEN $1 THEN $2 ELSE name END");
    expect(updateQuery.sql).toContain("WHERE id = $9::uuid AND tenant_id = $10");
    expectParameterized(updateQuery, [
      maliciousName,
      maliciousDescription,
      JSON.stringify(maliciousRules),
      maliciousId,
      maliciousTenant,
    ]);
  });
});
