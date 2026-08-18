import { describe, expect, test } from "bun:test";
import { PgDialect } from "drizzle-orm/pg-core";
import { auditRowAggregateQuery } from "../services/audit";

describe("doctor operational bounds", () => {
  test("caps the audit high-water aggregate before COUNT and MAX", () => {
    const query = new PgDialect().sqlToQuery(auditRowAggregateQuery("tenant-a", 7, 100));
    expect(query.sql).toContain("FROM (\n            SELECT seq FROM audit_events");
    expect(query.sql).toContain("LIMIT $3");
    expect(query.params).toEqual(["tenant-a", 7, 101]);
  });
});
