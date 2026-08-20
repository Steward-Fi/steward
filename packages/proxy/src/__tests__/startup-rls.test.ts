import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { assertProxyRlsReady } from "../startup-rls";

describe("proxy RLS startup gate", () => {
  const db = { execute: async () => [] };

  test("fails closed without both role expectations", async () => {
    await expect(assertProxyRlsReady(db, { NODE_ENV: "production" })).rejects.toThrow(
      "PROXY_RLS_DATABASE_ROLES_REQUIRED",
    );
  });

  test("checks the exact app and platform roles before serving", async () => {
    let options: unknown;
    await assertProxyRlsReady(
      db,
      {
        NODE_ENV: "production",
        STEWARD_APP_DATABASE_ROLE: "steward_app",
        STEWARD_BOOTSTRAP_DATABASE_ROLE: "steward_bootstrap_owner",
        STEWARD_MIGRATION_DATABASE_ROLE: "steward_migrator",
        STEWARD_PLATFORM_DATABASE_ROLE: "steward_platform",
      },
      async (_database, received) => {
        options = received;
      },
    );
    expect(options).toEqual({
      expectedRole: "steward_app",
      expectedPlatformRole: "steward_platform",
      expectedBootstrapRole: "steward_bootstrap_owner",
      expectedMigrationRole: "steward_migrator",
    });
  });

  test("does not require PostgreSQL readiness in test/development", async () => {
    await expect(assertProxyRlsReady(db, { NODE_ENV: "test" })).resolves.toBeUndefined();
  });

  test("loads the application only after the production readiness gate", () => {
    const source = readFileSync(new URL("../index.ts", import.meta.url), "utf8");
    const readiness = source.indexOf("await assertProxyRlsReady(getDb())");
    const appImport = source.indexOf('await import("./app")');
    expect(readiness).toBeGreaterThan(-1);
    expect(appImport).toBeGreaterThan(readiness);
    expect(source).not.toContain('import app from "./app"');
  });
});
