import { describe, expect, test } from "bun:test";
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
        STEWARD_PLATFORM_DATABASE_ROLE: "steward_platform",
      },
      async (_database, received) => {
        options = received;
      },
    );
    expect(options).toEqual({
      expectedRole: "steward_app",
      expectedPlatformRole: "steward_platform",
    });
  });

  test("does not require PostgreSQL readiness in test/development", async () => {
    await expect(assertProxyRlsReady(db, { NODE_ENV: "test" })).resolves.toBeUndefined();
  });
});
