import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";

let databaseReads = 0;
const originalNodeEnv = process.env.NODE_ENV;

mock.module("@stwd/db", () => ({
  getDb: () => {
    databaseReads += 1;
    throw new Error("database deliberately unavailable");
  },
  tenantAppClients: {},
  tenantConfigs: {},
}));

describe("tenant CORS development wildcard", () => {
  let tenantCors: typeof import("../middleware/tenant-cors").tenantCors;

  beforeAll(async () => {
    ({ tenantCors } = await import("../middleware/tenant-cors"));
  });

  afterAll(() => {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
  });

  test("does not consult tenant storage for an explicit development wildcard", async () => {
    databaseReads = 0;
    const app = new Hono();
    app.use("*", tenantCors);

    const response = await withRuntimeEnvironment({ NODE_ENV: "development" }, () =>
      app.request("/resource", {
        method: "OPTIONS",
        headers: {
          Origin: "https://local-ui.example",
          "Access-Control-Request-Method": "PATCH",
        },
      }),
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(databaseReads).toBe(0);
  });

  test("keeps production fail closed when origin storage is unavailable", async () => {
    databaseReads = 0;
    const app = new Hono();
    app.use("*", tenantCors);

    const response = await withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
      app.request("/resource", {
        method: "OPTIONS",
        headers: {
          Origin: "https://console.example.com",
          "Access-Control-Request-Method": "PATCH",
        },
      }),
    );

    expect(response.status).toBe(403);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(databaseReads).toBe(1);
  });

  test("isolates overlapping development, production, and missing bindings", async () => {
    databaseReads = 0;
    const request = () => {
      const app = new Hono();
      app.use("*", tenantCors);
      return app.request("/resource", {
        method: "OPTIONS",
        headers: {
          Origin: "https://hostile-overlap.example",
          "Access-Control-Request-Method": "PATCH",
        },
      });
    };

    const [development, production, missing] = await Promise.all([
      withRuntimeEnvironment({ NODE_ENV: "development" }, request),
      withRuntimeEnvironment({ NODE_ENV: "production" }, request),
      withRuntimeEnvironment({}, request),
    ]);

    expect(development.status).toBe(204);
    expect(development.headers.get("access-control-allow-origin")).toBe("*");
    expect(production.status).toBe(403);
    expect(missing.status).toBe(403);
    expect(databaseReads).toBe(2);
  });
});
