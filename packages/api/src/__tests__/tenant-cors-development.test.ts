import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
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
    process.env.NODE_ENV = "development";
    databaseReads = 0;
    const app = new Hono();
    app.use("*", tenantCors);

    const response = await app.request("/resource", {
      method: "OPTIONS",
      headers: {
        Origin: "https://local-ui.example",
        "Access-Control-Request-Method": "PATCH",
      },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(databaseReads).toBe(0);
  });

  for (const nodeEnv of [undefined, "staging", "production"] as const) {
    test(`keeps ${nodeEnv ?? "unset"} NODE_ENV fail closed when origin storage is unavailable`, async () => {
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      databaseReads = 0;
      const app = new Hono();
      app.use("*", tenantCors);

      const response = await app.request("/resource", {
        method: "OPTIONS",
        headers: {
          Origin: "https://console.example.com",
          "Access-Control-Request-Method": "PATCH",
        },
      });

      expect(response.status).toBe(403);
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
      expect(response.headers.get("vary")).toBe("Origin, X-Steward-Tenant");
      expect(databaseReads).toBe(1);
    });
  }
});
