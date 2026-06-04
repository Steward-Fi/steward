/**
 * Coverage for the schema-driven OpenAPI document.
 *
 * Proves the route definitions are the single source of truth: the migrated
 * `GET /token-status` route appears in the generated OpenAPI 3.1 document (under
 * every prefix it is mounted at), carries its declared query parameter and typed
 * response, and is served by the gated `/openapi.json` endpoint. This is the
 * contract the SDK types and reference docs are generated from, so a drift
 * between handler and spec fails here.
 */
import { afterEach, describe, expect, it } from "bun:test";
import pkg from "../../package.json";
import { app } from "../app";
import { isOpenApiHttpEnabled, OPENAPI_DOC } from "../openapi";

type OpenAPIDoc = {
  openapi: string;
  info: { title: string; version: string };
  paths: Record<string, Record<string, unknown>>;
  components?: { schemas?: Record<string, unknown> };
};

function doc(): OpenAPIDoc {
  return app.getOpenAPI31Document(OPENAPI_DOC) as unknown as OpenAPIDoc;
}

describe("OpenAPI document", () => {
  it("is a valid 3.1 document with Steward metadata", () => {
    const spec = doc();
    expect(spec.openapi).toBe("3.1.0");
    expect(spec.info.title).toBe("Steward API");
    expect(typeof spec.paths).toBe("object");
  });

  it("includes the migrated GET /token-status route under each mounted prefix", () => {
    const spec = doc();
    // tradeRoutes is mounted at both /trade and /v1/trade in app.ts.
    expect(spec.paths["/trade/token-status"]).toBeDefined();
    expect(spec.paths["/trade/token-status"].get).toBeDefined();
    expect(spec.paths["/v1/trade/token-status"]).toBeDefined();
  });

  it("documents the agentId query parameter and the typed response component", () => {
    const spec = doc();
    const op = spec.paths["/trade/token-status"].get as {
      parameters?: Array<{ name: string; in: string }>;
      responses: Record<string, unknown>;
    };
    const agentIdParam = op.parameters?.find((p) => p.name === "agentId");
    expect(agentIdParam?.in).toBe("query");
    expect(op.responses["200"]).toBeDefined();
    expect(op.responses["400"]).toBeDefined();
    // The success payload references the named TradeTokenStatus schema.
    expect(spec.components?.schemas?.TradeTokenStatus).toBeDefined();
  });

  it("serves the spec from the gated /openapi.json endpoint (enabled under NODE_ENV=test)", async () => {
    const res = await app.request("/openapi.json");
    expect(res.status).toBe(200);
    const body = (await res.json()) as OpenAPIDoc;
    expect(body.openapi).toBe("3.1.0");
    expect(body.paths["/trade/token-status"]).toBeDefined();
  });

  it("info.version stays in sync with package.json (drift guard)", () => {
    expect(OPENAPI_DOC.info.version).toBe(pkg.version);
  });
});

describe("OpenAPI HTTP gate fails closed", () => {
  const savedEnabled = process.env.STEWARD_OPENAPI_ENABLED;
  const savedNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    if (savedEnabled === undefined) delete process.env.STEWARD_OPENAPI_ENABLED;
    else process.env.STEWARD_OPENAPI_ENABLED = savedEnabled;
    if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedNodeEnv;
  });

  it("is DISABLED when NODE_ENV is unset (Cloudflare Workers) with no override", () => {
    delete process.env.STEWARD_OPENAPI_ENABLED;
    process.env.NODE_ENV = undefined as unknown as string;
    delete process.env.NODE_ENV;
    expect(isOpenApiHttpEnabled()).toBe(false);
  });

  it("is DISABLED in production without an explicit override", () => {
    delete process.env.STEWARD_OPENAPI_ENABLED;
    process.env.NODE_ENV = "production";
    expect(isOpenApiHttpEnabled()).toBe(false);
  });

  it("respects an explicit STEWARD_OPENAPI_ENABLED=1 even in production", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_OPENAPI_ENABLED = "1";
    expect(isOpenApiHttpEnabled()).toBe(true);
  });

  it("is enabled under an explicit non-production NODE_ENV (dev/test)", () => {
    delete process.env.STEWARD_OPENAPI_ENABLED;
    process.env.NODE_ENV = "development";
    expect(isOpenApiHttpEnabled()).toBe(true);
  });
});
