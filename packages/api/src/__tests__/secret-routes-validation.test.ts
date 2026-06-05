import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const secretsRouteSource = readFileSync(
  join(import.meta.dir, "..", "routes", "secrets.ts"),
  "utf8",
);

describe("secret route validation", () => {
  it("rejects oversized credential injection formats before persistence", () => {
    expect(secretsRouteSource).toContain("const MAX_SECRET_INJECT_FORMAT_LENGTH = 255");
    expect(secretsRouteSource).toContain("injectFormat cannot exceed");
    expect(secretsRouteSource).toContain("input.injectFormat.length");
  });

  it("rejects query credential injection because upstream bodies can reflect secrets", () => {
    expect(secretsRouteSource).toContain('const validInjectAs = ["header"]');
    expect(secretsRouteSource).toContain("'injectAs' must be one of:");
    expect(secretsRouteSource).not.toContain("STEWARD_ALLOW_QUERY_SECRET_INJECTION");
    expect(secretsRouteSource).not.toContain('const validInjectAs = ["header", "query"]');
  });

  it("rejects body credential injection until the proxy implements it", () => {
    expect(secretsRouteSource).toContain('const validInjectAs = ["header"]');
    expect(secretsRouteSource).toContain("'injectAs' must be one of:");
    expect(secretsRouteSource).not.toContain("STEWARD_ALLOW_QUERY_SECRET_INJECTION");
    expect(secretsRouteSource).not.toContain('const validInjectAs = ["header", "query"]');
  });

  it("type-checks route creation priority and enabled before persistence", () => {
    expect(secretsRouteSource).toContain("function parseSecretRouteCreate");
    expect(secretsRouteSource).toContain("'priority' must be an integer");
    expect(secretsRouteSource).toContain("'enabled' must be a boolean");
    expect(secretsRouteSource).toContain("const routeInput = parsedCreate.value");
    expect(secretsRouteSource).toContain("const MAX_SECRET_INJECT_FORMAT_LENGTH = 255");
  });

  it("rejects line breaks in secret values before header injection can use them", () => {
    expect(secretsRouteSource).toContain("function validateSecretValue");
    expect(secretsRouteSource).toContain("secret value must not contain line breaks");
    expect(secretsRouteSource).toContain(
      "const secretValueError = validateSecretValue(body.value)",
    );
  });

  it("rejects invalid injected header names before persistence", () => {
    expect(secretsRouteSource).toContain("const HTTP_HEADER_NAME =");
    expect(secretsRouteSource).toContain("!HTTP_HEADER_NAME.test(key)");
    expect(secretsRouteSource).toContain("injectKey is invalid");
  });

  it("marks secret inventory and route topology responses as non-cacheable", () => {
    expect(secretsRouteSource).toContain("setNoStoreHeaders");
    expect(secretsRouteSource).toContain('secretsRoutes.use("*"');
    expect(secretsRouteSource).toContain("setNoStoreHeaders(c)");
  });
});
