import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const secretsRouteSource = readFileSync(
  join(import.meta.dir, "..", "routes", "secrets.ts"),
  "utf8",
);

// Route-config validation rules now live in the single source of truth shared
// validator in @stwd/vault. These source-level guards assert the invariants
// stayed intact after the extraction, at the file that actually owns them.
const sharedValidatorSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "vault", "src", "secret-route-validator.ts"),
  "utf8",
);

describe("secret route validation", () => {
  it("routes both call sites through the shared validator", () => {
    expect(secretsRouteSource).toContain('from "@stwd/vault"');
    expect(secretsRouteSource).toContain("validateSecretRouteConfig");
    // The api route must NOT carry its own local copy of the validator anymore.
    expect(secretsRouteSource).not.toContain("function validateSecretRouteConfig");
  });

  it("rejects oversized credential injection formats before persistence", () => {
    expect(sharedValidatorSource).toContain("const MAX_SECRET_INJECT_FORMAT_LENGTH = 255");
    expect(sharedValidatorSource).toContain("injectFormat cannot exceed");
    expect(sharedValidatorSource).toContain("input.injectFormat.length");
  });

  it("rejects query credential injection because upstream bodies can reflect secrets", () => {
    expect(sharedValidatorSource).toContain('const validInjectAs = ["header"]');
    expect(sharedValidatorSource).toContain("'injectAs' must be one of:");
    expect(sharedValidatorSource).not.toContain("STEWARD_ALLOW_QUERY_SECRET_INJECTION");
    expect(sharedValidatorSource).not.toContain('const validInjectAs = ["header", "query"]');
  });

  it("rejects body credential injection until the proxy implements it", () => {
    expect(sharedValidatorSource).toContain('const validInjectAs = ["header"]');
    expect(sharedValidatorSource).toContain("'injectAs' must be one of:");
    expect(sharedValidatorSource).not.toContain("STEWARD_ALLOW_QUERY_SECRET_INJECTION");
    expect(sharedValidatorSource).not.toContain('const validInjectAs = ["header", "query"]');
  });

  it("type-checks route creation priority and enabled before persistence", () => {
    expect(secretsRouteSource).toContain("function parseSecretRouteCreate");
    expect(secretsRouteSource).toContain("'priority' must be an integer");
    expect(secretsRouteSource).toContain("'enabled' must be a boolean");
    expect(secretsRouteSource).toContain("const routeInput = parsedCreate.value");
    expect(sharedValidatorSource).toContain("const MAX_SECRET_INJECT_FORMAT_LENGTH = 255");
  });

  it("rejects line breaks in secret values before header injection can use them", () => {
    expect(secretsRouteSource).toContain("function validateSecretValue");
    expect(secretsRouteSource).toContain("secret value must not contain line breaks");
    expect(secretsRouteSource).toContain(
      "const secretValueError = validateSecretValue(body.value)",
    );
  });

  it("rejects invalid injected header names before persistence", () => {
    expect(sharedValidatorSource).toContain("const HTTP_HEADER_NAME =");
    expect(sharedValidatorSource).toContain("!HTTP_HEADER_NAME.test(key)");
    expect(sharedValidatorSource).toContain("injectKey is invalid");
  });

  it("marks secret inventory and route topology responses as non-cacheable", () => {
    expect(secretsRouteSource).toContain("setNoStoreHeaders");
    expect(secretsRouteSource).toContain('secretsRoutes.use("*"');
    expect(secretsRouteSource).toContain("setNoStoreHeaders(c)");
  });
});
