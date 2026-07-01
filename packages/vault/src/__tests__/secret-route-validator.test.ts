import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  configuredSecretRouteHosts,
  DEFAULT_SECRET_ROUTE_HOSTS,
  STRICT_HOSTS,
  validateSecretRouteConfig,
} from "../secret-route-validator";

// A complete, known-good route config for a non-strict allowlisted host. Used
// as the base for edge-case matrices so each case flips exactly one field.
const okBase = {
  agentId: "agent-1",
  hostPattern: "api.openai.com",
  pathPattern: "/v1/chat/completions",
  method: "POST",
  injectAs: "header",
  injectKey: "authorization",
  injectFormat: "Bearer {value}",
  priority: 0,
};

describe("validateSecretRouteConfig — core rules", () => {
  it("accepts a well-formed route on an allowlisted host", () => {
    expect(validateSecretRouteConfig(okBase)).toBeNull();
  });

  it("rejects a bare wildcard host", () => {
    expect(validateSecretRouteConfig({ ...okBase, hostPattern: "*" })).toContain(
      "hostPattern must be an explicit allowed host",
    );
  });

  it("rejects a non-allowlisted host", () => {
    expect(validateSecretRouteConfig({ ...okBase, hostPattern: "api.evil.com" })).toContain(
      "not in the secret route allowlist",
    );
  });

  it("rejects a raw IP host", () => {
    expect(validateSecretRouteConfig({ ...okBase, hostPattern: "10.0.0.1" })).toContain(
      "localhost, private, or internal hosts",
    );
  });

  it("rejects localhost", () => {
    expect(validateSecretRouteConfig({ ...okBase, hostPattern: "localhost" })).toContain(
      "localhost, private, or internal hosts",
    );
  });

  it("rejects .internal hosts", () => {
    expect(validateSecretRouteConfig({ ...okBase, hostPattern: "vault.internal" })).toContain(
      "localhost, private, or internal hosts",
    );
  });

  it("rejects a broad /* path without the broad-routes env flag", () => {
    const prev = process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    try {
      expect(
        validateSecretRouteConfig({
          ...okBase,
          hostPattern: "api.openai.com",
          pathPattern: "/*",
        }),
      ).toContain("broad pathPattern requires STEWARD_ALLOW_BROAD_SECRET_ROUTES=true");
    } finally {
      if (prev === undefined) delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
      else process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = prev;
    }
  });

  it("allows a broad /* path only when the env flag is set (non-strict host)", () => {
    const prev = process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = "true";
    try {
      expect(
        validateSecretRouteConfig({
          ...okBase,
          hostPattern: "api.openai.com",
          pathPattern: "/*",
          method: "GET",
        }),
      ).toBeNull();
    } finally {
      if (prev === undefined) delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
      else process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = prev;
    }
  });

  it("rejects a wildcard method without the broad-routes env flag", () => {
    const prev = process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    try {
      expect(validateSecretRouteConfig({ ...okBase, method: "*" })).toContain(
        "broad method requires STEWARD_ALLOW_BROAD_SECRET_ROUTES=true",
      );
    } finally {
      if (prev === undefined) delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
      else process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = prev;
    }
  });

  it("rejects an unknown method", () => {
    expect(validateSecretRouteConfig({ ...okBase, method: "CONNECT" })).toContain(
      "method is not allowed",
    );
  });

  it("rejects injectAs=query (header-only, reconciled to the stricter copy)", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectAs: "query" })).toContain(
      "'injectAs' must be one of:",
    );
  });

  it("rejects injectAs=body", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectAs: "body" })).toContain(
      "'injectAs' must be one of:",
    );
  });

  it("accepts injectAs=header", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectAs: "header" })).toBeNull();
  });

  it("rejects a hop-by-hop injectKey", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "host" })).toContain("is not allowed");
  });

  it("rejects an injectKey with an illegal character (colon)", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "x:y" })).toContain(
      "injectKey is invalid",
    );
  });

  it("rejects an injectFormat with zero {value} placeholders", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectFormat: "Bearer static" })).toContain(
      "exactly one {value} placeholder",
    );
  });

  it("rejects an injectFormat with two {value} placeholders", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectFormat: "{value}{value}" })).toContain(
      "exactly one {value} placeholder",
    );
  });

  it("rejects an injectFormat with a line break", () => {
    expect(
      validateSecretRouteConfig({ ...okBase, injectFormat: "Bearer {value}\r\ninjected" }),
    ).toBeTruthy();
  });

  it("round-trips the two GitHub auth header formats", () => {
    // GitHub accepts both `Authorization: Bearer <pat>` and `Authorization: token <pat>`.
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/repos/acme/widgets",
        method: "GET",
        injectFormat: "Bearer {value}",
      }),
    ).toBeNull();
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/repos/acme/widgets",
        method: "GET",
        injectFormat: "token {value}",
      }),
    ).toBeNull();
  });

  it("rejects a bad priority", () => {
    expect(validateSecretRouteConfig({ ...okBase, priority: -1 })).toContain(
      "priority must be an integer",
    );
  });
});

describe("STRICT_HOSTS — api.github.com narrowness", () => {
  it("declares api.github.com as a strict host", () => {
    expect(STRICT_HOSTS["api.github.com"]).toEqual({
      minPathSegments: 2,
      requireExplicitMethod: true,
    });
    expect(DEFAULT_SECRET_ROUTE_HOSTS).toContain("api.github.com");
    expect(configuredSecretRouteHosts()).toContain("api.github.com");
  });

  it("accepts a narrow, method-explicit github route", () => {
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/repos/acme/widgets/issues/1/comments",
        method: "POST",
      }),
    ).toBeNull();
  });

  it("rejects a github route with a single-segment path (GET /)", () => {
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/",
        method: "GET",
      }),
    ).toContain("at least 2 segments");
  });

  it("rejects a github route with a one-segment path (/user)", () => {
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/user",
        method: "GET",
      }),
    ).toContain("at least 2 segments");
  });

  it("rejects a github route without an explicit method", () => {
    const prev = process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = "true";
    try {
      expect(
        validateSecretRouteConfig({
          ...okBase,
          hostPattern: "api.github.com",
          pathPattern: "/repos/acme/widgets",
          method: "*",
        }),
      ).toContain("must specify an explicit HTTP method");
    } finally {
      if (prev === undefined) delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
      else process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = prev;
    }
  });

  it("skips strict-host rules on a partial patch (enforceStrictHosts=false)", () => {
    // A partial update patch that only sets the host to a strict host must NOT be
    // rejected in isolation — the caller re-validates the merged config with
    // strictness ON. This mirrors the PUT /routes/:id + updateRoute two-pass flow.
    expect(
      validateSecretRouteConfig({ hostPattern: "api.github.com" }, { enforceStrictHosts: false }),
    ).toBeNull();
  });

  it("still rejects a strict-host patch in isolation when strictness is ON (create path)", () => {
    // The create path always validates a complete config with strictness ON.
    expect(validateSecretRouteConfig({ hostPattern: "api.github.com" })).toContain(
      "must specify an explicit HTTP method",
    );
  });

  it("does not apply strict rules to non-strict hosts (openai keeps GET / semantics)", () => {
    // A single-segment path on openai remains valid — strictness is per-host.
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.openai.com",
        pathPattern: "/v1",
        method: "GET",
      }),
    ).toBeNull();
  });
});

// Parity net: both former call-path surfaces (the vault boundary and the api
// route) now import the SAME exported validator. Asserting on the shared export
// is therefore an assertion about both call sites at once. This matrix locks
// the reconciled accept/reject behavior so future edits to either surface can
// only change it here, in one place.
describe("validator parity across former call sites", () => {
  const matrix: Array<{
    name: string;
    input: Parameters<typeof validateSecretRouteConfig>[0];
    accept: boolean;
  }> = [
    { name: "allowlisted host", input: okBase, accept: true },
    {
      name: "non-allowlisted host",
      input: { ...okBase, hostPattern: "api.evil.com" },
      accept: false,
    },
    { name: "raw IP", input: { ...okBase, hostPattern: "127.0.0.1" }, accept: false },
    { name: "localhost", input: { ...okBase, hostPattern: "localhost" }, accept: false },
    { name: "bad injectAs", input: { ...okBase, injectAs: "query" }, accept: false },
    {
      name: "bad injectFormat",
      input: { ...okBase, injectFormat: "no placeholder" },
      accept: false,
    },
    { name: "bad injectKey", input: { ...okBase, injectKey: "content-length" }, accept: false },
  ];

  beforeEach(() => {
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
  });
  afterEach(() => {
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
  });

  for (const c of matrix) {
    it(`${c.accept ? "accepts" : "rejects"}: ${c.name}`, () => {
      const result = validateSecretRouteConfig(c.input);
      if (c.accept) expect(result).toBeNull();
      else expect(result).not.toBeNull();
    });
  }

  it("broad path is env-gated identically regardless of caller", () => {
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    expect(validateSecretRouteConfig({ ...okBase, pathPattern: "/*" })).not.toBeNull();
    process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = "true";
    expect(validateSecretRouteConfig({ ...okBase, pathPattern: "/*", method: "GET" })).toBeNull();
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
  });
});
