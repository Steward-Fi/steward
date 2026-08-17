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

  it("accepts only an exact EC2 SigV4 endpoint binding", () => {
    const sigv4 = {
      ...okBase,
      hostPattern: "ec2.us-west-2.amazonaws.com",
      pathPattern: "/",
      method: "POST",
      injectionStrategy: "sigv4",
      injectionConfig: { service: "ec2", region: "us-west-2" },
    };
    expect(validateSecretRouteConfig(sigv4)).toBeNull();
    expect(validateSecretRouteConfig({ ...sigv4, hostPattern: "*.amazonaws.com" })).toContain(
      "must be ec2.us-west-2.amazonaws.com",
    );
    expect(validateSecretRouteConfig({ ...sigv4, method: "GET" })).toContain("must be POST");
    expect(
      validateSecretRouteConfig({
        ...sigv4,
        injectionConfig: { service: "s3", region: "us-west-2" },
      }),
    ).toContain("must be ec2");
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

describe("cookie injection — fail-closed default with explicit opt-in (#157)", () => {
  beforeEach(() => {
    delete process.env.STEWARD_ALLOW_COOKIE_INJECTION;
  });
  afterEach(() => {
    delete process.env.STEWARD_ALLOW_COOKIE_INJECTION;
  });

  it("blocks injectKey=cookie by default", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "cookie" })).toContain(
      "STEWARD_ALLOW_COOKIE_INJECTION=true",
    );
  });

  it("blocks injectKey=set-cookie by default", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "set-cookie" })).toContain(
      "STEWARD_ALLOW_COOKIE_INJECTION=true",
    );
  });

  it("blocks cookie case-insensitively (Cookie / COOKIE / cookie)", () => {
    for (const key of ["Cookie", "COOKIE", "cookie", "CoOkIe"]) {
      expect(validateSecretRouteConfig({ ...okBase, injectKey: key })).toContain(
        "STEWARD_ALLOW_COOKIE_INJECTION=true",
      );
    }
  });

  it("blocks set-cookie case-insensitively (Set-Cookie / SET-COOKIE)", () => {
    for (const key of ["Set-Cookie", "SET-COOKIE", "set-cookie"]) {
      expect(validateSecretRouteConfig({ ...okBase, injectKey: key })).toContain(
        "STEWARD_ALLOW_COOKIE_INJECTION=true",
      );
    }
  });

  it("allows injectKey=cookie only when the opt-in flag is set", () => {
    process.env.STEWARD_ALLOW_COOKIE_INJECTION = "true";
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "cookie" })).toBeNull();
  });

  it("allows injectKey=Cookie (mixed case) when the opt-in flag is set", () => {
    process.env.STEWARD_ALLOW_COOKIE_INJECTION = "true";
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "Cookie" })).toBeNull();
  });

  it("allows injectKey=set-cookie when the opt-in flag is set", () => {
    process.env.STEWARD_ALLOW_COOKIE_INJECTION = "true";
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "set-cookie" })).toBeNull();
  });

  it("treats any non-'true' flag value as blocked (fail-closed)", () => {
    for (const val of ["1", "yes", "TRUE", "", "false"]) {
      process.env.STEWARD_ALLOW_COOKIE_INJECTION = val;
      expect(validateSecretRouteConfig({ ...okBase, injectKey: "cookie" })).toContain(
        "STEWARD_ALLOW_COOKIE_INJECTION=true",
      );
    }
  });

  it("leaves unconditionally-blocked hop-by-hop headers blocked even with the cookie flag on", () => {
    process.env.STEWARD_ALLOW_COOKIE_INJECTION = "true";
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "host" })).toContain("is not allowed");
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "content-length" })).toContain(
      "is not allowed",
    );
  });

  it("does not affect other injectKeys — authorization stays valid regardless of the flag", () => {
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "authorization" })).toBeNull();
    process.env.STEWARD_ALLOW_COOKIE_INJECTION = "true";
    expect(validateSecretRouteConfig({ ...okBase, injectKey: "authorization" })).toBeNull();
  });
});

describe("STRICT_HOSTS — api.github.com narrowness", () => {
  it("declares api.github.com as a strict host", () => {
    expect(STRICT_HOSTS["api.github.com"]).toEqual({
      minPathSegments: 2,
      requireExplicitMethod: true,
      disallowPathWildcards: true,
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

  it("rejects a github route with a trailing wildcard path (/repos/*)", () => {
    // /repos/* has 2 segments but the proxy treats * as a prefix wildcard, so it
    // would attach the PAT to every /repos/** endpoint. Must be rejected.
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/repos/*",
        method: "GET",
      }),
    ).toContain('exact path (no "*" wildcards)');
  });

  it("rejects a github route with an inner wildcard segment (/repos/*/issues)", () => {
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "api.github.com",
        pathPattern: "/repos/*/issues",
        method: "GET",
      }),
    ).toContain('exact path (no "*" wildcards)');
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

describe("STRICT_HOSTS — slack.com narrowness", () => {
  it("allows only a method-explicit, exact Slack API route", () => {
    expect(STRICT_HOSTS["slack.com"]).toEqual({
      minPathSegments: 2,
      requireExplicitMethod: true,
      disallowPathWildcards: true,
    });
    expect(DEFAULT_SECRET_ROUTE_HOSTS).toContain("slack.com");
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "slack.com",
        pathPattern: "/api/chat.postMessage",
        method: "POST",
      }),
    ).toBeNull();
  });

  it("rejects a wildcard Slack API route", () => {
    expect(
      validateSecretRouteConfig({
        ...okBase,
        hostPattern: "slack.com",
        pathPattern: "/api/*",
        method: "POST",
      }),
    ).toContain('exact path (no "*" wildcards)');
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
    {
      name: "cookie injectKey blocked by default",
      input: { ...okBase, injectKey: "cookie" },
      accept: false,
    },
  ];

  beforeEach(() => {
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    delete process.env.STEWARD_ALLOW_COOKIE_INJECTION;
  });
  afterEach(() => {
    delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    delete process.env.STEWARD_ALLOW_COOKIE_INJECTION;
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
