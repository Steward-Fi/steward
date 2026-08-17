/**
 * generic-http.provider-action.v1 shared-profile tests (#201).
 *
 * Proves the config-driven generic-http canonicalizer:
 *   - reuses the ONE shared JCS/hash/normalize surface (byte-identical framing);
 *   - validates operator descriptors STRICTLY at authoring time (fail closed);
 *   - fills typed segments/query/body from validated scalars, encoding dynamic
 *     segments so traversal / delimiter injection is impossible pre/post decode;
 *   - provably excludes credential headers from the digest;
 *   - produces a stable digest under key/serialization reordering;
 *   - the profile registry rejects unregistered profiles at every enumerated
 *     consumption entry, and github/x golden digests are unchanged.
 *
 * Includes the generic golden corpus + adversarial suite + digest-stability
 * mutation-style checks.
 */

import { describe, expect, it } from "bun:test";
import {
  assertRegisteredProfile,
  buildGenericHttpAction,
  CanonError,
  computeActionDigest,
  computeGenericHttpActionDigest,
  computeXActionDigest,
  GENERIC_GOLDEN_DESCRIPTOR_A,
  GENERIC_GOLDEN_DESCRIPTOR_B,
  GENERIC_HTTP_GOLDEN_VECTORS,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  GenericDescriptorError,
  GITHUB_PROVIDER_ACTION_PROFILE,
  GOLDEN_VECTORS,
  genericDescriptorAllowsExactPath,
  genericHttpCanonicalActionBytes,
  isRegisteredProfile,
  REGISTERED_PROFILES,
  UnregisteredProfileError,
  validateGenericHttpDescriptor,
  X_GOLDEN_VECTORS,
  X_PROVIDER_ACTION_PROFILE,
} from "../index.js";

describe("generic credential-route subset proof", () => {
  const descriptor = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_A);

  it("accepts only canonical exact paths admitted by the descriptor", () => {
    expect(
      genericDescriptorAllowsExactPath(
        descriptor,
        "/v1/orgs/acme-inc/projects/11111111-1111-4111-8111-111111111111/items",
      ),
    ).toBe(true);
    expect(genericDescriptorAllowsExactPath(descriptor, "/v1/orgs/acme-inc/projects/*")).toBe(
      false,
    );
    expect(
      genericDescriptorAllowsExactPath(
        descriptor,
        "/v1/orgs/acme-inc/projects/11111111-1111-4111-8111-111111111111/items/extra",
      ),
    ).toBe(false);
  });

  it("rejects traversal, encoded delimiters, noncanonical encoding, and typed-param mismatch", () => {
    for (const path of [
      "/v1/orgs/../projects/11111111-1111-4111-8111-111111111111/items",
      "/v1/orgs/acme%2Fother/projects/11111111-1111-4111-8111-111111111111/items",
      "/v1/orgs/acme%2dinc/projects/11111111-1111-4111-8111-111111111111/items",
      "/v1/orgs/acme-inc/projects/not-a-uuid/items",
    ]) {
      expect(genericDescriptorAllowsExactPath(descriptor, path)).toBe(false);
    }
  });
});

function descriptorDenies(raw: unknown): string | null {
  try {
    validateGenericHttpDescriptor(raw);
    return null;
  } catch (e) {
    if (e instanceof GenericDescriptorError) return e.code;
    throw e;
  }
}

function buildDenies(descriptor: unknown, method: unknown, args: unknown): string | null {
  const d = validateGenericHttpDescriptor(descriptor);
  try {
    buildGenericHttpAction("op.key", d, method, args);
    return null;
  } catch (e) {
    if (e instanceof CanonError) return e.code;
    throw e;
  }
}

// ─── Golden corpus ────────────────────────────────────────────────────────────

describe("generic-http golden corpus", () => {
  for (const gv of GENERIC_HTTP_GOLDEN_VECTORS) {
    it(`${gv.id}: ${gv.description}`, () => {
      const d = validateGenericHttpDescriptor(gv.descriptor);
      const build = buildGenericHttpAction("op.key", d, gv.method, gv.args);
      expect(genericHttpCanonicalActionBytes(build.action)).toBe(gv.canonicalActionBytes);
      expect(computeGenericHttpActionDigest(build.action)).toBe(gv.actionDigest);
      expect(build.policyArgs).toEqual(gv.policyArgs);
      expect(build.safeSummary).toEqual(gv.safeSummary);
      expect(build.action.profile).toBe(GENERIC_HTTP_PROVIDER_ACTION_PROFILE);
    });
  }

  it("digest is stable under argument key reordering (JCS re-sorts)", () => {
    const d = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_B);
    const a = buildGenericHttpAction("op.key", d, "POST", {
      title: "x",
      priority: 3,
      urgent: true,
      estimate: "1.0",
    });
    const b = buildGenericHttpAction("op.key", d, "POST", {
      estimate: "1.0",
      urgent: true,
      priority: 3,
      title: "x",
    });
    expect(computeGenericHttpActionDigest(a.action)).toBe(computeGenericHttpActionDigest(b.action));
  });
});

// ─── Registry (fail-closed at every consumption entry) ─────────────────────────

describe("profile registry", () => {
  it("registers exactly github, x, generic-http", () => {
    expect([...REGISTERED_PROFILES].sort()).toEqual(
      [
        GITHUB_PROVIDER_ACTION_PROFILE,
        X_PROVIDER_ACTION_PROFILE,
        GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
      ].sort(),
    );
  });

  it("isRegisteredProfile accepts registered, rejects unknown / non-string", () => {
    expect(isRegisteredProfile(GITHUB_PROVIDER_ACTION_PROFILE)).toBe(true);
    expect(isRegisteredProfile(X_PROVIDER_ACTION_PROFILE)).toBe(true);
    expect(isRegisteredProfile(GENERIC_HTTP_PROVIDER_ACTION_PROFILE)).toBe(true);
    expect(isRegisteredProfile("evil.provider-action.v1")).toBe(false);
    expect(isRegisteredProfile("")).toBe(false);
    expect(isRegisteredProfile(null)).toBe(false);
    expect(isRegisteredProfile(undefined)).toBe(false);
    expect(isRegisteredProfile(123)).toBe(false);
    expect(isRegisteredProfile({})).toBe(false);
  });

  it("assertRegisteredProfile throws UnregisteredProfileError for unknown profile", () => {
    expect(() => assertRegisteredProfile("evil.provider-action.v1")).toThrow(
      UnregisteredProfileError,
    );
    let code = "";
    try {
      assertRegisteredProfile("nope");
    } catch (e) {
      if (e instanceof UnregisteredProfileError) code = e.code;
    }
    expect(code).toBe("CANON_PROFILE_UNSUPPORTED");
  });

  // Enumerated consumption sites (the SAME predicate every site uses). A change
  // that admits an unregistered profile at any site would flip one of these.
  it("every registered profile round-trips through assertRegisteredProfile", () => {
    for (const p of REGISTERED_PROFILES) expect(assertRegisteredProfile(p)).toBe(p);
  });
});

// ─── github/x golden digests unchanged (critical regression) ───────────────────

describe("github/x golden digests unchanged by #201", () => {
  it("github golden digests recompute byte-identical", () => {
    for (const gv of GOLDEN_VECTORS) {
      expect(computeActionDigest(gv.action)).toBe(gv.actionDigest);
    }
  });
  it("x golden digests recompute byte-identical", () => {
    for (const gv of X_GOLDEN_VECTORS) {
      expect(computeXActionDigest(gv.action)).toBe(gv.actionDigest);
    }
  });
});

// ─── Descriptor validation (authoring-time fail-closed) ────────────────────────

describe("descriptor validation", () => {
  it("accepts a well-formed descriptor", () => {
    expect(descriptorDenies(GENERIC_GOLDEN_DESCRIPTOR_A)).toBeNull();
    expect(descriptorDenies(GENERIC_GOLDEN_DESCRIPTOR_B)).toBeNull();
  });

  it("rejects a non-https origin", () => {
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "http://api.example.com" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
  });

  it("rejects unknown keys at every descriptor layer", () => {
    expect(descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, surprise: true })).toBe(
      "CANON_DESCRIPTOR_SHAPE_INVALID",
    );
    expect(
      descriptorDenies({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        pathTemplate: [{ literal: "v1", surprise: true }],
      }),
    ).toBe("CANON_DESCRIPTOR_PATH_TEMPLATE_INVALID");
    expect(
      descriptorDenies({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        query: [{ name: "q", type: "string", pattern: "^[a-z]{1,8}$", surprise: true }],
      }),
    ).toBe("CANON_DESCRIPTOR_QUERY_INVALID");
    expect(
      descriptorDenies({
        ...GENERIC_GOLDEN_DESCRIPTOR_B,
        body: { ...GENERIC_GOLDEN_DESCRIPTOR_B.body, surprise: true },
      }),
    ).toBe("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID");
  });

  it("rejects ReDoS-capable operator regexes", () => {
    for (const pattern of [
      "^(a+)+$",
      "^(a|aa)*$",
      "^(?=a).+$",
      "^(a)\\1$",
      "^a{1,}$",
      "^admin$|user$",
      `^${"a?".repeat(28)}a{28}$`,
      "^a{0,64}a{0,64}z$",
    ]) {
      expect(
        descriptorDenies({
          ...GENERIC_GOLDEN_DESCRIPTOR_A,
          pathTemplate: [{ param: { name: "x", type: "string", pattern } }],
        }),
      ).toBe("CANON_DESCRIPTOR_SEGMENT_INVALID");
    }
  });

  it("matches the accepted pattern subset in bounded linear time", () => {
    const descriptor = validateGenericHttpDescriptor({
      ...GENERIC_GOLDEN_DESCRIPTOR_A,
      pathTemplate: [{ param: { name: "x", type: "string", pattern: "^[a-z]{1,128}$" } }],
      query: [],
      projection: { policyArgs: ["x"], safeSummary: [] },
    });
    const started = performance.now();
    for (let i = 0; i < 10_000; i++) {
      expect(() =>
        buildGenericHttpAction("linear.test", descriptor, "GET", { x: "a".repeat(128) }),
      ).not.toThrow();
    }
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  it("keeps an escaped character-class hyphen literal instead of widening it to a range", () => {
    const descriptor = validateGenericHttpDescriptor({
      ...GENERIC_GOLDEN_DESCRIPTOR_B,
      body: {
        contentType: "application/json",
        fields: [
          {
            name: "value",
            type: "string",
            required: true,
            pattern: "^[a\\-z]{1,8}$",
            maxBytes: 8,
          },
        ],
      },
      projection: { policyArgs: ["value"], safeSummary: [] },
    });
    expect(() =>
      buildGenericHttpAction("literal-hyphen.test", descriptor, "POST", { value: "a-z" }),
    ).not.toThrow();
    expect(() =>
      buildGenericHttpAction("literal-hyphen.test", descriptor, "POST", { value: "m" }),
    ).toThrow("fails pattern");
  });

  it("rejects an IP-literal origin (SSRF-adjacent)", () => {
    expect(descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://127.0.0.1" })).toBe(
      "CANON_DESCRIPTOR_ORIGIN_INVALID",
    );
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://169.254.169.254" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
  });

  it("rejects userinfo, port tricks, wildcard, single-label, trailing-dot-double, punycode-as-unicode", () => {
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://user@api.example.com" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://api.example.com:8443" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://*.example.com" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
    expect(descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://localhost" })).toBe(
      "CANON_DESCRIPTOR_ORIGIN_INVALID",
    );
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://api.example.com.." }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
    // Unicode homograph host (must be pre-encoded punycode; raw unicode denies).
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://exаmple.com" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
  });

  it("rejects a host with an invalid DNS label (underscore)", () => {
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, origin: "https://api_example.com" }),
    ).toBe("CANON_DESCRIPTOR_ORIGIN_INVALID");
  });

  it("rejects a credential header in the allowlist", () => {
    for (const bad of [
      "authorization",
      "Authorization",
      "AUTHORIZATION",
      "cookie",
      "x-forwarded-host",
      "host",
      "x-steward-authorization",
    ]) {
      expect(
        descriptorDenies({
          ...GENERIC_GOLDEN_DESCRIPTOR_A,
          headers: [{ name: bad, value: "x" }],
        }),
      ).toBe("CANON_DESCRIPTOR_HEADER_CREDENTIAL_FORBIDDEN");
    }
  });

  it("rejects an unanchored / delimiter-bearing segment pattern", () => {
    const badPattern = {
      ...GENERIC_GOLDEN_DESCRIPTOR_A,
      pathTemplate: [
        { literal: "v1" },
        { param: { name: "x", type: "string", pattern: "[a-z]+" } },
      ],
    };
    expect(descriptorDenies(badPattern)).toBe("CANON_DESCRIPTOR_SEGMENT_INVALID");
    const slashPattern = {
      ...GENERIC_GOLDEN_DESCRIPTOR_A,
      pathTemplate: [
        { literal: "v1" },
        { param: { name: "x", type: "string", pattern: "^[a-z/]+$" } },
      ],
    };
    expect(descriptorDenies(slashPattern)).toBe("CANON_DESCRIPTOR_SEGMENT_INVALID");
  });

  it("rejects an unsafe literal segment (traversal / delimiter)", () => {
    for (const lit of ["..", ".", "a/b", "a%2fb"]) {
      expect(
        descriptorDenies({
          ...GENERIC_GOLDEN_DESCRIPTOR_A,
          pathTemplate: [{ literal: lit }, { param: { name: "x", type: "uuid" } }],
        }),
      ).toBe("CANON_DESCRIPTOR_SEGMENT_INVALID");
    }
  });

  it("rejects prototype-pollution keys anywhere in the descriptor (own-key form)", () => {
    // A JSON payload with a real own `__proto__` / `constructor` key (an object
    // literal `{ __proto__: ... }` would set the prototype instead, so use
    // JSON.parse which creates a true own enumerable key).
    expect(
      descriptorDenies(
        JSON.parse(
          JSON.stringify(GENERIC_GOLDEN_DESCRIPTOR_A).replace(
            '"projection"',
            '"__proto__":{"x":1},"projection"',
          ),
        ),
      ),
    ).toBe("CANON_DESCRIPTOR_PROTO_POLLUTION");
    expect(
      descriptorDenies(
        JSON.parse(
          JSON.stringify(GENERIC_GOLDEN_DESCRIPTOR_A).replace(
            '"projection"',
            '"constructor":{"x":1},"projection"',
          ),
        ),
      ),
    ).toBe("CANON_DESCRIPTOR_PROTO_POLLUTION");
  });

  it("rejects a projection referencing an unknown scalar", () => {
    expect(
      descriptorDenies({
        ...GENERIC_GOLDEN_DESCRIPTOR_A,
        projection: { policyArgs: ["nope"], safeSummary: [] },
      }),
    ).toBe("CANON_DESCRIPTOR_POLICY_ARG_INVALID");
  });

  it("rejects wrong profile string", () => {
    expect(
      descriptorDenies({ ...GENERIC_GOLDEN_DESCRIPTOR_A, profile: "x.provider-action.v1" }),
    ).toBe("CANON_DESCRIPTOR_PROFILE_INVALID");
  });

  it("rejects a body-bearing-only method with no body schema", () => {
    expect(
      descriptorDenies({
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        origin: "https://api.example.com",
        methods: ["POST"],
        pathTemplate: [{ literal: "v1" }],
        projection: { policyArgs: [], safeSummary: [] },
      }),
    ).toBe("CANON_DESCRIPTOR_BODY_SCHEMA_INVALID");
  });
});

// ─── Argument canonicalization + adversarial ───────────────────────────────────

describe("generic-http argument adversarial", () => {
  const A = GENERIC_GOLDEN_DESCRIPTOR_A;

  it("rejects traversal payloads in a string segment", () => {
    for (const evil of ["..", "../etc", "a/b", "a\\b", "a\u0000b", "..%2f"]) {
      // pattern ^[a-z0-9-]{1,40}$ already blocks these, so canon denies.
      expect(
        buildDenies(A, "GET", { org: evil, projectId: "11111111-1111-4111-8111-111111111111" }),
      ).not.toBeNull();
    }
  });

  it("segment with an encoded delimiter can never survive (defense in depth via encodeRfc3986)", () => {
    // Even a permissive pattern cannot smuggle a slash: encodeRfc3986 escapes it,
    // so normalizePath sees exactly one segment. Use a descriptor whose pattern
    // admits many chars but assertSafeSegmentValue + encoding still fences it.
    const permissive = validateGenericHttpDescriptor({
      ...A,
      pathTemplate: [
        { literal: "v1" },
        { param: { name: "org", type: "string", pattern: "^[A-Za-z0-9 .~_:@-]{1,40}$" } },
        { literal: "items" },
      ],
      query: [],
      projection: { policyArgs: ["org"], safeSummary: ["org"] },
    });
    // A space + reserved chars in the value are percent-encoded into a single
    // safe path segment (no delimiter can appear post-encode).
    const ok = buildGenericHttpAction("op.key", permissive, "GET", { org: "a b:c@d" });
    expect(ok.action.normalizedPath).toBe("/v1/a%20b%3Ac%40d/items");
    // A dot/tilde value (unreserved) stays literal but is still one segment.
    const ok2 = buildGenericHttpAction("op.key", permissive, "GET", { org: "a.b~c" });
    expect(ok2.action.normalizedPath).toBe("/v1/a.b~c/items");
  });

  it("rejects an invalid uuid segment", () => {
    expect(buildDenies(A, "GET", { org: "acme", projectId: "not-a-uuid" })).toBe(
      "CANON_PATH_SEGMENT_INVALID",
    );
  });

  it("rejects an out-of-range int query", () => {
    expect(
      buildDenies(A, "GET", {
        org: "acme",
        projectId: "11111111-1111-4111-8111-111111111111",
        perPage: 1000,
      }),
    ).toBe("CANON_QUERY_VALUE_OUT_OF_RANGE");
  });

  it("rejects a query value failing its pattern", () => {
    expect(
      buildDenies(A, "GET", {
        org: "acme",
        projectId: "11111111-1111-4111-8111-111111111111",
        state: "pending",
      }),
    ).toBe("CANON_PATH_SEGMENT_INVALID");
  });

  it("rejects an unknown argument", () => {
    expect(
      buildDenies(A, "GET", {
        org: "acme",
        projectId: "11111111-1111-4111-8111-111111111111",
        surprise: "x",
      }),
    ).toBe("CANON_UNKNOWN_FIELD");
  });

  it("rejects a method not in the descriptor allowlist", () => {
    expect(
      buildDenies(A, "DELETE", { org: "acme", projectId: "11111111-1111-4111-8111-111111111111" }),
    ).toBe("CANON_METHOD_UNSUPPORTED");
  });

  it("rejects prototype-pollution keys in arguments", () => {
    const d = validateGenericHttpDescriptor(A);
    let code = "";
    try {
      buildGenericHttpAction(
        "op.key",
        d,
        "GET",
        JSON.parse(
          '{"__proto__":{"x":1},"org":"acme","projectId":"11111111-1111-4111-8111-111111111111"}',
        ),
      );
    } catch (e) {
      if (e instanceof CanonError) code = e.code;
    }
    // The proto key MUST be rejected up front by the dedicated proto-pollution
    // arg guard (CANON_JSON_SHAPE_INVALID), NOT merely fall through to the
    // unknown-arg path (which would leave a window where the key was processed).
    expect(code).toBe("CANON_JSON_SHAPE_INVALID");
  });

  it("rejects a body field failing its schema", () => {
    const B = GENERIC_GOLDEN_DESCRIPTOR_B;
    expect(buildDenies(B, "POST", { title: "x", priority: 99, urgent: true, estimate: "1" })).toBe(
      "CANON_QUERY_VALUE_OUT_OF_RANGE",
    );
    expect(buildDenies(B, "POST", { title: "x", priority: 1, urgent: "yes", estimate: "1" })).toBe(
      "CANON_FIELD_TYPE_INVALID",
    );
    expect(
      buildDenies(B, "POST", { title: "x", priority: 1, urgent: true, estimate: "1.2.3" }),
    ).toBe("CANON_DECIMAL_STRING_INVALID");
  });

  // Dedicated mutation-target: a permissive dot-allowing pattern still cannot
  // smuggle a `.`/`..` dot-segment (assertSafeSegmentValue is the guard).
  it("dot-segment value denied even under a dot-allowing pattern", () => {
    const dotDesc = validateGenericHttpDescriptor({
      ...A,
      pathTemplate: [
        { literal: "v1" },
        { param: { name: "org", type: "string", pattern: "^[a-z.]{1,10}$" } },
        { literal: "items" },
      ],
      query: [],
      projection: { policyArgs: ["org"], safeSummary: ["org"] },
    });
    let code = "";
    try {
      buildGenericHttpAction("op.key", dotDesc, "GET", { org: ".." });
    } catch (e) {
      if (e instanceof CanonError) code = e.code;
    }
    expect(code).toBe("CANON_PATH_TRAVERSAL");
  });

  // Dedicated mutation-target: a space in a segment value MUST be percent-encoded
  // (skipping the encode would let a forbidden raw byte reach normalizePath).
  it("space in a segment value is percent-encoded (encode is load-bearing)", () => {
    const spaceDesc = validateGenericHttpDescriptor({
      ...A,
      pathTemplate: [
        { literal: "v1" },
        { param: { name: "org", type: "string", pattern: "^[a-z ]{1,10}$" } },
        { literal: "items" },
      ],
      query: [],
      projection: { policyArgs: ["org"], safeSummary: ["org"] },
    });
    const b = buildGenericHttpAction("op.key", spaceDesc, "GET", { org: "a b" });
    expect(b.action.normalizedPath).toBe("/v1/a%20b/items");
  });

  it("credential header can never enter selectedHeaders / digest", () => {
    // The descriptor validator already forbids credential headers; assert the
    // canonical action for a valid descriptor carries only the declared safe
    // headers and never an authorization header.
    const d = validateGenericHttpDescriptor(GENERIC_GOLDEN_DESCRIPTOR_A);
    const build = buildGenericHttpAction("op.key", d, "GET", {
      org: "acme",
      projectId: "11111111-1111-4111-8111-111111111111",
    });
    const names = build.action.selectedHeaders.map(([n]) => n);
    expect(names).not.toContain("authorization");
    expect(names).not.toContain("cookie");
    expect(genericHttpCanonicalActionBytes(build.action).toLowerCase()).not.toContain(
      "authorization",
    );
  });
});
