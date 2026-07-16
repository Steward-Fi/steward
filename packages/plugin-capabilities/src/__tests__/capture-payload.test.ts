/**
 * capture-payload.test.ts - the CONTRACT test for CapturePayload.
 *
 * pins the typed contract between the slice-1 capture extension (`packageJar()`
 * in steward-extension/src/jar.js) and any future Steward-side capture receiver
 * (session-handoff #157, slice 3). asserts:
 *   (a) a realistic x.com capture payload parses valid,
 *   (b) the ttl enum / scope shape / empty-jar / missing-name-or-value rejections,
 *   (c) the mock<->real field names round-trip (drift is caught by a PINNED field list),
 *   (d) a no-leak property: the safe/loggable view never emits a cookie value,
 *       AND the values DO live in the parsed payload (so the absence test isn't vacuous).
 *
 * this test locks NO ingress architecture (sealed-vs-plaintext is slice 2) - it
 * only pins the payload SHAPE and the redaction discipline.
 */

import { describe, expect, setDefaultTimeout, test } from "bun:test";
import {
  CAPTURED_COOKIE_FIELDS,
  capturedCookieSchema,
  captureMetadataSchema,
  capturePayloadSchema,
  MAX_CAPTURE_PAYLOAD_BYTES,
  MAX_COOKIE_COUNT,
  MAX_COOKIE_NAME_BYTES,
  MAX_COOKIE_VALUE_BYTES,
  redactCapturePayload,
} from "../capture-payload";

setDefaultTimeout(30000);

// ── fixture: a realistic x.com capture, matching steward-extension's
//    test/fixtures/cookies-x.json after packageJar() normalization. the values
//    are SENTINELS we grep for in the no-leak test - they must be distinctive
//    strings that could not appear by accident in a redacted view.
const AUTH_TOKEN_SECRET = "SENTINEL_auth_token_VALUE_ff00 deadbeef";
const CT0_SECRET = "SENTINEL_ct0_VALUE_1234567890abcdef";
const TWID_SECRET = "SENTINEL_twid_VALUE_u3D9999999999";
const GUEST_ID_SECRET = "SENTINEL_guest_id_VALUE_v1_17000000";

const ALL_SECRETS = [AUTH_TOKEN_SECRET, CT0_SECRET, TWID_SECRET, GUEST_ID_SECRET];

function realisticXComPayload() {
  return {
    jar: [
      // httpOnly auth_token - the one a page script can't read; full attrs.
      {
        name: "auth_token",
        value: AUTH_TOKEN_SECRET,
        domain: ".x.com",
        path: "/",
        secure: true,
        httpOnly: true,
        sameSite: "no_restriction",
        expirationDate: 1799999999.123,
        hostOnly: false,
        session: false,
        storeId: "0",
      },
      {
        name: "ct0",
        value: CT0_SECRET,
        domain: ".x.com",
        path: "/",
        secure: true,
        httpOnly: false,
        sameSite: "lax",
        expirationDate: 1799999999.5,
        hostOnly: false,
        session: false,
        storeId: "0",
      },
      {
        name: "twid",
        value: TWID_SECRET,
        domain: ".x.com",
        path: "/",
        secure: true,
        httpOnly: false,
        sameSite: "no_restriction",
        expirationDate: 1799999999.9,
        hostOnly: false,
        session: false,
        storeId: "0",
      },
      // guest_id: a SESSION cookie - NO expirationDate. proves attribute
      // optionality (the extension omits, never defaults to a lie).
      {
        name: "guest_id",
        value: GUEST_ID_SECRET,
        domain: ".x.com",
        path: "/",
        secure: true,
        httpOnly: false,
        sameSite: "lax",
        session: true,
        storeId: "0",
      },
    ],
    metadata: {
      domain: "x.com",
      capturedAt: "2026-07-02T00:00:00.000Z",
      ttl: "24h",
      scope: { read: true, write: false },
      originUA: "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0",
      captureMethod: "extension-prototype",
      channel: "PROTOTYPE-plaintext-localhost",
      cookieCount: 4,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
describe("(a) valid parse", () => {
  test("a realistic x.com capture payload parses valid", () => {
    const parsed = capturePayloadSchema.safeParse(realisticXComPayload());
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.jar).toHaveLength(4);
    expect(parsed.data.jar.map((c) => c.name)).toEqual(["auth_token", "ct0", "twid", "guest_id"]);
    // the httpOnly auth_token is preserved as httpOnly.
    expect(parsed.data.jar[0]?.httpOnly).toBe(true);
    // the session cookie has NO expirationDate (optional, never defaulted).
    expect(parsed.data.jar[3]?.expirationDate).toBeUndefined();
    expect("expirationDate" in parsed.data.jar[3]!).toBe(false);
  });

  test("a cookie with only name+value (all attrs absent) is valid - attrs never defaulted", () => {
    const parsed = capturedCookieSchema.safeParse({
      name: "auth_token",
      value: "x",
    });
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    // schema does NOT inject defaults for absent attrs.
    expect("httpOnly" in parsed.data).toBe(false);
    expect("secure" in parsed.data).toBe(false);
    expect("sameSite" in parsed.data).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("(b) rejections", () => {
  test("ttl enum rejects garbage", () => {
    for (const bad of ["forever", "-1", "1H", "24 h", "", "1d"]) {
      const p = { ...realisticXComPayload() };
      p.metadata = { ...p.metadata, ttl: bad as never };
      expect(capturePayloadSchema.safeParse(p).success).toBe(false);
    }
    // and the four valid ones pass at the metadata level.
    for (const good of ["1h", "24h", "7d", "until-revoked"]) {
      const meta = { ...realisticXComPayload().metadata, ttl: good as never };
      expect(captureMetadataSchema.safeParse(meta).success).toBe(true);
    }
  });

  test("scope requires BOTH read and write booleans", () => {
    for (const badScope of [
      { read: true }, // missing write
      { write: false }, // missing read
      { read: "yes", write: false }, // non-boolean
      { read: true, write: true, admin: true }, // extra key (strict)
      {},
    ]) {
      const p = realisticXComPayload();
      p.metadata = { ...p.metadata, scope: badScope as never };
      expect(capturePayloadSchema.safeParse(p).success).toBe(false);
    }
  });

  test("an empty jar is REJECTED (pinned decision: nothing to inject -> fail closed)", () => {
    const p = realisticXComPayload();
    p.jar = [];
    const parsed = capturePayloadSchema.safeParse(p);
    expect(parsed.success).toBe(false);
  });

  test("a cookie missing `name` or missing `value` is rejected", () => {
    // missing name
    const noName = realisticXComPayload();
    delete (noName.jar[0] as Record<string, unknown>).name;
    expect(capturePayloadSchema.safeParse(noName).success).toBe(false);

    // missing value
    const noValue = realisticXComPayload();
    delete (noValue.jar[0] as Record<string, unknown>).value;
    expect(capturePayloadSchema.safeParse(noValue).success).toBe(false);

    // empty-string name is rejected (min 1); empty-string value is ALLOWED.
    const emptyName = realisticXComPayload();
    emptyName.jar[0]!.name = "";
    expect(capturePayloadSchema.safeParse(emptyName).success).toBe(false);

    const emptyValue = realisticXComPayload();
    emptyValue.jar[0]!.value = "";
    expect(capturePayloadSchema.safeParse(emptyValue).success).toBe(true);
  });

  test("an unexpected cookie attribute is rejected (.strict guards against silent drift)", () => {
    const p = realisticXComPayload();
    (p.jar[0] as Record<string, unknown>).evil = "surprise";
    expect(capturePayloadSchema.safeParse(p).success).toBe(false);
  });

  test("an unexpected sameSite value is rejected, including case variants", () => {
    for (const sameSite of ["definitely_not_a_real_value", "Lax", "None", "NONE"]) {
      const p = realisticXComPayload();
      p.jar[0]!.sameSite = sameSite as never;
      expect(capturePayloadSchema.safeParse(p).success).toBe(false);
    }
  });

  test("enforces UTF-8 name/value byte bounds, not only JS string length", () => {
    expect(
      capturedCookieSchema.safeParse({ name: "n".repeat(MAX_COOKIE_NAME_BYTES), value: "" })
        .success,
    ).toBe(true);
    expect(
      capturedCookieSchema.safeParse({ name: "n".repeat(MAX_COOKIE_NAME_BYTES + 1), value: "" })
        .success,
    ).toBe(false);
    expect(
      capturedCookieSchema.safeParse({ name: "n", value: "x".repeat(MAX_COOKIE_VALUE_BYTES) })
        .success,
    ).toBe(true);
    expect(
      capturedCookieSchema.safeParse({
        name: "n",
        value: "é".repeat(MAX_COOKIE_VALUE_BYTES / 2 + 1),
      }).success,
    ).toBe(false);
  });

  test("rejects oversized jars and oversized serialized payloads", () => {
    const tooMany = realisticXComPayload();
    tooMany.jar = Array.from({ length: MAX_COOKIE_COUNT + 1 }, (_, i) => ({
      name: `c${i}`,
      value: "x",
    })) as typeof tooMany.jar;
    tooMany.metadata.cookieCount = tooMany.jar.length;
    expect(capturePayloadSchema.safeParse(tooMany).success).toBe(false);

    const tooLarge = realisticXComPayload();
    tooLarge.jar = Array.from({ length: 80 }, (_, i) => ({
      name: `c${i}`,
      value: "x".repeat(MAX_COOKIE_VALUE_BYTES),
    })) as typeof tooLarge.jar;
    tooLarge.metadata.cookieCount = tooLarge.jar.length;
    expect(new TextEncoder().encode(JSON.stringify(tooLarge)).byteLength).toBeGreaterThan(
      MAX_CAPTURE_PAYLOAD_BYTES,
    );
    expect(capturePayloadSchema.safeParse(tooLarge).success).toBe(false);
  });

  test("requires canonical domains and paths", () => {
    for (const domain of ["X.COM", "x.com.", " x.com", "-bad.com", ".X.com"]) {
      expect(capturedCookieSchema.safeParse({ name: "n", value: "v", domain }).success).toBe(false);
    }
    expect(
      capturedCookieSchema.safeParse({ name: "n", value: "v", domain: ".x.com", path: "/api" })
        .success,
    ).toBe(true);
    expect(capturedCookieSchema.safeParse({ name: "n", value: "v", path: "api" }).success).toBe(
      false,
    );
  });

  test("validates expiration precision and session consistency", () => {
    for (const expirationDate of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.0001]) {
      expect(
        capturedCookieSchema.safeParse({ name: "n", value: "v", expirationDate }).success,
      ).toBe(false);
    }
    expect(
      capturedCookieSchema.safeParse({ name: "n", value: "v", expirationDate: 1.001 }).success,
    ).toBe(true);
    expect(
      capturedCookieSchema.safeParse({ name: "n", value: "v", session: true, expirationDate: 1 })
        .success,
    ).toBe(false);
  });

  test("enforces cookie-prefix and hostOnly invariants", () => {
    expect(capturedCookieSchema.safeParse({ name: "__Secure-id", value: "v" }).success).toBe(false);
    expect(
      capturedCookieSchema.safeParse({ name: "__Secure-id", value: "v", secure: true }).success,
    ).toBe(true);
    expect(
      capturedCookieSchema.safeParse({
        name: "__Host-id",
        value: "v",
        secure: true,
        path: "/",
        hostOnly: true,
      }).success,
    ).toBe(true);
    expect(
      capturedCookieSchema.safeParse({
        name: "__Host-id",
        value: "v",
        secure: true,
        path: "/",
        hostOnly: true,
        domain: "x.com",
      }).success,
    ).toBe(false);
    expect(
      capturedCookieSchema.safeParse({ name: "n", value: "v", hostOnly: true, domain: ".x.com" })
        .success,
    ).toBe(false);
  });

  test("rejects duplicate cookie identities and inconsistent metadata counts", () => {
    const duplicate = realisticXComPayload();
    duplicate.jar.push({ ...duplicate.jar[0]! });
    duplicate.metadata.cookieCount = duplicate.jar.length;
    expect(capturePayloadSchema.safeParse(duplicate).success).toBe(false);

    const wrongCount = realisticXComPayload();
    wrongCount.metadata.cookieCount = 999;
    expect(capturePayloadSchema.safeParse(wrongCount).success).toBe(false);
  });

  test("rejects partitioned/SameParty drift and prototype-ish object inputs", () => {
    for (const key of ["partitioned", "sameParty", "__proto__", "constructor", "prototype"]) {
      const raw = JSON.parse(`{"name":"n","value":"v","${key}":true}`);
      expect(capturedCookieSchema.safeParse(raw).success).toBe(false);
    }
    for (const name of ["__proto__", "constructor", "prototype"]) {
      expect(capturedCookieSchema.safeParse({ name, value: "v" }).success).toBe(false);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("(c) mock<->real field round-trip (drift guard)", () => {
  // PINNED field list, kept in lockstep with jar.js PRESERVED_ATTRS. if the
  // extension adds/removes a preserved attribute, or the schema does, this test
  // fails - forcing the contract to be updated on BOTH sides intentionally.
  const EXPECTED_FIELDS = [
    "name",
    "value",
    "domain",
    "path",
    "secure",
    "httpOnly",
    "sameSite",
    "expirationDate",
    "hostOnly",
    "session",
    "storeId",
  ];

  test("the schema's pinned field list matches jar.js PRESERVED_ATTRS exactly", () => {
    expect([...CAPTURED_COOKIE_FIELDS]).toEqual(EXPECTED_FIELDS);
  });

  test("the schema accepts EXACTLY the fields packageJar emits (a full-attr cookie round-trips)", () => {
    // build a cookie with every preserved attr set, parse it, and assert the
    // parsed object carries exactly those keys - no dropped field, no injected default.
    const fullCookie: Record<string, unknown> = {
      name: "auth_token",
      value: AUTH_TOKEN_SECRET,
      domain: ".x.com",
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "no_restriction",
      expirationDate: 1799999999.123,
      hostOnly: false,
      session: false,
      storeId: "0",
    };
    const parsed = capturedCookieSchema.safeParse(fullCookie);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(Object.keys(parsed.data).sort()).toEqual([...EXPECTED_FIELDS].sort());
  });

  test("metadata field names match packageJar()'s metadata block", () => {
    const parsed = captureMetadataSchema.safeParse(realisticXComPayload().metadata);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    // the metadata keys the extension emits (channel + cookieCount optional/present).
    expect(Object.keys(parsed.data).sort()).toEqual(
      [
        "domain",
        "capturedAt",
        "ttl",
        "scope",
        "originUA",
        "captureMethod",
        "channel",
        "cookieCount",
      ].sort(),
    );
  });

  test("originUA null round-trips (the one field packageJar defaults, to null not a lie)", () => {
    const meta = { ...realisticXComPayload().metadata, originUA: null };
    const parsed = captureMetadataSchema.safeParse(meta);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.originUA).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("(d) no-leak / redaction property", () => {
  test("the parsed payload DOES carry the secret values (guards against a vacuous absence test)", () => {
    const parsed = capturePayloadSchema.parse(realisticXComPayload());
    const serialized = JSON.stringify(parsed);
    for (const secret of ALL_SECRETS) {
      expect(serialized).toContain(secret);
    }
  });

  test("redactCapturePayload NEVER emits any cookie value", () => {
    const parsed = capturePayloadSchema.parse(realisticXComPayload());
    const safe = redactCapturePayload(parsed);
    const serialized = JSON.stringify(safe);

    // serialize-and-grep: NONE of the sentinel secrets may appear.
    for (const secret of ALL_SECRETS) {
      expect(serialized).not.toContain(secret);
    }

    // and the safe view carries the NON-secret signal it is supposed to.
    expect(safe.domain).toBe("x.com");
    expect(safe.cookieCount).toBe(4);
    expect(safe.cookieNames).toEqual(["auth_token", "ct0", "twid", "guest_id"]);
    expect(safe.httpOnlyCount).toBe(1); // only auth_token is httpOnly
    // the safe view has no `value`, no `jar`, no `metadata.scope` leak beyond the
    // non-secret scope object.
    expect("value" in safe).toBe(false);
    expect("jar" in safe).toBe(false);
  });

  test("redactCapturePayload recomputes cookieCount from the jar", () => {
    const parsed = capturePayloadSchema.parse(realisticXComPayload());
    const safe = redactCapturePayload(parsed);
    expect(safe.cookieCount).toBe(parsed.jar.length);
  });
});
