import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  canonicalizeJson,
  createDstackTdxProvider,
  createNoopDevProvider,
  type MeasurementRegistryFile,
  type MeasurementRegistryPayload,
  normalizeReportData,
  registryPayloadDigest,
  verifyQuoteAgainstRegistry,
  verifyRegistrySignatures,
} from "..";

const now = () => new Date("2026-07-30T00:00:00.000Z");

describe("attestation providers", () => {
  test("noop-dev refuses to silently verify", async () => {
    const provider = createNoopDevProvider({ now });
    const quote = await provider.generateQuote();
    expect(quote.provider).toBe("noop-dev");
    expect(quote.verified).toBe(false);
  });

  test("noop-dev can be explicitly allowed only outside production with dual consent", async () => {
    const provider = createNoopDevProvider({
      allowUnverified: true,
      allowDevSecrets: true,
      environment: "test",
      now,
    });
    expect((await provider.verifyQuote({})).verified).toBe(true);
    expect(() =>
      createNoopDevProvider({
        allowUnverified: true,
        allowDevSecrets: true,
        environment: "production",
      }),
    ).toThrow(/production/);
  });

  // SEC-029: the insecure noop mode must not key solely on NODE_ENV — it
  // requires STEWARD_ALLOW_DEV_SECRETS-style dual consent like every other
  // dev escape hatch in this repo.
  test("noop-dev refuses without dev-secrets dual consent even outside production", () => {
    expect(() => createNoopDevProvider({ allowUnverified: true, environment: "test" })).toThrow(
      /dual consent/,
    );
  });

  test("dstack report data is exactly 64 bytes", () => {
    expect(normalizeReportData("abc")).toHaveLength(128);
    expect(normalizeReportData("abc")).toStartWith(Buffer.from("abc").toString("hex"));
    expect(() => normalizeReportData("x".repeat(65))).toThrow(/<= 64 bytes/);
  });
});

describe("dstack verification (stubbed verifier)", () => {
  function stubbedProvider(verifierBody: unknown) {
    return createDstackTdxProvider({
      verifierUrl: "https://verifier.example.com",
      fetchImpl: async () =>
        new Response(JSON.stringify(verifierBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      now,
    });
  }

  const validVerifierDetails = {
    quote_verified: true,
    event_log_verified: true,
    os_image_hash_verified: true,
    tee_variant: "dstack-tdx",
  };

  const attackerRaw = {
    quote: "AA==",
    info: { os_image_hash: "attacker-image", compose_hash: "attacker-compose" },
  };

  // SEC-009: a verifier response without details.app_info must NOT let the
  // measurement fall back to attacker-controlled raw quote info.
  test("fails closed when the verifier omits app_info (no measurement from raw info)", async () => {
    const provider = stubbedProvider({
      is_valid: true,
      details: {
        ...validVerifierDetails,
        report_data: normalizeReportData("nonce-1"),
      },
    });
    const quote = await provider.verifyQuote(attackerRaw, { nonce: "nonce-1" });
    expect(quote.verified).toBe(false);
    // Measurement is still reported for diagnostics but never as verified.
    expect(quote.measurement.imageDigest).toBe("attacker-image");
  });

  test("verified quote binds measurement from verifier app_info, not raw info", async () => {
    const provider = stubbedProvider({
      is_valid: true,
      details: {
        ...validVerifierDetails,
        report_data: normalizeReportData("nonce-1"),
        app_info: { os_image_hash: "verified-image", compose_hash: "verified-compose" },
      },
    });
    const quote = await provider.verifyQuote(attackerRaw, { nonce: "nonce-1" });
    expect(quote.verified).toBe(true);
    expect(quote.measurement).toEqual({
      imageDigest: "verified-image",
      configHash: "verified-compose",
    });
  });

  // SEC-028: without a nonce no freshness check was performed, so the quote
  // must not verify — a captured once-valid quote would otherwise replay.
  test("nonce-less verification never reports verified", async () => {
    const provider = stubbedProvider({
      is_valid: true,
      details: {
        ...validVerifierDetails,
        report_data: normalizeReportData("nonce-1"),
        app_info: { os_image_hash: "verified-image", compose_hash: "verified-compose" },
      },
    });
    const quote = await provider.verifyQuote(attackerRaw);
    expect(quote.verified).toBe(false);
  });

  test("a nonce mismatch never verifies", async () => {
    const provider = stubbedProvider({
      is_valid: true,
      details: {
        ...validVerifierDetails,
        report_data: normalizeReportData("nonce-1"),
        app_info: { os_image_hash: "verified-image", compose_hash: "verified-compose" },
      },
    });
    const quote = await provider.verifyQuote(attackerRaw, { nonce: "different-nonce" });
    expect(quote.verified).toBe(false);
  });
});

describe("measurement registry", () => {
  test("verifies signatures and matches a verified quote", () => {
    const payload: MeasurementRegistryPayload = {
      schemaVersion: 1,
      registryId: "test",
      updatedAt: "2026-07-30T00:00:00.000Z",
      deployments: {
        prod: {
          provider: "dstack-tdx",
          measurement: { imageDigest: "sha256:img", configHash: "compose" },
          status: "active",
        },
      },
    };
    const registry = signRegistry(payload);
    expect(verifyRegistrySignatures(registry, 1, ["test"]).ok).toBe(true);
    expect(registryPayloadDigest(payload)).toHaveLength(64);
    expect(canonicalizeJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(
      verifyQuoteAgainstRegistry(
        {
          provider: "dstack-tdx",
          measurement: { imageDigest: "sha256:img", configHash: "compose" },
          timestamp: now().toISOString(),
          verified: true,
          raw: {},
        },
        registry,
        "prod",
      ).ok,
    ).toBe(true);
  });

  test("fails closed on unverified quotes and mismatched measurements", () => {
    const registry = signRegistry({
      schemaVersion: 1,
      registryId: "test",
      updatedAt: "2026-07-30T00:00:00.000Z",
      deployments: {
        prod: {
          provider: "dstack-tdx",
          measurement: { imageDigest: "expected", configHash: "compose" },
          status: "active",
        },
      },
    });
    const result = verifyQuoteAgainstRegistry(
      {
        provider: "dstack-tdx",
        measurement: { imageDigest: "different", configHash: "compose" },
        timestamp: now().toISOString(),
        verified: true,
        raw: {},
      },
      registry,
      "prod",
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("image digest");
    expect(
      verifyQuoteAgainstRegistry(
        {
          provider: "dstack-tdx",
          measurement: { imageDigest: "expected", configHash: "compose" },
          timestamp: now().toISOString(),
          verified: false,
          raw: {},
        },
        registry,
        "prod",
      ).reason,
    ).toContain("not cryptographically verified");
  });

  // SEC-027: with no pinned trust anchor the signature check is ceremony —
  // anyone can re-sign a tampered registry. Fail closed unless the caller
  // explicitly opts into unpinned verification.
  test("unpinned verification fails closed without an explicit opt-in", () => {
    const registry = signRegistry(basePayload());
    expect(verifyRegistrySignatures(registry).ok).toBe(false);
    expect(verifyRegistrySignatures(registry).reason).toContain("trust anchor");
    expect(
      verifyRegistrySignatures(registry, 1, undefined, undefined, {
        dangerouslyAllowUnpinned: true,
      }).ok,
    ).toBe(true);
  });

  // SEC-007: an empty (0) or malformed (NaN) required count must fail closed,
  // not silently disable the signature gate.
  test("zero/NaN requiredSignatureCount fails closed", () => {
    const registry = signRegistry(basePayload());
    for (const bad of [0, Number.NaN, -1, 1.5]) {
      expect(verifyRegistrySignatures(registry, bad, ["test"]).ok).toBe(false);
    }
    expect(verifyRegistrySignatures(registry, 1, ["test"]).ok).toBe(true);
  });

  // SEC-008: the same signature pasted twice must not satisfy a two-person
  // quorum — count distinct keys, not array entries.
  test("duplicated signatures from one key cannot satisfy a 2-of-2 quorum", () => {
    const registry = signRegistry(basePayload());
    const duplicated: MeasurementRegistryFile = {
      payload: registry.payload,
      signatures: [registry.signatures[0], registry.signatures[0]],
    };
    const denied = verifyRegistrySignatures(duplicated, 2, ["test"]);
    expect(denied.ok).toBe(false);
    expect(denied.reason).toContain("1 valid trusted signature(s)");

    const twoKeys = signRegistryWithKeys(basePayload(), 2);
    expect(
      verifyRegistrySignatures(
        twoKeys,
        2,
        twoKeys.signatures.map((s) => s.keyId),
      ).ok,
    ).toBe(true);
  });

  // SEC-086: pin the expected registryId and reject registries older than the
  // last-known-good updatedAt (replay/rollback protection).
  test("registry metadata is bound: registryId and updatedAt freshness", () => {
    const registry = signRegistry(basePayload());
    expect(
      verifyRegistrySignatures(registry, 1, ["test"], undefined, {
        expectedRegistryId: "other-registry",
      }).ok,
    ).toBe(false);
    expect(
      verifyRegistrySignatures(registry, 1, ["test"], undefined, {
        expectedRegistryId: "test",
      }).ok,
    ).toBe(true);

    const stale = verifyRegistrySignatures(registry, 1, ["test"], undefined, {
      minimumUpdatedAt: "2026-07-31T00:00:00.000Z",
    });
    expect(stale.ok).toBe(false);
    expect(stale.reason).toContain("older than minimum");
    expect(
      verifyRegistrySignatures(registry, 1, ["test"], undefined, {
        minimumUpdatedAt: "2026-07-30T00:00:00.000Z",
      }).ok,
    ).toBe(true);
  });
});

function basePayload(): MeasurementRegistryPayload {
  return {
    schemaVersion: 1,
    registryId: "test",
    updatedAt: "2026-07-30T00:00:00.000Z",
    deployments: {
      prod: {
        provider: "dstack-tdx",
        measurement: { imageDigest: "sha256:img", configHash: "compose" },
        status: "active",
      },
    },
  };
}

function signRegistry(payload: MeasurementRegistryPayload): MeasurementRegistryFile {
  return signRegistryWithKeys(payload, 1);
}

function signRegistryWithKeys(
  payload: MeasurementRegistryPayload,
  keyCount: number,
): MeasurementRegistryFile {
  const signatures = Array.from({ length: keyCount }, (_, i) => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    return {
      keyId: keyCount === 1 ? "test" : `test-${i + 1}`,
      algorithm: "ed25519" as const,
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      signatureBase64: sign(null, Buffer.from(canonicalizeJson(payload)), privateKey).toString(
        "base64",
      ),
    };
  });
  return { payload, signatures };
}
