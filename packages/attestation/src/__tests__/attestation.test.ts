import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  canonicalizeJson,
  createDstackTdxProvider,
  createNoopDevProvider,
  type MeasurementRegistryFile,
  type MeasurementRegistryPayload,
  normalizeReportData,
  parseMeasurementRegistryJson,
  publicKeyFingerprint,
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

  // The insecure noop mode requires explicit dual consent outside production.
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

  // Verified measurements cannot fall back to attacker-controlled raw quote fields.
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

  // A quote without a nonce has no freshness proof and must not verify.
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
    expect(verifyRegistrySignatures(registry, 1, ["test"], registryFingerprints(registry)).ok).toBe(
      true,
    );
    expect(registryPayloadDigest(payload)).toHaveLength(64);
    expect(canonicalizeJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalizeJson({ ä: 1, z: 2 })).toBe('{"z":2,"ä":1}');
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

  // Unpinned verification is available only through an explicit local-development opt-in.
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

  // An invalid quorum cannot disable the signature gate.
  test("zero/NaN requiredSignatureCount fails closed", () => {
    const registry = signRegistry(basePayload());
    for (const bad of [0, Number.NaN, -1, 1.5]) {
      expect(verifyRegistrySignatures(registry, bad, ["test"]).ok).toBe(false);
    }
    expect(verifyRegistrySignatures(registry, 1, ["test"], registryFingerprints(registry)).ok).toBe(
      true,
    );
  });

  // Repeated entries from one key cannot satisfy a multi-key quorum.
  test("duplicated signatures from one key cannot satisfy a 2-of-2 quorum", () => {
    const registry = signRegistry(basePayload());
    const duplicated: MeasurementRegistryFile = {
      payload: registry.payload,
      signatures: [registry.signatures[0], registry.signatures[0]],
    };
    const denied = verifyRegistrySignatures(
      duplicated,
      2,
      ["test"],
      registryFingerprints(registry),
    );
    expect(denied.ok).toBe(false);
    expect(denied.reason).toContain("1 valid trusted signature(s)");

    const twoKeys = signRegistryWithKeys(basePayload(), 2);
    expect(
      verifyRegistrySignatures(
        twoKeys,
        2,
        twoKeys.signatures.map((s) => s.keyId),
        registryFingerprints(twoKeys),
      ).ok,
    ).toBe(true);

    const reformatted: MeasurementRegistryFile = {
      payload: registry.payload,
      signatures: [
        registry.signatures[0],
        { ...registry.signatures[0], publicKeyPem: rewrapPem(registry.signatures[0].publicKeyPem) },
      ],
    };
    expect(
      verifyRegistrySignatures(reformatted, 2, ["test"], undefined, {
        dangerouslyAllowUnpinned: true,
      }).ok,
    ).toBe(false);
    expect(publicKeyFingerprint(reformatted.signatures[1].publicKeyPem)).toBe(
      publicKeyFingerprint(registry.signatures[0].publicKeyPem),
    );
    expect(
      verifyRegistrySignatures(reformatted, 1, ["test"], registryFingerprints(registry)).ok,
    ).toBe(true);
  });

  // Registry identity and freshness pins prevent substitution and rollback.
  test("registry metadata is bound: registryId and updatedAt freshness", () => {
    const registry = signRegistry(basePayload());
    expect(
      verifyRegistrySignatures(registry, 1, ["test"], registryFingerprints(registry), {
        expectedRegistryId: "other-registry",
      }).ok,
    ).toBe(false);
    expect(
      verifyRegistrySignatures(registry, 1, ["test"], registryFingerprints(registry), {
        expectedRegistryId: "test",
      }).ok,
    ).toBe(true);

    const stale = verifyRegistrySignatures(registry, 1, ["test"], registryFingerprints(registry), {
      minimumUpdatedAt: "2026-07-31T00:00:00.000Z",
    });
    expect(stale.ok).toBe(false);
    expect(stale.reason).toContain("older than minimum");
    expect(
      verifyRegistrySignatures(registry, 1, ["test"], registryFingerprints(registry), {
        minimumUpdatedAt: "2026-07-30T00:00:00.000Z",
      }).ok,
    ).toBe(true);
  });

  test("key IDs alone cannot authorize an attacker-substituted signing key", () => {
    const trusted = signRegistry(basePayload());
    const attacker = signRegistry({
      ...basePayload(),
      deployments: {
        ...basePayload().deployments,
        prod: {
          ...basePayload().deployments.prod,
          measurement: { imageDigest: "attacker-image", configHash: "attacker-config" },
        },
      },
    });
    // Both files claim keyId "test". Only the trusted file owns the pinned
    // public key fingerprint.
    expect(verifyRegistrySignatures(attacker, 1, ["test"]).ok).toBe(false);
    expect(verifyRegistrySignatures(attacker, 1, ["test"], registryFingerprints(trusted)).ok).toBe(
      false,
    );
  });

  test("malformed public keys fail closed without throwing", () => {
    const registry = signRegistry(basePayload());
    registry.signatures[0].publicKeyPem = "not a public key";
    const verify = () =>
      verifyRegistrySignatures(registry, 1, undefined, undefined, {
        dangerouslyAllowUnpinned: true,
      });
    expect(verify).not.toThrow();
    expect(verify().ok).toBe(false);

    const wrongRuntimeType = signRegistry(basePayload()) as unknown as {
      payload: MeasurementRegistryPayload;
      signatures: Array<Record<string, unknown>>;
    };
    wrongRuntimeType.signatures[0].publicKeyPem = 42;
    expect(() =>
      verifyRegistrySignatures(
        wrongRuntimeType as unknown as MeasurementRegistryFile,
        1,
        undefined,
        ["0".repeat(64)],
      ),
    ).not.toThrow();
    expect(
      verifyRegistrySignatures(
        wrongRuntimeType as unknown as MeasurementRegistryFile,
        1,
        undefined,
        ["0".repeat(64)],
      ).ok,
    ).toBe(false);

    const valid = signRegistry(basePayload());
    expect(
      verifyRegistrySignatures(
        {
          ...valid,
          signatures: [valid.signatures[0], { ...valid.signatures[0], unexpected: true } as never],
        },
        1,
        undefined,
        registryFingerprints(valid),
      ).ok,
    ).toBe(false);
  });

  test("malformed pins and signatures fail closed", () => {
    const registry = signRegistry(basePayload());
    expect(verifyRegistrySignatures(registry, 1, undefined, ["not-a-sha256"]).ok).toBe(false);

    const corrupt = structuredClone(registry);
    corrupt.signatures[0].signatureBase64 += "garbage";
    expect(verifyRegistrySignatures(corrupt, 1, undefined, registryFingerprints(registry)).ok).toBe(
      false,
    );

    expect(
      verifyRegistrySignatures(
        { payload: registry.payload, signatures: Array(65).fill(registry.signatures[0]) },
        1,
        undefined,
        registryFingerprints(registry),
      ).ok,
    ).toBe(false);
  });

  test("registry structure and canonicalization are bounded and fail closed", () => {
    const registry = signRegistry(basePayload());
    for (const payload of [
      { ...basePayload(), updatedAt: "2026-07-30" },
      { ...basePayload(), unexpected: true },
      { ...basePayload(), deployments: [] },
      {
        ...basePayload(),
        deployments: {
          prod: {
            ...basePayload().deployments.prod,
            measurement: { imageDigest: "x".repeat(1025), configHash: "compose" },
          },
        },
      },
    ]) {
      expect(
        verifyRegistrySignatures(
          { ...registry, payload: payload as never },
          1,
          undefined,
          registryFingerprints(registry),
        ).ok,
      ).toBe(false);
    }

    const tooManyDeployments = Object.fromEntries(
      Array.from({ length: 1025 }, (_, index) => [
        `deployment-${index}`,
        basePayload().deployments.prod,
      ]),
    );
    expect(
      verifyRegistrySignatures(
        { ...registry, payload: { ...basePayload(), deployments: tooManyDeployments } },
        1,
        undefined,
        registryFingerprints(registry),
      ).ok,
    ).toBe(false);

    expect(() => canonicalizeJson({ value: Number.NaN })).toThrow();
    expect(() => canonicalizeJson({ value: undefined })).toThrow();
    expect(() => canonicalizeJson({ value: "\ud800" })).toThrow();
    expect(() => canonicalizeJson({ "\udc00": true })).toThrow();
    const decoratedArray = [1];
    Object.assign(decoratedArray, { extra: true });
    expect(() => canonicalizeJson(decoratedArray)).toThrow();
    const disguisedSparseArray = Array(2);
    disguisedSparseArray[1] = 1;
    Object.assign(disguisedSparseArray, { extra: true });
    expect(() => canonicalizeJson(disguisedSparseArray)).toThrow();
    const symbolDecorated = { value: 1 };
    Object.assign(symbolDecorated, { [Symbol("extra")]: true });
    expect(() => canonicalizeJson(symbolDecorated)).toThrow();
    const accessorDecorated = {};
    Object.defineProperty(accessorDecorated, "value", { enumerable: true, get: () => 1 });
    expect(() => canonicalizeJson(accessorDecorated)).toThrow();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeJson(cyclic)).toThrow();

    const malformedQuote = () =>
      verifyQuoteAgainstRegistry({ verified: true, measurement: null } as never, registry, "prod");
    expect(malformedQuote).not.toThrow();
    expect(malformedQuote().ok).toBe(false);
    expect(
      verifyQuoteAgainstRegistry(
        {
          provider: "dstack-tdx",
          measurement: { imageDigest: "sha256:img", configHash: "compose" },
          timestamp: new Date().toISOString(),
          verified: "true",
          raw: {},
        } as never,
        registry,
        "prod",
      ).ok,
    ).toBe(false);
    expect(
      verifyQuoteAgainstRegistry(
        {
          provider: "dstack-tdx",
          measurement: { imageDigest: "sha256:img", configHash: "compose" },
          timestamp: 42,
          verified: true,
          raw: {},
        } as never,
        registry,
        "prod",
      ).ok,
    ).toBe(false);
    const throwingQuote = Object.defineProperty({}, "timestamp", {
      enumerable: true,
      get() {
        throw new Error("hostile accessor");
      },
    });
    expect(() =>
      verifyQuoteAgainstRegistry(throwingQuote as never, registry, "prod"),
    ).not.toThrow();
    expect(verifyQuoteAgainstRegistry(throwingQuote as never, registry, "prod").ok).toBe(false);
    expect(
      verifyRegistrySignatures(
        { ...registry, unsignedMetadata: "misleading" } as never,
        1,
        undefined,
        registryFingerprints(registry),
      ).ok,
    ).toBe(false);

    const accessorEnvelope = Object.defineProperties(
      {},
      {
        payload: { enumerable: true, get: () => registry.payload },
        signatures: { enumerable: true, value: registry.signatures },
      },
    );
    expect(
      verifyRegistrySignatures(
        accessorEnvelope as MeasurementRegistryFile,
        1,
        undefined,
        registryFingerprints(registry),
      ).ok,
    ).toBe(false);

    const throwingEnvelope = new Proxy(registry, {
      getPrototypeOf() {
        throw new Error("hostile proxy");
      },
    });
    expect(() =>
      verifyRegistrySignatures(throwingEnvelope, 1, undefined, registryFingerprints(registry)),
    ).not.toThrow();

    let mutableReads = 0;
    const mutableReadEnvelope = new Proxy(registry, {
      get() {
        mutableReads += 1;
        throw new Error("mutable proxy read");
      },
    });
    expect(
      verifyRegistrySignatures(mutableReadEnvelope, 1, undefined, registryFingerprints(registry))
        .ok,
    ).toBe(true);
    expect(
      verifyQuoteAgainstRegistry(
        {
          provider: "dstack-tdx",
          measurement: { imageDigest: "sha256:img", configHash: "compose" },
          timestamp: new Date().toISOString(),
          verified: true,
          raw: {},
        },
        mutableReadEnvelope,
        "prod",
      ).ok,
    ).toBe(true);
    expect(mutableReads).toBe(0);
  });

  test("rejects oversized canonical JSON before constructing a full canonical copy", () => {
    expect(() => canonicalizeJson({ value: "x".repeat(1024 * 1024 + 1) })).toThrow(
      "registry payload exceeded the 1 MiB limit",
    );
  });

  test("rejects deeply nested canonical JSON without recursive stack exhaustion", () => {
    let nested: Record<string, unknown> = {};
    for (let depth = 0; depth < 1000; depth += 1) nested = { nested };

    expect(() => canonicalizeJson(nested)).toThrow(
      "registry payload exceeded the maximum depth of 64",
    );
  });

  test("rejects malformed UTF-8 before parsing a registry file", () => {
    expect(() => parseMeasurementRegistryJson(Uint8Array.from([0x7b, 0xff, 0x7d]))).toThrow(
      "measurement registry file is not valid UTF-8 JSON",
    );
  });

  test("rejects excessive JSON depth and structure before JSON.parse", () => {
    const deep = Buffer.from(`${"[".repeat(73)}0${"]".repeat(73)}`);
    expect(() => parseMeasurementRegistryJson(deep)).toThrow(
      "measurement registry JSON exceeded the maximum depth of 72",
    );

    const wide = Buffer.from(`[${"0,".repeat(100_001)}0]`);
    expect(() => parseMeasurementRegistryJson(wide)).toThrow(
      "measurement registry JSON exceeded the structural token limit",
    );
  });

  test.each([
    ['{"payload":{},"payload":{},"signatures":[]}', "literal duplicate"],
    [
      '{"payload":{"registryId":"test","\\u0072egistryId":"other"},"signatures":[]}',
      "escape-equivalent duplicate",
    ],
    ['{"payload":{},"signatures":[{"keyId":"one","keyId":"two"}]}', "nested duplicate"],
  ])("rejects %s before JSON.parse (%s)", (json) => {
    expect(() => parseMeasurementRegistryJson(Buffer.from(json))).toThrow(
      "measurement registry JSON contains a duplicate object key",
    );
  });

  test("allows the same decoded key in separate object scopes", () => {
    expect(
      parseMeasurementRegistryJson(Buffer.from('{"payload":{"id":1},"other":{"id":2}}')),
    ).toEqual({ payload: { id: 1 }, other: { id: 2 } });
  });

  test("counts canonical UTF-8 bytes, escaped bytes, keys, and nodes", () => {
    expect(() => canonicalizeJson({ value: "\u0000".repeat(200_000) })).toThrow(
      "registry payload exceeded the 1 MiB limit",
    );
    expect(() => canonicalizeJson({ ["💥".repeat(262_145)]: true })).toThrow(
      "registry payload exceeded the 1 MiB limit",
    );
    expect(() => canonicalizeJson(Array.from({ length: 100_001 }, () => null))).toThrow(
      "registry payload exceeded the maximum node count of 100000",
    );
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

function registryFingerprints(registry: MeasurementRegistryFile): string[] {
  return registry.signatures.map((signature) => publicKeyFingerprint(signature.publicKeyPem));
}

function rewrapPem(pem: string): string {
  const body = pem
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith("-----"))
    .join("");
  return `-----BEGIN PUBLIC KEY-----\n${body.match(/.{1,32}/g)?.join("\n")}\n-----END PUBLIC KEY-----\n`;
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
