import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  canonicalizeJson,
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

  test("noop-dev can be explicitly allowed only outside production", async () => {
    const provider = createNoopDevProvider({ allowUnverified: true, environment: "test", now });
    expect((await provider.verifyQuote({})).verified).toBe(true);
    expect(() =>
      createNoopDevProvider({ allowUnverified: true, environment: "production" }),
    ).toThrow(/production/);
  });

  test("dstack report data is exactly 64 bytes", () => {
    expect(normalizeReportData("abc")).toHaveLength(128);
    expect(normalizeReportData("abc")).toStartWith(Buffer.from("abc").toString("hex"));
    expect(() => normalizeReportData("x".repeat(65))).toThrow(/<= 64 bytes/);
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
    expect(verifyRegistrySignatures(registry).ok).toBe(true);
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
});

function signRegistry(payload: MeasurementRegistryPayload): MeasurementRegistryFile {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    payload,
    signatures: [
      {
        keyId: "test",
        algorithm: "ed25519",
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
        signatureBase64: sign(null, Buffer.from(canonicalizeJson(payload)), privateKey).toString(
          "base64",
        ),
      },
    ],
  };
}
