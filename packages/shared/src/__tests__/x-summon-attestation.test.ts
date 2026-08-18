import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  verifyXSummonAttestation,
  type XSummonAttestationV1,
  xSummonAttestationSignatureInput,
} from "../x-summon-attestation";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
const keysJson = JSON.stringify({ "adapter-2026-08": rawPublicKey.toString("base64url") });
const now = new Date("2026-08-18T01:00:00.000Z");
const expected = {
  audience: "steward-prod-us",
  tenantId: "tenant-a",
  workspaceId: "22000000-0000-4000-8000-000000000001",
  actorAgentId: "agent-a",
  providerAccountId: "32000000-0000-4000-8000-000000000001",
  sourcePostId: "1900000000000000000",
  idempotencyKeyHash: `sha256:${"a".repeat(64)}`,
};

function attestation(overrides: Partial<XSummonAttestationV1> = {}): XSummonAttestationV1 {
  const unsigned: XSummonAttestationV1 = {
    schemaVersion: "steward.x-summon-attestation.v1",
    keyId: "adapter-2026-08",
    ...expected,
    operationKey: "x.tweet.create",
    summoned: true,
    attestedAt: "2026-08-18T00:59:30.000Z",
    expiresAt: "2026-08-18T01:04:30.000Z",
    signature: "A".repeat(86),
    ...overrides,
  };
  unsigned.signature = sign(
    null,
    Buffer.from(xSummonAttestationSignatureInput(unsigned), "utf8"),
    privateKey,
  ).toString("base64url");
  return unsigned;
}

describe("authenticated X summon provenance", () => {
  test("accepts an exact, current adapter signature", () => {
    const result = verifyXSummonAttestation(attestation(), expected, keysJson, now);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test.each([
    ["deployment audience", { audience: "steward-staging" }],
    ["tenant", { tenantId: "tenant-b" }],
    ["workspace", { workspaceId: "22000000-0000-4000-8000-000000000002" }],
    ["agent", { actorAgentId: "agent-b" }],
    ["account", { providerAccountId: "32000000-0000-4000-8000-000000000002" }],
    ["post", { sourcePostId: "1900000000000000001" }],
    ["retry identity", { idempotencyKeyHash: `sha256:${"b".repeat(64)}` }],
  ])("rejects replay across %s", (_name, overrides) => {
    expect(verifyXSummonAttestation(attestation(overrides), expected, keysJson, now)).toEqual({
      ok: false,
      reason: "binding_mismatch",
    });
  });

  test("rejects forged, stale, overlong and unknown-key attestations", () => {
    const forged = attestation();
    forged.signature = `${forged.signature.startsWith("A") ? "B" : "A"}${forged.signature.slice(1)}`;
    expect(verifyXSummonAttestation(forged, expected, keysJson, now).ok).toBe(false);
    expect(
      verifyXSummonAttestation(
        attestation({ expiresAt: "2026-08-18T00:59:59.000Z" }),
        expected,
        keysJson,
        now,
      ),
    ).toEqual({ ok: false, reason: "stale" });
    expect(
      verifyXSummonAttestation(
        attestation({ attestedAt: "2026-08-18T00:50:00.000Z" }),
        expected,
        keysJson,
        now,
      ),
    ).toEqual({ ok: false, reason: "stale" });
    expect(
      verifyXSummonAttestation(attestation({ keyId: "retired" }), expected, keysJson, now),
    ).toEqual({ ok: false, reason: "unknown_key" });
    expect(
      verifyXSummonAttestation(
        attestation({ attestedAt: "2026-02-31T00:59:30.000Z" }),
        expected,
        keysJson,
        now,
      ),
    ).toEqual({ ok: false, reason: "stale" });
  });

  test("rejects unknown fields and missing key configuration", () => {
    expect(
      verifyXSummonAttestation({ ...attestation(), rawPost: "secret" }, expected, keysJson, now),
    ).toEqual({ ok: false, reason: "malformed" });
    expect(verifyXSummonAttestation(attestation(), expected, undefined, now)).toEqual({
      ok: false,
      reason: "unknown_key",
    });
  });

  test("rejects inherited key ids and non-canonical signature encodings without throwing", () => {
    expect(
      verifyXSummonAttestation(
        attestation({ keyId: "toString" }),
        expected,
        keysJson,
        now,
      ),
    ).toEqual({ ok: false, reason: "unknown_key" });

    const nonCanonical = attestation();
    const last = nonCanonical.signature.at(-1) ?? "";
    // An Ed25519 signature's 86th base64url character has four unused bits.
    // Flip only those bits so decoding yields the same 64 signature bytes.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const index = alphabet.indexOf(last);
    nonCanonical.signature = `${nonCanonical.signature.slice(0, -1)}${alphabet[index ^ 1]}`;
    expect(Buffer.from(nonCanonical.signature, "base64url")).toEqual(
      Buffer.from(attestation().signature, "base64url"),
    );
    expect(verifyXSummonAttestation(nonCanonical, expected, keysJson, now)).toEqual({
      ok: false,
      reason: "signature_invalid",
    });
  });
});
