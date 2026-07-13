import { describe, expect, it } from "bun:test";
import { sign as edSign, generateKeyPairSync } from "node:crypto";
import {
  AuditSigningKeyError,
  type CheckpointEventContent,
  type CheckpointPayload,
  canonicalCheckpointBytes,
  createCheckpointSigner,
  eventsContentDigest,
  parseSigningKey,
  publicKeyPem,
  verifyCheckpoint,
} from "../services/audit-checkpoint";

function ed25519() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pkcs8Pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const der = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  // The raw 32-byte seed is the last 32 bytes of the PKCS#8 DER (16-byte prefix).
  const seed = Uint8Array.prototype.slice.call(der, der.length - 32);
  return { privateKey, pkcs8Pem, seedHex: Buffer.from(seed).toString("hex") };
}

const basePayload: CheckpointPayload = {
  v: 1,
  tenantId: "tenant-ckpt",
  seq: 42,
  headHmac: "ab".repeat(32),
  expectedCount: 42,
  floorSeq: 0,
  timestamp: "2026-01-01T00:00:00.000Z",
  softwareVersion: "0.0.0-test",
  eventsDigest: "",
  eventsFromSeq: 0,
  eventsToSeq: 0,
};

function ev(seq: number, over: Partial<CheckpointEventContent> = {}): CheckpointEventContent {
  return {
    tenantId: "tenant-ckpt",
    seq,
    actorType: "user",
    actorId: `user-${seq}`,
    action: `act.${seq}`,
    resourceType: "wallet",
    resourceId: `w-${seq}`,
    metadata: { seq },
    ipAddress: null,
    userAgent: null,
    requestId: `r-${seq}`,
    createdAt: "2026-01-01T00:00:00.000Z",
    ...over,
  };
}

describe("audit checkpoint signer", () => {
  it("signs and self-verifies with a PKCS#8 PEM key", () => {
    const { pkcs8Pem } = ed25519();
    const signer = createCheckpointSigner(pkcs8Pem);
    const signed = signer.sign(basePayload);
    expect(signed.publicKey).toContain("BEGIN PUBLIC KEY");
    expect(signed.payload).toEqual(basePayload);
    expect(verifyCheckpoint(signed)).toBe(true);
  });

  it("accepts a raw 32-byte hex seed and produces the same key as its PEM", () => {
    const { pkcs8Pem, seedHex } = ed25519();
    const fromPem = createCheckpointSigner(pkcs8Pem);
    const fromSeed = createCheckpointSigner(seedHex);
    // Same private key -> identical public key + identical signature bytes.
    expect(fromSeed.publicKeyPem).toBe(fromPem.publicKeyPem);
    expect(fromSeed.sign(basePayload).signature).toBe(fromPem.sign(basePayload).signature);
  });

  it("accepts a base64 seed", () => {
    const { seedHex } = ed25519();
    const seedB64 = Buffer.from(seedHex, "hex").toString("base64");
    const signer = createCheckpointSigner(seedB64);
    expect(verifyCheckpoint(signer.sign(basePayload))).toBe(true);
  });

  it("canonical bytes are key-order independent and whitespace-free", () => {
    const bytes = canonicalCheckpointBytes(basePayload);
    const text = Buffer.from(bytes).toString("utf8");
    expect(text).not.toContain(" ");
    expect(text).not.toContain("\n");
    // Keys sorted: expectedCount before floorSeq before headHmac ...
    const parsed = JSON.parse(text);
    expect(Object.keys(parsed)).toEqual([...Object.keys(parsed)].sort());
    // Reordering the source object must not change the canonical bytes.
    const reordered: CheckpointPayload = {
      softwareVersion: basePayload.softwareVersion,
      timestamp: basePayload.timestamp,
      floorSeq: basePayload.floorSeq,
      expectedCount: basePayload.expectedCount,
      headHmac: basePayload.headHmac,
      seq: basePayload.seq,
      tenantId: basePayload.tenantId,
      eventsToSeq: basePayload.eventsToSeq,
      eventsFromSeq: basePayload.eventsFromSeq,
      eventsDigest: basePayload.eventsDigest,
      v: 1,
    };
    expect(Buffer.from(canonicalCheckpointBytes(reordered)).toString("utf8")).toBe(text);
  });

  it("verifyCheckpoint fails when the payload is mutated after signing", () => {
    const { pkcs8Pem } = ed25519();
    const signed = createCheckpointSigner(pkcs8Pem).sign(basePayload);
    const tampered = {
      ...signed,
      payload: { ...signed.payload, expectedCount: signed.payload.expectedCount + 1 },
    };
    expect(verifyCheckpoint(tampered)).toBe(false);
  });

  it("verifyCheckpoint fails when the signature is from a different key", () => {
    const a = ed25519();
    const b = ed25519();
    const signed = createCheckpointSigner(a.pkcs8Pem).sign(basePayload);
    // Re-sign with key B but keep A's published public key.
    const forgedSig = edSign(null, canonicalCheckpointBytes(basePayload), b.privateKey);
    const forged = { ...signed, signature: Buffer.from(forgedSig).toString("base64") };
    expect(verifyCheckpoint(forged)).toBe(false);
  });

  describe("bad key inputs throw AuditSigningKeyError", () => {
    it("empty key", () => {
      expect(() => parseSigningKey("")).toThrow(AuditSigningKeyError);
    });

    it("garbage string", () => {
      expect(() => parseSigningKey("not-a-key-at-all")).toThrow(AuditSigningKeyError);
    });

    it("wrong-length hex seed", () => {
      expect(() => parseSigningKey("abcd")).toThrow(AuditSigningKeyError);
    });

    it("a non-Ed25519 PEM (RSA) is rejected", () => {
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const rsaPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
      expect(() => parseSigningKey(rsaPem)).toThrow(AuditSigningKeyError);
    });

    it("a malformed PEM is rejected", () => {
      expect(() =>
        parseSigningKey("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"),
      ).toThrow(AuditSigningKeyError);
    });
  });

  it("publicKeyPem derives the same public key from PEM and seed inputs", () => {
    const { pkcs8Pem, seedHex } = ed25519();
    expect(publicKeyPem(parseSigningKey(seedHex))).toBe(publicKeyPem(parseSigningKey(pkcs8Pem)));
  });
});

describe("eventsContentDigest", () => {
  it("returns empty string for no events", () => {
    expect(eventsContentDigest([])).toBe("");
  });

  it("is deterministic for the same ordered events", () => {
    const list = [ev(1), ev(2), ev(3)];
    expect(eventsContentDigest(list)).toBe(eventsContentDigest([ev(1), ev(2), ev(3)]));
    expect(eventsContentDigest(list)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when ANY content field changes", () => {
    const base = eventsContentDigest([ev(1), ev(2)]);
    expect(eventsContentDigest([ev(1), ev(2, { action: "different" })])).not.toBe(base);
    expect(eventsContentDigest([ev(1), ev(2, { metadata: { seq: 999 } })])).not.toBe(base);
    expect(eventsContentDigest([ev(1), ev(2, { actorId: "x" })])).not.toBe(base);
    expect(eventsContentDigest([ev(1), ev(2, { createdAt: "2030-01-01T00:00:00.000Z" })])).not.toBe(
      base,
    );
  });

  it("is order-sensitive (reordering breaks the digest)", () => {
    expect(eventsContentDigest([ev(1), ev(2)])).not.toBe(eventsContentDigest([ev(2), ev(1)]));
  });

  it("detects insertion/removal of an event", () => {
    const base = eventsContentDigest([ev(1), ev(2), ev(3)]);
    expect(eventsContentDigest([ev(1), ev(2)])).not.toBe(base);
    expect(eventsContentDigest([ev(1), ev(2), ev(3), ev(4)])).not.toBe(base);
  });
});
