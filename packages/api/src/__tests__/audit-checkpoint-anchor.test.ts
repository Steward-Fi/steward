import { afterEach, describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { type CheckpointPayload, createCheckpointSigner } from "../services/audit-checkpoint";
import {
  AuditCheckpointAnchorError,
  assertGrantedRfc3161Response,
  auditCheckpointAnchorDigest,
  configuredAuditCheckpointAnchor,
  createRfc3161TimestampQuery,
  maybeAnchorAuditCheckpoint,
  Rfc3161TimestampSink,
  registerAuditCheckpointAnchorSink,
} from "../services/audit-checkpoint-anchor";

const ENV_KEYS = [
  "NODE_ENV",
  "STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE",
  "STEWARD_AUDIT_CHECKPOINT_ANCHOR_PROVIDER",
  "STEWARD_AUDIT_RFC3161_URL",
  "STEWARD_AUDIT_RFC3161_CA_FILE",
  "STEWARD_AUDIT_RFC3161_TIMEOUT_MS",
] as const;
const originalEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));

const payload: CheckpointPayload = {
  v: 1,
  tenantId: "tenant-anchor",
  seq: 7,
  headHmac: "ab".repeat(32),
  expectedCount: 7,
  floorSeq: 0,
  timestamp: "2026-08-16T00:00:00.000Z",
  softwareVersion: "test",
  eventsDigest: "cd".repeat(32),
  eventsFromSeq: 1,
  eventsToSeq: 7,
};

function checkpoint() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  return createCheckpointSigner(pem).sign(payload);
}

// Deliberately fake non-CMS response used to prove acquisition never accepts a
// byte scan or a shallow ASN.1 wrapper as a timestamp token.
function grantedResponse(digest: string): Uint8Array {
  const imprint = Buffer.from(digest, "hex");
  return Uint8Array.from([
    0x30,
    0x29,
    0x30,
    0x03,
    0x02,
    0x01,
    0x00,
    0x30,
    0x22,
    0x04,
    0x20,
    ...imprint,
  ]);
}

afterEach(() => {
  for (const key of ENV_KEYS) {
    const value = originalEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("audit checkpoint anchoring", () => {
  it("is byte-shape neutral and makes no network call when unconfigured", async () => {
    delete process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE;
    delete process.env.STEWARD_AUDIT_RFC3161_URL;
    let calls = 0;
    const result = await maybeAnchorAuditCheckpoint(checkpoint(), {
      mode: "off",
      sink: {
        id: "must-not-run",
        async anchor() {
          calls++;
          throw new Error("network must remain unreachable");
        },
      },
    });
    expect(result).toBeUndefined();
    expect(calls).toBe(0);
    expect(configuredAuditCheckpointAnchor()).toEqual({ mode: "off" });
  });

  it("uses a fresh nonce and rejects a fabricated non-CMS response in required acquisition", async () => {
    const signed = checkpoint();
    const responseBytes = grantedResponse(auditCheckpointAnchorDigest(signed));
    const first = createRfc3161TimestampQuery(auditCheckpointAnchorDigest(signed));
    const second = createRfc3161TimestampQuery(auditCheckpointAnchorDigest(signed));
    expect(first).not.toEqual(second);
    const sink = new Rfc3161TimestampSink({
      url: "https://tsa.example.test/v1",
      caFile: "/definitely-not-a-trust-anchor.pem",
      fetch: async () => {
        return new Response(responseBytes, {
          status: 200,
          headers: { "content-type": "application/timestamp-reply" },
        });
      },
    });
    await expect(sink.anchor(signed)).rejects.toThrow();
  });

  it("rejects malformed, denied, oversized and token-less responses", () => {
    expect(() => assertGrantedRfc3161Response(new Uint8Array([1, 2, 3]))).toThrow();
    expect(() =>
      assertGrantedRfc3161Response(
        Uint8Array.from([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x02, 0x30, 0x01, 0x00]),
      ),
    ).toThrow("rejected");
    expect(() =>
      assertGrantedRfc3161Response(Uint8Array.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00])),
    ).toThrow("did not include");
    expect(() => assertGrantedRfc3161Response(new Uint8Array(1024 * 1024 + 1))).toThrow("size");
  });

  it("fails closed in required mode and degrades only when explicitly best-effort", async () => {
    const failingSink = {
      id: "failure",
      async anchor(): Promise<never> {
        throw new AuditCheckpointAnchorError("tsa unavailable");
      },
    };
    await expect(
      maybeAnchorAuditCheckpoint(checkpoint(), { mode: "required", sink: failingSink }),
    ).rejects.toThrow("tsa unavailable");
    expect(
      await maybeAnchorAuditCheckpoint(checkpoint(), { mode: "best-effort", sink: failingSink }),
    ).toBeUndefined();
  });

  it("rejects incomplete required configuration and insecure production transport", () => {
    process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE = "required";
    delete process.env.STEWARD_AUDIT_RFC3161_URL;
    expect(() => configuredAuditCheckpointAnchor()).toThrow("URL is required");

    process.env.NODE_ENV = "production";
    process.env.STEWARD_AUDIT_RFC3161_CA_FILE = "/tmp/tsa-ca.pem";
    process.env.STEWARD_AUDIT_RFC3161_URL = "http://tsa.example.test";
    expect(() => configuredAuditCheckpointAnchor()).toThrow("HTTPS");
  });

  it("routes and verifies a provider-native custom witness proof", async () => {
    const signed = checkpoint();
    let verified = 0;
    const sink = {
      id: "customer-log",
      async anchor() {
        return {
          v: 1 as const,
          type: "custom" as const,
          provider: "customer-log",
          sinkId: "customer-log",
          hashAlgorithm: "sha256" as const,
          checkpointDigest: auditCheckpointAnchorDigest(signed),
          verifiedAt: "2026-08-16T00:00:00.000Z",
          evidence: { logIndex: 42, inclusionProof: ["aa", "bb"] },
        };
      },
    };
    const verifier = (_checkpoint: unknown, proof: { evidence: Record<string, unknown> }) => {
      expect(proof.evidence.logIndex).toBe(42);
      verified++;
    };
    const unregister = registerAuditCheckpointAnchorSink("customer-log", () => sink, verifier);
    try {
      process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE = "required";
      process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_PROVIDER = "customer-log";
      const configured = configuredAuditCheckpointAnchor();
      expect(configured).toEqual({
        mode: "required",
        provider: "customer-log",
        sink,
        verify: verifier,
      });
      const proof = await maybeAnchorAuditCheckpoint(signed, configured);
      expect(proof).toMatchObject({
        type: "custom",
        provider: "customer-log",
        checkpointDigest: auditCheckpointAnchorDigest(signed),
      });
      expect(verified).toBe(1);
    } finally {
      unregister();
    }
  });

  it("rejects unverified or incorrectly bound custom witness evidence", async () => {
    const signed = checkpoint();
    const customSink = (checkpointDigest: string) => ({
      id: "customer-log",
      async anchor() {
        return {
          v: 1 as const,
          type: "custom" as const,
          provider: "customer-log",
          sinkId: "customer-log",
          hashAlgorithm: "sha256" as const,
          checkpointDigest,
          verifiedAt: "2026-08-16T00:00:00.000Z",
          evidence: { treeHead: "signed-head" },
        };
      },
    });
    await expect(
      maybeAnchorAuditCheckpoint(signed, {
        mode: "required",
        provider: "customer-log",
        sink: customSink(auditCheckpointAnchorDigest(signed)),
      }),
    ).rejects.toThrow("requires a proof verifier");
    await expect(
      maybeAnchorAuditCheckpoint(signed, {
        mode: "required",
        provider: "customer-log",
        sink: customSink("00".repeat(32)),
        verify: () => undefined,
      }),
    ).rejects.toThrow("does not bind");
    await expect(
      maybeAnchorAuditCheckpoint(signed, {
        mode: "required",
        provider: "customer-log",
        sink: customSink(auditCheckpointAnchorDigest(signed)),
        verify: () => {
          throw new AuditCheckpointAnchorError("inclusion proof rejected");
        },
      }),
    ).rejects.toThrow("inclusion proof rejected");
  });
});
