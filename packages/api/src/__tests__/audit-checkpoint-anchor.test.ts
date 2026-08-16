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

// Minimal structurally granted TimeStampResp carrying the requested imprint.
// Full CMS signature trust is the offline verifier's job with an
// auditor-supplied CA.
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

  it("builds the exact SHA-256 RFC 3161 query and attaches only opaque public proof", async () => {
    const signed = checkpoint();
    const responseBytes = grantedResponse(auditCheckpointAnchorDigest(signed));
    let observedUrl = "";
    let observedInit: RequestInit | undefined;
    const sink = new Rfc3161TimestampSink({
      url: "https://tsa.example.test/v1",
      fetch: async (input, init) => {
        observedUrl = String(input);
        observedInit = init;
        return new Response(responseBytes, {
          status: 200,
          headers: { "content-type": "application/timestamp-reply" },
        });
      },
    });
    const proof = await sink.anchor(signed);
    expect(observedUrl).toBe("https://tsa.example.test/v1");
    expect(observedInit?.method).toBe("POST");
    expect(observedInit?.redirect).toBe("error");
    expect(new Headers(observedInit?.headers).get("content-type")).toBe(
      "application/timestamp-query",
    );
    const expectedQuery = createRfc3161TimestampQuery(auditCheckpointAnchorDigest(signed));
    expect(Buffer.from(observedInit?.body as Uint8Array)).toEqual(Buffer.from(expectedQuery));
    expect(proof).toEqual({
      v: 1,
      type: "rfc3161",
      sinkId: "rfc3161",
      hashAlgorithm: "sha256",
      checkpointDigest: auditCheckpointAnchorDigest(signed),
      timestampResponse: Buffer.from(responseBytes).toString("base64"),
    });
    expect(JSON.stringify(proof).toLowerCase()).not.toContain("private");
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
    process.env.STEWARD_AUDIT_RFC3161_URL = "http://tsa.example.test";
    expect(() => configuredAuditCheckpointAnchor()).toThrow("HTTPS");
  });

  it("routes an explicitly registered custom witness through the pluggable interface", () => {
    const sink = {
      id: "customer-log",
      async anchor(): Promise<never> {
        throw new Error("not invoked by configuration discovery");
      },
    };
    const unregister = registerAuditCheckpointAnchorSink("customer-log", () => sink);
    try {
      process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE = "required";
      process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_PROVIDER = "customer-log";
      expect(configuredAuditCheckpointAnchor()).toEqual({ mode: "required", sink });
    } finally {
      unregister();
    }
  });
});
