/**
 * Optional third-party anchoring for signed audit checkpoints.
 *
 * Disabled means exactly disabled: no sink is constructed and no network call
 * is made. RFC 3161 is the reference implementation; the interface is public
 * so another append-only witness can be supplied without changing bundle
 * assembly.
 */

import { createHash } from "node:crypto";
import { canonicalCheckpointBytes, type SignedCheckpoint } from "./audit-checkpoint";

export type AuditCheckpointAnchorMode = "off" | "best-effort" | "required";

export interface Rfc3161CheckpointAnchorProof {
  v: 1;
  type: "rfc3161";
  sinkId: string;
  hashAlgorithm: "sha256";
  /** SHA-256 of canonicalCheckpointBytes(checkpoint.payload). */
  checkpointDigest: string;
  /** Base64 DER TimeStampResp, including the TSA certificate when supplied. */
  timestampResponse: string;
}

export interface AuditCheckpointAnchorSink {
  readonly id: string;
  anchor(checkpoint: SignedCheckpoint): Promise<Rfc3161CheckpointAnchorProof>;
}

export type AuditCheckpointAnchorSinkFactory = () => AuditCheckpointAnchorSink;

const registeredSinkFactories = new Map<string, AuditCheckpointAnchorSinkFactory>();

/** Register an operator-supplied append-only witness implementation. */
export function registerAuditCheckpointAnchorSink(
  provider: string,
  factory: AuditCheckpointAnchorSinkFactory,
): () => void {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(provider) || provider === "rfc3161") {
    throw new AuditCheckpointAnchorError("Custom checkpoint anchor provider name is invalid");
  }
  if (registeredSinkFactories.has(provider)) {
    throw new AuditCheckpointAnchorError(
      `Checkpoint anchor provider ${provider} is already registered`,
    );
  }
  registeredSinkFactories.set(provider, factory);
  return () => {
    if (registeredSinkFactories.get(provider) === factory) registeredSinkFactories.delete(provider);
  };
}

export interface Rfc3161TimestampSinkOptions {
  url: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

export class AuditCheckpointAnchorError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuditCheckpointAnchorError";
  }
}

const MAX_TIMESTAMP_RESPONSE_BYTES = 1024 * 1024;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Digest anchored by the TSA. The Ed25519 signature authenticates these bytes separately. */
export function auditCheckpointAnchorDigest(checkpoint: SignedCheckpoint): string {
  return createHash("sha256").update(canonicalCheckpointBytes(checkpoint.payload)).digest("hex");
}

/**
 * DER TimeStampReq v1 with SHA-256 MessageImprint and certReq=true.
 * The fixed-size SHA-256 request uses only short-form DER lengths.
 */
export function createRfc3161TimestampQuery(checkpointDigest: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(checkpointDigest)) {
    throw new AuditCheckpointAnchorError(
      "RFC 3161 checkpoint digest must be 32-byte lowercase hex",
    );
  }
  const sha256AlgorithmIdentifier = Uint8Array.from([
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
  ]);
  const imprint = concatBytes(
    Uint8Array.from([0x30, 0x31]),
    sha256AlgorithmIdentifier,
    Uint8Array.from([0x04, 0x20]),
    hexToBytes(checkpointDigest),
  );
  return concatBytes(
    Uint8Array.from([0x30, 0x39, 0x02, 0x01, 0x01]),
    imprint,
    Uint8Array.from([0x01, 0x01, 0xff]),
  );
}

interface DerElement {
  tag: number;
  start: number;
  contentStart: number;
  end: number;
}

function readDerElement(bytes: Uint8Array, offset: number): DerElement {
  const tag = bytes[offset];
  const firstLength = bytes[offset + 1];
  if (tag === undefined || firstLength === undefined) {
    throw new AuditCheckpointAnchorError("RFC 3161 response is truncated");
  }
  let length = 0;
  let contentStart = offset + 2;
  if ((firstLength & 0x80) === 0) {
    length = firstLength;
  } else {
    const lengthBytes = firstLength & 0x7f;
    if (lengthBytes < 1 || lengthBytes > 3 || contentStart + lengthBytes > bytes.length) {
      throw new AuditCheckpointAnchorError("RFC 3161 response has an invalid DER length");
    }
    if (bytes[contentStart] === 0) {
      throw new AuditCheckpointAnchorError("RFC 3161 response has a non-canonical DER length");
    }
    for (let i = 0; i < lengthBytes; i++) length = length * 256 + bytes[contentStart + i];
    if (length < 128) {
      throw new AuditCheckpointAnchorError("RFC 3161 response has a non-canonical DER length");
    }
    contentStart += lengthBytes;
  }
  const end = contentStart + length;
  if (end > bytes.length) throw new AuditCheckpointAnchorError("RFC 3161 response is truncated");
  return { tag, start: offset, contentStart, end };
}

/** Reject malformed, denied, or token-less TSA responses before attaching them. */
export function assertGrantedRfc3161Response(bytes: Uint8Array): void {
  if (bytes.length < 7 || bytes.length > MAX_TIMESTAMP_RESPONSE_BYTES) {
    throw new AuditCheckpointAnchorError("RFC 3161 response size is invalid");
  }
  const outer = readDerElement(bytes, 0);
  if (outer.tag !== 0x30 || outer.end !== bytes.length) {
    throw new AuditCheckpointAnchorError("RFC 3161 response is not one canonical DER sequence");
  }
  const statusInfo = readDerElement(bytes, outer.contentStart);
  if (statusInfo.tag !== 0x30) {
    throw new AuditCheckpointAnchorError("RFC 3161 response is missing PKIStatusInfo");
  }
  const status = readDerElement(bytes, statusInfo.contentStart);
  if (status.tag !== 0x02 || status.end - status.contentStart !== 1) {
    throw new AuditCheckpointAnchorError("RFC 3161 response has an invalid PKIStatus");
  }
  const statusValue = bytes[status.contentStart];
  if (statusValue !== 0 && statusValue !== 1) {
    throw new AuditCheckpointAnchorError(
      `RFC 3161 TSA rejected the request (status ${statusValue})`,
    );
  }
  if (statusInfo.end >= outer.end) {
    throw new AuditCheckpointAnchorError(
      "RFC 3161 granted response did not include a timestamp token",
    );
  }
  const token = readDerElement(bytes, statusInfo.end);
  if (token.tag !== 0x30 || token.end !== outer.end) {
    throw new AuditCheckpointAnchorError("RFC 3161 response contains an invalid timestamp token");
  }
}

function assertRfc3161ResponseContainsImprint(bytes: Uint8Array, digest: string): void {
  const expected = concatBytes(Uint8Array.from([0x04, 0x20]), hexToBytes(digest));
  outer: for (let offset = 0; offset <= bytes.length - expected.length; offset++) {
    for (let i = 0; i < expected.length; i++) {
      if (bytes[offset + i] !== expected[i]) continue outer;
    }
    return;
  }
  throw new AuditCheckpointAnchorError(
    "RFC 3161 response does not contain the requested SHA-256 message imprint",
  );
}

async function readTimestampResponse(response: Response): Promise<Uint8Array> {
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > MAX_TIMESTAMP_RESPONSE_BYTES) {
      throw new AuditCheckpointAnchorError("RFC 3161 response exceeds 1 MiB");
    }
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += chunk.length;
      if (total > MAX_TIMESTAMP_RESPONSE_BYTES) {
        await reader.cancel();
        throw new AuditCheckpointAnchorError("RFC 3161 response exceeds 1 MiB");
      }
      chunks.push(chunk);
    }
    return concatBytes(...chunks);
  } finally {
    reader.releaseLock();
  }
}

function validateTimestampUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new AuditCheckpointAnchorError("STEWARD_AUDIT_RFC3161_URL must be a valid URL");
  }
  if (url.username || url.password) {
    throw new AuditCheckpointAnchorError("RFC 3161 URL must not contain credentials");
  }
  if (url.protocol !== "https:" && process.env.NODE_ENV === "production") {
    throw new AuditCheckpointAnchorError("RFC 3161 URL must use HTTPS in production");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new AuditCheckpointAnchorError("RFC 3161 URL must use HTTP or HTTPS");
  }
  return url;
}

export class Rfc3161TimestampSink implements AuditCheckpointAnchorSink {
  readonly id = "rfc3161";
  private readonly url: URL;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: Rfc3161TimestampSinkOptions) {
    this.url = validateTimestampUrl(options.url);
    this.timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 100 || this.timeoutMs > 60_000) {
      throw new AuditCheckpointAnchorError("RFC 3161 timeout must be between 100 and 60000ms");
    }
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  async anchor(checkpoint: SignedCheckpoint): Promise<Rfc3161CheckpointAnchorProof> {
    const checkpointDigest = auditCheckpointAnchorDigest(checkpoint);
    const query = createRfc3161TimestampQuery(checkpointDigest);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          Accept: "application/timestamp-reply",
          "Content-Type": "application/timestamp-query",
        },
        // Both Node/Bun and Workers accept Uint8Array bodies. workers-types in
        // this package narrows BodyInit incompatibly, so preserve the runtime
        // value while widening only the compile-time view.
        body: query as unknown as string,
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new AuditCheckpointAnchorError(`RFC 3161 TSA returned HTTP ${response.status}`);
      }
      const declaredLength = Number(response.headers.get("content-length") ?? "0");
      if (declaredLength > MAX_TIMESTAMP_RESPONSE_BYTES) {
        throw new AuditCheckpointAnchorError("RFC 3161 response exceeds 1 MiB");
      }
      const bytes = await readTimestampResponse(response);
      assertGrantedRfc3161Response(bytes);
      assertRfc3161ResponseContainsImprint(bytes, checkpointDigest);
      return {
        v: 1,
        type: "rfc3161",
        sinkId: this.id,
        hashAlgorithm: "sha256",
        checkpointDigest,
        timestampResponse: bytesToBase64(bytes),
      };
    } catch (error) {
      if (error instanceof AuditCheckpointAnchorError) throw error;
      throw new AuditCheckpointAnchorError("RFC 3161 timestamp request failed", {
        cause: error,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}

function configuredMode(): AuditCheckpointAnchorMode {
  const value = process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE?.trim() || "off";
  if (value === "off" || value === "best-effort" || value === "required") return value;
  throw new AuditCheckpointAnchorError(
    "STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE must be off, best-effort, or required",
  );
}

export function configuredAuditCheckpointAnchor(): {
  mode: AuditCheckpointAnchorMode;
  sink?: AuditCheckpointAnchorSink;
} {
  const mode = configuredMode();
  if (mode === "off") return { mode };
  const provider = process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_PROVIDER?.trim() || "rfc3161";
  if (provider !== "rfc3161") {
    const factory = registeredSinkFactories.get(provider);
    if (!factory) {
      throw new AuditCheckpointAnchorError(
        `Checkpoint anchor provider ${provider} is not registered`,
      );
    }
    return { mode, sink: factory() };
  }
  const url = process.env.STEWARD_AUDIT_RFC3161_URL?.trim();
  if (!url) {
    throw new AuditCheckpointAnchorError(
      "STEWARD_AUDIT_RFC3161_URL is required when checkpoint anchoring is enabled",
    );
  }
  const rawTimeout = process.env.STEWARD_AUDIT_RFC3161_TIMEOUT_MS?.trim();
  const timeoutMs = rawTimeout ? Number(rawTimeout) : undefined;
  return { mode, sink: new Rfc3161TimestampSink({ url, timeoutMs }) };
}

/** Anchor according to environment policy; required mode never degrades silently. */
export async function maybeAnchorAuditCheckpoint(
  checkpoint: SignedCheckpoint,
  configured = configuredAuditCheckpointAnchor(),
): Promise<Rfc3161CheckpointAnchorProof | undefined> {
  if (configured.mode === "off") return undefined;
  if (!configured.sink) {
    throw new AuditCheckpointAnchorError("Checkpoint anchor sink is not configured");
  }
  try {
    return await configured.sink.anchor(checkpoint);
  } catch (error) {
    if (configured.mode === "required") {
      throw error instanceof AuditCheckpointAnchorError
        ? error
        : new AuditCheckpointAnchorError("Required checkpoint anchoring failed", { cause: error });
    }
    console.error("[audit] best-effort checkpoint anchoring failed; returning unanchored bundle");
    return undefined;
  }
}
