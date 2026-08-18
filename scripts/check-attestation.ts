#!/usr/bin/env bun
import { open } from "node:fs/promises";
import {
  createDstackTdxProvider,
  MAX_MEASUREMENT_REGISTRY_FILE_BYTES,
  type MeasurementRegistryFile,
  parseMeasurementRegistryJson,
  verifyQuoteAgainstRegistry,
  verifyRegistrySignatures,
} from "@stwd/attestation";

const MAX_QUOTE_RESPONSE_BYTES = 1024 * 1024;
const QUOTE_REQUEST_TIMEOUT_MS = 10_000;

function quoteRequestUrl(rawEndpoint: string, nonce: string): URL {
  let url: URL;
  try {
    url = new URL(rawEndpoint);
  } catch {
    throw new Error("STEWARD_ATTESTATION_ENDPOINT must be a valid HTTP(S) URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("STEWARD_ATTESTATION_ENDPOINT must use HTTP or HTTPS");
  }
  if (url.username || url.password) {
    throw new Error("STEWARD_ATTESTATION_ENDPOINT must not contain URL credentials");
  }
  if (url.hash) {
    throw new Error("STEWARD_ATTESTATION_ENDPOINT must not contain a URL fragment");
  }
  url.searchParams.set("nonce", nonce);
  return url;
}

async function readBoundedRegistry(path: string): Promise<MeasurementRegistryFile> {
  const handle = await open(path, "r");
  try {
    const bytes = Buffer.alloc(MAX_MEASUREMENT_REGISTRY_FILE_BYTES + 1);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_MEASUREMENT_REGISTRY_FILE_BYTES) {
      throw new Error("measurement registry file exceeded the 4 MiB ingestion limit");
    }
    return parseMeasurementRegistryJson(bytes.subarray(0, offset));
  } finally {
    await handle.close();
  }
}

async function readBoundedQuoteResponse(response: Response): Promise<unknown> {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_QUOTE_RESPONSE_BYTES) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("quote endpoint response exceeded the 1 MiB limit");
  }
  if (!response.body) throw new Error("quote endpoint returned an empty response");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_QUOTE_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("quote endpoint response exceeded the 1 MiB limit");
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    if (
      error instanceof Error &&
      error.message === "quote endpoint response exceeded the 1 MiB limit"
    ) {
      throw error;
    }
    throw new Error("quote endpoint response could not be read");
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text);
  } catch {
    throw new Error("quote endpoint returned invalid JSON");
  }
}

const endpoint = process.env.STEWARD_ATTESTATION_ENDPOINT;
const deployment = process.env.STEWARD_ATTESTATION_DEPLOYMENT ?? "local-dev";
const registryPath =
  process.env.STEWARD_MEASUREMENT_REGISTRY ?? "docs/attestation/measurements.json";
const requiredSignaturesRaw = process.env.STEWARD_REGISTRY_REQUIRED_SIGNATURES ?? "1";
const requiredSignatures = Number(requiredSignaturesRaw);
// An empty or malformed count must fail before it can disable the signature gate.
if (!Number.isInteger(requiredSignatures) || requiredSignatures < 1) {
  console.error(
    `STEWARD_REGISTRY_REQUIRED_SIGNATURES must be a positive integer, got "${requiredSignaturesRaw}"`,
  );
  process.exit(2);
}
const trustedKeyIds = process.env.STEWARD_REGISTRY_TRUSTED_KEY_IDS?.split(",")
  .map((keyId) => keyId.trim())
  .filter(Boolean);
const trustedKeyFingerprints = process.env.STEWARD_REGISTRY_TRUSTED_KEY_SHA256?.split(",")
  .map((fingerprint) => fingerprint.trim())
  .filter(Boolean);
if (trustedKeyFingerprints?.some((fingerprint) => !/^[a-f0-9]{64}$/i.test(fingerprint))) {
  console.error(
    "STEWARD_REGISTRY_TRUSTED_KEY_SHA256 must contain comma-separated 64-character hexadecimal SHA-256 fingerprints",
  );
  process.exit(2);
}
// Without a pinned trust anchor, anyone can replace and re-sign the registry.
const allowUnpinned = process.env.STEWARD_REGISTRY_ALLOW_UNPINNED === "true";
if (allowUnpinned && (process.env.NODE_ENV === "production" || process.env.CI === "true")) {
  console.error("STEWARD_REGISTRY_ALLOW_UNPINNED is forbidden in production and CI");
  process.exit(2);
}
if (!trustedKeyFingerprints?.length && !allowUnpinned) {
  console.error(
    "no cryptographic registry trust anchor configured: set " +
      "STEWARD_REGISTRY_TRUSTED_KEY_SHA256 (key IDs are selectors, not trust anchors), " +
      "or STEWARD_REGISTRY_ALLOW_UNPINNED=true for local development only",
  );
  process.exit(2);
}
// These optional pins prevent registry substitution and rollback.
const expectedRegistryId = process.env.STEWARD_REGISTRY_ID;
const minimumUpdatedAt = process.env.STEWARD_REGISTRY_MIN_UPDATED_AT;

if (!endpoint) {
  console.error(
    "STEWARD_ATTESTATION_ENDPOINT is required (for example https://steward.example.com/quote)",
  );
  process.exit(2);
}

let registry: MeasurementRegistryFile;
try {
  registry = await readBoundedRegistry(registryPath);
} catch (error) {
  const safeMessage =
    error instanceof Error && error.message.startsWith("measurement registry")
      ? error.message
      : "measurement registry file could not be read";
  console.error(safeMessage);
  process.exit(2);
}
const registryOk = verifyRegistrySignatures(
  registry,
  requiredSignatures,
  trustedKeyIds,
  trustedKeyFingerprints,
  { expectedRegistryId, minimumUpdatedAt, dangerouslyAllowUnpinned: allowUnpinned },
);
if (!registryOk.ok) {
  console.error(`measurement registry signature check failed: ${registryOk.reason}`);
  process.exit(1);
}

const nonce = crypto.randomUUID();
let requestUrl: URL;
try {
  requestUrl = quoteRequestUrl(endpoint, nonce);
} catch (error) {
  console.error(error instanceof Error ? error.message : "invalid attestation endpoint");
  process.exit(2);
}
let response: Response;
try {
  response = await fetch(requestUrl, {
    redirect: "error",
    signal: AbortSignal.timeout(QUOTE_REQUEST_TIMEOUT_MS),
  });
} catch {
  console.error("quote endpoint request failed");
  process.exit(1);
}
if (!response.ok && response.status !== 503) {
  await response.body?.cancel().catch(() => undefined);
  console.error(`quote endpoint failed with HTTP ${response.status}`);
  process.exit(1);
}

let rawQuote: unknown;
try {
  rawQuote = await readBoundedQuoteResponse(response);
} catch (error) {
  console.error(error instanceof Error ? error.message : "quote endpoint response was invalid");
  process.exit(1);
}
const provider = createDstackTdxProvider();
const quoteEnvelope = rawQuote as { raw?: { quote?: unknown } | unknown };
const raw = quoteEnvelope?.raw;
const quote =
  raw && typeof raw === "object" && "quote" in raw ? (raw as { quote: unknown }).quote : raw;
let verifiedQuote;
try {
  verifiedQuote = await provider.verifyQuote(quote ?? rawQuote, { nonce });
} catch {
  console.error("quote verification failed");
  process.exit(1);
}
const match = verifyQuoteAgainstRegistry(verifiedQuote, registry, deployment);
if (!match.ok) {
  console.error(`attestation measurement check failed: ${match.reason}`);
  console.error(
    JSON.stringify(
      { provider: verifiedQuote.provider, measurement: verifiedQuote.measurement },
      null,
      2,
    ),
  );
  process.exit(1);
}

console.log(`attestation measurement ok for ${deployment}`);
