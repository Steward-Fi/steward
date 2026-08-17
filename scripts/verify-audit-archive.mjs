#!/usr/bin/env node

/** Offline verifier for a Steward signed JSONL audit archive directory. */

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function canonical(value) {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) return value.map(canonical);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonical(value)), "utf8");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const manifestPath = process.argv[2];
if (!manifestPath) {
  console.error(
    "usage: node scripts/verify-audit-archive.mjs <manifest.json> [archive-directory] [--expected-key-fingerprint <sha256>] [--expected-key-id <id>]",
  );
  process.exit(2);
}
const archiveDir = process.argv[3] || dirname(manifestPath);
const fingerprintFlag = process.argv.indexOf("--expected-key-fingerprint");
const expectedFingerprint = fingerprintFlag >= 0 ? process.argv[fingerprintFlag + 1] : undefined;
const keyIdFlag = process.argv.indexOf("--expected-key-id");
const expectedKeyId = keyIdFlag >= 0 ? process.argv[keyIdFlag + 1] : undefined;
if (fingerprintFlag >= 0 && !/^[0-9a-f]{64}$/i.test(expectedFingerprint ?? "")) {
  fail("expected key fingerprint must be exactly 64 hexadecimal characters");
}
if (keyIdFlag >= 0 && !/^[A-Za-z0-9_.:-]{1,64}$/.test(expectedKeyId ?? "")) {
  fail("expected key id is invalid");
}
let envelope;
try {
  envelope = JSON.parse(readFileSync(manifestPath, "utf8"));
} catch (error) {
  fail(`manifest cannot be read: ${error.message}`);
}
const { manifest, manifestSha256, signature, publicKey } = envelope;
if (!manifest || manifest.schemaVersion !== "steward.audit-archive.v1") {
  fail("unsupported or missing archive manifest");
}
if (!Array.isArray(manifest.chunks) || manifest.chunks.length === 0) {
  fail("manifest chunks are missing");
}
if (expectedKeyId && manifest.signingKeyId !== expectedKeyId) {
  fail("archive signing key id does not match the trusted identity");
}
const bytes = canonicalBytes(manifest);
if (sha256(bytes) !== manifestSha256) fail("manifest SHA-256 does not match");
let key;
try {
  key = createPublicKey({ key: publicKey, format: "pem" });
} catch (error) {
  fail(`archive public key is invalid: ${error.message}`);
}
if (key.asymmetricKeyType !== "ed25519") fail("archive signing key is not Ed25519");
const signatureBytes = Buffer.from(signature, "base64");
if (signatureBytes.length !== 64 || signatureBytes.toString("base64") !== signature) {
  fail("archive signature is not canonical Ed25519 base64");
}
const actualFingerprint = sha256(key.export({ format: "der", type: "spki" }));
if (expectedFingerprint && actualFingerprint !== expectedFingerprint.toLowerCase()) {
  fail("archive signing key fingerprint does not match the trusted key");
}
if (!verify(null, bytes, key, signatureBytes)) {
  fail("archive manifest signature does not verify");
}

let expectedSeq = manifest.fromSeq;
let previousHmac = manifest.startPrevHash;
let observed = 0;
for (let index = 0; index < manifest.chunks.length; index++) {
  const chunk = manifest.chunks[index];
  if (chunk.index !== index || chunk.fromSeq !== expectedSeq) {
    fail(`chunk ${index} range is not contiguous`);
  }
  if (!/^chunk-\d{6}\.jsonl$/.test(chunk.file)) fail(`chunk ${index} filename is unsafe`);
  const path = join(archiveDir, chunk.file);
  let raw;
  try {
    raw = readFileSync(path);
  } catch (error) {
    fail(`chunk ${index} cannot be read: ${error.message}`);
  }
  if (raw.length !== chunk.byteLength) fail(`chunk ${index} byte length does not match`);
  if (sha256(raw) !== chunk.sha256) fail(`chunk ${index} SHA-256 does not match`);
  const text = raw.toString("utf8");
  if (!text.endsWith("\n")) fail(`chunk ${index} is not newline-terminated JSONL`);
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== chunk.eventCount) fail(`chunk ${index} event count does not match`);
  for (const line of lines) {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      fail(`chunk ${index} contains invalid JSONL`);
    }
    if (event.tenantId !== manifest.tenantId) fail(`event ${expectedSeq} tenant mismatch`);
    if (event.seq !== expectedSeq) fail(`expected event seq ${expectedSeq}, got ${event.seq}`);
    if (!/^[0-9a-f]{64}$/.test(event.prevHash) || !/^[0-9a-f]{64}$/.test(event.hmac)) {
      fail(`event ${event.seq} contains a malformed chain hash`);
    }
    if (event.prevHash !== previousHmac) fail(`event ${event.seq} chain linkage mismatch`);
    previousHmac = event.hmac;
    expectedSeq++;
    observed++;
  }
  if (chunk.toSeq !== expectedSeq - 1) fail(`chunk ${index} toSeq does not match content`);
}
if (observed !== manifest.eventCount || expectedSeq - 1 !== manifest.toSeq) {
  fail("archive manifest event range/count does not match JSONL content");
}
if (previousHmac !== manifest.endHmac) fail("archive end HMAC does not match manifest");

console.log("PASS");
console.log(`  archive: ${manifest.archiveId}`);
console.log(`  tenant:  ${manifest.tenantId}`);
console.log(`  events:  ${manifest.eventCount} (seq ${manifest.fromSeq}..${manifest.toSeq})`);
console.log(`  chunks:  ${manifest.chunks.length}`);
console.log("  manifest signature: Ed25519 OK");
console.log("  JSONL hashes/linkage: OK");
