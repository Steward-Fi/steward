#!/usr/bin/env node
/**
 * Standalone offline verifier for a Steward audit evidence bundle.
 *
 * ZERO project imports, ZERO third-party dependencies — only Node builtins.
 * An auditor can run this on any machine with Node, holding nothing but the
 * bundle JSON (which carries its own Ed25519 public key). No Steward access, no
 * secret HMAC key.
 *
 *   node scripts/verify-evidence-bundle.mjs <bundle.json>
 *   cat bundle.json | node scripts/verify-evidence-bundle.mjs
 *
 * Exit code 0 = PASS, 1 = FAIL, 2 = usage/parse error.
 *
 * ─── WHAT THIS PROVES ────────────────────────────────────────────────────────
 *   (a) Ed25519 signature: the checkpoint payload was signed by the holder of
 *       the private key matching the bundle's published public key, and has not
 *       been altered since (any change to a payload field breaks the signature).
 *   (b) Event linkage: within the exported list, each event's `prevHash` equals
 *       the previous event's `hmac` — the exported rows form an unbroken
 *       segment of one hash chain (no row inserted, removed, or reordered
 *       inside the exported range without detection).
 *   (c) Head binding: when the export includes the chain head (range.includesHead),
 *       the last event's `hmac` equals the checkpoint's signed `headHmac`. This
 *       ties the exported set to the exact head the operator committed to at
 *       signing time.
 *   (d) Sequence continuity: seqs increase by exactly 1 with no gaps.
 *
 * ─── WHAT THIS DOES NOT PROVE ────────────────────────────────────────────────
 *   • It does not recompute the per-row HMACs. Those are keyed with the
 *     operator's SECRET HMAC key, which (correctly) is not in the bundle. So
 *     this verifier cannot detect an operator who, holding BOTH the HMAC key and
 *     the signing key, fabricates a self-consistent chain and signs it. It
 *     raises the bar from "trust the operator's secret" to "trust the operator's
 *     published, append-only, third-partyly-witnessable checkpoints."
 *   • It does not prove the exported range is the WHOLE history — only that what
 *     is present is internally consistent and (if includesHead) reaches the
 *     signed head. A gap BELOW range.from is expected for partial exports.
 *   • It does not timestamp-anchor the checkpoint externally (out of scope v1).
 */

import { readFileSync } from "node:fs";
import { createPublicKey, verify as edVerify } from "node:crypto";

function fail(msg, seq) {
  const at = seq === undefined ? "" : ` (seq ${seq})`;
  console.error(`FAIL: ${msg}${at}`);
  process.exit(1);
}

function usage(msg) {
  console.error(`usage error: ${msg}`);
  console.error("  node scripts/verify-evidence-bundle.mjs <bundle.json>");
  console.error("  cat bundle.json | node scripts/verify-evidence-bundle.mjs");
  process.exit(2);
}

// ─── Load bundle (file arg or stdin) ────────────────────────────────────────
function loadBundle() {
  const arg = process.argv[2];
  let raw;
  if (arg && arg !== "-") {
    try {
      raw = readFileSync(arg, "utf8");
    } catch (err) {
      usage(`could not read ${arg}: ${err.message}`);
    }
  } else {
    try {
      raw = readFileSync(0, "utf8");
    } catch {
      usage("no bundle file argument and nothing on stdin");
    }
  }
  if (!raw || raw.trim().length === 0) usage("empty bundle input");
  try {
    return JSON.parse(raw);
  } catch (err) {
    usage(`bundle is not valid JSON: ${err.message}`);
  }
}

// Canonical bytes MUST match packages/api/src/services/audit-checkpoint.ts
// canonicalCheckpointBytes: sort top-level keys, JSON.stringify, no whitespace.
function canonicalCheckpointBytes(payload) {
  const ordered = {};
  for (const key of Object.keys(payload).sort()) {
    ordered[key] = payload[key];
  }
  return Buffer.from(JSON.stringify(ordered), "utf8");
}

function main() {
  const bundle = loadBundle();

  if (!bundle || typeof bundle !== "object") fail("bundle is not an object");
  if (bundle.version !== 1) fail(`unsupported bundle version: ${bundle.version}`);
  const { checkpoint, events, range, tenantId } = bundle;
  if (!checkpoint || typeof checkpoint !== "object") fail("bundle.checkpoint missing");
  if (!Array.isArray(events)) fail("bundle.events is not an array");

  const { payload, signature, publicKey } = checkpoint;
  if (!payload || typeof payload !== "object") fail("checkpoint.payload missing");
  if (typeof signature !== "string") fail("checkpoint.signature missing");
  if (typeof publicKey !== "string") fail("checkpoint.publicKey missing");

  // ── (a) Ed25519 signature over the canonical checkpoint payload ──────────
  let pubKeyObj;
  try {
    pubKeyObj = createPublicKey({ key: publicKey, format: "pem" });
  } catch (err) {
    fail(`checkpoint.publicKey is not a valid PEM: ${err.message}`);
  }
  if (pubKeyObj.asymmetricKeyType !== "ed25519") {
    fail(`checkpoint.publicKey is not Ed25519 (got ${pubKeyObj.asymmetricKeyType})`);
  }
  let sigBytes;
  try {
    sigBytes = Buffer.from(signature, "base64");
  } catch (err) {
    fail(`checkpoint.signature is not valid base64: ${err.message}`);
  }
  const sigOk = edVerify(null, canonicalCheckpointBytes(payload), pubKeyObj, sigBytes);
  if (!sigOk) fail("Ed25519 checkpoint signature does not verify");

  // Cross-check the payload's tenantId against the bundle envelope.
  if (tenantId !== undefined && payload.tenantId !== tenantId) {
    fail(`checkpoint tenantId (${payload.tenantId}) != bundle tenantId (${tenantId})`);
  }

  // ── (b)+(d) Event linkage + sequence continuity ──────────────────────────
  let prevHmac = null; // hmac (hex) of the previous event; null before first
  let prevSeq = null;
  for (const ev of events) {
    if (typeof ev.seq !== "number") fail("event has non-numeric seq", ev.seq);
    if (typeof ev.hmac !== "string" || typeof ev.prevHash !== "string") {
      fail("event missing hmac/prevHash hex", ev.seq);
    }
    if (prevSeq !== null && ev.seq !== prevSeq + 1) {
      fail(`sequence gap: expected ${prevSeq + 1}, got ${ev.seq}`, ev.seq);
    }
    if (prevHmac !== null && ev.prevHash !== prevHmac) {
      fail("prevHash does not match previous event's hmac (chain break)", ev.seq);
    }
    prevHmac = ev.hmac;
    prevSeq = ev.seq;
  }

  // ── (c) Head binding (only when the export reaches the chain head) ────────
  const includesHead = range && range.includesHead === true;
  if (includesHead) {
    if (events.length === 0) {
      fail("range.includesHead is true but the event list is empty");
    }
    const lastHmac = events[events.length - 1].hmac;
    if (lastHmac !== payload.headHmac) {
      fail(
        `last event hmac (${lastHmac}) != checkpoint headHmac (${payload.headHmac})`,
        events[events.length - 1].seq,
      );
    }
    if (typeof payload.seq === "number" && events[events.length - 1].seq !== payload.seq) {
      fail(
        `last event seq (${events[events.length - 1].seq}) != checkpoint seq (${payload.seq})`,
        events[events.length - 1].seq,
      );
    }
  }

  // ── PASS ─────────────────────────────────────────────────────────────────
  const headNote = includesHead
    ? "includes chain head, bound to signed checkpoint"
    : "partial range (does NOT include chain head — head binding not checked)";
  console.log("PASS");
  console.log(`  tenant:        ${payload.tenantId}`);
  console.log(`  events:        ${events.length}` +
    (events.length ? ` (seq ${events[0].seq}..${events[events.length - 1].seq})` : ""));
  console.log(`  checkpoint:    seq=${payload.seq} count=${payload.expectedCount} floorSeq=${payload.floorSeq}`);
  console.log(`  signed at:     ${payload.timestamp} (software ${payload.softwareVersion})`);
  console.log(`  signature:     Ed25519 OK`);
  console.log(`  linkage:       OK`);
  console.log(`  head:          ${headNote}`);
  console.log("");
  console.log("Proven: exported rows form an unbroken hash-chain segment; " +
    (includesHead ? "the head matches the operator's signed checkpoint; " : "") +
    "the checkpoint is authentically Ed25519-signed and unaltered.");
  console.log("NOT proven: per-row HMAC recomputation (needs the operator's secret key); " +
    "that the export is the complete history; third-party timestamp anchoring.");
  process.exit(0);
}

main();
