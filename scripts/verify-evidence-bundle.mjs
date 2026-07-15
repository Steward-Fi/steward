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
 *   (b) Event content authentication: the checkpoint signs `eventsDigest`, a
 *       SHA-256 commitment over EVERY exported event's canonical fields. The
 *       verifier recomputes it from the bundle events and requires a match, so
 *       mutating ANY field (action, metadata, actorId, createdAt, ...) or
 *       inserting/removing/reordering events breaks verification, even without
 *       the operator's secret HMAC key.
 *   (c) Event linkage: within the exported list, each event's `prevHash` equals
 *       the previous event's `hmac` — the exported rows form an unbroken
 *       segment of one hash chain.
 *   (d) Head binding: head inclusion is DERIVED from the signed checkpoint
 *       (`lastEvent.seq === payload.seq`), never from an unsigned envelope flag.
 *       When the export reaches the head, the last event's `hmac` MUST equal the
 *       signed `headHmac`, tying the exported set to the operator's committed head.
 *   (e) Sequence continuity: seqs increase by exactly 1 with no gaps.
 *
 * ─── WHAT THIS DOES NOT PROVE ────────────────────────────────────────────────
 *   • It does not recompute the per-row HMACs. Those are keyed with the
 *     operator's SECRET HMAC key, which (correctly) is not in the bundle. So
 *     this verifier cannot detect an operator who, holding BOTH the HMAC key and
 *     the signing key, fabricates a self-consistent chain and signs it. It
 *     raises the bar from "trust the operator's secret" to "trust the operator's
 *     published, append-only, third-partyly-witnessable checkpoints."
 *   • It does not prove the exported range is the WHOLE history — only that what
 *     is present is internally consistent, its contents are authentic, and (when
 *     it reaches the head) it matches the signed head. A gap BELOW the first
 *     exported seq is expected for partial exports.
 *   • It does not timestamp-anchor the checkpoint externally (out of scope v1).
 */

import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";

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

// Recursively canonicalize a JSON value: sort keys, null for undefined/null.
// MUST match canonicalJsonValue in services/audit.ts + audit-checkpoint.ts.
function canonicalJsonValue(value) {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) return value.map((item) => canonicalJsonValue(item));
  if (typeof value === "object") {
    const ordered = {};
    for (const key of Object.keys(value).sort()) {
      ordered[key] = canonicalJsonValue(value[key]);
    }
    return ordered;
  }
  return value;
}

// Canonical bytes of one event's CONTENT. Field names are snake_case to match
// the server's HMAC-chain canonicalization and audit-checkpoint.ts exactly.
function canonicalEventContentBytes(ev, tenantId) {
  const fields = {
    tenant_id: tenantId,
    seq: ev.seq,
    actor_type: ev.actorType ?? null,
    actor_id: ev.actorId ?? null,
    action: ev.action ?? null,
    resource_type: ev.resourceType ?? null,
    resource_id: ev.resourceId ?? null,
    metadata: ev.metadata ?? {},
    ip_address: ev.ipAddress ?? null,
    user_agent: ev.userAgent ?? null,
    request_id: ev.requestId ?? null,
    created_at: ev.createdAt ?? null,
  };
  return Buffer.from(JSON.stringify(canonicalJsonValue(fields)), "utf8");
}

// Rolling SHA-256 content commitment over the ordered events. MUST match
// eventsContentDigest in services/audit-checkpoint.ts: "" for empty; else
// acc = SHA256("steward-audit-events/v1"); acc = SHA256(acc_hex || leaf_hex).
function eventsContentDigest(events, tenantId) {
  if (events.length === 0) return "";
  let acc = createHash("sha256").update("steward-audit-events/v1").digest("hex");
  for (const ev of events) {
    const leaf = createHash("sha256")
      .update(canonicalEventContentBytes(ev, tenantId))
      .digest("hex");
    acc = createHash("sha256").update(acc).update(leaf).digest("hex");
  }
  return acc;
}

function main() {
  const bundle = loadBundle();

  if (!bundle || typeof bundle !== "object") fail("bundle is not an object");
  if (bundle.version !== 1) fail(`unsupported bundle version: ${bundle.version}`);
  const { checkpoint, events, tenantId } = bundle;
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

  // ── (c)+(e) Event linkage + sequence continuity ──────────────────────────
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

  // ── (b) Event content authentication ─────────────────────────────────────
  // Recompute the signed content digest from the bundle events. This is the
  // check that catches mutation of any event FIELD (action, metadata, actorId,
  // createdAt, ...) even though the offline verifier has no HMAC key. The
  // recomputation uses the CHECKPOINT'S tenantId (which is signed), so an
  // attacker cannot dodge it by rewriting the unsigned envelope tenantId.
  const recomputedDigest = eventsContentDigest(events, payload.tenantId);
  if (typeof payload.eventsDigest !== "string") {
    fail("checkpoint payload is missing eventsDigest (unsupported/old bundle)");
  }
  if (recomputedDigest !== payload.eventsDigest) {
    fail("event content digest does not match the signed checkpoint (events tampered)");
  }
  // The signed eventsFromSeq/eventsToSeq must bracket exactly the present events.
  if (events.length > 0) {
    if (payload.eventsFromSeq !== events[0].seq) {
      fail(
        `signed eventsFromSeq (${payload.eventsFromSeq}) != first event seq (${events[0].seq})`,
        events[0].seq,
      );
    }
    if (payload.eventsToSeq !== events[events.length - 1].seq) {
      fail(
        `signed eventsToSeq (${payload.eventsToSeq}) != last event seq (${events[events.length - 1].seq})`,
        events[events.length - 1].seq,
      );
    }
  } else if (payload.eventsFromSeq !== 0 || payload.eventsToSeq !== 0) {
    fail("signed eventsFromSeq/eventsToSeq are non-zero but the bundle has no events");
  }

  // ── (d) Head binding: DERIVE inclusion from signed data, never the envelope.
  // The export reaches the chain head iff its last event's seq equals the
  // checkpoint's signed head seq. `range.includesHead` in the envelope is
  // unsigned and advisory only — we ignore it for the security decision.
  const includesHead =
    events.length > 0 &&
    typeof payload.seq === "number" &&
    events[events.length - 1].seq === payload.seq;
  if (includesHead) {
    const lastHmac = events[events.length - 1].hmac;
    if (lastHmac !== payload.headHmac) {
      fail(
        `last event hmac (${lastHmac}) != checkpoint headHmac (${payload.headHmac})`,
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
  console.log(
    `  events:        ${events.length}` +
      (events.length ? ` (seq ${events[0].seq}..${events[events.length - 1].seq})` : ""),
  );
  console.log(
    `  checkpoint:    seq=${payload.seq} count=${payload.expectedCount} floorSeq=${payload.floorSeq}`,
  );
  console.log(`  signed at:     ${payload.timestamp} (software ${payload.softwareVersion})`);
  console.log(`  signature:     Ed25519 OK`);
  console.log(`  content:       SHA-256 events digest OK`);
  console.log(`  linkage:       OK`);
  console.log(`  head:          ${headNote}`);
  console.log("");
  console.log(
    "Proven: exported event contents are authentic (signed SHA-256 digest); " +
      "rows form an unbroken hash-chain segment; " +
      (includesHead ? "the head matches the operator's signed checkpoint; " : "") +
      "the checkpoint is authentically Ed25519-signed and unaltered.",
  );
  console.log(
    "NOT proven: per-row HMAC recomputation (needs the operator's secret key); " +
      "that the export is the complete history; third-party timestamp anchoring.",
  );
  process.exit(0);
}

main();
