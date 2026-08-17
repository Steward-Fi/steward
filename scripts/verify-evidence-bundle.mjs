#!/usr/bin/env node

/**
 * Standalone offline verifier for a Steward audit evidence bundle.
 *
 * ZERO project imports and ZERO package dependencies. Base bundle checks use
 * only Node builtins; optional RFC 3161 trust verification invokes OpenSSL.
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
 *   • RFC 3161 verification is optional and trusts only an auditor-supplied
 *     TSA CA. Anchoring narrows the pre-anchor rewrite window; it does not make
 *     the system tamper-proof or operator-proof.
 */

import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function fail(msg, seq) {
  const at = seq === undefined ? "" : ` (seq ${seq})`;
  console.error(`FAIL: ${msg}${at}`);
  process.exit(1);
}

function usage(msg) {
  console.error(`usage error: ${msg}`);
  console.error(
    "  node scripts/verify-evidence-bundle.mjs <bundle.json> [--expected-key-fingerprint <hex>] [--tsa-ca <pem>]",
  );
  console.error("  cat bundle.json | node scripts/verify-evidence-bundle.mjs [--fp <hex>]");
  console.error("");
  console.error("  --expected-key-fingerprint <hex>  SHA-256 of the trusted signing key SPKI PEM,");
  console.error("       supplied out of band. Repeatable (rotation set). Also read from");
  console.error("       STEWARD_EXPECTED_AUDIT_KEY_FP (comma-separated). If absent, the verifier");
  console.error("       prints the observed fingerprint and states trust-root matching is the");
  console.error("       auditor responsibility.");
  console.error(
    "  --tsa-ca <pem>  Verify an included RFC 3161 token against this auditor-supplied CA.",
  );
  console.error("  --tsa-untrusted <pem>  Optional intermediate TSA certificate chain.");
  console.error("  --tsa-policy <oid>  Require the signed TSTInfo policy OID.");
  console.error("  --require-anchor  Fail unless an RFC 3161 proof is present and verifies.");
  console.error("  --anchored-before <ISO-8601>  Require verified TSA time at/before this bound.");
  process.exit(2);
}

// ─── Parse args (positional bundle path + optional fingerprint flags) ────────
function parseArgs() {
  const argv = process.argv.slice(2);
  let bundleArg;
  const expectedFps = [];
  let tsaCa;
  let tsaUntrusted;
  let requireAnchor = false;
  let anchoredBefore;
  let tsaPolicy;
  const clean = (s) => s.toLowerCase().replace(/[^0-9a-f]/g, "");
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--expected-key-fingerprint" || a === "--fp") {
      const v = argv[i + 1];
      if (!v) usage(`${a} requires a hex value`);
      expectedFps.push(clean(v));
      i++;
    } else if (a.startsWith("--expected-key-fingerprint=") || a.startsWith("--fp=")) {
      expectedFps.push(clean(a.slice(a.indexOf("=") + 1)));
    } else if (
      a === "--tsa-ca" ||
      a === "--tsa-untrusted" ||
      a === "--anchored-before" ||
      a === "--tsa-policy"
    ) {
      const v = argv[i + 1];
      if (!v) usage(`${a} requires a value`);
      if (a === "--tsa-ca") tsaCa = v;
      if (a === "--tsa-untrusted") tsaUntrusted = v;
      if (a === "--anchored-before") anchoredBefore = v;
      if (a === "--tsa-policy") tsaPolicy = v;
      i++;
    } else if (a === "--require-anchor") {
      requireAnchor = true;
    } else if (a.startsWith("--")) {
      usage(`unknown option ${a}`);
    } else if (!bundleArg) {
      bundleArg = a;
    } else {
      usage(`unexpected positional argument ${a}`);
    }
  }
  const envFp = process.env.STEWARD_EXPECTED_AUDIT_KEY_FP;
  if (envFp) {
    for (const part of envFp.split(",")) {
      const c = clean(part.trim());
      if (c) expectedFps.push(c);
    }
  }
  if (anchoredBefore && !Number.isFinite(new Date(anchoredBefore).getTime())) {
    usage("--anchored-before must be a valid ISO-8601 timestamp");
  }
  if (tsaUntrusted && !tsaCa) usage("--tsa-untrusted requires --tsa-ca");
  if ((requireAnchor || anchoredBefore) && !tsaCa) {
    usage("--require-anchor/--anchored-before require an auditor-supplied --tsa-ca");
  }
  return {
    bundleArg,
    expectedFps,
    tsaCa,
    tsaUntrusted,
    tsaPolicy,
    requireAnchor,
    anchoredBefore,
  };
}

function checkpointAnchorDigest(payload) {
  return createHash("sha256").update(canonicalCheckpointBytes(payload)).digest("hex");
}

function strictBase64(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    fail(`${name} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) {
    fail(`${name} is not canonical base64`);
  }
  return decoded;
}

function verifyRfc3161Anchor(anchor, payload, options) {
  if (!anchor) {
    if (options.requireAnchor || options.tsaCa || options.anchoredBefore) {
      fail("required RFC 3161 checkpoint anchor is missing");
    }
    return { present: false, verified: false, time: null };
  }
  if (
    anchor.v !== 1 ||
    anchor.type !== "rfc3161" ||
    anchor.hashAlgorithm !== "sha256" ||
    typeof anchor.sinkId !== "string" ||
    !/^[0-9a-f]{64}$/.test(anchor.checkpointDigest) ||
    !/^[0-9a-f]{32}$/.test(anchor.nonce) ||
    typeof anchor.policyOid !== "string" ||
    typeof anchor.genTime !== "string" ||
    !Number.isFinite(Date.parse(anchor.genTime)) ||
    !Number.isFinite(anchor.accuracyMillis) ||
    anchor.accuracyMillis < 0 ||
    typeof anchor.verifiedAt !== "string" ||
    !Number.isFinite(Date.parse(anchor.verifiedAt)) ||
    !/^[0-9a-f]{64}$/.test(anchor.trustAnchorSha256)
  ) {
    fail("checkpoint RFC 3161 anchor schema is invalid");
  }
  const digest = checkpointAnchorDigest(payload);
  if (anchor.checkpointDigest !== digest) {
    fail("RFC 3161 anchor digest does not match the signed checkpoint payload");
  }
  const response = strictBase64(anchor.timestampResponse, "RFC 3161 timestampResponse");
  if (response.length > 1024 * 1024) fail("RFC 3161 timestampResponse exceeds 1 MiB");
  if (!options.tsaCa) return { present: true, verified: false, time: null };

  const dir = mkdtempSync(join(tmpdir(), "steward-rfc3161-"));
  const responsePath = join(dir, "response.tsr");
  try {
    writeFileSync(responsePath, response, { mode: 0o600 });
    const inspected = spawnSync("openssl", ["ts", "-reply", "-in", responsePath, "-text"], {
      encoding: "utf8",
      timeout: 30_000,
    });
    if (inspected.error || inspected.status !== 0) {
      fail("RFC 3161 token could not be inspected for its timestamp");
    }
    const match = inspected.stdout.match(/^Time stamp:\s*(.+)$/m);
    if (!match) fail("RFC 3161 token did not contain a timestamp");
    const time = new Date(match[1]);
    if (!Number.isFinite(time.getTime())) fail("RFC 3161 token timestamp is not parseable");
    const verifyArgs = [
      "ts",
      "-verify",
      "-digest",
      digest,
      "-in",
      responsePath,
      "-CAfile",
      options.tsaCa,
      "-attime",
      String(Math.floor(time.getTime() / 1000)),
    ];
    if (options.tsaUntrusted) verifyArgs.push("-untrusted", options.tsaUntrusted);
    const verified = spawnSync("openssl", verifyArgs, {
      encoding: "utf8",
      timeout: 30_000,
    });
    if (verified.error) fail(`could not run OpenSSL RFC 3161 verifier: ${verified.error.message}`);
    if (verified.status !== 0) {
      fail(`RFC 3161 token verification failed: ${(verified.stderr || verified.stdout).trim()}`);
    }
    const policyOid = inspected.stdout.match(/^Policy OID:\s*([^\s]+)\s*$/m)?.[1];
    const nonceText = inspected.stdout.match(/^Nonce:\s*(0x[0-9a-f]+|[0-9]+)\s*$/im)?.[1];
    if (!policyOid || !nonceText) fail("verified RFC 3161 TSTInfo is missing policy or nonce");
    const tokenNonce = BigInt(nonceText).toString(16).padStart(32, "0");
    if (tokenNonce !== anchor.nonce)
      fail("verified RFC 3161 nonce does not match the proof binding");
    if (policyOid !== anchor.policyOid || (options.tsaPolicy && policyOid !== options.tsaPolicy)) {
      fail("verified RFC 3161 policy OID is not allowed");
    }
    const accuracyLine = inspected.stdout.match(/^Accuracy:\s*(.+)$/m)?.[1] ?? "";
    const accuracyPart = (name, scale) => {
      const found = accuracyLine.match(new RegExp(`(?:0x([0-9a-f]+)|([0-9]+))\\s+${name}`, "i"));
      return found ? Number.parseInt(found[1] ?? found[2], found[1] ? 16 : 10) * scale : 0;
    };
    const accuracyMillis =
      accuracyPart("seconds", 1000) + accuracyPart("millis", 1) + accuracyPart("micros", 0.001);
    if (accuracyMillis !== anchor.accuracyMillis || time.toISOString() !== anchor.genTime) {
      fail("RFC 3161 proof metadata does not match the signed TSTInfo");
    }
    const latestTime = new Date(time.getTime() + accuracyMillis);
    if (options.anchoredBefore && latestTime > new Date(options.anchoredBefore)) {
      fail(
        `RFC 3161 latest accuracy bound ${latestTime.toISOString()} is after required bound ${options.anchoredBefore}`,
      );
    }
    return {
      present: true,
      verified: true,
      time: time.toISOString(),
      latestTime: latestTime.toISOString(),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// SHA-256 fingerprint of a signing key SPKI DER (spec §7.1/§7.2, C6).
function keyFingerprint(pubKeyObj) {
  const spki = pubKeyObj.export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki).digest("hex");
}

// ─── Load bundle (file arg or stdin) ────────────────────────────────────────
function loadBundle(bundleArg) {
  const arg = bundleArg;
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
  const options = parseArgs();
  const { bundleArg, expectedFps } = options;
  const input = loadBundle(bundleArg);

  if (!input || typeof input !== "object") fail("bundle is not an object");

  // Two accepted shapes, both backward-compatible:
  //   1. raw /audit/bundle: { version, tenantId, events, checkpoint, ... }
  //   2. PR5 /evidence envelope: { version, tenantId, caseId, manifest,
  //      bundle: { ...raw bundle... }, completeness }
  // Detect the envelope by a nested `bundle` object + a `manifest`, then verify
  // the inner bundle exactly as before and additionally cross-check the manifest
  // against the signed events (spec §7.4). A plain bundle behaves EXACTLY as
  // today (no regression).
  const isEvidenceEnvelope =
    input.bundle &&
    typeof input.bundle === "object" &&
    input.manifest &&
    typeof input.manifest === "object";
  const bundle = isEvidenceEnvelope ? input.bundle : input;
  const manifest = isEvidenceEnvelope ? input.manifest : null;

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

  // Optional third-party time proof. Its message imprint MUST bind the exact
  // canonical checkpoint payload. Trust comes only from an auditor-supplied CA.
  const anchorResult = verifyRfc3161Anchor(checkpoint.anchor, payload, options);

  // ── Trust-root fingerprint match (spec §7.1/§7.2, C6) ────────────────────
  // The bundle is self-describing (it carries its own public key); an auditor
  // supplies the trusted fingerprint(s) out of band. We NEVER auto-trust the
  // embedded key. If one or more expected fingerprints are supplied, at least
  // one MUST match (a rotation set may be supplied). If NONE are supplied we do
  // not fail, but we clearly state trust-root matching is the auditor's job (E7).
  const observedFp = keyFingerprint(pubKeyObj);
  let trustRootChecked = false;
  if (expectedFps.length > 0) {
    if (!expectedFps.includes(observedFp)) {
      fail(`untrusted signing key fingerprint ${observedFp}`);
    }
    trustRootChecked = true;
  }

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

  // ── (f) Manifest cross-check (spec §7.4) — only for a PR5 evidence envelope.
  // The manifest carries NO independent trust: every fact must be checkable
  // against a signed event. If ANY manifest fact is not backed, or a claimed
  // `complete` hides a missing required role, we FAIL. A plain /audit/bundle
  // (manifest === null) skips this entirely (no regression).
  if (manifest) {
    verifyManifest(manifest, events, payload);
  }

  // ── PASS ─────────────────────────────────────────────────────────────────
  const headNote = includesHead
    ? "includes chain head, bound to signed checkpoint"
    : "partial range (does NOT include chain head — head binding not checked)";
  console.log("PASS");
  console.log(`  tenant:        ${payload.tenantId}`);
  if (manifest) {
    console.log(`  case:          ${manifest.caseId}`);
    console.log(`  terminalState: ${manifest.terminalState}`);
    console.log(`  completeness:  ${manifest.completeness}`);
  }
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
  console.log(
    `  anchor:        ${
      anchorResult.verified
        ? `RFC 3161 verified; checkpoint existed no later than ${anchorResult.time}`
        : anchorResult.present
          ? "RFC 3161 proof present but NOT trusted; supply --tsa-ca"
          : "not present (optional)"
    }`,
  );
  if (manifest)
    console.log(`  manifest:      cross-check OK (every fact backed by a signed event)`);
  console.log(`  head:          ${headNote}`);
  console.log(
    `  trust root:    ${
      trustRootChecked
        ? `matched supplied fingerprint (${observedFp})`
        : `NOT checked — observed key fingerprint ${observedFp}; supply --expected-key-fingerprint to bind trust root`
    }`,
  );
  console.log("");
  console.log(
    "Proven: exported event contents are authentic (signed SHA-256 digest); " +
      "rows form an unbroken hash-chain segment; " +
      (manifest ? "every manifest fact is backed by a signed event; " : "") +
      (includesHead ? "the head matches the operator's signed checkpoint; " : "") +
      (trustRootChecked
        ? "the signing key matches an auditor-supplied trusted fingerprint; "
        : "") +
      (anchorResult.verified
        ? `a trusted TSA proves the checkpoint existed no later than ${anchorResult.time}; `
        : "") +
      "the checkpoint is authentically Ed25519-signed and unaltered.",
  );
  console.log(
    "NOT proven: per-row HMAC recomputation (needs the operator's secret key), so an " +
      "operator holding BOTH the HMAC key AND the signing key could fabricate a " +
      "self-consistent history; that the export is the complete history; " +
      (trustRootChecked ? "" : "trust-root binding (no expected fingerprint supplied); ") +
      (anchorResult.verified
        ? "events after the anchor or TSA/operator collusion. Anchoring narrows the pre-anchor rewrite window; it is not operator-proof."
        : "out-of-band time anchoring."),
  );
  process.exit(0);
}

// ─── PR5 manifest cross-check (spec §7.4) ────────────────────────────────

const MANIFEST_SCHEMA_VERSION = "steward.provider-case-manifest.v1";

// Map an event action to its case role. MUST mirror roleForAction in
// @stwd/shared/provider-case.ts (kept in sync by a golden test).
function roleForAction(action) {
  switch (action) {
    case "provider.action.allowed":
    case "provider.action.denied":
    case "provider.action.approval_required":
      return "genesis";
    case "provider.access.decided":
      return "access_decided";
    case "provider.policy.decided":
      return "policy_decided";
    case "provider.approval.requested":
      return "approval_requested";
    case "provider.approval.decided":
      return "approval_decided";
    case "provider.approval.expired":
    case "provider.approval.staled":
      return "approval_terminal";
    case "provider.resume.ready":
      return "resume_ready";
    case "provider.execution.authorized":
      return "exec_authorized";
    case "provider.execution.claimed":
      return "exec_claimed";
    case "provider.execution.denied_at_boundary":
      return "exec_denied_at_boundary";
    case "provider.execution.dispatched":
      return "exec_dispatched";
    case "provider.execution.succeeded":
    case "provider.execution.failed":
    case "provider.execution.outcome_unknown":
      return "exec_terminal";
    case "provider.execution.reconciled":
      return "exec_reconciled";
    default:
      // Unknown/drifted action: classified but role NEVER satisfies a required
      // slot (mirrors @stwd/shared roleForAction fallback in the manifest).
      return "unclassified";
  }
}

// MUST mirror requiredRoles in @stwd/shared/provider-case.ts.
function requiredRoles(terminalState) {
  switch (terminalState) {
    case "denied_access":
    case "denied_policy":
    case "pending_approval":
      return ["genesis"];
    case "approval_denied":
      return ["genesis", "approval_decided"];
    case "approval_expired":
    case "approval_staled":
      return ["genesis", "approval_terminal"];
    case "execution_ready":
      return ["genesis", "approval_decided", "resume_ready"];
    case "executing":
      return ["genesis", "exec_authorized", "exec_claimed"];
    case "succeeded":
    case "failed":
    case "outcome_unknown":
      return ["genesis", "exec_authorized", "exec_claimed", "exec_dispatched", "exec_terminal"];
    default:
      return ["genesis", "exec_authorized", "exec_claimed", "exec_dispatched", "exec_terminal"];
  }
}

function verifyManifest(manifest, events, payload) {
  if (manifest.schemaVersion !== MANIFEST_SCHEMA_VERSION) {
    fail(`unsupported manifest schemaVersion: ${manifest.schemaVersion}`);
  }
  // Tenant cross-check (N22): manifest tenant must equal the SIGNED payload
  // tenant, so a foreign case id cannot be smuggled under one tenant's checkpoint.
  if (manifest.tenantId !== payload.tenantId) {
    fail(
      `manifest tenantId (${manifest.tenantId}) != signed checkpoint tenant (${payload.tenantId})`,
    );
  }

  // Build seq -> signed bundle event. (§7.4.1) Each manifest event MUST match
  // the signed bundle event at its seq by hmac AND action. The bundle carries
  // the CONTIGUOUS chain segment spanning the case, which may include unrelated
  // same-tenant events (§5.3/§7.5); we therefore collect ONLY the SIGNED events
  // the manifest references (the case's own seqs) into `caseEvents` and derive
  // ALL role/fact reasoning from that set — never from the whole segment — so an
  // unrelated case's `exec_authorized` (or any role) can neither back a fact nor
  // satisfy the forged-completeness guard (codex P1).
  const bySeq = new Map();
  for (const ev of events) bySeq.set(ev.seq, ev);
  if (!Array.isArray(manifest.events)) fail("manifest.events is not an array");
  const caseEvents = [];
  for (const me of manifest.events) {
    const be = bySeq.get(me.seq);
    if (!be) {
      fail(`manifest event seq ${me.seq} is not present in the signed bundle segment`, me.seq);
    }
    if (be.hmac !== me.hmac) {
      fail(`manifest event seq ${me.seq} hmac does not match signed bundle event`, me.seq);
    }
    if (be.action !== me.action) {
      fail(`manifest event seq ${me.seq} action does not match signed bundle event`, me.seq);
    }
    // The manifest's declared role must be the role its (signed) action maps to,
    // so a forged role cannot mis-satisfy a required-set slot.
    const expectedRole = roleForAction(be.action);
    if (expectedRole !== null && me.role !== expectedRole) {
      fail(`manifest event seq ${me.seq} role ${me.role} != role for action ${be.action}`, me.seq);
    }
    caseEvents.push(be);
  }

  // (§7.4.2) Each manifest FACT that a signed event carries in metadata must
  // equal the value in the owning signed event. A fact with no backing signed
  // event is REJECTED.
  const eventByRole = new Map();
  for (const ev of caseEvents) {
    const r = roleForAction(ev.action);
    if (r && r !== "unclassified" && !eventByRole.has(r)) eventByRole.set(r, ev);
  }
  const genesis = eventByRole.get("genesis");
  const factCheck = (role, metaKey, manifestVal) => {
    if (manifestVal === null || manifestVal === undefined) return;
    const ev = eventByRole.get(role);
    if (!ev) fail(`manifest fact ${metaKey} not backed by any signed event (role ${role})`);
    const signedVal = ev.metadata ? ev.metadata[metaKey] : undefined;
    if (signedVal === undefined) {
      fail(`manifest fact ${metaKey} absent from the signed ${role} event metadata`);
    }
    if (signedVal !== manifestVal) {
      fail(
        `manifest fact ${metaKey} (${manifestVal}) != signed ${role} event value (${signedVal})`,
      );
    }
  };
  // Genesis-backed facts (PR2 folded genesis carries action + decision hashes).
  if (genesis) {
    factCheck("genesis", "actionDigest", manifest.actionDigest);
    factCheck("genesis", "requestHash", manifest.requestHash);
    factCheck("genesis", "accessDecisionHash", manifest.accessDecision?.hash);
    if (manifest.policyDecision?.hash) {
      factCheck("genesis", "policyDecisionHash", manifest.policyDecision.hash);
    }
  }
  // Execution-backed facts (PR4 authorized/dispatched/terminal metadata).
  if (manifest.execution) {
    const authEv = eventByRole.get("exec_authorized");
    if (manifest.execution.authorizationId && authEv) {
      if (authEv.metadata?.authorizationId !== manifest.execution.authorizationId) {
        fail("manifest execution.authorizationId != signed exec_authorized event");
      }
      if (
        manifest.approvalCommitmentHash &&
        authEv.metadata?.approvalCommitmentHash !== manifest.approvalCommitmentHash
      ) {
        fail("manifest approvalCommitmentHash != signed exec_authorized event");
      }
      if (
        manifest.execution.providerIdempotencyKeyHash &&
        authEv.metadata?.providerIdempotencyKeyHash !==
          manifest.execution.providerIdempotencyKeyHash
      ) {
        fail("manifest providerIdempotencyKeyHash != signed exec_authorized event");
      }
    }
  }

  // (§7.4.3) Forged-completeness guard: recompute the required roles from the
  // manifest's declared terminalState and require missingRequiredRoles equals
  // the required roles ABSENT from the signed event set. A manifest claiming
  // `complete` while a required role is not present in the SIGNED events FAILS.
  const presentRoles = new Set();
  for (const ev of caseEvents) {
    const r = roleForAction(ev.action);
    if (r && r !== "unclassified") presentRoles.add(r);
  }
  const required = requiredRoles(manifest.terminalState);
  const actuallyMissing = required.filter((r) => !presentRoles.has(r));
  if (manifest.completeness === "complete" && actuallyMissing.length > 0) {
    fail(
      `manifest claims complete but required role(s) [${actuallyMissing.join(", ")}] are not in the signed events`,
    );
  }
  // Cross-check the manifest's own missingRequiredRoles against the signed truth.
  const declaredMissing = new Set(manifest.missingRequiredRoles || []);
  for (const r of actuallyMissing) {
    if (!declaredMissing.has(r)) {
      fail(
        `manifest omits required missing role ${r} (present in signed set? no) but did not declare it missing`,
      );
    }
  }
}

main();
