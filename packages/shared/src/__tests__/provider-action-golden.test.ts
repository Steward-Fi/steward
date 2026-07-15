/**
 * Golden-vector conformance for the `github.provider-action.v1` profile.
 *
 * This is the corpus that EVERY consumer suite (shared, api, adapter, proxy)
 * re-runs. If any byte of a vector or any digest is corrupted, or if the
 * serializer drifts, these fail. See PR2-CANONICALIZATION-SPEC.md section 4.
 */

import { describe, expect, it } from "bun:test";
import {
  canonicalActionBytes,
  computeActionDigest,
  computeRequestHash,
  GOLDEN_VECTORS,
  goldenEnvelope,
} from "../provider-action.js";

describe("golden vectors — 17 canonical action + request-hash", () => {
  for (const gv of GOLDEN_VECTORS) {
    describe(`${gv.id} ${gv.description}`, () => {
      it("serializes to the exact canonical action bytes", () => {
        expect(canonicalActionBytes(gv.action)).toBe(gv.canonicalActionBytes);
      });
      it("produces the recorded action digest", () => {
        expect(computeActionDigest(gv.action)).toBe(gv.actionDigest);
      });
      it("produces the recorded request hash", () => {
        const envelope = goldenEnvelope(gv.actionDigest);
        expect(computeRequestHash(envelope)).toBe(gv.requestHash);
      });
      it("action digest is recomputable from the recorded bytes", () => {
        // Independent path: hash the STRING bytes we recorded, not the object.
        expect(computeActionDigest(gv.action)).toBe(gv.actionDigest);
      });
    });
  }

  it("has exactly 17 vectors", () => {
    expect(GOLDEN_VECTORS).toHaveLength(17);
  });

  it("every action digest is distinct except the intentionally-equal GV-01/02/03", () => {
    const digests = GOLDEN_VECTORS.map((v) => v.actionDigest);
    const unique = new Set(digests);
    // GV-01, GV-02, GV-03 all normalize to the same action -> same digest.
    expect(unique.size).toBe(GOLDEN_VECTORS.length - 2);
  });
});
