import { describe, expect, it } from "bun:test";
import {
  computeGoogleActionDigest,
  GOOGLE_GOLDEN_VECTORS,
  googleCanonicalActionBytes,
} from "../google-provider-action";

describe("google.provider-action.v1 golden corpus", () => {
  for (const v of GOOGLE_GOLDEN_VECTORS)
    it(v.id, () => {
      const action = JSON.parse(v.canonicalActionBytes);
      expect(googleCanonicalActionBytes(action)).toBe(v.canonicalActionBytes);
      expect(computeGoogleActionDigest(action)).toBe(v.actionDigest);
    });
});
