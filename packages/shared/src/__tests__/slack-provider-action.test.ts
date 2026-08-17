import { describe, expect, test } from "bun:test";
import {
  canonicalizeRawInternalSlackAction,
  canonicalizeSlackOrigin,
  jcsStringify,
  SLACK_GOLDEN_VECTORS,
  sha256HexPrefixed,
} from "../index";

describe("slack.provider-action.v1", () => {
  test("matches the shared golden corpus exactly", () => {
    for (const vector of SLACK_GOLDEN_VECTORS) {
      expect(jcsStringify(vector.action)).toBe(vector.canonicalActionBytes);
      expect(sha256HexPrefixed(vector.canonicalActionBytes)).toBe(vector.actionDigest);
    }
  });
  test("allows only Slack's canonical origin and /api paths", () => {
    expect(canonicalizeSlackOrigin("HTTPS://SLACK.COM.:443/")).toBe("https://slack.com");
    expect(() => canonicalizeSlackOrigin("https://hooks.slack.com")).toThrow();
    expect(() =>
      canonicalizeRawInternalSlackAction({
        method: "GET",
        origin: "https://slack.com",
        path: "/services/T/B/secret",
      }),
    ).toThrow();
  });
});
