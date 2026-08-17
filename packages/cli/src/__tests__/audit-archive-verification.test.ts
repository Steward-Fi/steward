import { describe, expect, it } from "bun:test";
import { auditArchiveVerificationMode } from "../index";

describe("audit archive verification trust mode", () => {
  it("requires an independent fingerprint for a trusted --verify claim", () => {
    expect(() => auditArchiveVerificationMode({ verify: true })).toThrow(
      "--verify requires --fp from an independent trusted channel",
    );
    expect(
      auditArchiveVerificationMode({ verify: true, fp: "a".repeat(64), "key-id": "archive-v1" }),
    ).toEqual({ mode: "trusted", fingerprint: "a".repeat(64), keyId: "archive-v1" });
  });

  it("makes embedded-key checking an explicit integrity-only mode", () => {
    expect(auditArchiveVerificationMode({ "integrity-only": true })).toEqual({
      mode: "integrity-only",
      keyId: undefined,
    });
    expect(() =>
      auditArchiveVerificationMode({ verify: true, "integrity-only": true, fp: "a".repeat(64) }),
    ).toThrow("mutually exclusive");
    expect(() =>
      auditArchiveVerificationMode({ "integrity-only": true, fp: "a".repeat(64) }),
    ).toThrow("Use --verify with --fp");
  });
});
