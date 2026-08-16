import { describe, expect, it } from "bun:test";
import {
  computeProviderPolicyInputDigest,
  jcsStringify,
  PROVIDER_POLICY_INPUT_HASH_DOMAIN,
  PROVIDER_POLICY_INPUT_SCHEMA_VERSION,
  sha256HexPrefixed,
} from "../provider-action.js";

describe("provider policy-input replay identity", () => {
  it("is deterministic under object-key reordering", () => {
    expect(computeProviderPolicyInputDigest({ summoned: true, isReply: true })).toBe(
      computeProviderPolicyInputDigest({ isReply: true, summoned: true }),
    );
  });

  it("changes when a policy-only boolean changes", () => {
    expect(computeProviderPolicyInputDigest({ summoned: false })).not.toBe(
      computeProviderPolicyInputDigest({ summoned: true }),
    );
  });

  it("uses an explicit hash domain, not the bare policy document hash", () => {
    const policyArgs = { summoned: true };
    const bareBytes = jcsStringify({
      schemaVersion: PROVIDER_POLICY_INPUT_SCHEMA_VERSION,
      policyArgs,
    });
    const digest = computeProviderPolicyInputDigest(policyArgs);
    expect(digest).toBe(sha256HexPrefixed(`${PROVIDER_POLICY_INPUT_HASH_DOMAIN}${bareBytes}`));
    expect(digest).not.toBe(sha256HexPrefixed(bareBytes));
  });

  it("rejects unsupported values instead of silently dropping identity fields", () => {
    expect(() => computeProviderPolicyInputDigest({ summoned: undefined })).toThrow();
    expect(() => computeProviderPolicyInputDigest({ amount: Number.NaN })).toThrow();
  });
});
