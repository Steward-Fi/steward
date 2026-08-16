import { afterEach, describe, expect, it } from "bun:test";
import type { ProviderExecutionCommitmentV2 } from "../provider-action.js";
import {
  signProviderExecutionCommitmentV2,
  verifyProviderExecutionCommitmentV2,
} from "../provider-execution-auth.js";

const saved = process.env.STEWARD_EXECUTION_AUTH_SECRET;

function commitment(keyId: string): ProviderExecutionCommitmentV2 {
  return {
    schemaVersion: "steward.provider-execution-commitment.v2",
    authorizationId: "authz-1",
    executionId: "execution-1",
    intentId: "intent-1",
    requestId: "request-1",
    tenantId: "tenant",
    workspaceId: "workspace",
    actorAgentId: "agent",
    providerAccountId: "provider-account",
    operationId: "operation",
    operationRevision: 1,
    requestHash: "0".repeat(64),
    actionDigest: "1".repeat(64),
    grantDependencyHash: "2".repeat(64),
    policyRevisionHash: "3".repeat(64),
    accessDecisionHash: "4".repeat(64),
    approvalId: "approval-1",
    approvalCommitmentHash: "5".repeat(64),
    target: {
      scheme: "https",
      host: "api.github.com",
      port: 443,
      normalizedPath: "/repos/a/b/issues",
      method: "POST",
    },
    headerAllowlistDigest: "6".repeat(64),
    routeId: "route-1",
    routeRevision: 1,
    secretId: "secret-1",
    secretVersion: 1,
    backend: "credential-proxy",
    providerIdempotencyKey: "idem-1",
    maxUses: 1,
    nonce: "nonce-1",
    issuedAt: "2026-07-16T00:00:00.000Z",
    expiresAt: "2026-07-16T00:05:00.000Z",
    keyId,
  };
}

afterEach(() => {
  if (saved === undefined) delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
  else process.env.STEWARD_EXECUTION_AUTH_SECRET = saved;
});

describe("execution authorization v2 key rotation", () => {
  it("keeps the retired key verify-only during overlap", () => {
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "old:old-secret-material";
    const oldCommitment = commitment("old");
    const oldSignature = signProviderExecutionCommitmentV2(oldCommitment);

    process.env.STEWARD_EXECUTION_AUTH_SECRET = "new:new-secret-material,old:old-secret-material";
    expect(verifyProviderExecutionCommitmentV2(oldCommitment, oldSignature)).toBe(true);
    expect(() => signProviderExecutionCommitmentV2(oldCommitment)).toThrow(
      "commitment keyId does not match the active signing key",
    );

    const newCommitment = commitment("new");
    expect(
      verifyProviderExecutionCommitmentV2(
        newCommitment,
        signProviderExecutionCommitmentV2(newCommitment),
      ),
    ).toBe(true);
  });

  it("rejects the retired key after overlap removal", () => {
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "old:old-secret-material";
    const oldCommitment = commitment("old");
    const oldSignature = signProviderExecutionCommitmentV2(oldCommitment);

    process.env.STEWARD_EXECUTION_AUTH_SECRET = "new:new-secret-material";
    expect(verifyProviderExecutionCommitmentV2(oldCommitment, oldSignature)).toBe(false);
  });
});
