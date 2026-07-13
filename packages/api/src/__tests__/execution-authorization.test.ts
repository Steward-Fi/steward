import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, executionAuthorizationNonces, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { ExecutionAuthorization } from "@stwd/shared";
import { ExecutionPayloadNormalizationError } from "@stwd/shared";
import { eq } from "drizzle-orm";
import {
  consumeExecutionAuthorization,
  executionPayloadDigestForEvmSign,
  mintExecutionAuthorization,
  sha256Hex,
  verifyExecutionAuthorization,
} from "../services/execution-authorization";

const TENANT_ID = `exec-auth-tenant-${Date.now()}`;
const AGENT_ID = `exec-auth-agent-${Date.now()}`;

describe("execution authorization service", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_DB_MODE = "pglite";
    process.env.STEWARD_JWT_SECRET = "execution-authorization-test-jwt-secret-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Execution Authorization Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Execution Authorization Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
  });

  afterAll(async () => {
    await closeDb();
  });

  it("canonicalizes JSON before digesting", () => {
    expect(sha256Hex({ b: 2, a: { d: 4, c: 3 } })).toBe(sha256Hex({ a: { c: 3, d: 4 }, b: 2 }));
  });

  it("mints a signed 60s authorization and atomically consumes it once", async () => {
    const payloadDigest = executionPayloadDigestForEvmSign({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      to: "0x1111111111111111111111111111111111111111",
      value: "1",
      data: "0x",
      chainId: 8453,
      broadcast: false,
    });
    const issuedAt = new Date();
    const authorization = await mintExecutionAuthorization({
      requestId: "tx-exec-auth-once",
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction",
      backend: "local-vault",
      payloadDigest,
      policyRevisionHash: "a".repeat(64),
      idempotencyKey: "idem-exec-auth-once",
      now: issuedAt,
    });

    expect(Date.parse(authorization.expiresAt) - Date.parse(authorization.issuedAt)).toBe(60_000);
    expect(authorization.signature).toBeString();

    await consumeExecutionAuthorization(authorization, {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction",
      backend: "local-vault",
      payloadDigest,
    });

    const [row] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorization.id));
    expect(row?.status).toBe("consumed");

    await expect(
      consumeExecutionAuthorization(authorization, {
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        capability: "wallet.sign_transaction",
        backend: "local-vault",
        payloadDigest,
      }),
    ).rejects.toThrow("expired or already consumed");
  });

  it("rejects a valid signature when the expected digest changes", async () => {
    const authorization = await mintExecutionAuthorization({
      requestId: "tx-exec-auth-digest",
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction",
      backend: "local-vault",
      payloadDigest: "b".repeat(64),
      policyRevisionHash: "c".repeat(64),
    });

    await expect(
      consumeExecutionAuthorization(authorization, {
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        capability: "wallet.sign_transaction",
        backend: "local-vault",
        payloadDigest: "d".repeat(64),
      }),
    ).rejects.toThrow("context does not match");
  });

  it("normalizes chainId/nonce as non-negative safe integers before digesting", () => {
    const base = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      to: "0x1111111111111111111111111111111111111111",
      value: "1",
      data: "0x",
      chainId: 8453,
      broadcast: false,
    };
    // Valid nonce digests fine and is stable.
    expect(executionPayloadDigestForEvmSign({ ...base, nonce: 7 })).toBe(
      executionPayloadDigestForEvmSign({ ...base, nonce: 7 }),
    );
    // Negative nonce rejected.
    expect(() => executionPayloadDigestForEvmSign({ ...base, nonce: -1 })).toThrow(
      ExecutionPayloadNormalizationError,
    );
    // Non-safe-integer nonce rejected.
    expect(() =>
      executionPayloadDigestForEvmSign({ ...base, nonce: Number.MAX_SAFE_INTEGER + 1 }),
    ).toThrow(ExecutionPayloadNormalizationError);
    // Negative chainId rejected.
    expect(() => executionPayloadDigestForEvmSign({ ...base, chainId: -8453 })).toThrow(
      ExecutionPayloadNormalizationError,
    );
  });

  it("table-driven: HMAC signature covers every signed field (tamper detection)", async () => {
    const payloadDigest = "a".repeat(64);
    const expected = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction" as const,
      backend: "local-vault" as const,
      payloadDigest,
    };
    const authorization = await mintExecutionAuthorization({
      requestId: "tx-hmac-tamper-req",
      ...expected,
      policyRevisionHash: "b".repeat(64),
      approvalId: "approval-hmac-tamper",
      idempotencyKey: "idem-hmac-tamper",
    });

    // Each mutation flips exactly one signed field; the HMAC verify must reject
    // every one of them with an invalid-signature error. Context-checked fields
    // (tenantId/agentId/capability/backend/payloadDigest/status) are verified
    // separately via the context guard; here we prove the SIGNATURE itself binds
    // the non-context fields the reviewer called out.
    const tampers: Array<{
      field: string;
      mutate: (a: ExecutionAuthorization) => ExecutionAuthorization;
    }> = [
      { field: "id", mutate: (a) => ({ ...a, id: "00000000-0000-4000-8000-000000000000" }) },
      { field: "requestId", mutate: (a) => ({ ...a, requestId: "tampered-request" }) },
      {
        field: "policyRevisionHash",
        mutate: (a) => ({ ...a, policyRevisionHash: "c".repeat(64) }),
      },
      { field: "approvalId", mutate: (a) => ({ ...a, approvalId: "tampered-approval" }) },
      { field: "nonce", mutate: (a) => ({ ...a, nonce: "tampered-nonce" }) },
      { field: "issuedAt", mutate: (a) => ({ ...a, issuedAt: new Date(0).toISOString() }) },
      {
        field: "expiresAt",
        mutate: (a) => ({ ...a, expiresAt: new Date(Date.now() + 3_600_000).toISOString() }),
      },
      { field: "idempotencyKey", mutate: (a) => ({ ...a, idempotencyKey: "tampered-idem" }) },
    ];

    for (const { field, mutate } of tampers) {
      const tampered = mutate(authorization);
      expect(
        () => verifyExecutionAuthorization(tampered, expected),
        `tampering ${field} must invalidate the signature`,
      ).toThrow("signature is invalid");
    }

    // Sanity: the untampered authorization still verifies.
    expect(() => verifyExecutionAuthorization(authorization, expected)).not.toThrow();
  });

  it("consumes a nonce exactly once under concurrent replay (race)", async () => {
    const payloadDigest = "1".repeat(64);
    const expected = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction" as const,
      backend: "local-vault" as const,
      payloadDigest,
    };
    const authorization = await mintExecutionAuthorization({
      requestId: "tx-concurrent-consume",
      ...expected,
      policyRevisionHash: "2".repeat(64),
    });

    // Fire many concurrent consumes of the SAME authorization. The atomic
    // conditional UPDATE (status='active' AND not expired) must let exactly one
    // succeed; all others reject as already-consumed.
    const attempts = 12;
    const results = await Promise.allSettled(
      Array.from({ length: attempts }, () =>
        consumeExecutionAuthorization(authorization, expected),
      ),
    );
    const fulfilled = results.filter((r) => r.status === "fulfilled").length;
    const rejected = results.filter((r) => r.status === "rejected").length;
    expect(fulfilled).toBe(1);
    expect(rejected).toBe(attempts - 1);

    const [row] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorization.id));
    expect(row?.status).toBe("consumed");
  });

  it("never stores private key or secret material in the nonce row", async () => {
    const payloadDigest = "3".repeat(64);
    const authorization = await mintExecutionAuthorization({
      requestId: "tx-no-secret-material",
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction",
      backend: "local-vault",
      payloadDigest,
      policyRevisionHash: "4".repeat(64),
    });
    const [row] = await getDb()
      .select()
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorization.id));
    const serialized = JSON.stringify(row).toLowerCase();
    // The persisted authorization evidence must contain no private-key or raw
    // secret material. The HMAC signature is derived from STEWARD_JWT_SECRET but
    // never contains it; assert the secret itself does not leak.
    for (const forbidden of ["privatekey", "private_key", "0x", "mnemonic", "seed phrase"]) {
      expect(serialized.includes(forbidden)).toBe(false);
    }
    // The JWT secret used to derive the HMAC key must never appear.
    expect(serialized.includes("execution-authorization-test-jwt-secret")).toBe(false);
  });

  it("rejects expired, tenant/backend-mismatched, and tampered authorizations", async () => {
    const payloadDigest = "e".repeat(64);
    const expected = {
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      capability: "wallet.sign_transaction" as const,
      backend: "local-vault" as const,
      payloadDigest,
    };
    const authorization = await mintExecutionAuthorization({
      requestId: "tx-exec-auth-negative",
      ...expected,
      policyRevisionHash: "f".repeat(64),
    });

    expect(() =>
      verifyExecutionAuthorization(authorization, { ...expected, tenantId: "other-tenant" }),
    ).toThrow("context does not match");
    expect(() =>
      verifyExecutionAuthorization(authorization, { ...expected, backend: "external-custody" }),
    ).toThrow("context does not match");
    expect(() =>
      verifyExecutionAuthorization({ ...authorization, signature: "tampered" }, expected),
    ).toThrow("signature is invalid");

    const expired = await mintExecutionAuthorization({
      requestId: "tx-exec-auth-expired",
      ...expected,
      now: new Date(Date.now() - 61_000),
    });
    expect(() => verifyExecutionAuthorization(expired, expected)).toThrow("expired");
  });
});
