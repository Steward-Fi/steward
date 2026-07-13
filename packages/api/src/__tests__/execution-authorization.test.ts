import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, executionAuthorizationNonces, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import {
  consumeExecutionAuthorization,
  executionPayloadDigestForEvmSign,
  mintExecutionAuthorization,
  sha256Hex,
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
});
