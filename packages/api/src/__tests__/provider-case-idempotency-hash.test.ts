/**
 * PR5 §3.4 / C3 data-minimization guard (review-gate): the RAW provider
 * idempotency key must NEVER enter the manifest — only its sha256 hash. The
 * existing service test only checks the allowed-stub path where `execution` is
 * null (no nonce), so it never exercises the hashing branch. This seeds a v2
 * execution nonce with a distinctive CANARY raw key and proves:
 *   (a) the raw key is absent from the serialized manifest, and
 *   (b) manifest.execution.providerIdempotencyKeyHash === sha256HexPrefixed(rawKey).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";

process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
process.env.STEWARD_MASTER_PASSWORD ||= "pr5-idem-hash-master";

import { closeDb, executionAuthorizationNonces, getDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { sha256HexPrefixed } from "@stwd/shared";
import { getProviderCase } from "../services/provider-case";
import { createAllowedCase, F, seedCaseFixture, wipeCase } from "./provider-case-fixture";

const CANARY_RAW_KEY = "prov-idem-CANARY-6f1b9d3a2c8e4f5a-do-not-leak";

describe("PR5 §3.4 provider idempotency key is hashed, never raw", () => {
  beforeAll(async () => {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });
  beforeEach(async () => {
    await wipeCase();
    await seedCaseFixture();
  });

  it("seeds a v2 nonce with a raw key → manifest carries only the hash", async () => {
    const intentId = await createAllowedCase();
    // Attach a v2 execution nonce carrying the CANARY raw key + a succeeded
    // dispatch, and flip the binding to a terminal execution state so the
    // resolver produces an `execution` block.
    const sha = (s: string) => `sha256:${sha256HexPrefixed(s).slice("sha256:".length)}`;
    await getDb()
      .insert(executionAuthorizationNonces)
      .values({
        authorizationId: `auth-${intentId.slice(0, 12)}`,
        requestId: `req-${intentId.slice(0, 12)}`,
        tenantId: F.TENANT,
        agentId: F.AGENT,
        capability: "credential.inject_http",
        backend: "credential-proxy",
        payloadDigest: "0".repeat(64),
        nonce: `nonce-${intentId.slice(0, 12)}`,
        signature: "sig",
        status: "active",
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 3600_000),
        // Full v2 arm (exec_auth_nonces_v2_arm_chk).
        version: 2,
        executionId: `exec-${intentId.slice(0, 12)}`,
        intentId,
        workspaceId: F.WORKSPACE,
        providerAccountId: F.ACCOUNT,
        operationId: F.OP,
        operationRevision: 1,
        requestHash: sha("req"),
        actionDigest: sha("act"),
        grantDependencyHash: sha("grant"),
        routeId: F.ROUTE,
        routeRevision: 1,
        secretId: F.SECRET,
        secretVersion: 1,
        providerIdempotencyKey: CANARY_RAW_KEY,
        commitmentHash: sha("commit"),
        keyId: "key-1",
        dispatchState: "succeeded",
        dispatchedAt: new Date(),
        outcomeRecordedAt: new Date(),
      } as never);
    // NOTE: we do NOT force the binding status to a terminal execution state
    // (a DB trigger forbids illegal transitions from allowed_stub). The manifest
    // builds an `execution` block whenever a version=2 nonce is present, which is
    // exactly the code path (§3.4) under test — the raw provider idempotency key
    // must be hashed regardless of the binding's terminal state.
    const assembly = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE]);
    expect(assembly).not.toBeNull();
    const manifest = assembly?.manifest;
    const serialized = JSON.stringify(manifest);

    // (a) raw canary key NEVER appears anywhere in the manifest.
    expect(serialized).not.toContain(CANARY_RAW_KEY);
    expect(serialized).not.toContain("prov-idem-CANARY");
    // (b) the hash is present and correct.
    expect(manifest?.execution).not.toBeNull();
    expect(manifest?.execution?.providerIdempotencyKeyHash).toBe(sha256HexPrefixed(CANARY_RAW_KEY));
  });
});
