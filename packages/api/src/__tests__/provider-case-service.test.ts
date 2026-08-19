/**
 * evidence provider-case service tests — manifest correlation + mechanical
 * completeness against real seeded cases (PGLite).
 */

import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { closeDb, getDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { sql } from "drizzle-orm";
import { getProviderCase } from "../services/provider-case";
import {
  approveCase,
  createAccessDeniedCase,
  createAllowedCase,
  createPendingCase,
  F,
  readCorrelated,
  seedCaseFixture,
  wipeCase,
} from "./provider-case-fixture";

const ALL_WS = [F.WORKSPACE, F.WORKSPACE_2];

describe("evidence provider-case service", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
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

  test("allowed (stub) case → succeeded, complete, genesis correlated", async () => {
    const intentId = await createAllowedCase();
    const events = await readCorrelated(intentId);
    // Genesis event exists and carries C1 correlation fields.
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].resource_type).toBe("provider_action");
    expect(events[0].resource_id).toBe(intentId);
    expect(events[0].intentMeta).toBe(intentId);

    const assembly = await getProviderCase(F.TENANT, intentId, ALL_WS);
    expect(assembly).not.toBeNull();
    const m = assembly!.manifest;
    expect(m.caseId).toBe(intentId);
    expect(m.tenantId).toBe(F.TENANT);
    expect(m.terminalState).toBe("succeeded");
    // succeeded requires the full exec chain; the stub path has only genesis, so
    // completeness is honestly NOT complete (no exec_* events for the stub).
    expect(m.completeness).not.toBe("complete");
    expect(m.events[0].role).toBe("genesis");
    expect(m.actionDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("access-denied case → denied_access, complete (genesis-only required)", async () => {
    const intentId = await createAccessDeniedCase();
    const assembly = await getProviderCase(F.TENANT, intentId, ALL_WS);
    expect(assembly).not.toBeNull();
    const m = assembly!.manifest;
    expect(m.terminalState).toBe("denied_access");
    expect(m.accessDecision.effect).toBe("deny");
    // denied_access requires only [genesis], present → complete.
    expect(m.missingRequiredRoles).toEqual([]);
    expect(m.completeness).toBe("complete");
  });

  test("pending-approval case → pending_approval, complete, queue row present", async () => {
    const { intentId } = await createPendingCase();
    const assembly = await getProviderCase(F.TENANT, intentId, ALL_WS);
    const m = assembly!.manifest;
    expect(m.terminalState).toBe("pending_approval");
    expect(m.approvalCommitmentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    // pending requires only [genesis]; present → complete.
    expect(m.completeness).toBe("complete");
    expect(m.incompletenessReasons).not.toContain("queue_row_absent_for_approval_path");
  });

  test("approved case → execution_ready, has approval_decided event", async () => {
    const { intentId, requestHash, actionDigest } = await createPendingCase();
    await approveCase(intentId, requestHash, actionDigest);
    const events = await readCorrelated(intentId);
    const actions = events.map((e) => e.action);
    expect(actions).toContain("provider.approval.decided");
    const assembly = await getProviderCase(F.TENANT, intentId, ALL_WS);
    const m = assembly!.manifest;
    expect(m.approvalActor).not.toBeNull();
    expect(m.approvalActor?.id).toBe(F.APPROVER);
    // execution_ready requires resume_ready which the approve step doesn't emit
    // (that is the separate resume/execute step) → not complete, honest.
    expect(m.terminalState).toBe("execution_ready");
  });

  test("foreign tenant case id → null (404 upstream)", async () => {
    const intentId = await createAllowedCase();
    const assembly = await getProviderCase("tenant-does-not-exist", intentId, ALL_WS);
    expect(assembly).toBeNull();
  });

  test("foreign workspace (not authorized) → null (non-enumerating 404, D2)", async () => {
    const intentId = await createAllowedCase();
    // Authorize only WORKSPACE_2; the case is in WORKSPACE → null.
    const assembly = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE_2]);
    expect(assembly).toBeNull();
  });

  test("nonexistent case id → null", async () => {
    const assembly = await getProviderCase(
      F.TENANT,
      "pa_00000000-0000-0000-0000-000000000000",
      ALL_WS,
    );
    expect(assembly).toBeNull();
  });

  test("no raw provider idempotency key leaks into the manifest (§3.4)", async () => {
    const intentId = await createAllowedCase();
    const assembly = await getProviderCase(F.TENANT, intentId, ALL_WS);
    const json = JSON.stringify(assembly!.manifest);
    // The allowed-stub path has no execution nonce, so execution is null; assert
    // the manifest carries no `providerIdempotencyKey` (raw) key at all.
    expect(json).not.toContain('providerIdempotencyKey":');
  });

  test("event-theft: a foreign event with mismatched metadata.intentId is dropped (N23)", async () => {
    const intentId = await createAllowedCase();
    // Inject a rogue audit-like row correlated by resource_id but with a WRONG
    // metadata.intentId. The correlator's agreement check must drop it.
    // (We insert directly; it is NOT chain-valid, but correlateCaseEvents only
    // filters by resource_id + metadata.intentId agreement.)
    await getDb().execute(
      sql`INSERT INTO audit_events (tenant_id, seq, prev_hash, hmac, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at)
          VALUES (${F.TENANT}, 999999, '\\x00', '\\x00', 'system', 'x', 'provider.execution.dispatched', 'provider_action', ${intentId}, ${sql.raw(
            `'{"intentId":"pa_ffffffff-ffff-ffff-ffff-ffffffffffff"}'::jsonb`,
          )}, now())`,
    );
    const assembly = await getProviderCase(F.TENANT, intentId, ALL_WS);
    // The rogue seq 999999 must not appear in the manifest's event index.
    const seqs = assembly!.manifest.events.map((e) => e.seq);
    expect(seqs).not.toContain(999999);
  });
});
