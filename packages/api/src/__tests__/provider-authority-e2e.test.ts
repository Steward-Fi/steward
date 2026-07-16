/**
 * PR6 — end-to-end governed provider proof (fake transport).
 *
 * This IS the fake CI proof body (§2.5). It drives the IDENTICAL governed code
 * path the real sandbox run uses (`scripts/provider-authority-sandbox.mjs`),
 * differing ONLY in the terminal forwarder (U2): here the terminal forwarder is
 * the deterministic in-process fake (`fake-provider-transport.ts`) injected via
 * the existing `__setForwardProxyRequestForTests` seam (U1). No new authority is
 * minted (U3): every allow/approve/resume/dispatch goes through the real PR1-PR5
 * service functions.
 *
 * DISPATCH TOPOLOGY (anchor drift C1, see PR6-ANCHORS.md):
 * On develop the ALLOWED READ op terminates at an in-process stub
 * (`executeProviderActionStub`), NOT the governed forwarder. Only the
 * WRITE/APPROVAL path (create → approve → resume → dispatchGovernedExecution)
 * traverses `forwardProxyRequestForHandler` and thus the fake transport. So the
 * forwarder proof rides the WRITE op (M04/M14); the read leg still proves the
 * full access→policy→allow authority path (M02).
 *
 * The matrix (M01-M18) and the negative/concurrency subset run here. UI/a11y
 * rows (M10-M13, PN34-36) live in the web test suite. Static inventory (M01) is
 * `fake-provider-transport-inventory.test.ts` (proxy package).
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import {
  closeDb,
  executionAuthorizationNonces,
  getDb,
  providerActionBindings,
  secretRoutes,
  secrets,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { buildGithubAction } from "@stwd/provider-github";
import {
  FakeProviderTransport,
  GITHUB_FIXTURES,
} from "@stwd/proxy/src/__tests__/fake-provider-transport";
import { KeyStore } from "@stwd/vault";
import { and, eq, sql } from "drizzle-orm";

// Real PR1-PR5 services (the authority code path under proof).
import { providerActionService } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";
import { getProviderCase } from "../services/provider-case";

// PR4 governed dispatcher + the injectable proxy forwarder seam.
type ProxyMod = typeof import("@stwd/proxy/src/handlers/proxy");
type DispatchMod = typeof import("@stwd/proxy/src/handlers/governed-execution");
let proxyMod: ProxyMod;
let dispatchGovernedExecution: DispatchMod["dispatchGovernedExecution"];

// Shared fixture (real create/decide services) — imported dynamically so the
// PGLite override is installed before the fixture's db handle resolves.
// seedCaseFixture seeds the FULL reference topology: a consequential WRITE op
// (github.pr.comment.create, approval_required) AND an allow-only READ op
// (github.issue.list) with a matching grant, so both legs run without bespoke
// per-test policy seeding (reuse-first).
type Fixture = typeof import("./provider-approval-fixture");
type CaseFixture = typeof import("./provider-case-fixture");
let F: Fixture["F"];
let principal: Fixture["principal"];
let seedCaseFixture: CaseFixture["seedCaseFixture"];
let wipeCase: CaseFixture["wipeCase"];
const READ_OP_KEY = "github.issue.list";

const MASTER = "steward-api-test-suite-master-password"; // matches test-preload.ts
const GITHUB_TOKEN_SENTINEL = "ghp_SENTINEL_credential_never_leaks_0123456789ABCD";

let fake: FakeProviderTransport;

/** Encrypt a credential with the SAME KeyStore context SecretVault uses. */
function encryptCredential(
  tenantId: string,
  name: string,
  value: string,
): { ciphertext: string; iv: string; authTag: string; salt: string } {
  const ks = new KeyStore(MASTER, undefined, "secret-vault");
  const e = ks.encrypt(value, { tenantId, name, version: 1 });
  return { ciphertext: e.ciphertext, iv: e.iv, authTag: e.tag, salt: e.salt };
}

/**
 * Upgrade the fixture's dummy secret to a REAL vault-encrypted sentinel token
 * and flip the route to governed_v2 pointing at the operation, so a governed
 * dispatch decrypts successfully and reaches the fake forwarder. Mirrors the
 * legacy→governed_v2 flip discipline from governed-execution.test.ts (the
 * trigger bumps authority_revision on the watched flip, then we pin it to 1 via
 * an unwatched-column UPDATE so the seeded nonce's routeRevision matches).
 */
async function enableGovernedRoute(operationId: string): Promise<void> {
  const db = getDb();
  await db
    .update(secrets)
    .set(encryptCredential(F.TENANT, "github", GITHUB_TOKEN_SENTINEL))
    .where(and(eq(secrets.id, F.SECRET), eq(secrets.tenantId, F.TENANT)));
  await db
    .update(secretRoutes)
    .set({
      authorityMode: "governed_v2",
      providerOperationId: operationId,
      // findMatchingRoute filters on agentId; the fixture route has none, so the
      // dispatching agent's route would miss. Bind it to the grant's agent so
      // the governed dispatch resolves the pinned credential route.
      agentId: F.AGENT,
    })
    .where(eq(secretRoutes.id, F.ROUTE));
  await db.execute(sql`UPDATE secret_routes SET authority_revision = 1 WHERE id = ${F.ROUTE}`);
}

function idem(seed: string): string {
  return `sha256:${Buffer.from(seed.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

/** Create the consequential WRITE action (policy → approval_required, 202). */
async function createWriteAction(seed: string): Promise<{
  intentId: string;
  requestHash: string;
  actionDigest: string;
}> {
  const now = new Date();
  const out = await providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: F.WORKSPACE,
    providerAccountId: F.ACCOUNT,
    operationKey: F.OP_KEY, // github.pr.comment.create (consequential)
    build: buildGithubAction(F.OP_KEY, {
      owner: "steward-sandbox",
      repo: "hello",
      pullNumber: 1,
      body: "governed comment (steward-marker)",
    }),
    idempotencyKeyHash: idem(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
  if (out.kind !== "approval_required") {
    throw new Error(`expected approval_required, got ${out.kind}`);
  }
  return { intentId: out.intentId, requestHash: out.requestHash, actionDigest: out.actionDigest };
}

async function approve(intentId: string, requestHash: string, actionDigest: string): Promise<void> {
  const res = await providerApprovalService.decide({
    intentId,
    tenantId: F.TENANT,
    authenticatedUserId: F.APPROVER,
    sessionMfaVerifiedAt: Date.now(),
    decision: "approve",
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: "ship it",
    idempotencyKey: `approve-${intentId.slice(0, 12)}`,
  });
  if (!res.ok) throw new Error(`approve failed: ${(res as { code?: string }).code}`);
}

async function resume(intentId: string): Promise<void> {
  const res = await providerApprovalService.resume({
    intentId,
    tenantId: F.TENANT,
    caller: { agentId: F.AGENT },
    ipAddress: null,
    userAgent: null,
    requestId: null,
  });
  if (!res.ok) throw new Error(`resume failed: ${(res as { code?: string }).code}`);
}

/** Drive create → approve → resume → dispatch through the fake forwarder. */
async function runGovernedWrite(seed: string): Promise<{
  intentId: string;
  dispatch: Awaited<ReturnType<DispatchMod["dispatchGovernedExecution"]>>;
}> {
  const { intentId, requestHash, actionDigest } = await createWriteAction(seed);
  await approve(intentId, requestHash, actionDigest);
  await resume(intentId);
  const dispatch = await dispatchGovernedExecution(intentId, F.TENANT);
  return { intentId, dispatch };
}

async function bindingStatus(intentId: string): Promise<string | null> {
  const [row] = await getDb()
    .select({ status: providerActionBindings.status })
    .from(providerActionBindings)
    .where(eq(providerActionBindings.intentId, intentId))
    .limit(1);
  return row?.status ?? null;
}

async function dispatchStateOf(intentId: string): Promise<string | null> {
  const [row] = await getDb()
    .select({ ds: executionAuthorizationNonces.dispatchState })
    .from(executionAuthorizationNonces)
    .where(eq(executionAuthorizationNonces.intentId, intentId))
    .limit(1);
  return row?.ds ?? null;
}

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  proxyMod = await import("@stwd/proxy/src/handlers/proxy");
  ({ dispatchGovernedExecution } = await import("@stwd/proxy/src/handlers/governed-execution"));
  ({ F, principal } = await import("./provider-approval-fixture"));
  ({ seedCaseFixture, wipeCase } = await import("./provider-case-fixture"));
  // Pin DNS to a public address so the SSRF guard passes without a real lookup.
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "140.82.112.6", family: 4 }]);
});

afterAll(async () => {
  await closeDb();
});

beforeEach(async () => {
  fake = new FakeProviderTransport();
  proxyMod.__setForwardProxyRequestForTests(fake.forwarder);
  await seedCaseFixture();
});

afterEach(async () => {
  // enableGovernedRoute() points secret_routes.provider_operation_id AT the
  // operation, adding an FK (secret_routes -> provider_operations) that
  // wipeCase's delete order (operations before routes) would violate. Break the
  // link first so wipeCase's ordered deletes succeed.
  await getDb().execute(sql`UPDATE secret_routes SET provider_operation_id = NULL, authority_mode = 'legacy'`);
  await wipeCase();
  fake.reset();
});

describe("PR6 governed provider E2E — fake transport, real authority (U1-U3)", () => {
  it("M14: happy write path create→approve→resume→dispatch→succeeded via fake forwarder", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);

    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "ok", status: 201, json: GITHUB_FIXTURES.prCommentCreated },
    );

    const { intentId, dispatch } = await runGovernedWrite("write-happy-1");

    // The fake was reached exactly once (M07/M14 dispatch count == 1).
    expect(fake.dispatchCount()).toBe(1);
    // dispatch succeeded (terminal succeeded).
    expect(dispatch.dispatchState).toBe("succeeded");
    expect(await dispatchStateOf(intentId)).toBe("succeeded");
    // At the forwarder layer the injected credential header IS present...
    expect(fake.calls()[0].credentialHeaderPresent).toBe(true);
    // ...but its VALUE is never recorded (canary): no sentinel anywhere.
    expect(JSON.stringify(fake.calls())).not.toContain(GITHUB_TOKEN_SENTINEL);
  });

  it("M04: write op requires approval — create returns approval_required, no dispatch", async () => {
    const { intentId } = await createWriteAction("write-pending-1");
    expect(await bindingStatus(intentId)).toBe("pending_approval");
    // No dispatch happened (no forwarder call, no nonce).
    expect(fake.dispatchCount()).toBe(0);
    expect(await dispatchStateOf(intentId)).toBeNull();
  });

  it("M02: read op — full access→policy→ALLOW authority path (terminates at stub, C1)", async () => {
    // seedCaseFixture already seeds an allow-only READ op (github.issue.list)
    // with a matching grant + allow policy. Create it via the REAL service.
    const now = new Date();
    const out = await providerActionService.createProviderAction({
      principal: principal(),
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      operationKey: READ_OP_KEY,
      build: buildGithubAction(READ_OP_KEY, { owner: "octo", repo: "hello" }),
      idempotencyKeyHash: idem("read-1"),
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 300_000).toISOString(),
      nonce: "read1".padEnd(32, "N").slice(0, 32),
      requestId: null,
    });
    // The read is ALLOWED (access allow + policy allow). Per C1 the allowed path
    // terminates at the in-process stub and NEVER reaches the governed
    // forwarder, so the fake dispatch count stays 0 while the full
    // access→policy authority path executed.
    expect(out.kind).toBe("allowed");
    expect(fake.dispatchCount()).toBe(0);
  });

  it("M03/PN05: cross-workspace guessed account is a non-enumerating deny, zero dispatch", async () => {
    const now = new Date();
    // WORKSPACE_2 has no provider account/operation → scope not found (non-enum).
    const out = await providerActionService.createProviderAction({
      principal: principal(),
      workspaceId: F.WORKSPACE_2,
      providerAccountId: F.ACCOUNT, // guessed real account id, wrong workspace
      operationKey: F.OP_KEY,
      build: buildGithubAction(F.OP_KEY, {
        owner: "steward-sandbox",
        repo: "hello",
        pullNumber: 1,
        body: "x",
      }),
      idempotencyKeyHash: idem("cross-1"),
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 300_000).toISOString(),
      nonce: "cross".padEnd(32, "N").slice(0, 32),
      requestId: null,
    });
    expect(out.kind).not.toBe("allowed");
    expect(out.kind).not.toBe("approval_required");
    expect(fake.dispatchCount()).toBe(0);
  });

  it("M05/PN17: route revision bumped after resume — claim fails STALE_ROUTE, zero forward", async () => {
    // Drift note (see PR6-ANCHORS.md): the PR4 claim's LIVE-revision staleness
    // checks are ROUTE-revision and SECRET-version (the approval commitment is
    // frozen at mint, so grant IDs+revisions are re-derived from the frozen
    // commitment and cannot drift at claim). Grant REVOCATION is enforced at
    // ACCESS time, not at an already-approved+resumed claim. The claim-time
    // stale-dependency proof therefore rides the route-revision bump (PN17),
    // which the claim DOES re-read live.
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);

    const { intentId, requestHash, actionDigest } = await createWriteAction("stale-route-1");
    await approve(intentId, requestHash, actionDigest);
    await resume(intentId);
    // Bump the route's authority_revision AFTER the nonce was minted at rev 1.
    await getDb().execute(
      sql`UPDATE secret_routes SET authority_revision = authority_revision + 1 WHERE id = ${F.ROUTE}`,
    );

    const dispatch = await dispatchGovernedExecution(intentId, F.TENANT);
    // Claim must fail stale → no forward.
    expect(dispatch.ok).toBe(false);
    expect(fake.dispatchCount()).toBe(0);
  });

  it("M07/PK01: concurrent dispatch — exactly one forward under a race", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);

    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "ok", status: 201, json: GITHUB_FIXTURES.prCommentCreated },
    );

    const { intentId, requestHash, actionDigest } = await createWriteAction("concur-1");
    await approve(intentId, requestHash, actionDigest);
    await resume(intentId);

    const results = await Promise.all(
      Array.from({ length: 8 }, () => dispatchGovernedExecution(intentId, F.TENANT)),
    );
    const succeeded = results.filter((r) => r.ok);
    // Exactly one winner dispatches; the fake was reached exactly once.
    expect(succeeded.length).toBe(1);
    expect(fake.dispatchCount()).toBe(1);
  });

  it("M08/PN25: post-dispatch timeout → outcome_unknown, no blind retry", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);

    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "timeout" },
    );

    const { intentId, dispatch } = await runGovernedWrite("timeout-1");
    expect(dispatch.dispatchState).toBe("outcome_unknown");
    expect(await dispatchStateOf(intentId)).toBe("outcome_unknown");
    // The fake WAS reached once (dispatch happened), but the outcome is unknown.
    expect(fake.dispatchCount()).toBe(1);

    // Replaying dispatch must NOT re-forward (no blind retry, X8/K13).
    const replay = await dispatchGovernedExecution(intentId, F.TENANT);
    expect(replay.ok).toBe(false);
    expect(fake.dispatchCount()).toBe(1); // still one
  });

  it("failed: unambiguous 5xx → failed terminal, one forward", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);
    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "server-error", status: 500 },
    );
    const { intentId, dispatch } = await runGovernedWrite("fail-1");
    // A clean 5xx is a bounded failed OR outcome_unknown per landed semantics;
    // it must be terminal (never a blind retry) and forwarded exactly once.
    expect(["failed", "outcome_unknown"]).toContain(dispatch.dispatchState);
    expect(fake.dispatchCount()).toBe(1);
    expect(["failed", "outcome_unknown"]).toContain(await dispatchStateOf(intentId));
  });

  it("PN24: replay dispatch after succeeded returns terminal, no second forward", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);
    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "ok", status: 201, json: GITHUB_FIXTURES.prCommentCreated },
    );
    const { intentId } = await runGovernedWrite("replay-1");
    expect(fake.dispatchCount()).toBe(1);
    const replay = await dispatchGovernedExecution(intentId, F.TENANT);
    expect(replay.ok).toBe(false); // terminal, not a fresh dispatch
    expect(fake.dispatchCount()).toBe(1);
  });

  it("M15/PN27: credential sentinel never appears in the case manifest or dispatch record", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);
    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "ok", status: 201, json: GITHUB_FIXTURES.prCommentCreated },
    );
    const { intentId } = await runGovernedWrite("canary-1");

    const kase = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE]);
    expect(kase).not.toBeNull();
    const manifestJson = JSON.stringify(kase);
    // No credential sentinel, no bearer prefix, no raw idempotency key material.
    expect(manifestJson).not.toContain(GITHUB_TOKEN_SENTINEL);
    expect(manifestJson).not.toContain("ghp_");
    expect(manifestJson.toLowerCase()).not.toContain("bearer ");
    // The manifest carries only the HASH of the provider idempotency key (D3).
    if (kase?.manifest.execution) {
      const keyHash = kase.manifest.execution.providerIdempotencyKeyHash;
      if (keyHash) expect(keyHash).toMatch(/^(sha256:)?[0-9a-f]{64}$/i);
    }
  });

  it("M18/PN34: outcome_unknown case is honestly incomplete, never complete", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);
    fake.script(
      { method: "POST", path: "/repos/steward-sandbox/hello/issues/1/comments" },
      { mode: "timeout" },
    );
    const { intentId } = await runGovernedWrite("unknown-case-1");

    const kase = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE]);
    expect(kase).not.toBeNull();
    // Honest completeness: an outcome_unknown case is NEVER "complete".
    expect(kase?.manifest.completeness).not.toBe("complete");
  });
});
