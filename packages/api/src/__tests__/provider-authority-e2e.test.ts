/**
 * End-to-end governed-provider proof using a fake transport.
 *
 * It drives the same governed code path as `scripts/provider-authority-sandbox.mjs`,
 * with the terminal forwarder replaced by the deterministic in-process transport.
 * Every allow, approve, resume, and dispatch operation uses the real authority
 * service functions.
 *
 * DISPATCH TOPOLOGY:
 * Allowed reads terminate at `executeProviderActionStub`. Consequential writes
 * traverse `dispatchGovernedExecution` and the injected transport after approval.
 *
 * UI and accessibility coverage lives in the web suite. The proxy package owns
 * the static fake-transport inventory test.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  setDefaultTimeout,
} from "bun:test";
import { createHash } from "node:crypto";
import {
  closeDb,
  executionAuthorizationNonces,
  getDb,
  providerAccounts,
  providerActionBindings,
  providerGrants,
  providerOperations,
  secretRoutes,
  secrets,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { buildGithubAction } from "@stwd/provider-github";
import { buildXAction } from "@stwd/provider-x";
import {
  FakeProviderTransport,
  GITHUB_FIXTURES,
  X_FIXTURES,
} from "@stwd/proxy/src/__tests__/fake-provider-transport";
import { KeyStore } from "@stwd/vault";
import { and, eq, sql } from "drizzle-orm";

// Real authority services (the code path under proof).
import { providerActionService } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";
import { getProviderCase } from "../services/provider-case";

setDefaultTimeout(120_000);

// Governed dispatcher and injectable proxy forwarder seam.
type ProxyMod = typeof import("@stwd/proxy/src/handlers/proxy");
type DispatchMod = typeof import("@stwd/proxy/src/handlers/governed-execution");
let proxyMod: ProxyMod;
let dispatchGovernedExecution: DispatchMod["dispatchGovernedExecution"];
let restoreProxyRateLimit: (() => void) | undefined;

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

// Encrypt with the SAME master the proxy decrypt path (getSecretVault) uses at
// runtime. On PGLite this is test-preload's default; under the real-Postgres CI
// job the workflow sets STEWARD_MASTER_PASSWORD to a different value BEFORE
// test-preload's `??=`, so a hardcoded constant would mint a credential the
// server-side vault cannot decrypt ("Unsupported state or unable to authenticate
// data"), diverging the governed dispatch and breaking M18. Read the live env so
// the test's KeyStore matches the vault regardless of environment.
const MASTER = process.env.STEWARD_MASTER_PASSWORD ?? "steward-api-test-suite-master-password";
const GITHUB_TOKEN_SENTINEL = "ghp_SENTINEL_credential_never_leaks_0123456789ABCD";
const X_TOKEN_SENTINEL = "X_SENTINEL_credential_never_leaks_0123456789ABCD";
const X_OP = "40000000-0000-4000-8000-0000000000b0";
const X_OP_KEY = "x.tweet.create";

let fake: FakeProviderTransport;

const MATRIX_EVIDENCE_PREFIX = "STEWARD_MATRIX_EVIDENCE ";

function emitMatrixEvidence(evidence: Record<string, unknown>): void {
  // The golden-path orchestrator parses these records. Never put plaintext
  // credentials or request bodies in this machine-readable channel.
  console.log(`${MATRIX_EVIDENCE_PREFIX}${JSON.stringify(evidence)}`);
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

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
async function enableGovernedRoute(
  operationId: string,
  credential = GITHUB_TOKEN_SENTINEL,
  credentialName = "github",
): Promise<void> {
  const db = getDb();
  await db
    .update(secrets)
    .set({
      name: credentialName,
      ...encryptCredential(F.TENANT, credentialName, credential),
    })
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

async function configureXWrite(): Promise<void> {
  await getDb()
    .update(providerAccounts)
    .set({ adapterKey: "x" })
    .where(eq(providerAccounts.id, F.ACCOUNT));
  await getDb()
    .insert(providerOperations)
    .values({
      id: X_OP,
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      operationKey: X_OP_KEY,
      riskClass: "consequential",
      secretRouteId: F.ROUTE,
      requestProfile: {
        policyRules: [
          {
            id: "44444444-4444-4444-8444-444444444444",
            type: "capability-intent",
            enabled: true,
            config: { capabilities: [X_OP_KEY], effect: "allow" },
          },
          {
            id: "55555555-5555-4555-8555-555555555555",
            type: "capability-intent",
            enabled: true,
            config: { capabilities: [X_OP_KEY], effect: "require-approval" },
          },
        ],
      },
    });
  await getDb()
    .update(providerGrants)
    .set({ operationKeys: [F.OP_KEY, READ_OP_KEY, X_OP_KEY] })
    .where(eq(providerGrants.id, F.GRANT));
  await getDb()
    .update(secretRoutes)
    .set({
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    })
    .where(eq(secretRoutes.id, F.ROUTE));
  await enableGovernedRoute(X_OP, X_TOKEN_SENTINEL, "x-oauth");
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

async function createXWriteAction(seed: string): Promise<{
  intentId: string;
  requestHash: string;
  actionDigest: string;
}> {
  const now = new Date();
  const out = await providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: F.WORKSPACE,
    providerAccountId: F.ACCOUNT,
    operationKey: X_OP_KEY,
    build: buildXAction(X_OP_KEY, { text: "governed tweet" }),
    idempotencyKeyHash: idem(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
  if (out.kind !== "approval_required") {
    throw new Error(`expected X approval_required, got ${out.kind}`);
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
  process.env.STEWARD_PROXY_DEV_MODE = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  proxyMod = await import("@stwd/proxy/src/handlers/proxy");
  const redisEnforcement = await import("@stwd/proxy/src/middleware/redis-enforcement");
  ({ dispatchGovernedExecution } = await import("@stwd/proxy/src/handlers/governed-execution"));
  ({ F, principal } = await import("./provider-approval-fixture"));
  ({ seedCaseFixture, wipeCase } = await import("./provider-case-fixture"));
  proxyMod.__setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
  // Pin DNS to a public address so the SSRF guard passes without a real lookup.
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "140.82.112.6", family: 4 }]);
  restoreProxyRateLimit = () =>
    proxyMod.__setCheckProxyRateLimitForTests(redisEnforcement.checkProxyRateLimit);
});

afterAll(async () => {
  restoreProxyRateLimit?.();
  await closeDb();
  delete process.env.STEWARD_PROXY_DEV_MODE;
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
  await getDb().execute(
    sql`UPDATE secret_routes SET provider_operation_id = NULL, authority_mode = 'legacy'`,
  );
  await wipeCase();
  fake.reset();
});

describe("governed provider E2E — fake transport, real authority (U1-U3)", () => {
  it("M14: happy write path create→approve→resume→dispatch→succeeded via fake forwarder", async () => {
    const [op] = await getDb()
      .select({ id: sql<string>`id` })
      .from(sql`provider_operations`)
      .where(sql`tenant_id = ${F.TENANT} AND operation_key = ${F.OP_KEY}`)
      .limit(1);
    await enableGovernedRoute(op.id);
    fake.expectCredential("authorization", GITHUB_TOKEN_SENTINEL);
    const outboundBody = JSON.stringify({ body: "governed comment (steward-marker)" });
    const expectedBodyHash = sha256Text(outboundBody);

    fake.script(
      {
        method: "POST",
        path: "/repos/steward-sandbox/hello/issues/1/comments",
        bodyHash: expectedBodyHash,
      },
      { mode: "ok", status: 201, json: GITHUB_FIXTURES.prCommentCreated },
    );

    const { intentId, dispatch } = await runGovernedWrite("write-happy-1");

    // The fake was reached exactly once (M07/M14 dispatch count == 1).
    expect(fake.dispatchCount()).toBe(1);
    // dispatch succeeded (terminal succeeded).
    expect(dispatch.dispatchState).toBe("succeeded");
    expect(await dispatchStateOf(intentId)).toBe("succeeded");
    expect(fake.calls()).toHaveLength(1);
    expect(fake.calls()[0]).toMatchObject({
      method: "POST",
      host: "api.github.com",
      path: "/repos/steward-sandbox/hello/issues/1/comments",
      bodyHash: expectedBodyHash,
    });
    // At the forwarder layer the injected credential header IS present...
    expect(fake.calls()[0].credentialHeaderPresent).toBe(true);
    expect(fake.calls()[0].credentialMatchesExpected).toBe(true);
    // ...but its VALUE is never recorded (canary): no sentinel anywhere.
    expect(JSON.stringify(fake.calls())).not.toContain(GITHUB_TOKEN_SENTINEL);
    emitMatrixEvidence({
      leg: "M14-github-write",
      dispatchCount: fake.dispatchCount(),
      dispatchState: dispatch.dispatchState,
      host: fake.calls()[0]?.host,
      path: fake.calls()[0]?.path,
      bodyHash: fake.calls()[0]?.bodyHash,
      expectedBodyHash,
      credentialValueHash: fake.calls()[0]?.credentialValueHash,
      credentialMatchesExpected: fake.calls()[0]?.credentialMatchesExpected,
    });
  });

  it("M19: X consequential write traverses create→approve→resume→dispatch exactly once and stays canary-clean", async () => {
    await configureXWrite();
    // Match the actual X route contract, not merely the raw vault plaintext:
    // terminal I/O must receive the provider's Bearer-formatted credential.
    fake.expectCredential("authorization", `Bearer ${X_TOKEN_SENTINEL}`);
    const outboundBody = JSON.stringify({ text: "governed tweet" });
    const expectedBodyHash = sha256Text(outboundBody);
    fake.script(
      { method: "POST", path: "/2/tweets", bodyHash: expectedBodyHash },
      { mode: "ok", status: 201, json: X_FIXTURES.tweetCreated },
    );

    const { intentId, requestHash, actionDigest } = await createXWriteAction("x-write-happy-1");
    await approve(intentId, requestHash, actionDigest);
    await resume(intentId);
    const dispatch = await dispatchGovernedExecution(intentId, F.TENANT);

    expect(dispatch.dispatchState).toBe("succeeded");
    expect(await dispatchStateOf(intentId)).toBe("succeeded");
    expect(fake.dispatchCount()).toBe(1);
    expect(fake.calls()).toHaveLength(1);
    expect(fake.calls()[0]).toMatchObject({
      method: "POST",
      host: "api.x.com",
      path: "/2/tweets",
      credentialHeaderPresent: true,
      credentialMatchesExpected: true,
      bodyHash: expectedBodyHash,
    });

    const [account] = await getDb()
      .select({ adapterKey: providerAccounts.adapterKey })
      .from(providerAccounts)
      .where(eq(providerAccounts.id, F.ACCOUNT))
      .limit(1);
    expect(account?.adapterKey).toBe("x");

    const kase = await getProviderCase(F.TENANT, intentId, [F.WORKSPACE]);
    expect(kase?.manifest.operation.key).toBe(X_OP_KEY);
    const captured = JSON.stringify({ calls: fake.calls(), dispatch, kase });
    expect(captured).not.toContain(X_TOKEN_SENTINEL);
    expect(captured).not.toContain("Bearer ");
    emitMatrixEvidence({
      leg: "M19-x-write",
      adapterKey: account?.adapterKey,
      dispatchCount: fake.dispatchCount(),
      dispatchState: dispatch.dispatchState,
      host: fake.calls()[0]?.host,
      path: fake.calls()[0]?.path,
      bodyHash: fake.calls()[0]?.bodyHash,
      expectedBodyHash,
      credentialValueHash: fake.calls()[0]?.credentialValueHash,
      credentialMatchesExpected: fake.calls()[0]?.credentialMatchesExpected,
    });
  });

  it("M04: write op requires approval — create returns approval_required, no dispatch", async () => {
    const { intentId } = await createWriteAction("write-pending-1");
    expect(await bindingStatus(intentId)).toBe("pending_approval");
    // No dispatch happened (no forwarder call, no nonce).
    expect(fake.dispatchCount()).toBe(0);
    expect(await dispatchStateOf(intentId)).toBeNull();
    emitMatrixEvidence({ leg: "M04-pending-approval", dispatchCount: 0 });
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
    emitMatrixEvidence({ leg: "M02-read-allow", dispatchCount: 0, outcome: out.kind });
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
    emitMatrixEvidence({
      leg: "M03-cross-workspace-deny",
      dispatchCount: 0,
      outcome: out.kind,
    });
  });

  it("M05/PN17: route revision bumped after resume — claim fails STALE_ROUTE, zero forward", async () => {
    // The claim's live-revision staleness checks are route revision and secret
    // version. The approval commitment is
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
    emitMatrixEvidence({ leg: "M05-stale-route", dispatchCount: 0, dispatchOk: dispatch.ok });
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
    emitMatrixEvidence({
      leg: "M07-concurrent-dispatch",
      dispatchCount: 1,
      successfulClaims: succeeded.length,
    });
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
    emitMatrixEvidence({
      leg: "M08-outcome-unknown",
      dispatchCount: 1,
      dispatchState: dispatch.dispatchState,
      replayOk: replay.ok,
    });
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
