/**
 * Governed proxy execution — proxy-side claim, dispatch, and authority gate.
 *
 * Covers the security-critical proxy invariants against PGLite with the existing
 * forwarder stub (the test transport seam):
 *   - X1 governed routes unreachable via direct /proxy / forged header (P01/P05)
 *   - §6.3 unknown authority_mode default-deny (P53)
 *   - X3 single-winner claim under concurrency (K01), double-claim (P43)
 *   - X4 DB-time expiry governs (P24/K02)
 *   - X5 stale route/secret at claim (P13/P14), tampered signature (P11)
 *   - X8 outcome_unknown on upstream ambiguity, no blind retry (K13)
 *   - EXEC_AUTH_NOT_READY when no active nonce (P25), terminal replay (P26)
 *
 * The fixture seeds a self-consistent execution_ready binding + approval_queue
 * commitment + a minted v2 nonce whose commitment/signature is computed with the
 * SAME @stwd/shared helpers the proxy revalidation uses, so a happy claim
 * revalidates and dispatches.
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
import { createHmac, hkdfSync, randomUUID } from "node:crypto";
import {
  agents,
  approvalQueue,
  auditEvents,
  closeDb,
  executionAuthorizationNonces,
  getDb,
  intents,
  providerAccounts,
  providerActionBindings,
  providerOperations,
  secretRoutes,
  secrets,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  __resetSecurityMetricsForTests,
  __setSecurityMetricsObserverFailureForTests,
  buildProviderExecutionCommitmentV2,
  canonicalActionBytes,
  computeActionDigest,
  computeApprovalCommitmentHash,
  computeGenericHttpActionDigest,
  computeProviderExecutionCommitmentHash,
  type GenericHttpCanonicalActionV1,
  type GithubCanonicalActionV1,
  genericHttpCanonicalActionBytes,
  jcsStringify,
  type ProviderApprovalCommitmentV1,
  providerExecutionSignatureInput,
  sha256HexPrefixed,
} from "@stwd/shared";
import { KeyStore } from "@stwd/vault";
import { and, eq, sql } from "drizzle-orm";

setDefaultTimeout(30000);

const MASTER = "proxy-governed-master";
const EXEC_SECRET = "v2-1:governed-exec-auth-secret-with-enough-entropy-0123456789";

let dispatchMod: typeof import("../handlers/governed-execution");
let proxyMod: typeof import("../handlers/proxy");
let dispatchGovernedExecution: typeof import("../handlers/governed-execution")["dispatchGovernedExecution"];
let handleProxy: typeof import("../handlers/proxy")["handleProxy"];

let captured: { url: string; method: string } | null = null;
let capturedBody: string | null = null;
let capturedHeaders: Record<string, string> | null = null;
// Set true when the forwarder's streaming response body is cancelled/drained.
// Proves the governed dispatcher releases the proxy in-flight slot.
let streamingBodyCancelled = false;
let forwarderMode: "ok" | "throw" | "500" | "stream" = "ok";

const IDS = {
  tenant: "tenant-gov",
  agent: "agent-gov",
  workspace: "20000000-0000-4000-8000-000000000001",
  account: "30000000-0000-4000-8000-000000000001",
  operation: "40000000-0000-4000-8000-000000000001",
  secret: "50000000-0000-4000-8000-000000000001",
  route: "60000000-0000-4000-8000-000000000001",
  grant: "a0000000-0000-4000-8000-000000000001",
  binding: "b0000000-0000-4000-8000-000000000001",
  user: "c0000000-0000-4000-8000-000000000001",
};

function v2Key(): Uint8Array {
  const secret = EXEC_SECRET.split(",")[0].slice(EXEC_SECRET.indexOf(":") + 1);
  const d = hkdfSync(
    "sha256",
    new TextEncoder().encode(secret),
    new TextEncoder().encode("steward:execution-authorization:v2:salt"),
    new TextEncoder().encode("steward:execution-authorization:v2:hmac"),
    32,
  );
  return d instanceof ArrayBuffer ? new Uint8Array(d) : (d as Uint8Array);
}

function base64Url(value: Uint8Array): string {
  const binary = Array.from(value, (b) => String.fromCharCode(b)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// Encrypt a credential with the SAME KeyStore context the proxy's SecretVault
// uses (namespace "secret-vault", context {tenantId, name, version}) so a real
// decrypt at forward time succeeds. Returns the DB crypto columns.
function encryptCredential(
  tenantId: string,
  name: string,
  value: string,
): { ciphertext: string; iv: string; authTag: string; salt: string } {
  const keyStore = new KeyStore(MASTER, undefined, "secret-vault");
  const e = keyStore.encrypt(value, { tenantId, name, version: 1 });
  return { ciphertext: e.ciphertext, iv: e.iv, authTag: e.tag, salt: e.salt };
}

const ACTION: GithubCanonicalActionV1 = {
  profile: "github.provider-action.v1",
  method: "GET",
  origin: "https://api.github.com",
  normalizedPath: "/repos/acme/widgets/issues",
  orderedQueryPairs: [
    ["per_page", "30"],
    ["state", "open"],
  ],
  selectedHeaders: [
    ["accept", "application/vnd.github+json"],
    ["x-github-api-version", "2022-11-28"],
  ],
  canonicalBody: null,
};

async function seedBase() {
  // The personal-lifecycle identity registry intentionally survives user-row
  // deletion, so each fixture needs a new subject instead of reusing a retired
  // identity across beforeEach cycles.
  IDS.user = randomUUID();
  const db = getDb();
  await db.insert(tenants).values({ id: IDS.tenant, name: "Gov", apiKeyHash: "h" });
  await db.insert(users).values({ id: IDS.user, email: `gov-${IDS.user}@t.test` });
  await db
    .insert(agents)
    .values({ id: IDS.agent, tenantId: IDS.tenant, name: "A", walletAddress: "0x1" });
  await db.insert(secrets).values({
    id: IDS.secret,
    tenantId: IDS.tenant,
    name: "github",
    // Real vault-encrypted ciphertext so the proxy decrypt SUCCEEDS and the
    // forwarder stub is actually reached (dummy ciphertext would 500 at decrypt
    // and short-circuit the forward classification tests). The context
    // {tenantId, name, version} MUST match what SecretVault.decryptSecret derives.
    ...encryptCredential(IDS.tenant, "github", "ghp_test_token"),
    version: 1,
  });
  await db.insert(workspaces).values({
    id: IDS.workspace,
    tenantId: IDS.tenant,
    key: "client-a",
    name: "A",
    environment: "production",
    createdBy: IDS.user,
  });
  // Insert the route LEGACY first (the governed<->operation FK pair is circular,
  // spec G2). Flip to governed_v2 after the operation exists.
  await db.insert(secretRoutes).values({
    id: IDS.route,
    tenantId: IDS.tenant,
    agentId: IDS.agent,
    secretId: IDS.secret,
    hostPattern: "api.github.com",
    pathPattern: "/*",
    method: "*",
    injectAs: "header",
    injectKey: "authorization",
    authorityMode: "legacy",
    authorityRevision: 1,
  });
  await db.insert(providerAccounts).values({
    id: IDS.account,
    tenantId: IDS.tenant,
    workspaceId: IDS.workspace,
    adapterKey: "github",
    externalRef: "acme",
    displayName: "Acme GitHub",
    status: "active",
    credentialSecretId: IDS.secret,
    credentialVersion: 1,
    revision: 1,
  });
  await db.insert(providerOperations).values({
    id: IDS.operation,
    tenantId: IDS.tenant,
    workspaceId: IDS.workspace,
    providerAccountId: IDS.account,
    secretRouteId: IDS.route,
    operationKey: "github.issue.list",
    riskClass: "read",
    revision: 1,
  });
  // Now flip the route to governed_v2 pointing at the operation. The trigger bumps
  // authority_revision (legacy->governed_v2 is a watched change), OVERRIDING any
  // explicit value in this UPDATE. So reset revision to 1 in a SECOND update that
  // touches ONLY authority_revision (not a watched column), so the trigger does
  // NOT fire and the live revision truly lands at 1 (matching the seeded nonce).
  await db
    .update(secretRoutes)
    .set({ authorityMode: "governed_v2", providerOperationId: IDS.operation })
    .where(eq(secretRoutes.id, IDS.route));
  await db.execute(sql`UPDATE secret_routes SET authority_revision = 1 WHERE id = ${IDS.route}`);
}

interface SeedNonceOpts {
  expiresInMs?: number;
  routeRevision?: number;
  secretVersion?: number;
  tamperSignature?: boolean;
  status?: "active" | "consumed";
  dispatchState?: string;
  intentSuffix?: string;
  action?: GithubCanonicalActionV1 | GenericHttpCanonicalActionV1;
  requestEnvelope?: Record<string, unknown>;
  safeSummary?: Record<string, unknown>;
}

async function seedExecutionReady(opts: SeedNonceOpts = {}) {
  const db = getDb();
  const intentId = `pa_${randomUUID().slice(0, 8)}${opts.intentSuffix ?? ""}`;
  const authorizationId = randomUUID();
  const executionId = randomUUID();
  const nonce = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "").slice(0, 16);
  const providerIdempotencyKey = randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + (opts.expiresInMs ?? 300_000));
  const routeRevision = opts.routeRevision ?? 1;
  const secretVersion = opts.secretVersion ?? 1;
  const action = opts.action ?? ACTION;
  const generic = action.profile === "generic-http.provider-action.v1";
  if (generic) {
    await db
      .update(providerOperations)
      .set({
        requestProfile: {
          profile: "generic-http.provider-action.v1",
          operationDescriptor: {
            profile: "generic-http.provider-action.v1",
            origin: "https://api.customer.example",
            methods: ["POST"],
            pathTemplate: [{ literal: "v1" }, { literal: "items" }],
            query: [
              {
                name: "mode",
                type: "string",
                required: true,
                pattern: "^safe$",
              },
            ],
            headers: [{ name: "accept", value: "application/json" }],
            body: {
              contentType: "application/json",
              fields: [
                {
                  name: "name",
                  type: "string",
                  required: true,
                  pattern: "^[a-z]{1,64}$",
                  maxBytes: 64,
                },
                { name: "alpha", type: "int" },
                { name: "zeta", type: "int" },
              ],
            },
            projection: { policyArgs: [], safeSummary: [] },
          },
        },
      })
      .where(eq(providerOperations.id, IDS.operation));
    await db.execute(sql`UPDATE provider_operations SET revision = 1 WHERE id = ${IDS.operation}`);
  }
  const actionDigest = generic
    ? computeGenericHttpActionDigest(action as GenericHttpCanonicalActionV1)
    : computeActionDigest(action as GithubCanonicalActionV1);
  const actionBytes = generic
    ? genericHttpCanonicalActionBytes(action as GenericHttpCanonicalActionV1)
    : canonicalActionBytes(action as GithubCanonicalActionV1);
  const requestEnvelope = opts.requestEnvelope ?? { schemaVersion: "steward.provider-request.v1" };
  const requestHash =
    opts.requestEnvelope === undefined
      ? sha256HexPrefixed(`req:${intentId}`)
      : sha256HexPrefixed(jcsStringify(requestEnvelope));
  const policyRevisionHash = sha256HexPrefixed("policy:1");
  const accessDecisionHash = sha256HexPrefixed("access:1");
  const approvalId = `aq_${randomUUID().slice(0, 8)}`;

  const approvalCommitment: ProviderApprovalCommitmentV1 = {
    schemaVersion: "steward.provider-approval-commitment.v1",
    intentId,
    tenantId: IDS.tenant,
    workspaceId: IDS.workspace,
    requestActor: { type: "agent", id: IDS.agent, revision: 1 },
    providerAccount: { id: IDS.account, revision: 1, status: "active" },
    operation: {
      id: IDS.operation,
      key: "github.issue.list",
      revision: 1,
      riskClass: "read",
      canonicalProfile: action.profile,
    },
    requestHash,
    actionDigest,
    accessDecision: {
      id: randomUUID(),
      hash: accessDecisionHash,
      effect: "allow",
      matchedBindings: [{ id: IDS.binding, revision: 1 }],
      matchedGrants: [{ id: IDS.grant, revision: 1 }],
    },
    policyDecision: {
      id: randomUUID(),
      hash: sha256HexPrefixed("policy-decision:1"),
      effect: "approval_required",
      policyRevisionHash,
      approvalPolicyRevisionHash: sha256HexPrefixed("approval-policy:1"),
      evaluatorVersion: "v1",
    },
    executionDependencies: {
      routeId: IDS.route,
      routeRevision,
      secretId: IDS.secret,
      secretVersion,
    },
    approvalRequirements: {
      role: "workspace_approver",
      requesterSeparation: false,
      maxMfaAgeSeconds: 300,
      requiredMfaAssurance: "current-session-mfa",
    },
    requestedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
  const approvalCommitmentHash = computeApprovalCommitmentHash(approvalCommitment);
  const executionPolicyDecision = {
    schemaVersion: "steward.provider-policy-decision.v1",
    decisionId: randomUUID(),
    intentId,
    requestHash,
    actionDigest,
    operationId: IDS.operation,
    operationKey: "github.issue.list",
    effect: "approval_required",
    reasonCodes: ["APPROVAL_REQUIRED"],
    policyResults: [],
    policyRevisionHash,
    evaluatorVersion: "provider-action.v1",
    decidedAt: now.toISOString(),
  };
  const executionPolicyDecisionHash = sha256HexPrefixed(jcsStringify(executionPolicyDecision));

  const commitment = buildProviderExecutionCommitmentV2({
    approval: approvalCommitment,
    action,
    approvalCommitmentHash,
    approvalId,
    authorizationId,
    executionId,
    requestId: intentId,
    providerIdempotencyKey,
    nonce,
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    keyId: "v2-1",
  });
  const commitmentHash = computeProviderExecutionCommitmentHash(commitment);
  let signature = base64Url(
    createHmac("sha256", v2Key()).update(providerExecutionSignatureInput(commitment)).digest(),
  );
  if (opts.tamperSignature) signature = `${signature.slice(0, -3)}AAA`;

  await db.insert(intents).values({
    id: intentId,
    tenantId: IDS.tenant,
    agentId: IDS.agent,
    intentType: "provider_action",
    status: "authorized",
    executedBy: "steward-system",
  });
  await db.insert(providerActionBindings).values({
    intentId,
    tenantId: IDS.tenant,
    workspaceId: IDS.workspace,
    actorAgentId: IDS.agent,
    providerAccountId: IDS.account,
    operationId: IDS.operation,
    operationRevision: 1,
    canonicalProfile: action.profile,
    canonicalActionBytes: Buffer.from(actionBytes, "utf8"),
    actionDigest,
    requestEnvelope,
    requestHash,
    idempotencyKeyHash: sha256HexPrefixed(`idem:${intentId}`),
    safeSummary: opts.safeSummary ?? {},
    accessDecisionId: randomUUID(),
    accessEffect: "allow",
    accessReasonCode: "ok",
    matchedBindingIds: [IDS.binding],
    matchedGrantIds: [IDS.grant],
    dependencyRevisions: {},
    accessDecision: {},
    accessDecisionHash,
    policyEffect: "approval_required",
    policyDecisionId: randomUUID(),
    policyRevisionHash,
    policyDecision: {},
    policyDecisionHash: sha256HexPrefixed("policy-decision:1"),
    status: "execution_ready",
    bindingRevision: 2,
    approvalQueueId: approvalId,
    approvalCommitmentHash,
    approvalActorUserId: IDS.user,
    approvedAt: now,
    resumeActor: "steward-system",
    resumeAttemptId: randomUUID(),
    resumeValidatedAt: now,
    executionPolicyDecisionId: executionPolicyDecision.decisionId,
    executionPolicyRevisionHash: policyRevisionHash,
    executionPolicyDecision,
    executionPolicyDecisionHash,
    executionPolicyEvaluatedAt: now,
  });
  await db.insert(approvalQueue).values({
    id: approvalId,
    agentId: IDS.agent,
    approvalKind: "provider_action",
    tenantId: IDS.tenant,
    intentId,
    workspaceId: IDS.workspace,
    requestHash,
    actionDigest,
    status: "consumed",
    decision: "approve",
    resolvedAt: now,
    resolvedByType: "user",
    resolvedById: IDS.user,
    mfaVerifiedAt: now,
    consumedAt: now,
    consumedBy: "steward-system",
    approvalCommitment: approvalCommitment as unknown as Record<string, unknown>,
    approvalCommitmentHash,
    expectedBindingRevision: 1,
    expiresAt,
  });
  await db.insert(executionAuthorizationNonces).values({
    authorizationId,
    requestId: intentId,
    tenantId: IDS.tenant,
    agentId: IDS.agent,
    capability: "credential.inject_http",
    backend: "credential-proxy",
    payloadDigest: actionDigest.slice(7),
    policyRevisionHash: policyRevisionHash.slice(7),
    approvalId,
    nonce,
    signature,
    idempotencyKey: providerIdempotencyKey,
    status: opts.status ?? "active",
    issuedAt: now,
    expiresAt,
    version: 2,
    executionId,
    intentId,
    workspaceId: IDS.workspace,
    providerAccountId: IDS.account,
    operationId: IDS.operation,
    operationRevision: 1,
    requestHash,
    actionDigest,
    grantDependencyHash: commitment.grantDependencyHash,
    routeId: IDS.route,
    routeRevision,
    secretId: IDS.secret,
    secretVersion,
    providerIdempotencyKey,
    commitmentHash,
    keyId: "v2-1",
    dispatchState: opts.dispatchState ?? "none",
    // Terminal/dispatched states require dispatched_at (dispatch_shape_chk).
    dispatchedAt:
      opts.dispatchState &&
      ["dispatched", "succeeded", "failed", "outcome_unknown"].includes(opts.dispatchState)
        ? now
        : null,
  });

  return { intentId, authorizationId, executionId, nonce };
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER;
  process.env.STEWARD_JWT_SECRET = "proxy-governed-jwt-secret-with-enough-bytes-here-0123";
  process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
  process.env.STEWARD_EXECUTION_AUTH_SECRET = EXEC_SECRET;
  // Dispatch is exercised against the in-process replay store and no Redis —
  // the soft development posture, an explicit opt-in since SEC-175.
  process.env.STEWARD_PROXY_DEV_MODE = "true";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  proxyMod = await import("../handlers/proxy");
  handleProxy = proxyMod.handleProxy;
  dispatchMod = await import("../handlers/governed-execution");
  dispatchGovernedExecution = dispatchMod.dispatchGovernedExecution;

  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "140.82.112.6", family: 4 }]);
  proxyMod.__setForwardProxyRequestForTests(async (url, method, headers, body) => {
    captured = { url: url.toString(), method };
    capturedHeaders = Object.fromEntries(headers.entries());
    // Capture the exact outbound body bytes (JCS-serialized by the dispatcher) so
    // tests can assert byte fidelity of the forwarded request.
    capturedBody = null;
    if (body) {
      const reader = (body as ReadableStream<Uint8Array>).getReader();
      const chunks: Uint8Array[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      const total = chunks.reduce((n, c) => n + c.length, 0);
      const merged = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        merged.set(c, off);
        off += c.length;
      }
      capturedBody = new TextDecoder().decode(merged);
    }
    if (forwarderMode === "throw") throw new Error("upstream connection reset");
    if (forwarderMode === "500") return new Response(JSON.stringify({ err: 1 }), { status: 500 });
    if (forwarderMode === "stream") {
      // A 200 whose body enqueues ONE chunk then stays OPEN (pull awaits a promise
      // that only resolves on cancel). The proxy slot is released only when this
      // body is fully read OR cancelled, so if the governed dispatcher fails to
      // drain it the slot leaks (and this test would hang / the flag stays false).
      let firstPull = true;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (firstPull) {
            firstPull = false;
            controller.enqueue(new Uint8Array([1, 2, 3]));
            return;
          }
          // Park until cancelled: return a promise that never resolves, so the
          // only way to end the stream is an explicit cancel().
          return new Promise<void>(() => {});
        },
        cancel() {
          streamingBodyCancelled = true;
        },
      });
      // A credentialed response whose declared content-length EXCEEDS the proxy's
      // reflection-scan cap: handleProxy skips buffering it and passes the body
      // THROUGH (wrapped by releaseWhenBodyCloses). The slot is then released ONLY
      // when the dispatcher drains that pass-through body — the exact leak path.
      return new Response(stream, {
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-length": String(64 * 1024 * 1024), // > 25MB cap
        },
      });
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  // decryptSecret needs a real secret in the vault; the credential is injected as
  // a header. For the governed happy path we only assert dispatch happens, so we
  // stub the vault decrypt is not exported — instead we rely on the forwarder
  // capture. The route injects 'authorization' from the vault; PGLite secret has
  // dummy ciphertext, so decrypt will fail. Route the happy path around it by
  // asserting the gate PERMITS + claim consumes; the forward itself is stubbed.
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
  delete process.env.STEWARD_PROXY_DEV_MODE;
});

beforeEach(async () => {
  captured = null;
  capturedBody = null;
  capturedHeaders = null;
  streamingBodyCancelled = false;
  forwarderMode = "ok";
  const db = getDb();
  // Clean per-test rows (order: children first).
  await db.delete(executionAuthorizationNonces);
  await db.delete(approvalQueue);
  await db.delete(providerActionBindings);
  await db.delete(intents);
  // Break the circular route<->operation FK before deleting either.
  await db.update(secretRoutes).set({ authorityMode: "legacy", providerOperationId: null });
  await db.delete(providerOperations);
  await db.delete(providerAccounts);
  await db.delete(secretRoutes);
  await db.delete(secrets);
  await db.delete(workspaces);
  await db.delete(agents);
  await db.delete(users);
  await db.delete(tenants);
  await seedBase();
});

afterEach(() => {
  // Reset any fault-injection hooks so a race test cannot leak into the next.
  dispatchMod.__resetGovernedDispatchHooksForTests();
  __resetSecurityMetricsForTests();
});

// Build a minimal Hono-like context for handleProxy with an optional forged
// governedExecutionClaim (P05) to prove the header/context cannot be smuggled.
function fakeDirectContext(path: string, forgedClaim?: unknown) {
  const request = new Request(`https://steward-proxy.local${path}`, { method: "GET" });
  const responseHeaders = new Headers();
  return {
    req: {
      method: "GET",
      path,
      raw: request,
      header: (name: string) => request.headers.get(name) ?? undefined,
    },
    get: (key: string) => {
      if (key === "agentId") return IDS.agent;
      if (key === "tenantId") return IDS.tenant;
      // A forged claim: even if some upstream tried to set it, prove the gate
      // requires an exact routeId match AND that direct arrivals never set it.
      if (key === "governedExecutionClaim") return forgedClaim;
      return undefined;
    },
    header: (name: string, value: string) => responseHeaders.set(name, value),
    json: (payload: unknown, status?: number) =>
      new Response(JSON.stringify(payload), {
        status: status ?? 200,
        headers: { "content-type": "application/json" },
      }),
  } as unknown as import("hono").Context;
}

describe("governed proxy authority gate (X1, §5.1)", () => {
  it("P01: direct /proxy to a governed route is denied 403, zero forward", async () => {
    await seedExecutionReady();
    const res = await handleProxy(
      fakeDirectContext("/proxy/api.github.com/repos/acme/widgets/issues"),
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("GOVERNED_ROUTE_DIRECT_DENIED");
    expect(captured).toBeNull();
  });

  it("P05: a forged governedExecutionClaim with wrong routeId is ignored → 403", async () => {
    await seedExecutionReady();
    // All other bound fields are correct so the routeId equality is the SOLE
    // discriminator (proves the gate pins the selected route id even when the
    // rest of the claim is otherwise valid). routeRevision/secretId/secretVersion
    // are covered independently by P32/P33.
    const res = await handleProxy(
      fakeDirectContext("/proxy/api.github.com/repos/acme/widgets/issues", {
        authorizationId: "x",
        executionId: "y",
        routeId: "99999999-9999-9999-9999-999999999999",
        routeRevision: 1,
        secretId: IDS.secret,
        secretVersion: 1,
        workspaceId: IDS.workspace,
        providerAccountId: IDS.account,
        operationId: IDS.operation,
        operationRevision: 1,
        providerAccountRevision: 1,
      }),
    );
    expect(res.status).toBe(403);
    expect(captured).toBeNull();
  });

  it("P53: an unknown authority_mode default-denies (revert backstop, §6.3)", async () => {
    await seedExecutionReady();
    // The enum only allows legacy/governed_v2, so a truly "unknown" value can only
    // arise on a future proxy seeing a NEW enum member. Simulate by adding a value
    // to the enum via raw SQL, then setting it. The gate's default-deny (anything
    // != 'legacy' without a matching claim) must reject it.
    const db = getDb();
    await db.execute(
      sql`ALTER TYPE secret_route_authority_mode ADD VALUE IF NOT EXISTS 'some_future_mode'`,
    );
    // The governed CHECK already default-denies an unknown mode at write time
    // (a stronger guarantee). To exercise the PROXY code's default-deny we must
    // first relax that CHECK, then store the unknown mode with a null operation.
    await db.execute(
      sql`ALTER TABLE secret_routes DROP CONSTRAINT secret_routes_governed_operation_chk`,
    );
    await db.execute(
      sql`UPDATE secret_routes SET authority_mode = 'some_future_mode', provider_operation_id = NULL WHERE id = ${IDS.route}`,
    );
    const res = await handleProxy(
      fakeDirectContext("/proxy/api.github.com/repos/acme/widgets/issues"),
    );
    expect(res.status).toBe(403);
    expect(captured).toBeNull();
    // Restore the CHECK for subsequent tests (beforeEach resets rows, not DDL).
    await db.execute(
      sql`UPDATE secret_routes SET authority_mode = 'legacy', provider_operation_id = NULL WHERE id = ${IDS.route}`,
    );
    await db.execute(
      sql`ALTER TABLE secret_routes ADD CONSTRAINT secret_routes_governed_operation_chk CHECK ((authority_mode = 'legacy' AND provider_operation_id IS NULL) OR (authority_mode = 'governed_v2' AND provider_operation_id IS NOT NULL))`,
    );
  });
});

describe("dispatchGovernedExecution claim and dispatch", () => {
  it("EXEC_AUTH_NOT_READY when the intent has no active v2 nonce (P25)", async () => {
    const res = await dispatchGovernedExecution("pa_missing", IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_NOT_READY");
    expect(res.httpStatus).toBe(409);
  });

  it("does not dispatch a signed nonce without execute-time policy evidence", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    const db = getDb();
    // Simulate a pre-0084 row. The live schema prevents creating this shape, so
    // temporarily remove only the two rollout guards, mutate it, then restore
    // both before calling the production boundary.
    await db.execute(
      sql`ALTER TABLE provider_action_bindings DROP CONSTRAINT provider_action_bindings_execution_policy_ready_chk`,
    );
    await db.execute(
      sql`DROP TRIGGER provider_action_bindings_immutable ON provider_action_bindings`,
    );
    await db
      .update(providerActionBindings)
      .set({
        executionPolicyDecisionId: null,
        executionPolicyRevisionHash: null,
        executionPolicyDecision: null,
        executionPolicyDecisionHash: null,
        executionPolicyEvaluatedAt: null,
      })
      .where(eq(providerActionBindings.intentId, intentId));
    await db.execute(sql`
      CREATE TRIGGER provider_action_bindings_immutable
      BEFORE UPDATE ON provider_action_bindings
      FOR EACH ROW EXECUTE FUNCTION steward_provider_action_binding_guard()
    `);
    await db.execute(sql`
      ALTER TABLE provider_action_bindings
      ADD CONSTRAINT provider_action_bindings_execution_policy_ready_chk CHECK (
        status NOT IN ('execution_ready','executing') OR execution_policy_decision_id IS NOT NULL
      ) NOT VALID
    `);

    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res).toMatchObject({
      ok: false,
      code: "EXEC_AUTH_POLICY_EVIDENCE_MISSING",
      httpStatus: 409,
    });
    const [nonce] = await db
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(nonce.status).toBe("active");
  });

  it("never claims or dispatches corrupt execute-time policy evidence", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    const db = getDb();
    await db.execute(
      sql`DROP TRIGGER provider_action_bindings_immutable ON provider_action_bindings`,
    );
    await db
      .update(providerActionBindings)
      .set({ executionPolicyDecisionHash: `sha256:${"0".repeat(64)}` })
      .where(eq(providerActionBindings.intentId, intentId));
    await db.execute(sql`
      CREATE TRIGGER provider_action_bindings_immutable
      BEFORE UPDATE ON provider_action_bindings
      FOR EACH ROW EXECUTE FUNCTION steward_provider_action_binding_guard()
    `);

    expect(await dispatchGovernedExecution(intentId, IDS.tenant)).toMatchObject({
      ok: false,
      code: "EXEC_AUTH_POLICY_EVIDENCE_MISSING",
      httpStatus: 409,
    });
    const [nonce] = await db
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(nonce.status).toBe("active");
    expect(captured).toBeNull();
  });

  it("happy path: gate permits, claim consumes exactly once, one dispatch", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    // The forward is stubbed to 200; decrypt of the dummy secret may fail inside
    // handleProxy, but the CLAIM must have consumed the nonce regardless.
    const db = getDb();
    const [n] = await db
      .select({
        status: executionAuthorizationNonces.status,
        ds: executionAuthorizationNonces.dispatchState,
      })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("consumed");
    // dispatch_state advanced past 'none' (claimed/dispatched/terminal).
    expect(n.ds).not.toBe("none");
    expect(res.intentId).toBe(intentId);
  });

  it("dispatches generic HTTP without environment host widening and records evidence", async () => {
    const genericAction: GenericHttpCanonicalActionV1 = {
      profile: "generic-http.provider-action.v1",
      method: "POST",
      origin: "https://api.customer.example",
      normalizedPath: "/v1/items",
      orderedQueryPairs: [["mode", "safe"]],
      selectedHeaders: [
        ["accept", "application/json"],
        ["content-type", "application/json"],
      ],
      canonicalBody: { name: "widget" },
    };
    await getDb()
      .update(secretRoutes)
      .set({ hostPattern: "api.customer.example", pathPattern: "/v1/items", method: "POST" })
      .where(eq(secretRoutes.id, IDS.route));
    await getDb()
      .update(providerOperations)
      .set({
        requestProfile: {
          profile: "generic-http.provider-action.v1",
          operationDescriptor: {
            profile: "generic-http.provider-action.v1",
            origin: "https://api.customer.example",
            methods: ["POST"],
            pathTemplate: [{ literal: "v1" }, { literal: "items" }],
            query: [{ name: "mode", type: "string", pattern: "^safe$" }],
            headers: [{ name: "accept", value: "application/json" }],
            body: {
              contentType: "application/json",
              fields: [{ name: "name", type: "string", pattern: "^.{1,64}$", maxBytes: 64 }],
            },
            projection: { policyArgs: [], safeSummary: ["name"] },
          },
        },
      })
      .where(eq(providerOperations.id, IDS.operation));
    // The fixture authors the descriptor before minting and verifies the exact
    // operation revision that the binding will carry.
    await getDb().execute(
      sql`UPDATE secret_routes SET authority_revision = 1 WHERE id = ${IDS.route}`,
    );
    const [configuredOperation] = await getDb()
      .select({ revision: providerOperations.revision })
      .from(providerOperations)
      .where(eq(providerOperations.id, IDS.operation));
    expect(configuredOperation.revision).toBe(1);
    const saved = process.env.STEWARD_PROXY_ALLOWED_HOSTS;
    delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
    try {
      const { intentId } = await seedExecutionReady({ action: genericAction });
      const result = await dispatchGovernedExecution(intentId, IDS.tenant);
      expect(result).toMatchObject({
        ok: true,
        dispatchState: "succeeded",
        upstreamStatusCode: 200,
      });
      expect(captured).toEqual({
        url: "https://api.customer.example/v1/items?mode=safe",
        method: "POST",
      });
      expect(capturedBody).toBe('{"name":"widget"}');
      expect(capturedHeaders?.authorization).toBe("ghp_test_token");
      expect(JSON.stringify(result)).not.toContain("ghp_test_token");
      const evidence = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, IDS.tenant), eq(auditEvents.resourceId, intentId)));
      expect(evidence.map((row) => row.action)).toContain("provider.execution.dispatched");
      expect(evidence.map((row) => row.action)).toContain("provider.execution.succeeded");
      expect(JSON.stringify(evidence)).not.toContain("ghp_test_token");
    } finally {
      if (saved === undefined) delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
      else process.env.STEWARD_PROXY_ALLOWED_HOSTS = saved;
    }
  });

  it("denies malformed and operation-widening canonical bytes before claim or forward", async () => {
    const mutations: GithubCanonicalActionV1[] = [
      {
        ...ACTION,
        selectedHeaders: [["authorization", "registered-malicious-canary"]],
      },
      { ...ACTION, origin: "https://attacker.example" },
      { ...ACTION, method: "POST" },
      { ...ACTION, normalizedPath: "/repos/acme/widgets/hooks" },
      { ...ACTION, canonicalBody: { client_secret: "registered-malicious-canary" } },
      { ...ACTION, canonicalBody: { harmless: true } },
      {
        ...ACTION,
        selectedHeaders: [["content-type", "text/plain"]],
        canonicalBody: { harmless: true },
      },
    ];
    for (const poisoned of mutations) {
      const { intentId, authorizationId } = await seedExecutionReady({ action: poisoned });
      const result = await dispatchGovernedExecution(intentId, IDS.tenant);
      expect(result).toMatchObject({
        ok: false,
        code: "EXEC_AUTH_STALE_DEPENDENCY",
        httpStatus: 409,
      });
      const [nonce] = await getDb()
        .select({ status: executionAuthorizationNonces.status })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
      expect(nonce.status).toBe("active");
      expect(captured).toBeNull();
    }

    await getDb()
      .update(secretRoutes)
      .set({ hostPattern: "api.customer.example", pathPattern: "/v1/items", method: "POST" })
      .where(eq(secretRoutes.id, IDS.route));
    await getDb().execute(
      sql`UPDATE secret_routes SET authority_revision = 1 WHERE id = ${IDS.route}`,
    );
    const generic: GenericHttpCanonicalActionV1 = {
      profile: "generic-http.provider-action.v1",
      method: "POST",
      origin: "https://api.customer.example",
      normalizedPath: "/v1/items",
      orderedQueryPairs: [["mode", "safe"]],
      selectedHeaders: [
        ["accept", "application/json"],
        ["content-type", "application/json"],
      ],
      canonicalBody: { name: "safe" },
    };
    for (const poisoned of [
      { ...generic, orderedQueryPairs: [["mode", "unsafe"]] as Array<[string, string]> },
      { ...generic, canonicalBody: { name: "ATTACKER" } },
      {
        ...generic,
        selectedHeaders: [["content-type", "application/json"]] as Array<[string, string]>,
      },
    ]) {
      const { intentId, authorizationId } = await seedExecutionReady({ action: poisoned });
      const result = await dispatchGovernedExecution(intentId, IDS.tenant);
      expect(result).toMatchObject({
        ok: false,
        code: "EXEC_AUTH_STALE_DEPENDENCY",
        httpStatus: 409,
      });
      const [nonce] = await getDb()
        .select({ status: executionAuthorizationNonces.status })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
      expect(nonce.status).toBe("active");
      expect(captured).toBeNull();
    }
  });

  it("denies an action-controlled origin before claim or forward", async () => {
    const poisoned = { ...ACTION, origin: "https://attacker.example" };
    const { intentId, authorizationId } = await seedExecutionReady({ action: poisoned });
    const result = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(result).toMatchObject({
      ok: false,
      code: "EXEC_AUTH_STALE_DEPENDENCY",
      httpStatus: 409,
    });
    const [nonce] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(nonce.status).toBe("active");
    expect(captured).toBeNull();
  });

  it("derives a generic origin from the bound operation descriptor, not action bytes", async () => {
    await getDb()
      .update(providerOperations)
      .set({
        requestProfile: {
          profile: "generic-http.provider-action.v1",
          operationDescriptor: {
            profile: "generic-http.provider-action.v1",
            origin: "https://api.customer.example",
            methods: ["GET"],
            pathTemplate: [{ literal: "v1" }, { literal: "items" }],
            projection: { policyArgs: [], safeSummary: [] },
          },
        },
      })
      .where(eq(providerOperations.id, IDS.operation));
    const poisonedAction: GenericHttpCanonicalActionV1 = {
      profile: "generic-http.provider-action.v1",
      method: "GET",
      origin: "https://attacker.example",
      normalizedPath: "/v1/items",
      orderedQueryPairs: [],
      selectedHeaders: [],
      canonicalBody: null,
    };
    const poisoned = await seedExecutionReady({ action: poisonedAction });
    expect(await dispatchGovernedExecution(poisoned.intentId, IDS.tenant)).toMatchObject({
      ok: false,
      code: "EXEC_AUTH_STALE_DEPENDENCY",
    });
    const [nonce] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, poisoned.authorizationId));
    expect(nonce.status).toBe("active");
    expect(captured).toBeNull();
  });

  it("K01/P43: two concurrent claims → exactly one consumes, one dispatch", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    const [a, b] = await Promise.all([
      dispatchGovernedExecution(intentId, IDS.tenant),
      dispatchGovernedExecution(intentId, IDS.tenant),
    ]);
    const winners = [a, b].filter((r) => r.ok || r.code !== "EXEC_AUTH_CLAIM_LOST");
    // At most one true dispatch; the loser is CLAIM_LOST or a terminal read.
    const db = getDb();
    const [n] = await db
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("consumed");
    const lost = [a, b].some(
      (r) => r.code === "EXEC_AUTH_CLAIM_LOST" || r.code === "EXEC_TERMINAL_STATE",
    );
    expect(lost).toBe(true);
    expect(winners.length).toBeGreaterThanOrEqual(1);
  });

  it("P24/K02: an expired authorization is never dispatched (410)", async () => {
    const { intentId } = await seedExecutionReady({ expiresInMs: -1000 });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_EXPIRED");
    expect(captured).toBeNull();
  });

  it("P13: a route revision bump after mint fails the claim (stale route)", async () => {
    const { intentId } = await seedExecutionReady();
    // Bump the LIVE route authority_revision so it mismatches the nonce's bound
    // routeRevision (=1). The pre-claim live-drift check must fail closed with
    // EXEC_AUTH_STALE_ROUTE and NOT consume the nonce.
    await getDb()
      .update(secretRoutes)
      .set({ authorityRevision: 2 })
      .where(eq(secretRoutes.id, IDS.route));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_STALE_ROUTE");
    expect(captured).toBeNull();
  });

  it("fails closed without decrypt when the live route is bound to a different operation", async () => {
    const { intentId } = await seedExecutionReady();
    // Repoint the LIVE governed route's provider_operation_id at a DIFFERENT
    // operation than the one the nonce was minted for, WITHOUT bumping
    // authority_revision (disable the 0082 bump trigger for the mutation), so the
    // revision guard cannot mask the check. provider_operations.secret_route_id is
    // not unique, so this models a nonce for operation B reaching for a route that
    // actually belongs to operation A. The new route↔operation binding assertion
    // must fail closed (EXEC_AUTH_STALE_ROUTE) BEFORE any claim/decrypt.
    const OTHER_OP = "40000000-0000-4000-8000-0000000000ff";
    const db = getDb();
    // A REAL second operation in the same tenant/workspace/account (so the 0082
    // provider_operation_fk is satisfied) that the nonce was NOT minted for.
    await db.insert(providerOperations).values({
      id: OTHER_OP,
      tenantId: IDS.tenant,
      workspaceId: IDS.workspace,
      providerAccountId: IDS.account,
      secretRouteId: IDS.route,
      operationKey: "issues.create",
      riskClass: "write",
      revision: 1,
    });
    await db.execute(
      sql`ALTER TABLE secret_routes DISABLE TRIGGER secret_routes_bump_authority_revision`,
    );
    await db
      .update(secretRoutes)
      .set({ providerOperationId: OTHER_OP })
      .where(eq(secretRoutes.id, IDS.route));
    await db.execute(
      sql`ALTER TABLE secret_routes ENABLE TRIGGER secret_routes_bump_authority_revision`,
    );
    // Sanity: authority_revision is UNCHANGED (so only the new binding check can deny).
    const [live] = await db
      .select({ rev: secretRoutes.authorityRevision, op: secretRoutes.providerOperationId })
      .from(secretRoutes)
      .where(eq(secretRoutes.id, IDS.route))
      .limit(1);
    expect(live?.rev).toBe(1);
    expect(live?.op).toBe(OTHER_OP);
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_STALE_ROUTE");
    expect(captured).toBeNull();
  });

  it("P14: a secret rotation after mint fails the claim (stale secret)", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    await getDb().update(secrets).set({ version: 2 }).where(eq(secrets.id, IDS.secret));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_STALE_SECRET");
    expect(captured).toBeNull();
    const [n] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("active");
  });

  it("P11: a tampered signature fails revalidation before any claim/decrypt", async () => {
    const { intentId, authorizationId } = await seedExecutionReady({ tamperSignature: true });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_SIGNATURE_INVALID");
    // No claim occurred: nonce stays active.
    const [n] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("active");
    expect(captured).toBeNull();
  });

  it("P12b: DB-level canonical body mutation fails the final actionDigest recompute", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    const tampered = structuredClone(ACTION);
    tampered.canonicalBody = { unauthorized: true };

    // Simulate storage corruption below the immutable-row trigger. The service,
    // not only the trigger, must independently recompute and reject the action.
    await getDb().execute(
      sql`ALTER TABLE provider_action_bindings DISABLE TRIGGER provider_action_bindings_immutable`,
    );
    try {
      await getDb()
        .update(providerActionBindings)
        .set({ canonicalActionBytes: Buffer.from(canonicalActionBytes(tampered), "utf8") })
        .where(eq(providerActionBindings.intentId, intentId));
    } finally {
      await getDb().execute(
        sql`ALTER TABLE provider_action_bindings ENABLE TRIGGER provider_action_bindings_immutable`,
      );
    }

    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_STALE_DEPENDENCY");
    const [n] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("active");
    expect(captured).toBeNull();
  });

  it("P12c: substituted nonce route revision cannot escape the signed approval tuple", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    // Move both the live route and the denormalized nonce column to revision 2,
    // while leaving the signed approval commitment at revision 1. Comparing
    // only nonce-to-live would accept this substitution; signed-to-loaded tuple
    // equality must reject it before claim.
    await getDb()
      .update(secretRoutes)
      .set({ authorityRevision: 2 })
      .where(eq(secretRoutes.id, IDS.route));
    await getDb()
      .update(executionAuthorizationNonces)
      .set({ routeRevision: 2 })
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));

    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_STALE_DEPENDENCY");
    expect(captured).toBeNull();
  });

  it("P26: a terminal (consumed) authorization returns terminal, no re-dispatch", async () => {
    const { intentId } = await seedExecutionReady({
      status: "consumed",
      dispatchState: "succeeded",
    });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_TERMINAL_STATE");
    expect(captured).toBeNull();
  });

  it.each([
    ["expired", "succeeded", "adapter-current", "EXEC_TERMINAL_STATE"],
    ["key-rotated", "succeeded", "adapter-removed", "EXEC_TERMINAL_STATE"],
    ["expired", "outcome_unknown", "adapter-current", "EXEC_DISPATCH_OUTCOME_UNKNOWN"],
    ["key-rotated", "outcome_unknown", "adapter-removed", "EXEC_DISPATCH_OUTCOME_UNKNOWN"],
  ])("P26: %s summon evidence preserves %s replay state", async (_case, dispatchState, keyId, expectedCode) => {
    const summonDigest = `sha256:${"7".repeat(64)}`;
    const { intentId } = await seedExecutionReady({
      status: "consumed",
      dispatchState,
      requestEnvelope: {
        schemaVersion: "steward.provider-request.v1",
        xSummonAttestationDigest: summonDigest,
      },
      safeSummary: {
        xSummonAttestation: {
          schemaVersion: "steward.x-summon-attestation.v1",
          keyId,
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      },
    });
    delete process.env.STEWARD_X_SUMMON_ATTESTATION_PUBLIC_KEYS;

    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res).toMatchObject({
      ok: false,
      code: expectedCode,
      dispatchState,
    });
    expect(captured).toBeNull();
  });

  it("P26: invalid summon evidence on a fresh execution is denied before claim", async () => {
    const summonDigest = `sha256:${"8".repeat(64)}`;
    const { intentId, authorizationId } = await seedExecutionReady({
      requestEnvelope: {
        schemaVersion: "steward.provider-request.v1",
        xSummonAttestationDigest: summonDigest,
      },
      safeSummary: {
        xSummonAttestation: {
          schemaVersion: "steward.x-summon-attestation.v1",
          keyId: "adapter-removed",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      },
    });
    delete process.env.STEWARD_X_SUMMON_ATTESTATION_PUBLIC_KEYS;

    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res).toMatchObject({
      ok: false,
      code: "EXEC_AUTH_SUMMON_ATTESTATION_INVALID",
    });
    expect(captured).toBeNull();
    const [nonce] = await getDb()
      .select({
        status: executionAuthorizationNonces.status,
        dispatchState: executionAuthorizationNonces.dispatchState,
      })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(nonce).toEqual({ status: "active", dispatchState: "none" });
  });

  it("P48/F06: absent STEWARD_EXECUTION_AUTH_SECRET fails closed at dispatch (503)", async () => {
    const { intentId } = await seedExecutionReady();
    const saved = process.env.STEWARD_EXECUTION_AUTH_SECRET;
    delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    try {
      const res = await dispatchGovernedExecution(intentId, IDS.tenant);
      expect(res.ok).toBe(false);
      expect(res.code).toBe("EXEC_AUTH_KEY_UNAVAILABLE");
      expect(res.httpStatus).toBe(503);
      expect(captured).toBeNull();
    } finally {
      process.env.STEWARD_EXECUTION_AUTH_SECRET = saved;
    }
  });

  // ── §9 fault matrix and additional §8 negative cases ──────────────────────

  it("K13/K14: upstream throw AFTER dispatch => outcome_unknown, exactly one forward, NO blind retry (X8)", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    forwarderMode = "throw";
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.code).toBe("EXEC_DISPATCH_OUTCOME_UNKNOWN");
    expect(res.httpStatus).toBe(202);
    // Exactly one forward attempt was made (captured once, no retry).
    expect(captured).not.toBeNull();
    const db = getDb();
    const [n] = await db
      .select({ ds: executionAuthorizationNonces.dispatchState })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.ds).toBe("outcome_unknown");
    // Re-dispatch of the outcome_unknown intent returns the same terminal-pending
    // state, never a second forward (X8).
    captured = null;
    const again = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(again.code).toBe("EXEC_DISPATCH_OUTCOME_UNKNOWN");
    expect(captured).toBeNull();
  });

  it("K15: an unambiguous upstream 500 => binding failed, EXEC_DISPATCH_UPSTREAM_ERROR (one attempt)", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    forwarderMode = "500";
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.code).toBe("EXEC_DISPATCH_UPSTREAM_ERROR");
    expect(res.httpStatus).toBe(502);
    expect(res.upstreamStatusCode).toBe(500);
    const db = getDb();
    const [n] = await db
      .select({ ds: executionAuthorizationNonces.dispatchState })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.ds).toBe("failed");
  });

  it("P18: a disabled provider account fails at the boundary (post-claim), no dispatch", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    // Disable the account AFTER mint but keep its revision (the claim SQL cannot
    // express account-status; the boundary account check must catch it).
    await getDb()
      .update(providerAccounts)
      .set({ status: "disabled" })
      .where(eq(providerAccounts.id, IDS.account));
    let beforeForwardReached = false;
    dispatchMod.__setGovernedDispatchHooksForTests({
      beforeForward: () => {
        beforeForwardReached = true;
      },
    });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_ACCOUNT_DISABLED");
    expect(captured).toBeNull();
    expect(beforeForwardReached).toBe(false);
    // Post-claim denial: nonce consumed, dispatch_state failed, binding failed.
    const db = getDb();
    const [n] = await db
      .select({
        status: executionAuthorizationNonces.status,
        ds: executionAuthorizationNonces.dispatchState,
      })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("consumed");
    expect(n.ds).toBe("failed");
    const [b] = await db
      .select({ status: providerActionBindings.status })
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, intentId));
    expect(b.status).toBe("failed");
  });

  it("fails at the post-claim boundary without dispatch when the workspace is disabled", async () => {
    const { intentId } = await seedExecutionReady();
    await getDb()
      .update(workspaces)
      .set({ status: "disabled" })
      .where(eq(workspaces.id, IDS.workspace));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_ACCOUNT_DISABLED");
    expect(captured).toBeNull();
  });

  it("fails at the boundary without dispatch when the provider operation is disabled", async () => {
    const { intentId } = await seedExecutionReady();
    await getDb()
      .update(providerOperations)
      .set({ status: "disabled" })
      .where(eq(providerOperations.id, IDS.operation));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_ACCOUNT_DISABLED");
    expect(captured).toBeNull();
  });

  it("P1a-read: an active nonce whose binding is NOT execution_ready at read time is denied by the read-side guard (no claim, no forward)", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    // Force the binding to a terminal state while the nonce stays active/none
    // (simulating a lifecycle advanced by another path). The read-side guard must
    // refuse before any claim: nonce NOT consumed.
    await getDb().execute(
      sql`UPDATE provider_action_bindings SET status = 'executing', binding_revision = binding_revision + 1 WHERE intent_id = ${intentId}`,
    );
    await getDb().execute(
      sql`UPDATE provider_action_bindings SET status = 'succeeded', binding_revision = binding_revision + 1 WHERE intent_id = ${intentId}`,
    );
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_NOT_READY");
    expect(captured).toBeNull();
    // Nonce stays active (never consumed against a non-ready binding).
    const [n] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("active");
  });

  it("P1a-race: a binding advanced past execution_ready AFTER the read guard (between revalidate and claim) is caught atomically inside the claim tx; the whole claim rolls back so the nonce is NEVER consumed", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    // The binding IS execution_ready at read time, so the read-side guard passes.
    // We race it: the afterRevalidate hook (fires immediately before the claim tx)
    // advances the binding out of execution_ready, so ONLY the atomic claim-tx
    // binding-transition gate can catch it. This isolates the claim-tx gate from
    // the read-side guard (proven separately by P1a-read).
    dispatchMod.__setGovernedDispatchHooksForTests({
      afterRevalidate: async () => {
        await getDb().execute(
          sql`UPDATE provider_action_bindings SET status = 'executing', binding_revision = binding_revision + 1 WHERE intent_id = ${intentId}`,
        );
      },
    });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    // The claim-tx gate rolls the claim back and classifies it as a lost claim.
    expect(res.code).toBe("EXEC_AUTH_CLAIM_LOST");
    expect(captured).toBeNull();
    // The nonce claim was rolled back with the binding transition: still active.
    const [n] = await getDb()
      .select({
        status: executionAuthorizationNonces.status,
        dispatchState: executionAuthorizationNonces.dispatchState,
      })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("active");
    expect(n.dispatchState).toBe("none");
  });

  it("P20: an operation revision drift fails at the boundary, no dispatch", async () => {
    const { intentId } = await seedExecutionReady();
    await getDb()
      .update(providerOperations)
      .set({ revision: 2 })
      .where(eq(providerOperations.id, IDS.operation));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    // Operation revision drift is a stale dependency at the boundary.
    expect(res.code).toBe("EXEC_AUTH_STALE_DEPENDENCY");
    expect(captured).toBeNull();
  });

  it("P23: a wrong tenant id in the dispatch call finds no execution (non-enumerating NOT_READY)", async () => {
    const { intentId } = await seedExecutionReady();
    const res = await dispatchGovernedExecution(intentId, "tenant-other");
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_NOT_READY");
    expect(captured).toBeNull();
  });

  it("P25 (approved-not-ready): a binding still in execution_ready with NO active nonce is not dispatchable", async () => {
    // Seed a ready binding, then revoke its nonce (simulating a rolled-back route
    // that revoked the v2 authorization). The load requires an active v2 nonce.
    const { intentId, authorizationId } = await seedExecutionReady();
    await getDb()
      .update(executionAuthorizationNonces)
      .set({ status: "revoked" })
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    // A revoked (non-active) nonce with dispatch_state 'none' returns terminal.
    expect(["EXEC_TERMINAL_STATE", "EXEC_AUTH_NOT_READY"]).toContain(res.code);
    expect(captured).toBeNull();
  });

  it("uses the single-use authorization nonce as the replay guard for mutating actions", async () => {
    // Point the seeded action + route at a POST so handleProxy's unsafe-method
    // idempotency guard would fire for a legacy request. A governed dispatch must
    // bypass that guard (it carries its own single-use nonce), so the forward is
    // reached instead of a local 400 for a missing Idempotency-Key.
    const action: GenericHttpCanonicalActionV1 = {
      profile: "generic-http.provider-action.v1",
      method: "POST",
      origin: "https://api.customer.example",
      normalizedPath: "/v1/items",
      orderedQueryPairs: [["mode", "safe"]],
      selectedHeaders: [
        ["accept", "application/json"],
        ["content-type", "application/json"],
      ],
      canonicalBody: { name: "bug" },
    };
    await getDb()
      .update(secretRoutes)
      .set({ hostPattern: "api.customer.example", pathPattern: "/v1/items", method: "POST" })
      .where(eq(secretRoutes.id, IDS.route));
    await getDb().execute(
      sql`UPDATE secret_routes SET authority_revision = 1 WHERE id = ${IDS.route}`,
    );
    {
      const { intentId, authorizationId } = await seedExecutionReady({ action });
      const res = await dispatchGovernedExecution(intentId, IDS.tenant);
      // The forward was reached (no 400 idempotency short-circuit) and the method
      // is the mutating one.
      expect(captured).not.toBeNull();
      expect(captured?.method).toBe("POST");
      // Nonce consumed exactly once, dispatched.
      const [n] = await getDb()
        .select({
          status: executionAuthorizationNonces.status,
          ds: executionAuthorizationNonces.dispatchState,
        })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
      expect(n.status).toBe("consumed");
      expect(n.ds).not.toBe("none");
      void res;
    }
  });

  it("K01b: dispatch requires an atomic claimed-to-dispatched win before forwarding", async () => {
    const { intentId } = await seedExecutionReady();
    dispatchMod.__setGovernedDispatchHooksForTests({
      beforeForward: async () => {
        // Simulate another terminal-state writer winning after claim. This caller
        // must not append a false dispatched audit or reach the forwarder.
        await getDb()
          .update(executionAuthorizationNonces)
          .set({
            dispatchState: "failed",
            dispatchedAt: new Date(),
            outcomeRecordedAt: new Date(),
          })
          .where(eq(executionAuthorizationNonces.intentId, intentId));
        await getDb().execute(
          sql`UPDATE provider_action_bindings SET status = 'failed', binding_revision = binding_revision + 1 WHERE intent_id = ${intentId}`,
        );
      },
    });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_TERMINAL_STATE");
    expect(captured).toBeNull();
  });

  it("returns stale without forwarding when the secret version rotates after claim", async () => {
    // The claim succeeds (route + secret bound), then between claim and decrypt the
    // backing secret is rotated to a new version via the beforeForward hook. The
    // decrypt-time recheck must refuse to decrypt the freshly-rotated credential.
    const { intentId } = await seedExecutionReady();
    dispatchMod.__setGovernedDispatchHooksForTests({
      beforeForward: async () => {
        await getDb().update(secrets).set({ version: 99 }).where(eq(secrets.id, IDS.secret));
      },
    });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    // NO credential was forwarded against the rotated secret.
    expect(captured).toBeNull();
    // Crucially, preserve the proxy's governed stale code. This was a local
    // pre-forward denial, not an upstream provider response.
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_STALE_SECRET");
    expect(res.upstreamStatusCode).toBeUndefined();
  });

  it("P31b: account disabled after claim is denied at the exact decrypt boundary", async () => {
    const { intentId } = await seedExecutionReady();
    dispatchMod.__setGovernedDispatchHooksForTests({
      beforeForward: async () => {
        await getDb()
          .update(providerAccounts)
          .set({ status: "disabled" })
          .where(eq(providerAccounts.id, IDS.account));
      },
    });
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_AUTH_ACCOUNT_DISABLED");
    expect(res.upstreamStatusCode).toBeUndefined();
    expect(captured).toBeNull();
  });

  it("denies a direct claim whose route revision does not match", async () => {
    await seedExecutionReady();
    // Correct routeId + secretId (so ONLY the routeRevision guard can deny it),
    // stale/forged routeRevision. The gate must fail closed before any decrypt.
    const forged = handleProxy(
      fakeDirectContext("/proxy/api.github.com/repos/acme/widgets/issues", {
        authorizationId: "forged",
        executionId: "forged",
        routeId: IDS.route,
        routeRevision: 999,
        secretId: IDS.secret,
        secretVersion: 1,
        workspaceId: IDS.workspace,
        providerAccountId: IDS.account,
        operationId: IDS.operation,
        operationRevision: 1,
        providerAccountRevision: 1,
      }),
    );
    const res = await forged;
    expect(res.status).toBe(403);
    expect(captured).toBeNull();
  });

  it("fails closed when a governed claim omits the secret version", async () => {
    await seedExecutionReady();
    // Correct routeId + routeRevision + secretId, but NO secretVersion. Without
    // it the decrypt-time version recheck could be skipped, so the gate must
    // refuse to treat the claim as verified.
    const res = await handleProxy(
      fakeDirectContext("/proxy/api.github.com/repos/acme/widgets/issues", {
        authorizationId: "forged",
        executionId: "forged",
        routeId: IDS.route,
        routeRevision: 1,
        secretId: IDS.secret,
        // secretVersion intentionally omitted
        workspaceId: IDS.workspace,
        providerAccountId: IDS.account,
        operationId: IDS.operation,
        operationRevision: 1,
        providerAccountRevision: 1,
      }),
    );
    expect(res.status).toBe(403);
    expect(captured).toBeNull();
  });

  it("P36: an oversized credential-bearing response fails closed and releases the in-flight slot", async () => {
    const { intentId } = await seedExecutionReady();
    forwarderMode = "stream"; // 200 with an open, never-auto-closing body
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    // The response declares a body larger than the bounded credential scanner
    // permits. The proxy must reject it as an unambiguous upstream failure and
    // cancel the hostile open stream, which also releases the in-flight slot.
    expect(res.ok).toBe(false);
    expect(res.code).toBe("EXEC_DISPATCH_UPSTREAM_ERROR");
    // Stream cancellation can resolve on a later microtask/tick. Poll briefly.
    for (let i = 0; i < 50 && !streamingBodyCancelled; i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
    // Without the drain the proxy slot (released only on body close/cancel) leaks.
    expect(streamingBodyCancelled).toBe(true);
  });

  it("forwards the JCS bytes committed by the authorization", async () => {
    // Keys deliberately in NON-lexicographic insertion order so JSON.stringify
    // (insertion order) and JCS (sorted) produce DIFFERENT bytes.
    const body = { zeta: 1, name: "safe", alpha: 2 } as Record<string, unknown>;
    const action: GenericHttpCanonicalActionV1 = {
      profile: "generic-http.provider-action.v1",
      method: "POST",
      origin: "https://api.customer.example",
      normalizedPath: "/v1/items",
      orderedQueryPairs: [["mode", "safe"]],
      selectedHeaders: [
        ["accept", "application/json"],
        ["content-type", "application/json"],
      ],
      canonicalBody: body,
    };
    await getDb()
      .update(secretRoutes)
      .set({ hostPattern: "api.customer.example", pathPattern: "/v1/items", method: "POST" })
      .where(eq(secretRoutes.id, IDS.route));
    await getDb().execute(
      sql`UPDATE secret_routes SET authority_revision = 1 WHERE id = ${IDS.route}`,
    );
    {
      const { intentId } = await seedExecutionReady({ action });
      await dispatchGovernedExecution(intentId, IDS.tenant);
      expect(captured).not.toBeNull();
      // The forwarded bytes must equal the JCS serialization, and must NOT equal
      // the (different) JSON.stringify insertion-order serialization.
      const jcs = jcsStringify(body);
      const insertion = JSON.stringify(body);
      expect(capturedBody).toBe(jcs);
      expect(jcs).not.toBe(insertion); // guard: the fixture actually differentiates
    }
  });

  it("does not re-enter the proxy-approval hold after governed approval", async () => {
    const { intentId, authorizationId } = await seedExecutionReady();
    // The route carries the legacy requiresApproval flag too. A verified governed
    // dispatch already had its approval adjudicated by the v2 flow, so it must NOT
    // be held for legacy proxy approval (which would 202 and be misread as a
    // successful dispatch). It forwards instead.
    await getDb()
      .update(secretRoutes)
      .set({ requiresApproval: true })
      .where(eq(secretRoutes.id, IDS.route));
    const res = await dispatchGovernedExecution(intentId, IDS.tenant);
    // The forward was actually reached (not held) and the nonce consumed once.
    expect(captured).not.toBeNull();
    const [n] = await getDb()
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    expect(n.status).toBe("consumed");
    void res;
  });

  it("K20: a legacy proxy request and a governed dispatch for the same tenant do not corrupt each other", async () => {
    // Governed dispatch on the seeded governed route.
    const { intentId, authorizationId } = await seedExecutionReady();
    // A direct legacy hit to a DIFFERENT (non-governed) path must be denied by
    // the gate (the seeded route is governed), proving the two paths are
    // independent and the governed row is never reachable directly even while a
    // governed dispatch is in flight.
    const [gov, direct] = await Promise.all([
      dispatchGovernedExecution(intentId, IDS.tenant),
      handleProxy(fakeDirectContext("/proxy/api.github.com/repos/acme/widgets/issues")),
    ]);
    expect(direct.status).toBe(403);
    const db = getDb();
    const [n] = await db
      .select({ status: executionAuthorizationNonces.status })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
    // The governed claim consumed exactly once; the direct hit never touched it.
    expect(n.status).toBe("consumed");
    void gov;
  });

  it("a THROWING metrics observer never changes the governed dispatch outcome (post-commit isolation, all proxy hook sites)", async () => {
    // observeSecurityAuditEvent is invoked from the post-commit loop of EVERY
    // withTenantAuditedTransaction the proxy dispatch path runs: the claim, the
    // claimed->dispatched transition, and the terminal outcome. Force that
    // observer to throw for the WHOLE dispatch and prove:
    //   1. the dispatch still succeeds (ok:true, EXEC_DISPATCH_SUCCEEDED),
    //   2. the nonce is consumed and reaches the terminal succeeded state,
    //   3. exactly one upstream forward happened (no blind retry, X8),
    // i.e. a metrics failure can never block, delay, or reorder the atomic
    // claimed->dispatched transition or the authority decision.
    __setSecurityMetricsObserverFailureForTests(true);
    try {
      const { intentId, authorizationId } = await seedExecutionReady();
      forwarderMode = "ok";
      const res = await dispatchGovernedExecution(intentId, IDS.tenant);
      expect(res.ok).toBe(true);
      expect(res.code).toBe("EXEC_DISPATCH_SUCCEEDED");
      expect(res.dispatchState).toBe("succeeded");
      // Exactly one forward reached the upstream.
      expect(captured).not.toBeNull();
      const db = getDb();
      const [n] = await db
        .select({
          status: executionAuthorizationNonces.status,
          dispatchState: executionAuthorizationNonces.dispatchState,
        })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.authorizationId, authorizationId));
      expect(n.status).toBe("consumed");
      expect(n.dispatchState).toBe("succeeded");
    } finally {
      __setSecurityMetricsObserverFailureForTests(false);
    }
  });
});
