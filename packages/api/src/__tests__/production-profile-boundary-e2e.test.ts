/**
 * Registry-wide production boundary proof.
 *
 * Each profile enters through the authenticated public agent route, is reloaded
 * from the database, approved and resumed through the authenticated human
 * routes, assembled as provider-case evidence, and finally parsed by the exact
 * governed proxy pre-claim parser.  This deliberately complements the pure
 * builder conformance tests: no synthetic approval/evidence labels stand in for
 * a production boundary here.
 */
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:http";
import { signAccessToken } from "@stwd/auth";
import {
  closeDb,
  getDb,
  providerAccounts,
  providerActionBindings,
  providerGrants,
  providerOperations,
  proxyAuditLog,
  secretRoutes,
  secrets,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  AWS_PROVIDER_ACTION_PROFILE,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  GITHUB_PROVIDER_ACTION_PROFILE,
  GOOGLE_PROVIDER_ACTION_PROFILE,
  REGISTERED_PROFILES,
  SLACK_PROVIDER_ACTION_PROFILE,
  X_PROVIDER_ACTION_PROFILE,
} from "@stwd/shared";
import { KeyStore } from "@stwd/vault";
import { and, eq, sql } from "drizzle-orm";
import type { Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

const KID = "production-profile-boundary-kid";
setDefaultTimeout(120_000);

type ApprovalFixture = typeof import("./provider-approval-fixture");
type CaseFixture = typeof import("./provider-case-fixture");
let F: ApprovalFixture["F"];
let seedFixture: ApprovalFixture["seedFixture"];
let wipeCase: CaseFixture["wipeCase"];
let app: Hono<{ Variables: AppVariables }>;
let jwksServer: Server;
let agentPrivateKey: KeyLike;
let dispatchGovernedExecution: typeof import("@stwd/proxy/src/handlers/governed-execution")["dispatchGovernedExecution"];
let proxy: typeof import("@stwd/proxy/src/handlers/proxy");
let forwardCount = 0;

const PROFILES = [
  {
    profile: GITHUB_PROVIDER_ACTION_PROFILE,
    adapterKey: "github",
    operationKey: "github.pr.comment.create",
    host: "api.github.com",
    method: "POST",
    path: "/repos/octo/hello/issues/42/comments",
    args: { owner: "octo", repo: "hello", pullNumber: 42, body: "boundary proof" },
    requestProfile: {},
  },
  {
    profile: X_PROVIDER_ACTION_PROFILE,
    adapterKey: "x",
    operationKey: "x.tweet.create",
    host: "api.x.com",
    method: "POST",
    path: "/2/tweets",
    args: { text: "boundary proof", summoned: false },
    requestProfile: {},
  },
  {
    profile: SLACK_PROVIDER_ACTION_PROFILE,
    adapterKey: "slack",
    operationKey: "slack.chat.postMessage",
    host: "slack.com",
    method: "POST",
    path: "/api/chat.postMessage",
    args: { channel: "C12345678", text: "boundary proof" },
    requestProfile: {},
  },
  {
    profile: GOOGLE_PROVIDER_ACTION_PROFILE,
    adapterKey: "google",
    operationKey: "google.calendar.events.list",
    host: "www.googleapis.com",
    method: "GET",
    path: "/calendar/v3/calendars/primary/events",
    args: { maxResults: 50 },
    requestProfile: {},
  },
  {
    // AWS resolves its one permitted origin dynamically from the canonical
    // action bytes (registry dynamicOriginPolicy "aws-ec2-region"), so the
    // host below MUST equal `ec2.${args.region}.amazonaws.com` and the route
    // must carry the exact SigV4 binding (see the credential/route
    // special-cases in runAuthenticatedBoundary).
    profile: AWS_PROVIDER_ACTION_PROFILE,
    adapterKey: "aws",
    operationKey: "aws.ec2.DescribeInstances",
    host: "ec2.us-west-2.amazonaws.com",
    method: "POST",
    path: "/",
    args: { region: "us-west-2", instanceIds: ["i-0123456789abcdef0"] },
    requestProfile: {},
  },
  {
    profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
    adapterKey: "generic-http",
    operationKey: "generic.ticket.create",
    host: "api.example.com",
    method: "POST",
    path: "/v1/tickets",
    args: { title: "boundary proof" },
    requestProfile: {
      profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
      operationDescriptor: {
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        origin: "https://api.example.com",
        methods: ["POST"],
        pathTemplate: [{ literal: "v1" }, { literal: "tickets" }],
        body: {
          contentType: "application/json",
          fields: [{ name: "title", type: "string", pattern: "^.{1,200}$", maxBytes: 4096 }],
        },
        projection: { policyArgs: [], safeSummary: ["title"] },
      },
    },
  },
] as const;

function approvalRules(operationKey: string) {
  return [
    {
      id: "11111111-1111-4111-8111-111111111111",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [operationKey], effect: "allow" },
    },
    {
      id: "22222222-2222-4222-8222-222222222222",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [operationKey], effect: "require-approval" },
    },
  ];
}

async function sessionToken(userId = F.APPROVER): Promise<string> {
  return signAccessToken(
    {
      address: "0xprofile",
      tenantId: F.TENANT,
      userId,
      mfaVerifiedAt: Date.now(),
    } as never,
    "10m",
  );
}

async function agentToken(): Promise<string> {
  return new SignJWT({ agent_id: F.AGENT, scopes: [], tenant_id: F.TENANT })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setSubject(`agent:${F.AGENT}`)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(agentPrivateKey);
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_AUDIT_HMAC_KEY = "0".repeat(64);
  process.env.STEWARD_EXECUTION_AUTH_SECRET = "1".repeat(64);
  process.env.STEWARD_MASTER_PASSWORD = "profile-boundary-master-password";
  process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS =
    "api.github.com,api.x.com,slack.com,www.googleapis.com,api.example.com,ec2.us-west-2.amazonaws.com";
  process.env.STEWARD_PROXY_ALLOWED_HOSTS =
    "api.github.com,api.x.com,slack.com,www.googleapis.com,api.example.com,ec2.us-west-2.amazonaws.com";
  process.env.STEWARD_JWT_SECRET = "profile-boundary-jwt-secret-0123456789abcdef0123456789";
  const signingKeys = generateKeyPairSync("ed25519");
  process.env.STEWARD_AUDIT_SIGNING_KEY = signingKeys.privateKey
    .export({ format: "pem", type: "pkcs8" })
    .toString();

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  ({ F, seedFixture } = await import("./provider-approval-fixture"));
  ({ wipeCase } = await import("./provider-case-fixture"));

  const kp = await generateKeyPair("RS256");
  agentPrivateKey = kp.privateKey;
  const jwk = await exportJWK(kp.publicKey);
  const jwks = JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }] });
  jwksServer = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(jwks);
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, resolve));
  const address = jwksServer.address();
  const port = typeof address === "object" && address ? address.port : 0;
  process.env.ELIZA_CLOUD_JWKS_URL = `http://127.0.0.1:${port}/jwks`;
  process.env.GOOGLE_PROVIDER_CLIENT_ID = "boundary-google-client";
  process.env.GOOGLE_PROVIDER_CLIENT_SECRET = "boundary-google-secret";
  const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
  clearAgentJwksCacheForTests();
  const { resetCheckpointSignerCache } = await import("../services/audit-checkpoint");
  resetCheckpointSignerCache();
  app = (await import("../app")).app as Hono<{ Variables: AppVariables }>;
  proxy = await import("@stwd/proxy/src/handlers/proxy");
  proxy.__resetSecretVaultForTests();
  ({ dispatchGovernedExecution } = await import("@stwd/proxy/src/handlers/governed-execution"));
  proxy.__setCheckProxyRateLimitForTests(async () => ({
    allowed: true,
    remaining: Number.POSITIVE_INFINITY,
    resetMs: 0,
  }));
  proxy.__setCheckProxySpendLimitForTests(async () => ({
    allowed: true,
    configured: false,
    spent: 0,
    remaining: Number.POSITIVE_INFINITY,
  }));
  proxy.__setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  // The boundary proof is about canonical provider authority and exact
  // credential injection, not Redis availability. Make the rate-limit seam
  // deterministic so an unrelated process-local fallback cannot turn every
  // dispatch into a 429 when this file runs in a larger suite.
  proxy.__setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
  proxy.__setForwardProxyRequestForTests(async () => {
    forwardCount += 1;
    return new Response('{"ok":true}', { status: 201 });
  });
  resetGoogleExecutionTokenForwarder();
});

beforeEach(async () => {
  forwardCount = 0;
  await seedFixture();
});

afterEach(async () => {
  resetGoogleExecutionTokenForwarder();
  await getDb()
    .update(secretRoutes)
    .set({ authorityMode: "legacy", providerOperationId: null })
    .where(eq(secretRoutes.tenantId, F.TENANT));
  await wipeCase();
});

afterAll(async () => {
  await closeDb();
  await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
  for (const key of [
    "STEWARD_PGLITE_MEMORY",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_EXECUTION_AUTH_SECRET",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_SECRET_ROUTE_ALLOWED_HOSTS",
    "STEWARD_PROXY_ALLOWED_HOSTS",
    "STEWARD_JWT_SECRET",
    "STEWARD_AUDIT_SIGNING_KEY",
    "ELIZA_CLOUD_JWKS_URL",
    "GOOGLE_PROVIDER_CLIENT_ID",
    "GOOGLE_PROVIDER_CLIENT_SECRET",
  ]) {
    delete process.env[key];
  }
});

type BoundaryFixture = (typeof PROFILES)[number];

function resetGoogleExecutionTokenForwarder(): void {
  proxy.__setGoogleExecutionTokenForwarderForTests(async () =>
    Response.json({
      access_token: "profile-boundary-ephemeral-access",
      token_type: "Bearer",
      scope: "openid email https://www.googleapis.com/auth/calendar.readonly",
      expires_in: 3600,
    }),
  );
}

async function prepareAuthenticatedBoundary(
  fixture: BoundaryFixture,
  options: { maliciousOperationDescriptor?: boolean } = {},
): Promise<{ actionId: string }> {
  const requestProfile = {
    ...fixture.requestProfile,
    policyRules: approvalRules(fixture.operationKey),
  };
  const db = getDb();
  const vault = new KeyStore(
    process.env.STEWARD_MASTER_PASSWORD as string,
    undefined,
    "secret-vault",
  );
  const credential =
    fixture.profile === SLACK_PROVIDER_ACTION_PROFILE
      ? "xoxb-profile-boundary-credential"
      : fixture.profile === GOOGLE_PROVIDER_ACTION_PROFILE
        ? JSON.stringify({
            schemaVersion: "steward.provider-google.credential.v1",
            accessToken: "profile-boundary-stale-access",
            refreshToken: "profile-boundary-refresh",
            scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/calendar.readonly"],
          })
        : fixture.profile === AWS_PROVIDER_ACTION_PROFILE
          ? // Strict SigV4 credential schema (packages/proxy/src/sigv4.ts):
            // accessKeyId is /^[A-Z0-9]{16,128}$/, secretAccessKey 16..256
            // printable chars, optional sessionToken. No other keys allowed.
            JSON.stringify({
              accessKeyId: "AKIAPROFILEBOUNDARY0",
              secretAccessKey: "profile-boundary-aws-secret-key",
            })
          : "profile-boundary-credential";
  const encrypted = vault.encrypt(credential, {
    tenantId: F.TENANT,
    name: "github",
    version: 1,
  });
  await db
    .update(secrets)
    .set({
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.tag,
      salt: encrypted.salt,
    })
    .where(and(eq(secrets.tenantId, F.TENANT), eq(secrets.id, F.SECRET)));
  await db
    .update(providerAccounts)
    .set({ adapterKey: fixture.adapterKey })
    .where(and(eq(providerAccounts.tenantId, F.TENANT), eq(providerAccounts.id, F.ACCOUNT)));
  await db
    .update(providerOperations)
    .set({ operationKey: fixture.operationKey, requestProfile })
    .where(and(eq(providerOperations.tenantId, F.TENANT), eq(providerOperations.id, F.OP)));
  await db
    .update(providerGrants)
    .set({ operationKeys: [fixture.operationKey] })
    .where(and(eq(providerGrants.tenantId, F.TENANT), eq(providerGrants.id, F.GRANT)));
  await db
    .update(secretRoutes)
    .set({
      hostPattern: fixture.host,
      pathPattern: fixture.path,
      method: fixture.method,
      agentId: F.AGENT,
      authorityMode: "governed_v2",
      providerOperationId: F.OP,
      // The AWS profile dispatches through the SigV4 final-boundary signer,
      // which requires the route's exact sigv4 binding (service ec2 + the
      // region the fixture host commits to). Both assertAwsCredentialRouteBinding
      // (ingress) and injectAwsSigV4AtFinalBoundary (dispatch) fail closed
      // without it. Other profiles keep the seeded header-injection strategy.
      injectionStrategy: fixture.profile === AWS_PROVIDER_ACTION_PROFILE ? "sigv4" : "header",
      injectionConfig:
        fixture.profile === AWS_PROVIDER_ACTION_PROFILE
          ? { service: "ec2", region: "us-west-2" }
          : {},
    })
    .where(and(eq(secretRoutes.tenantId, F.TENANT), eq(secretRoutes.id, F.ROUTE)));

  const actionResponse = await app.request("/v2/provider-actions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${await agentToken()}`,
      "content-type": "application/json",
      "x-steward-tenant": F.TENANT,
    },
    body: JSON.stringify({
      workspaceId: F.WORKSPACE,
      providerAccountId: F.ACCOUNT,
      operationKey: fixture.operationKey,
      ...(fixture.profile === GENERIC_HTTP_PROVIDER_ACTION_PROFILE
        ? { method: fixture.method }
        : {}),
      arguments: fixture.args,
      idempotencyKey: `profile-boundary-${fixture.adapterKey}-${options.maliciousOperationDescriptor ? "malicious" : "valid"}`,
    }),
  });
  if (actionResponse.status !== 202) {
    throw new Error(
      `${fixture.profile} ingress returned ${actionResponse.status}: ${await actionResponse.text()}`,
    );
  }
  const action = (await actionResponse.json()) as {
    id: string;
    requestHash: string;
    actionDigest: string;
  };

  const [persisted] = await db
    .select({
      canonicalProfile: providerActionBindings.canonicalProfile,
      canonicalActionBytes: providerActionBindings.canonicalActionBytes,
    })
    .from(providerActionBindings)
    .where(
      and(
        eq(providerActionBindings.tenantId, F.TENANT),
        eq(providerActionBindings.intentId, action.id),
      ),
    );
  expect(persisted?.canonicalProfile).toBe(fixture.profile);
  expect(new TextDecoder().decode(persisted.canonicalActionBytes)).toContain(fixture.profile);

  const approver = await sessionToken();
  const approvalResponse = await app.request(`/v2/provider-actions/${action.id}/approval`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${approver}`,
      "content-type": "application/json",
      "x-steward-tenant": F.TENANT,
    },
    body: JSON.stringify({
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: action.requestHash,
      expectedActionDigest: action.actionDigest,
      idempotencyKey: `profile-approve-${fixture.adapterKey}-${options.maliciousOperationDescriptor ? "malicious" : "valid"}`,
    }),
  });
  expect(approvalResponse.status).toBe(200);
  const executeResponse = await app.request(`/v2/provider-actions/${action.id}/execute`, {
    method: "POST",
    headers: { authorization: `Bearer ${approver}`, "x-steward-tenant": F.TENANT },
  });
  expect(executeResponse.status).toBe(200);
  expect(await executeResponse.json()).toMatchObject({ status: "execution_ready" });

  if (options.maliciousOperationDescriptor) {
    expect(fixture.profile).toBe(GENERIC_HTTP_PROVIDER_ACTION_PROFILE);
    // Model a malicious registered-operation snapshot without weakening the
    // append-only action binding. Keep the approved revision number so the real
    // loader must parse the immutable approved action against the hostile live
    // descriptor, rather than short-circuiting on revision drift.
    await db
      .update(providerOperations)
      .set({
        requestProfile: {
          ...requestProfile,
          operationDescriptor: {
            ...(requestProfile.operationDescriptor as Record<string, unknown>),
            origin: "https://attacker.example",
          },
        },
      })
      .where(eq(providerOperations.id, F.OP));
    await db.execute(sql`UPDATE provider_operations SET revision = 1 WHERE id = ${F.OP}`);
  }

  return { actionId: action.id };
}

async function runAuthenticatedBoundary(
  fixture: BoundaryFixture,
  options: { maliciousOperationDescriptor?: boolean } = {},
): Promise<void> {
  const { actionId } = await prepareAuthenticatedBoundary(fixture, options);

  const dispatch = await dispatchGovernedExecution(actionId, F.TENANT);
  if (options.maliciousOperationDescriptor) {
    expect(dispatch).toMatchObject({
      ok: false,
      code: "EXEC_AUTH_STALE_DEPENDENCY",
      httpStatus: 409,
    });
    expect(forwardCount).toBe(0);
  } else {
    expect(dispatch).toMatchObject({ ok: true, dispatchState: "succeeded" });
    expect(forwardCount).toBe(1);
  }

  const admin = await sessionToken(F.APPROVER_2);
  const humanHeaders = { authorization: `Bearer ${admin}`, "x-steward-tenant": F.TENANT };
  const caseResponse = await app.request(`/v2/provider-actions/${actionId}/case`, {
    headers: humanHeaders,
  });
  expect(caseResponse.status).toBe(200);
  expect(await caseResponse.json()).toMatchObject({
    caseId: actionId,
    operation: { key: fixture.operationKey, canonicalProfile: fixture.profile },
    terminalState: options.maliciousOperationDescriptor ? "execution_ready" : "succeeded",
  });
  const evidenceResponse = await app.request(`/v2/provider-actions/${actionId}/evidence`, {
    headers: humanHeaders,
  });
  expect(evidenceResponse.status).toBe(200);
  const evidence = (await evidenceResponse.json()) as {
    manifest: { caseId: string; operation: { canonicalProfile: string } };
    bundle: { events: unknown[] };
  };
  expect(evidence.manifest).toMatchObject({
    caseId: actionId,
    operation: { canonicalProfile: fixture.profile },
  });
  expect(evidence.bundle.events.length).toBeGreaterThan(0);
}

describe("#220 real production profile boundaries", () => {
  test("the live runner covers exactly every registered profile", () => {
    expect(PROFILES.map(({ profile }) => profile).sort()).toEqual([...REGISTERED_PROFILES].sort());
  });

  for (const fixture of PROFILES) {
    test(`${fixture.profile}: identical authenticated ingress→dispatch→evidence runner`, async () => {
      await runAuthenticatedBoundary(fixture);
    });
  }

  test("the identical authenticated runner rejects a malicious registered fixture pre-claim", async () => {
    const genericFixture = PROFILES.find(
      ({ profile }) => profile === GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
    );
    expect(genericFixture).toBeDefined();
    if (!genericFixture) throw new Error("generic HTTP production fixture is missing");
    await runAuthenticatedBoundary(genericFixture, { maliciousOperationDescriptor: true });
  });

  test("google governed dispatch redacts thrown execution-token canaries from logs, response, and audit", async () => {
    const googleFixture = PROFILES.find(
      ({ profile }) => profile === GOOGLE_PROVIDER_ACTION_PROFILE,
    );
    expect(googleFixture).toBeDefined();
    if (!googleFixture) throw new Error("google production fixture is missing");
    const canary = "profile-boundary-refresh-canary profile-boundary-error-canary";
    const logged: string[] = [];
    const originalError = console.error;
    console.error = (...args: unknown[]) => {
      logged.push(
        args.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join(" "),
      );
    };
    proxy.__setGoogleExecutionTokenForwarderForTests(async () => {
      const error = Object.assign(new Error(canary), { name: canary, code: canary });
      throw error;
    });
    try {
      const { actionId } = await prepareAuthenticatedBoundary(googleFixture);
      const dispatch = await dispatchGovernedExecution(actionId, F.TENANT);
      expect(dispatch).toMatchObject({ ok: false });
      expect(JSON.stringify(dispatch)).not.toContain(canary);
      expect(forwardCount).toBe(0);
    } finally {
      console.error = originalError;
      resetGoogleExecutionTokenForwarder();
    }
    const audits = await getDb()
      .select()
      .from(proxyAuditLog)
      .where(eq(proxyAuditLog.tenantId, F.TENANT));
    expect(audits.some((audit) => audit.reason === "credential-resolution-failed")).toBeTrue();
    expect(JSON.stringify(audits)).not.toContain(canary);
    expect(logged.join("\n")).toContain('"errorClass":"Error"');
    expect(logged.join("\n")).toContain('"errorCode":null');
    expect(logged.join("\n")).not.toContain(canary);
    expect(logged.join("\n")).not.toContain("profile-boundary-name-canary");
  });
});
