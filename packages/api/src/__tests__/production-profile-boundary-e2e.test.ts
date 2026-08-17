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
  secretRoutes,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { parseGovernedCanonicalActionForDispatch } from "@stwd/proxy/src/handlers/governed-execution";
import {
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  GITHUB_PROVIDER_ACTION_PROFILE,
  jcsStringify,
  REGISTERED_PROFILES,
  X_PROVIDER_ACTION_PROFILE,
} from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";
import { getProviderCase, getProviderCaseEvidence } from "../services/provider-case";

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

async function sessionToken(): Promise<string> {
  return signAccessToken(
    {
      address: "0xprofile",
      tenantId: F.TENANT,
      userId: F.APPROVER,
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
  process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS = "api.github.com,api.x.com,api.example.com";
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.github.com,api.x.com,api.example.com";
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
  const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
  clearAgentJwksCacheForTests();
  const { resetCheckpointSignerCache } = await import("../services/audit-checkpoint");
  resetCheckpointSignerCache();
  app = (await import("../app")).app as Hono<{ Variables: AppVariables }>;
});

beforeEach(async () => {
  await seedFixture();
});

afterEach(async () => {
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
  ]) {
    delete process.env[key];
  }
});

describe("#220 real production profile boundaries", () => {
  test("the live runner covers exactly every registered profile", () => {
    expect(PROFILES.map(({ profile }) => profile).sort()).toEqual([...REGISTERED_PROFILES].sort());
  });

  for (const fixture of PROFILES) {
    test(`${fixture.profile}: authenticated ingress persists, approval reconstructs, evidence assembles, proxy parses`, async () => {
      const requestProfile = {
        ...fixture.requestProfile,
        policyRules: approvalRules(fixture.operationKey),
      };
      const db = getDb();
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
          idempotencyKey: `profile-boundary-${fixture.adapterKey}`,
        }),
      });
      expect(actionResponse.status).toBe(202);
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
      const operationContext = {
        operationKey: fixture.operationKey,
        requestProfile,
      };
      const parsed = parseGovernedCanonicalActionForDispatch(
        new Uint8Array(persisted.canonicalActionBytes),
        fixture.profile,
        [`https://${fixture.host}`],
        operationContext,
      );
      expect(parsed).toMatchObject({
        profile: fixture.profile,
        origin: `https://${fixture.host}`,
        method: fixture.method,
        normalizedPath: fixture.path,
      });

      const human = await sessionToken();
      const approvalResponse = await app.request(`/v2/provider-actions/${action.id}/approval`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human}`,
          "content-type": "application/json",
          "x-steward-tenant": F.TENANT,
        },
        body: JSON.stringify({
          decision: "approve",
          expectedVersion: 1,
          expectedRequestHash: action.requestHash,
          expectedActionDigest: action.actionDigest,
          idempotencyKey: `profile-approve-${fixture.adapterKey}`,
        }),
      });
      expect(approvalResponse.status).toBe(200);
      const executeResponse = await app.request(`/v2/provider-actions/${action.id}/execute`, {
        method: "POST",
        headers: { authorization: `Bearer ${human}`, "x-steward-tenant": F.TENANT },
      });
      expect(executeResponse.status).toBe(200);
      expect(await executeResponse.json()).toMatchObject({ status: "execution_ready" });

      const kase = await getProviderCase(F.TENANT, action.id, [F.WORKSPACE]);
      expect(kase?.manifest).toMatchObject({
        caseId: action.id,
        operation: { key: fixture.operationKey, canonicalProfile: fixture.profile },
        terminalState: "execution_ready",
      });
      const evidence = await getProviderCaseEvidence(F.TENANT, action.id, [F.WORKSPACE]);
      expect(evidence?.manifest).toMatchObject({
        caseId: kase?.manifest.caseId,
        actionDigest: kase?.manifest.actionDigest,
        requestHash: kase?.manifest.requestHash,
        operation: kase?.manifest.operation,
        terminalState: kase?.manifest.terminalState,
      });
      expect(evidence?.bundle.events.length).toBeGreaterThan(0);
      expect(jcsStringify(parsed)).toBe(new TextDecoder().decode(persisted.canonicalActionBytes));
    });
  }
});
