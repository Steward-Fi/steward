/**
 * Real-Postgres proof for the provider-action creation advisory-lock replay path.
 * PGLite cannot exercise pg_advisory_xact_lock or separate pooled connections.
 */

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  approvalQueue,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { buildXAction } from "@stwd/provider-x";
import {
  computeXSummonAttestationDigest,
  type XSummonAttestationV1,
  xSummonAttestationSignatureInput,
} from "@stwd/shared";
import { eq } from "drizzle-orm";
import {
  __setProviderCreateAfterOptimisticReplayLookupForTests,
  providerActionService,
} from "../services/provider-action-service";
import { F, principal, seedFixture } from "./provider-approval-fixture";

setDefaultTimeout(120_000);

const SKIP = !process.env.DATABASE_URL;
const OPERATION_KEY = "x.tweet.create";
const SOURCE_POST_ID = "1750000000000000000";
const RETRY_SEED = "summon-race-retry";
const SUMMON_KEY_ID = "summon-race-postgres";
const summonKeyPair = generateKeyPairSync("ed25519");
const summonPublicRaw = summonKeyPair.publicKey
  .export({ format: "der", type: "spki" })
  .subarray(-32);

function idempotencyKeyHash(): string {
  return `sha256:${Buffer.from(RETRY_SEED.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

function signedAttestation(offsetMs: number): XSummonAttestationV1 {
  const now = Date.now();
  const attestation: XSummonAttestationV1 = {
    schemaVersion: "steward.x-summon-attestation.v1",
    keyId: SUMMON_KEY_ID,
    audience: "steward-postgres-race",
    tenantId: F.TENANT,
    workspaceId: F.WORKSPACE,
    actorAgentId: F.AGENT,
    providerAccountId: F.ACCOUNT,
    operationKey: OPERATION_KEY,
    sourcePostId: SOURCE_POST_ID,
    idempotencyKeyHash: idempotencyKeyHash(),
    summoned: true,
    attestedAt: new Date(now - 1_000 + offsetMs).toISOString(),
    expiresAt: new Date(now + 299_000 + offsetMs).toISOString(),
    signature: "A".repeat(86),
  };
  attestation.signature = sign(
    null,
    Buffer.from(xSummonAttestationSignatureInput(attestation), "utf8"),
    summonKeyPair.privateKey,
  ).toString("base64url");
  return attestation;
}

async function wipe() {
  const db = getDb();
  await db.delete(providerActionAuditOutbox);
  await db.delete(approvalQueue);
  await db.delete(providerActionBindings);
  await db.delete(intents);
  await db.delete(providerGrants);
  await db.delete(providerRoleBindings);
  await db.delete(providerOperations);
  await db.delete(providerAccounts);
  await db.delete(secretRoutes);
  await db.delete(secrets);
  await db.delete(workspaces);
  await db.delete(userTenants);
  await db.delete(users);
  await db.delete(tenants);
}

async function seedXFixture() {
  await seedFixture();
  const db = getDb();
  await db
    .update(providerAccounts)
    .set({ adapterKey: "x", externalRef: "9999", displayName: "@summon-race" })
    .where(eq(providerAccounts.id, F.ACCOUNT));
  await db
    .update(providerOperations)
    .set({
      operationKey: OPERATION_KEY,
      riskClass: "write",
      requestProfile: {
        policyRules: [
          {
            id: "11111111-1111-4111-8111-1111111111b2",
            type: "capability-intent",
            enabled: true,
            config: {
              capabilities: [OPERATION_KEY],
              effect: "allow",
              constraints: { x: { replyPolicy: { mode: "summoned-only" } } },
            },
          },
        ],
      },
    })
    .where(eq(providerOperations.id, F.OP));
  await db
    .update(providerGrants)
    .set({ operationKeys: [OPERATION_KEY] })
    .where(eq(providerGrants.id, F.GRANT));
}

async function propose(attestation: XSummonAttestationV1) {
  const now = new Date();
  return providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: F.WORKSPACE,
    providerAccountId: F.ACCOUNT,
    operationKey: OPERATION_KEY,
    build: buildXAction(OPERATION_KEY as never, {
      text: "same canonical reply",
      replyToTweetId: SOURCE_POST_ID,
      summoned: true,
    }),
    idempotencyKeyHash: idempotencyKeyHash(),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: RETRY_SEED.padEnd(32, "N").slice(0, 32),
    requestId: null,
    summonAttestation: attestation,
  });
}

describe.skipIf(SKIP)("X summon replay race (real Postgres)", () => {
  beforeAll(() => {
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    process.env.STEWARD_X_SUMMON_ATTESTATION_PUBLIC_KEYS = JSON.stringify({
      [SUMMON_KEY_ID]: summonPublicRaw.toString("base64url"),
    });
    process.env.STEWARD_X_SUMMON_ATTESTATION_AUDIENCE = "steward-postgres-race";
  });

  afterAll(async () => {
    __setProviderCreateAfterOptimisticReplayLookupForTests(null);
    delete process.env.STEWARD_X_SUMMON_ATTESTATION_PUBLIC_KEYS;
    delete process.env.STEWARD_X_SUMMON_ATTESTATION_AUDIENCE;
    if (!SKIP) await wipe();
  });

  beforeEach(async () => {
    await wipe();
    await seedXFixture();
  });

  test("different valid attestations racing after the optimistic miss conflict under the advisory lock", async () => {
    const firstAttestation = signedAttestation(0);
    const secondAttestation = signedAttestation(1);
    expect(computeXSummonAttestationDigest(firstAttestation)).not.toBe(
      computeXSummonAttestationDigest(secondAttestation),
    );

    let arrivals = 0;
    let release!: () => void;
    const bothArrived = new Promise<void>((resolve) => {
      release = resolve;
    });
    __setProviderCreateAfterOptimisticReplayLookupForTests(async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await bothArrived;
    });

    let results!: Awaited<ReturnType<typeof propose>>[];
    try {
      results = await Promise.all([propose(firstAttestation), propose(secondAttestation)]);
    } finally {
      __setProviderCreateAfterOptimisticReplayLookupForTests(null);
    }

    expect(arrivals).toBe(2);
    expect(results.filter((result) => result.kind === "allowed")).toHaveLength(1);
    expect(results.filter((result) => result.kind === "replay_conflict")).toEqual([
      {
        kind: "replay_conflict",
        code: "REPLAY_IDEMPOTENCY_CONFLICT",
        httpStatus: 409,
      },
    ]);

    const [persisted] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.idempotencyKeyHash, idempotencyKeyHash()));
    expect(persisted).toBeDefined();
    expect([
      computeXSummonAttestationDigest(firstAttestation),
      computeXSummonAttestationDigest(secondAttestation),
    ]).toContain((persisted.requestEnvelope as Record<string, unknown>).xSummonAttestationDigest);
  });
});
