import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  computeXSummonAttestationDigest,
  jcsStringify,
  type XSummonAttestationV1,
  xSummonAttestationSignatureInput,
} from "@stwd/shared";
import { verifyDispatchXSummonProvenance } from "../handlers/governed-execution";

const pair = generateKeyPairSync("ed25519");
const rawPublic = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
const keysJson = JSON.stringify({ dispatch: rawPublic.toString("base64url") });
const now = new Date("2026-08-18T01:00:00.000Z");
const idempotencyKeyHash = `sha256:${"c".repeat(64)}`;
const audience = "steward-prod-us";

function signed(): XSummonAttestationV1 {
  const a: XSummonAttestationV1 = {
    schemaVersion: "steward.x-summon-attestation.v1",
    keyId: "dispatch",
    audience,
    tenantId: "tenant-a",
    workspaceId: "22000000-0000-4000-8000-000000000001",
    actorAgentId: "agent-a",
    providerAccountId: "32000000-0000-4000-8000-000000000001",
    operationKey: "x.tweet.create",
    sourcePostId: "1900000000000000000",
    idempotencyKeyHash,
    summoned: true,
    attestedAt: "2026-08-18T00:59:00.000Z",
    expiresAt: "2026-08-18T01:04:00.000Z",
    signature: "A".repeat(86),
  };
  a.signature = sign(
    null,
    Buffer.from(xSummonAttestationSignatureInput(a), "utf8"),
    pair.privateKey,
  ).toString("base64url");
  return a;
}

function fixture() {
  const attestation = signed();
  const requestEnvelope = {
    schemaVersion: "steward.provider-request.v1",
    tenantId: "tenant-a",
    workspaceId: "22000000-0000-4000-8000-000000000001",
    actorAgentId: "agent-a",
    providerAccountId: "32000000-0000-4000-8000-000000000001",
    operationId: "42000000-0000-4000-8000-000000000001",
    operationRevision: 1,
    actionDigest: `sha256:${"d".repeat(64)}`,
    policyInputDigest: `sha256:${"e".repeat(64)}`,
    idempotencyKeyHash,
    xSummonAttestationDigest: computeXSummonAttestationDigest(attestation),
    requestedAt: "2026-08-18T00:59:01.000Z",
    expiresAt: "2026-08-18T01:04:01.000Z",
    nonce: "nonce",
  };
  return {
    audience,
    tenantId: "tenant-a",
    workspaceId: "22000000-0000-4000-8000-000000000001",
    actorAgentId: "agent-a",
    providerAccountId: "32000000-0000-4000-8000-000000000001",
    idempotencyKeyHash,
    requestEnvelope,
    requestHash: `sha256:${createHash("sha256").update(jcsStringify(requestEnvelope)).digest("hex")}`,
    safeSummary: { xSummonAttestation: attestation },
    canonicalAction: {
      profile: "x.provider-action.v1",
      method: "POST" as const,
      origin: "https://api.x.com",
      normalizedPath: "/2/tweets",
      orderedQueryPairs: [],
      selectedHeaders: [["content-type", "application/json"]] as Array<[string, string]>,
      canonicalBody: {
        text: "not persisted in provenance",
        reply: { in_reply_to_tweet_id: "1900000000000000000" },
      },
    } as never,
    keysJson,
    now,
  };
}

describe("dispatch X summon provenance boundary", () => {
  test("accepts exact signed and request-hash-bound provenance", () => {
    expect(verifyDispatchXSummonProvenance(fixture())).toBe("valid");
  });

  test("fails closed on expired, removed, cross-post, or envelope-tampered evidence", () => {
    expect(
      verifyDispatchXSummonProvenance({
        ...fixture(),
        now: new Date("2026-08-18T01:04:00.001Z"),
      }),
    ).toBe("invalid");
    expect(verifyDispatchXSummonProvenance({ ...fixture(), safeSummary: {} })).toBe("invalid");
    const crossPost = fixture();
    crossPost.canonicalAction.canonicalBody = {
      text: "reply",
      reply: { in_reply_to_tweet_id: "1900000000000000001" },
    };
    expect(verifyDispatchXSummonProvenance(crossPost)).toBe("invalid");
    const tampered = fixture();
    tampered.requestEnvelope.workspaceId = "22000000-0000-4000-8000-000000000002";
    expect(verifyDispatchXSummonProvenance(tampered)).toBe("invalid");
    expect(verifyDispatchXSummonProvenance({ ...fixture(), audience: "steward-staging" })).toBe(
      "invalid",
    );
  });

  test("allows truly absent provenance for non-summon-governed actions", () => {
    const absent = fixture();
    delete absent.requestEnvelope.xSummonAttestationDigest;
    absent.requestHash = `sha256:${createHash("sha256")
      .update(jcsStringify(absent.requestEnvelope))
      .digest("hex")}`;
    absent.safeSummary = {};
    expect(verifyDispatchXSummonProvenance(absent)).toBe("absent");
  });
});
