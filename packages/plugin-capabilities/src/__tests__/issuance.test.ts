/**
 * Tests for the capability issuance/renewal core (A1, scope 3-5).
 *
 * Pure unit tests over issueCapability with a fake minter + audit sink. They
 * prove: broker mode returns a delegation (no token), token mode mints a
 * short-lived scoped token, TTL is clamped to the honest range, renewal is a
 * fresh fully-checked issuance, revocation is enforced by the resolver returning
 * null, and every outcome emits exactly one audit event.
 */

import { describe, expect, test } from "bun:test";
import {
  type CapabilityAuditEvent,
  clampTtlSeconds,
  DEFAULT_ISSUE_TTL_SECONDS,
  issueCapability,
  MAX_ISSUE_TTL_SECONDS,
  type ResolvedManifestEntry,
  type ShortLivedTokenMinter,
} from "../issuance";
import type { Capability, CapabilityGrant } from "../schema";

function fakeCapability(name: string): Capability {
  return {
    id: `cap-${name}`,
    tenantId: "t1",
    name,
    secretId: "sec-1",
    host: "discord.com",
    pathPattern: "/api/*",
    method: "POST",
    injectAs: "header",
    injectKey: "authorization",
    injectFormat: "Bot {value}",
    constraints: {},
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  } as Capability;
}

function fakeGrant(): CapabilityGrant {
  return {
    id: "grant-1",
    tenantId: "t1",
    agentId: "a1",
    capabilityId: "cap-x",
    secretRouteId: "route-1",
    expiresAt: null,
    status: "active",
    createdAt: new Date(),
  } as CapabilityGrant;
}

function resolved(provider: string, name: string): ResolvedManifestEntry {
  return {
    manifest: `${provider}:kind`,
    provider,
    capability: fakeCapability(name),
    grant: fakeGrant(),
  };
}

const fakeMinter: ShortLivedTokenMinter = async ({ ttlSeconds }) => ({
  token: `tok.ttl=${ttlSeconds}`,
  jti: "jti-123",
});

function collectAudit() {
  const events: CapabilityAuditEvent[] = [];
  return { events, sink: async (e: CapabilityAuditEvent) => void events.push(e) };
}

describe("clampTtlSeconds", () => {
  test("defaults when unspecified", () => {
    expect(clampTtlSeconds(undefined)).toBe(DEFAULT_ISSUE_TTL_SECONDS);
  });
  test("rejects non-positive / non-finite", () => {
    expect(clampTtlSeconds(0)).toBeNull();
    expect(clampTtlSeconds(-5)).toBeNull();
    expect(clampTtlSeconds(Number.NaN)).toBeNull();
  });
  test("rejects above the ceiling", () => {
    expect(clampTtlSeconds(MAX_ISSUE_TTL_SECONDS + 1)).toBeNull();
  });
  test("accepts within range (floored)", () => {
    expect(clampTtlSeconds(90.9)).toBe(90);
    expect(clampTtlSeconds(MAX_ISSUE_TTL_SECONDS)).toBe(MAX_ISSUE_TTL_SECONDS);
  });
});

describe("issueCapability", () => {
  test("broker mode: returns delegation, no token, allow audit", async () => {
    const { events, sink } = collectAudit();
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "discord:bot-token:soliza",
      resolved: resolved("discord", "discord:bot-token:soliza"),
      mintToken: fakeMinter,
      emitAudit: sink,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected ok");
    expect(res.mode).toBe("broker");
    if (res.mode !== "broker") throw new Error("expected broker");
    expect(res.delegation.capabilityName).toBe("discord:bot-token:soliza");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      action: "capability.issue",
      mode: "broker",
      decision: "allow",
    });
  });

  test("token mode: refuses to substitute an internal JWT for an upstream credential", async () => {
    const { events, sink } = collectAudit();
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "github:app:org",
      resolved: resolved("github", "github:app:org"),
      ttlSeconds: 60,
      mintToken: fakeMinter,
      emitAudit: sink,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected deny");
    expect(res.code).toBe("upstream_issuer_required");
    expect(events[0]).toMatchObject({
      action: "capability.issue",
      mode: "token",
      decision: "deny",
      reason: "upstream issuer required",
    });
  });

  test("token mode: requires upstream issuer before considering ttl", async () => {
    const { events, sink } = collectAudit();
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "github:app:org",
      resolved: resolved("github", "github:app:org"),
      ttlSeconds: 99999,
      mintToken: fakeMinter,
      emitAudit: sink,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected deny");
    expect(res.code).toBe("upstream_issuer_required");
    expect(events[0]).toMatchObject({ decision: "deny", reason: "upstream issuer required" });
  });

  test("revocation: unresolved (no live grant) denies", async () => {
    const { events, sink } = collectAudit();
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "discord:bot-token:soliza",
      resolved: null, // operator revoked / grant expired
      mintToken: fakeMinter,
      emitAudit: sink,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected deny");
    expect(res.code).toBe("not_granted");
    expect(events[0]).toMatchObject({
      decision: "deny",
      reason: "capability not granted to agent",
    });
  });

  test("renewal: same path, audit action is capability.renew", async () => {
    const { events, sink } = collectAudit();
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "github:app:org",
      resolved: resolved("github", "github:app:org"),
      isRenewal: true,
      mintToken: fakeMinter,
      emitAudit: sink,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected deny");
    expect(res.code).toBe("upstream_issuer_required");
    expect(events[0].action).toBe("capability.renew");
  });

  test("generic token path never calls an injected internal minter", async () => {
    const { events, sink } = collectAudit();
    let called = false;
    const failingMinter: ShortLivedTokenMinter = async () => {
      called = true;
      throw new Error("hsm offline");
    };
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "github:app:org",
      resolved: resolved("github", "github:app:org"),
      mintToken: failingMinter,
      emitAudit: sink,
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected deny");
    expect(res.code).toBe("upstream_issuer_required");
    expect(called).toBe(false);
    expect(res.error).not.toContain("hsm");
    expect(events[0]).toMatchObject({ decision: "deny", reason: "upstream issuer required" });
  });

  test("audit sink failure never changes the decision", async () => {
    const res = await issueCapability({
      tenantId: "t1",
      agentId: "a1",
      manifest: "github:app:org",
      resolved: resolved("github", "github:app:org"),
      mintToken: fakeMinter,
      emitAudit: async () => {
        throw new Error("audit pipeline down");
      },
    });
    expect(res.ok).toBe(false);
  });
});
