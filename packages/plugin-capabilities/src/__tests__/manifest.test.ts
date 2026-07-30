/**
 * manifest.test.ts — the per-agent manifest projection over live grants (A1
 * scope 2) + revocation semantics (scope 4).
 *
 * Uses the real store + pglite harness (mirrors store-lifecycle). Proves: a
 * granted capability carrying a manifest id appears in the agent's manifest;
 * resolveManifestEntry finds it; revoking the grant (or disabling the capability)
 * removes it from the manifest AND makes resolveManifestEntry return null (so the
 * issuance layer denies at the next renewal).
 */

import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { capabilityManifestId, listAgentManifest, resolveManifestEntry } from "../manifest";
import { CapabilityStore } from "../store";
import { validateCapabilitySpec } from "../validate";
import { ensureAgent, ensureSecret, ensureTenant, type Harness, makeHarness } from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
let store: CapabilityStore;
let tenantId: string;
let secretId: string;
const agentId = "agent-soliza";

const GH_SPEC = {
  host: "api.github.com",
  pathPattern: "/repos/acme/widgets/issues/1/comments",
  method: "POST",
  injectKey: "authorization",
  injectFormat: "Bearer {value}",
};

beforeEach(async () => {
  harness = await makeHarness();
  store = new CapabilityStore(harness.db);
  tenantId = `tenant-${crypto.randomUUID()}`;
  await ensureTenant(harness.db, tenantId);
  await ensureAgent(harness.db, tenantId, agentId);
  secretId = await ensureSecret(harness.db, tenantId, "github-pat");
});

afterEach(async () => {
  await harness?.close();
  harness = null;
});

async function createManifestCapability(name: string, manifest: string) {
  const v = validateCapabilitySpec({ secretId, ...GH_SPEC });
  if (!v.ok) throw new Error(`spec invalid: ${v.error}`);
  return store.createCapability({
    tenantId,
    name,
    spec: v.spec,
    constraints: { manifest },
    enabled: true,
  });
}

describe("capabilityManifestId", () => {
  test("prefers explicit constraints.manifest", () => {
    const cap = {
      name: "some-name",
      constraints: { manifest: "github:app:org" },
    } as Parameters<typeof capabilityManifestId>[0];
    expect(capabilityManifestId(cap)).toBe("github:app:org");
  });

  test("falls back to a name that is a valid identifier", () => {
    const cap = {
      name: "discord:bot-token:soliza",
      constraints: {},
    } as Parameters<typeof capabilityManifestId>[0];
    expect(capabilityManifestId(cap)).toBe("discord:bot-token:soliza");
  });

  test("returns null when neither is a valid identifier", () => {
    const cap = {
      name: "not-an-identifier",
      constraints: {},
    } as Parameters<typeof capabilityManifestId>[0];
    expect(capabilityManifestId(cap)).toBeNull();
  });
});

describe("manifest projection over grants", () => {
  test("a granted manifest capability appears in the agent manifest", async () => {
    const cap = await createManifestCapability("gh-comment", "github:app:org");
    await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });

    const listing = await listAgentManifest(store, tenantId, agentId);
    expect(listing).toHaveLength(1);
    expect(listing[0]).toMatchObject({
      manifest: "github:app:org",
      provider: "github",
      kind: "app",
      capabilityName: "gh-comment",
    });
  });

  test("resolveManifestEntry finds the live grant", async () => {
    const cap = await createManifestCapability("gh-comment", "github:app:org");
    await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });

    const entry = await resolveManifestEntry(store, tenantId, agentId, "github:app:org");
    expect(entry).not.toBeNull();
    expect(entry?.provider).toBe("github");
    expect(entry?.capability.id).toBe(cap.id);
  });

  test("a capability WITHOUT a manifest id is omitted from the manifest", async () => {
    const v = validateCapabilitySpec({ secretId, ...GH_SPEC });
    if (!v.ok) throw new Error("spec invalid");
    const cap = await store.createCapability({
      tenantId,
      name: "plain-capability",
      spec: v.spec,
      constraints: {},
      enabled: true,
    });
    await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });

    const listing = await listAgentManifest(store, tenantId, agentId);
    expect(listing).toHaveLength(0);
  });

  test("revocation: revoking the grant removes it from the manifest and resolve", async () => {
    const cap = await createManifestCapability("gh-comment", "github:app:org");
    const result = await store.createGrant({
      tenantId,
      capabilityId: cap.id,
      agentId,
      expiresAt: null,
    });
    if (!result) throw new Error("grant failed");

    // present before revoke
    expect(await resolveManifestEntry(store, tenantId, agentId, "github:app:org")).not.toBeNull();

    await store.revokeGrant(tenantId, result.grant.id);

    // gone after revoke → issuance layer will deny at next renewal
    expect(await listAgentManifest(store, tenantId, agentId)).toHaveLength(0);
    expect(await resolveManifestEntry(store, tenantId, agentId, "github:app:org")).toBeNull();
  });

  test("revocation: disabling the capability removes it from the manifest", async () => {
    const cap = await createManifestCapability("gh-comment", "github:app:org");
    await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });

    await store.updateCapability(tenantId, cap.id, { enabled: false });

    expect(await listAgentManifest(store, tenantId, agentId)).toHaveLength(0);
    expect(await resolveManifestEntry(store, tenantId, agentId, "github:app:org")).toBeNull();
  });

  test("resolveManifestEntry returns null for an unparseable identifier", async () => {
    const entry = await resolveManifestEntry(store, tenantId, agentId, "not-valid");
    expect(entry).toBeNull();
  });
});
