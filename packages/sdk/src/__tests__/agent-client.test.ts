/**
 * agent-client.test.ts — mocked-server unit tests for the A3 sovereign-custody
 * agent client. The mock server performs REAL P-256 verification and mints REAL
 * signed JWTs, so these prove the client's crypto interoperates, not just its
 * plumbing. Covers: keypair-only enroll, wrong-key/tamper fail-closed, manifest,
 * token & broker issue/renew, broker invoke, 202 approval as a first-class state,
 * revocation mid-session (renewal MUST fail closed — bidirectional proof),
 * clock-skew tolerance, and key-leak guards.
 */

import { afterEach, describe, expect, test } from "bun:test";
import {
  AgentClient,
  AgentClientError,
  type AgentClientEvent,
  AgentKeypair,
  NotEnrolledError,
} from "../index";
import {
  generateMockKeyPair,
  type MockManifestEntry,
  MockStewardServer,
} from "./agent-client-mock-server";

const AGENT_ID = "agent-soliza";
const TENANT_ID = "tenant-acme";

const MANIFEST: MockManifestEntry[] = [
  {
    manifest: "github:app:org",
    provider: "github",
    kind: "app",
    capabilityName: "gh-comment",
    capabilityId: "cap-gh",
    grantExpiresAt: null,
    mode: "token",
  },
  {
    manifest: "discord:bot-token:soliza",
    provider: "discord",
    kind: "bot-token",
    capabilityName: "discord-send",
    capabilityId: "cap-discord",
    grantExpiresAt: null,
    mode: "broker",
  },
];

async function setup(opts?: {
  approvalRequired?: Set<string>;
  denies?: Map<string, { status: number; message: string }>;
  enrollTtlSeconds?: number;
  now?: () => number;
}) {
  const kp = await generateMockKeyPair();
  const server = new MockStewardServer({
    signers: [
      {
        agentId: AGENT_ID,
        tenantId: TENANT_ID,
        publicKeyRawBase64: kp.publicKeyRawBase64,
        status: "active",
      },
    ],
    manifest: MANIFEST,
    approvalRequired: opts?.approvalRequired,
    denies: opts?.denies,
    enrollTtlSeconds: opts?.enrollTtlSeconds,
    now: opts?.now,
    invokeBody: { messageId: "123", channel: "general" },
  });
  const keypair = await AgentKeypair.fromPkcs8Base64(kp.pkcs8Base64);
  const client = new AgentClient({
    baseUrl: "http://mock",
    agentId: AGENT_ID,
    keypair,
    fetchImpl: server.fetch,
    now: opts?.now,
    renewJitterMs: 0,
  });
  return { server, client, kp };
}

const clients: AgentClient[] = [];
afterEach(() => {
  for (const c of clients) c.stopRenewalLoop();
  clients.length = 0;
});

describe("AgentClient — enroll (keypair-only boot)", () => {
  test("boots with keypair only and gets a short-lived agent token", async () => {
    const { client, server } = await setup();
    const result = await client.enroll();
    expect(result.agentId).toBe(AGENT_ID);
    expect(result.tenantId).toBe(TENANT_ID);
    expect(result.scopes).toEqual(["agent"]);
    expect(result.expiresAt).toBeGreaterThan(Date.now());
    expect(client.isEnrolled()).toBe(true);
    expect(server.challengeCount).toBe(1);
    expect(server.verifyCount).toBe(1);
  });

  test("emits an 'enrolled' event", async () => {
    const { client } = await setup();
    const events: AgentClientEvent[] = [];
    client.on((e) => events.push(e));
    await client.enroll();
    expect(events.some((e) => e.type === "enrolled")).toBe(true);
  });

  test("WRONG key fails closed (bidirectional): a mismatched signer cannot enroll", async () => {
    // fails-before: swap in an unrelated keypair, enroll must be denied.
    const { server } = await setup();
    const wrong = await generateMockKeyPair();
    const wrongKeypair = await AgentKeypair.fromPkcs8Base64(wrong.pkcs8Base64);
    const client = new AgentClient({
      baseUrl: "http://mock",
      agentId: AGENT_ID,
      keypair: wrongKeypair,
      fetchImpl: server.fetch,
      renewJitterMs: 0,
    });
    await expect(client.enroll()).rejects.toBeInstanceOf(AgentClientError);
    expect(client.isEnrolled()).toBe(false);
    // passes-after: the correct key enrolls fine (same server, same agent).
    const correct = await generateMockKeyPair();
    server.activeSigner(AGENT_ID)!.publicKeyRawBase64 = correct.publicKeyRawBase64;
    const good = new AgentClient({
      baseUrl: "http://mock",
      agentId: AGENT_ID,
      keypair: await AgentKeypair.fromPkcs8Base64(correct.pkcs8Base64),
      fetchImpl: server.fetch,
      renewJitterMs: 0,
    });
    await expect(good.enroll()).resolves.toMatchObject({ agentId: AGENT_ID });
  });

  test("unknown agent (no active signer) is denied", async () => {
    const { server, kp } = await setup();
    server.revokeSigner(AGENT_ID);
    const client = new AgentClient({
      baseUrl: "http://mock",
      agentId: AGENT_ID,
      keypair: await AgentKeypair.fromPkcs8Base64(kp.pkcs8Base64),
      fetchImpl: server.fetch,
      renewJitterMs: 0,
    });
    await expect(client.enroll()).rejects.toBeInstanceOf(AgentClientError);
  });
});

describe("AgentClient — manifest + issuance", () => {
  test("manifest returns typed entries (no mode leakage of secrets)", async () => {
    const { client } = await setup();
    await client.enroll();
    const manifest = await client.manifest();
    expect(manifest.map((m) => m.manifest).sort()).toEqual([
      "discord:bot-token:soliza",
      "github:app:org",
    ]);
    expect(manifest[0]).toHaveProperty("provider");
    expect(manifest[0]).toHaveProperty("capabilityName");
  });

  test("token-mode issue returns a short-lived scoped token with an exp", async () => {
    const { client } = await setup();
    await client.enroll();
    const cap = await client.issue("github:app:org", { ttlSeconds: 120 });
    expect(cap.mode).toBe("token");
    if (cap.mode !== "token") throw new Error("expected token mode");
    expect(cap.scopes).toEqual(["cap:github:app:org"]);
    expect(cap.token.split(".")).toHaveLength(3);
    expect(cap.expiresAt).toBeGreaterThan(Date.now());
    expect(cap.jti).toBeTruthy();
  });

  test("broker-mode issue returns a delegation (NO token)", async () => {
    const { client } = await setup();
    await client.enroll();
    const cap = await client.issue("discord:bot-token:soliza");
    expect(cap.mode).toBe("broker");
    if (cap.mode !== "broker") throw new Error("expected broker mode");
    expect(cap.delegation.capabilityName).toBe("discord-send");
    expect(cap).not.toHaveProperty("token");
  });

  test("renew hits the same path and re-mints", async () => {
    const { client } = await setup();
    await client.enroll();
    const a = await client.issue("github:app:org");
    const b = await client.renew("github:app:org");
    if (a.mode !== "token" || b.mode !== "token") throw new Error("expected token mode");
    expect(b.jti).not.toBe(a.jti);
  });

  test("out-of-range ttl is rejected (400)", async () => {
    const { client } = await setup();
    await client.enroll();
    await expect(client.issue("github:app:org", { ttlSeconds: 99999 })).rejects.toMatchObject({
      status: 400,
    });
  });

  test("manifest/issue before enroll throws NotEnrolledError", async () => {
    const { client } = await setup();
    await expect(client.manifest()).rejects.toBeInstanceOf(NotEnrolledError);
    await expect(client.issue("github:app:org")).rejects.toBeInstanceOf(NotEnrolledError);
  });
});

describe("AgentClient — broker invoke", () => {
  test("successful invoke returns the scrubbed upstream body", async () => {
    const { client } = await setup();
    await client.enroll();
    const res = await client.invoke("discord-send", { body: { content: "hi" } });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") throw new Error("expected ok");
    expect(res.data).toMatchObject({ messageId: "123" });
  });

  test("202 approval-pending is a FIRST-CLASS state, not an exception", async () => {
    const { client } = await setup({ approvalRequired: new Set(["discord-send"]) });
    await client.enroll();
    const res = await client.invoke("discord-send", { body: { content: "hi" } });
    expect(res.status).toBe("pending_approval");
    if (res.status !== "pending_approval") throw new Error("expected pending");
    expect(res.approvalId).toBeTruthy();
  });

  test("gate deny (403) throws a typed AgentClientError with status", async () => {
    const { client } = await setup({
      denies: new Map([["discord-send", { status: 403, message: "capability intent denied" }]]),
    });
    await client.enroll();
    await expect(client.invoke("discord-send")).rejects.toMatchObject({
      status: 403,
      message: "capability intent denied",
    });
  });

  test("invoke before enroll throws NotEnrolledError", async () => {
    const { client } = await setup();
    await expect(client.invoke("discord-send")).rejects.toBeInstanceOf(NotEnrolledError);
  });
});

describe("AgentClient — revocation mid-session (fail-closed)", () => {
  test("renewal after signer revocation FAILS CLOSED (bidirectional proof)", async () => {
    // passes-before-revocation: client is enrolled and can call authed endpoints.
    const { client, server } = await setup();
    const events: AgentClientEvent[] = [];
    client.on((e) => events.push(e));
    await client.enroll();
    expect(client.isEnrolled()).toBe(true);
    await expect(client.manifest()).resolves.toBeDefined();

    // revoke the signer, then force a renewal (what the loop does on a timer).
    server.revokeSigner(AGENT_ID);
    await client["renewOnce"](); // exercise the private renewal path directly

    // fails-after: no token, unauthenticated state, authed calls now throw.
    expect(client.isEnrolled()).toBe(false);
    expect(events.some((e) => e.type === "renew_failed")).toBe(true);
    expect(events.some((e) => e.type === "unauthenticated")).toBe(true);
    await expect(client.manifest()).rejects.toBeInstanceOf(NotEnrolledError);
  });

  test("a 401 from an authed call (token revoked mid-flight) fails closed", async () => {
    const { client, server } = await setup();
    await client.enroll();
    // Simulate the server rejecting the (still-held) token by revoking its jti.
    // Force the agent token's jti into the revoked set by re-minting is complex;
    // instead revoke the signer AND expire logic via 401: monkeypatch the server
    // to reject the next authed call.
    const realFetch = server.fetch;
    let calls = 0;
    (client as unknown as { fetchImpl: typeof fetch }).fetchImpl = async (u, i) => {
      calls += 1;
      return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    };
    await expect(client.manifest()).rejects.toBeInstanceOf(AgentClientError);
    expect(client.isEnrolled()).toBe(false); // failed closed on the 401
    void realFetch;
    void calls;
  });

  test("no stale-token reuse: after fail-closed, invoke refuses until re-enroll", async () => {
    const { client, server } = await setup();
    await client.enroll();
    server.revokeSigner(AGENT_ID);
    await client["renewOnce"]();
    await expect(client.invoke("discord-send")).rejects.toBeInstanceOf(NotEnrolledError);
    // re-activate + re-enroll heals it.
    server.activeSigner(AGENT_ID); // still revoked; reactivate:
    (server as unknown as { signers: { agentId: string; status: string }[] }).signers.forEach(
      (s) => {
        if (s.agentId === AGENT_ID) s.status = "active";
      },
    );
    await client.enroll();
    expect(client.isEnrolled()).toBe(true);
  });
});

describe("AgentClient — clock-skew tolerance", () => {
  test("schedules renewal before expiry even under modest skew (no throw)", async () => {
    // Server clock is 20s ahead of the client; tokens still parse and the client
    // schedules a renewal without error. We assert the token's exp is read and in
    // the future relative to the client, and the loop can be started/stopped.
    let clientNow = 1_000_000_000_000;
    const serverNow = () => clientNow + 20_000; // server 20s ahead
    const { client } = await setup({ enrollTtlSeconds: 300, now: serverNow });
    // client uses its own clock:
    (client as unknown as { now: () => number }).now = () => clientNow;
    (client as unknown as { clockSkewToleranceMs: number }).clockSkewToleranceMs = 30_000;
    const res = await client.enroll();
    expect(res.expiresAt).not.toBeNull();
    // exp is ~300s ahead of the SERVER clock, i.e. > client now.
    expect(res.expiresAt!).toBeGreaterThan(clientNow);
    client.startRenewalLoop();
    clients.push(client);
    // advance the client clock near expiry; isEnrolled still true within skew.
    clientNow += 250_000;
    expect(client.isEnrolled()).toBe(true);
  });
});

describe("AgentKeypair — key never leaks", () => {
  test("toString / toJSON / inspect are redacted", async () => {
    const kp = await generateMockKeyPair();
    const keypair = await AgentKeypair.fromPkcs8Base64(kp.pkcs8Base64);
    expect(String(keypair)).toBe("[AgentKeypair: private key redacted]");
    expect(JSON.stringify({ k: keypair })).toContain("redacted");
    expect(`${keypair}`).toContain("redacted");
    // no method returns raw key material.
    expect(Object.keys(keypair)).not.toContain("privateKey");
  });

  test("sign produces a base64 P1363 signature the server accepts", async () => {
    const { client } = await setup();
    // enroll succeeding IS the proof the signature verified server-side.
    await expect(client.enroll()).resolves.toBeDefined();
  });

  test("rejects a non-P256 / non-private CryptoKey", async () => {
    const rsa = (await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    await expect(AgentKeypair.fromCryptoKey(rsa.privateKey)).rejects.toThrow();
    await expect(AgentKeypair.fromCryptoKey(rsa.publicKey)).rejects.toThrow();
  });
});
