import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  exportP256PublicKeySpkiBase64,
  generateP256KeyPair,
  importP256PublicKey,
  signP256,
  verifyP256Signature,
} from "@stwd/auth";
import { agentKeyQuorums, agentSigners, agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import {
  authorizationSignature,
  buildAuthorizationCanonicalString,
  createAuthorizationSignature,
} from "../middleware/authorization-signature";
import type { AppVariables } from "../services/context";

const TENANT_ID = `authz-keys-tenant-${Date.now()}`;
const AGENT_ID = `authz-keys-agent-${Date.now()}`;
const HMAC_SECRET = "request-signing-secret-with-enough-entropy";
const PATH = `/vault/${AGENT_ID}/sign-message`;
const TRANSACTION_SIGN_PATH = `/vault/${AGENT_ID}/sign`;
const BITCOIN_PSBT_SIGN_PATH = `/vault/${AGENT_ID}/sign-bitcoin-psbt`;
const AUTHORIZATION_SIGN_PATH = `/vault/${AGENT_ID}/sign-authorization`;
const BODY = JSON.stringify({ value: "1000" });
const FRESH_TS = () => String(Math.floor(Date.now() / 1000));

type KeyPair = Awaited<ReturnType<typeof generateP256KeyPair>>;

// Seeded P-256 signer keypairs, populated in beforeAll.
const keypairs: Record<string, KeyPair> = {};
// Seeded signer ids.
const ids = {
  signerSign: "", // p256 signer with sign_message permission
  signerNoRole: "", // p256 signer WITHOUT sign permission (role-gating)
  quorumA: "", // quorum members
  quorumB: "",
  quorumC: "",
  childA: "", // nested-child quorum members
  childB: "",
  hmacSigner: "", // an HMAC signer (key_type defaults to hmac)
};
const quorumIds = {
  topLevel: "", // 2-of-3: [quorumA, quorumB] signers + [childQuorum] child
  child: "", // 2-of-2: [childA, childB]
  lowPermissionLeaf: "",
  duplicateChildA: "",
  duplicateChildB: "",
  duplicateParent: "",
  cyclicA: "",
  cyclicB: "",
  deep: "", // root of an over-deep nested chain
};

function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", authorizationSignature({ required: true, secrets: [HMAC_SECRET] }));
  const handler = (c: Parameters<Parameters<typeof app.post>[1]>[0]) =>
    c.json({ ok: true, verified: Boolean(c.get("requestSignatureVerified")) });
  app.post("/vault/:agentId/sign", handler);
  app.post("/vault/:agentId/sign-bitcoin-psbt", handler);
  app.post("/vault/:agentId/sign-message", handler);
  app.post("/vault/:agentId/sign-authorization", handler);
  return app;
}

/** Build the canonical string the middleware reconstructs for a single P-256 signer. */
async function canonicalForSigner(opts: {
  signerId: string;
  timestamp: string;
  idempotencyKey: string;
  body?: string;
}): Promise<string> {
  return buildAuthorizationCanonicalString({
    method: "POST",
    url: PATH,
    tenantId: TENANT_ID,
    signerId: opts.signerId,
    timestamp: opts.timestamp,
    idempotencyKey: opts.idempotencyKey,
    body: opts.body ?? BODY,
  });
}

/** Build the canonical string the middleware reconstructs for a quorum request. */
async function canonicalForQuorum(opts: {
  quorumId: string;
  timestamp: string;
  idempotencyKey: string;
  body?: string;
}): Promise<string> {
  return buildAuthorizationCanonicalString({
    method: "POST",
    url: PATH,
    tenantId: TENANT_ID,
    quorumId: opts.quorumId,
    timestamp: opts.timestamp,
    idempotencyKey: opts.idempotencyKey,
    body: opts.body ?? BODY,
  });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "authz-keys-master-password";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Authz Keys Tenant", apiKeyHash: "h" });
  await getDb().insert(agents).values({
    id: AGENT_ID,
    tenantId: TENANT_ID,
    name: "Authz Keys Agent",
    walletAddress: "0x1234567890123456789012345678901234567890",
  });

  for (const name of [
    "signerSign",
    "signerNoRole",
    "quorumA",
    "quorumB",
    "quorumC",
    "childA",
    "childB",
  ]) {
    keypairs[name] = await generateP256KeyPair();
  }

  const insertSigner = async (opts: {
    publicKey: string;
    permissions: string[];
    keyType?: string;
    status?: string;
  }): Promise<string> => {
    const [row] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "wallet",
        subjectId: `subj-${Math.random().toString(36).slice(2)}`,
        keyType: opts.keyType ?? "p256",
        publicKey: opts.publicKey,
        permissions: opts.permissions,
        status: opts.status ?? "active",
        createdBy: "seed",
      })
      .returning({ id: agentSigners.id });
    return row.id;
  };

  ids.signerSign = await insertSigner({
    publicKey: keypairs.signerSign.publicKeySpkiBase64,
    permissions: ["sign_message"],
  });
  ids.signerNoRole = await insertSigner({
    publicKey: keypairs.signerNoRole.publicKeySpkiBase64,
    permissions: ["read_only"],
  });
  ids.quorumA = await insertSigner({
    publicKey: keypairs.quorumA.publicKeySpkiBase64,
    permissions: ["sign_message"],
  });
  ids.quorumB = await insertSigner({
    publicKey: keypairs.quorumB.publicKeySpkiBase64,
    permissions: ["sign_message"],
  });
  ids.quorumC = await insertSigner({
    publicKey: keypairs.quorumC.publicKeySpkiBase64,
    permissions: ["sign_message"],
  });
  ids.childA = await insertSigner({
    publicKey: keypairs.childA.publicKeySpkiBase64,
    permissions: ["sign_message"],
  });
  ids.childB = await insertSigner({
    publicKey: keypairs.childB.publicKeySpkiBase64,
    permissions: ["sign_message"],
  });
  // An HMAC signer (no public key); proves HMAC signers are ignored by the P-256 path.
  ids.hmacSigner = await insertSigner({
    publicKey: "",
    permissions: ["sign_message"],
    keyType: "hmac",
  });

  const insertQuorum = async (opts: {
    threshold: number;
    memberSignerIds: string[];
    memberQuorumIds?: string[];
    permissions: string[];
  }): Promise<string> => {
    const [row] = await getDb()
      .insert(agentKeyQuorums)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        name: `quorum-${Math.random().toString(36).slice(2)}`,
        threshold: opts.threshold,
        memberSignerIds: opts.memberSignerIds,
        memberQuorumIds: opts.memberQuorumIds ?? [],
        permissions: opts.permissions,
        status: "active",
        createdBy: "seed",
      })
      .returning({ id: agentKeyQuorums.id });
    return row.id;
  };

  // child: 2-of-2 over [childA, childB]
  quorumIds.child = await insertQuorum({
    threshold: 2,
    memberSignerIds: [ids.childA, ids.childB],
    permissions: ["sign_message"],
  });
  // top-level: 2-of-3 over signers [quorumA, quorumB] + child quorum
  quorumIds.topLevel = await insertQuorum({
    threshold: 2,
    memberSignerIds: [ids.quorumA, ids.quorumB],
    memberQuorumIds: [quorumIds.child],
    permissions: ["sign_message"],
  });
  quorumIds.lowPermissionLeaf = await insertQuorum({
    threshold: 2,
    memberSignerIds: [ids.quorumA, ids.signerNoRole],
    permissions: ["sign_message"],
  });
  quorumIds.duplicateChildA = await insertQuorum({
    threshold: 1,
    memberSignerIds: [ids.childA],
    permissions: ["sign_message"],
  });
  quorumIds.duplicateChildB = await insertQuorum({
    threshold: 1,
    memberSignerIds: [ids.childA],
    permissions: ["sign_message"],
  });
  quorumIds.duplicateParent = await insertQuorum({
    threshold: 2,
    memberSignerIds: [],
    memberQuorumIds: [quorumIds.duplicateChildA, quorumIds.duplicateChildB],
    permissions: ["sign_message"],
  });

  // Cyclic pair: cyclicA → cyclicB → cyclicA (created via post-insert update).
  quorumIds.cyclicA = await insertQuorum({
    threshold: 1,
    memberSignerIds: [],
    permissions: ["sign_message"],
  });
  quorumIds.cyclicB = await insertQuorum({
    threshold: 1,
    memberSignerIds: [],
    memberQuorumIds: [quorumIds.cyclicA],
    permissions: ["sign_message"],
  });
  await getDb()
    .update(agentKeyQuorums)
    .set({ memberQuorumIds: [quorumIds.cyclicB] })
    .where(eq(agentKeyQuorums.id, quorumIds.cyclicA));

  // Over-deep chain: build 10 nested quorums each containing a single real
  // signer (childA) plus the next child, so depth > MAX_QUORUM_DEPTH (8).
  let previous = "";
  for (let i = 0; i < 10; i += 1) {
    previous = await insertQuorum({
      threshold: 1,
      memberSignerIds: i === 0 ? [ids.childA] : [],
      memberQuorumIds: previous ? [previous] : [],
      permissions: ["sign_message"],
    });
  }
  quorumIds.deep = previous;
}, 60_000); // pglite applies the full migration set in-memory; allow ample time.

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
});

// ── Pure crypto unit tests (no DB) ────────────────────────────────────────

describe("verifyP256Signature (unit)", () => {
  it("accepts a valid signature over the canonical string (SPKI key)", async () => {
    const kp = await generateP256KeyPair();
    const message = "steward-request-signature-v1\nPOST\n/x";
    const sig = await signP256(kp.privateKey, message);
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, message, sig)).toBe(true);
  });

  it("accepts a valid signature against a raw uncompressed (04||X||Y) key", async () => {
    const kp = await generateP256KeyPair();
    const message = "hello-world";
    const sig = await signP256(kp.privateKey, message);
    expect(await verifyP256Signature(kp.publicKeyRawBase64, message, sig)).toBe(true);
  });

  it("accepts a valid signature against a JWK key", async () => {
    const kp = await generateP256KeyPair();
    const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    const message = "jwk-message";
    const sig = await signP256(kp.privateKey, message);
    expect(await verifyP256Signature(JSON.stringify(jwk), message, sig)).toBe(true);
    expect(await verifyP256Signature(jwk, message, sig)).toBe(true);
  });

  it("rejects a signature from a different key (fail closed)", async () => {
    const kp = await generateP256KeyPair();
    const other = await generateP256KeyPair();
    const message = "msg";
    const sig = await signP256(other.privateKey, message);
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, message, sig)).toBe(false);
  });

  it("rejects when the signed data is tampered", async () => {
    const kp = await generateP256KeyPair();
    const sig = await signP256(kp.privateKey, "original");
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, "tampered", sig)).toBe(false);
  });

  it("rejects truncated / garbage signatures", async () => {
    const kp = await generateP256KeyPair();
    const sig = await signP256(kp.privateKey, "m");
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, "m", sig.slice(0, 20))).toBe(false);
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, "m", "!!!not-base64!!!")).toBe(false);
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, "m", "")).toBe(false);
  });

  it("rejects a wrong-curve key (P-384) — fail closed", async () => {
    const p384 = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", p384.publicKey));
    let bin = "";
    for (const b of spki) bin += String.fromCharCode(b);
    const spkiBase64 = btoa(bin);
    // Even with a "valid-looking" signature, the key import must reject P-384.
    const data = "m";
    const sig = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-384" },
        p384.privateKey,
        new TextEncoder().encode(data),
      ),
    );
    let sigBin = "";
    for (const b of sig) sigBin += String.fromCharCode(b);
    expect(await verifyP256Signature(spkiBase64, data, btoa(sigBin))).toBe(false);
    // And the importer itself returns null for the wrong curve.
    expect(await importP256PublicKey(spkiBase64)).toBeNull();
  });

  it("rejects a DER-encoded signature when r||s is expected but bytes are malformed DER", async () => {
    const kp = await generateP256KeyPair();
    const message = "m";
    const p1363 = await signP256(kp.privateKey, message);
    // Flip the scheme: prepend a fake SEQUENCE tag so it is mis-parsed as DER.
    const bytes = Uint8Array.from(atob(p1363), (ch) => ch.charCodeAt(0));
    const fakeDer = new Uint8Array([0x30, 0xff, ...bytes]);
    let bin = "";
    for (const b of fakeDer) bin += String.fromCharCode(b);
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, message, btoa(bin))).toBe(false);
  });

  it("accepts a correctly DER-encoded signature (DER → r||s conversion)", async () => {
    const kp = await generateP256KeyPair();
    const message = "der-roundtrip";
    const p1363 = Uint8Array.from(atob(await signP256(kp.privateKey, message)), (ch) =>
      ch.charCodeAt(0),
    );
    const der = p1363ToDer(p1363);
    let bin = "";
    for (const b of der) bin += String.fromCharCode(b);
    expect(await verifyP256Signature(kp.publicKeySpkiBase64, message, btoa(bin))).toBe(true);
  });

  it("round-trips an exported SPKI key", async () => {
    const kp = await generateP256KeyPair();
    const exported = await exportP256PublicKeySpkiBase64(kp.publicKey);
    expect(exported).toBe(kp.publicKeySpkiBase64);
  });
});

// ── Middleware integration tests (P-256 over the canonical request) ────────

describe("authorizationSignature P-256 path", () => {
  it("accepts a valid single-signer P-256 request", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-ok";
    const canonical = await canonicalForSigner({
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: idem,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });

  it("rejects a tampered body for a single-signer P-256 request", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-tamper";
    const canonical = await canonicalForSigner({
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: idem,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: JSON.stringify({ value: "9999" }),
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });

  it("rejects a P-256 signature from the wrong signer's key", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-wrongkey";
    const canonical = await canonicalForSigner({
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: idem,
    });
    // Sign with quorumA's key but claim to be signerSign.
    const sig = await signP256(keypairs.quorumA.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(401);
  });

  it("role-gates: a P-256 signer without sign permission is denied", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-norole";
    const canonical = await canonicalForSigner({
      signerId: ids.signerNoRole,
      timestamp: ts,
      idempotencyKey: idem,
    });
    const sig = await signP256(keypairs.signerNoRole.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerNoRole,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("sign_message");
  });

  it("does not let message-only P-256 signers authorize transaction signing", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-tx-scope";
    const canonical = await buildAuthorizationCanonicalString({
      method: "POST",
      url: TRANSACTION_SIGN_PATH,
      tenantId: TENANT_ID,
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: idem,
      body: BODY,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(TRANSACTION_SIGN_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("sign_transaction");
  });

  it("does not let message-only P-256 signers authorize Bitcoin PSBT signing", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-btc-psbt-scope";
    const canonical = await buildAuthorizationCanonicalString({
      method: "POST",
      url: BITCOIN_PSBT_SIGN_PATH,
      tenantId: TENANT_ID,
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: idem,
      body: BODY,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(BITCOIN_PSBT_SIGN_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("sign_transaction");
  });

  it("does not let message-only P-256 signers authorize EIP-7702 authorization signing", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-authz-scope";
    const canonical = await buildAuthorizationCanonicalString({
      method: "POST",
      url: AUTHORIZATION_SIGN_PATH,
      tenantId: TENANT_ID,
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: idem,
      body: BODY,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(AUTHORIZATION_SIGN_PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("sign_authorization");
  });

  it("rejects an unknown signer id", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-unknown";
    const canonical = await canonicalForSigner({
      signerId: "missing",
      timestamp: ts,
      idempotencyKey: idem,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": "missing",
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
  });

  it("ignores HMAC signers on the P-256 path (key_type mismatch → fail closed)", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-p256-hmacsigner";
    const canonical = await canonicalForSigner({
      signerId: ids.hmacSigner,
      timestamp: ts,
      idempotencyKey: idem,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.hmacSigner,
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
  });

  it("enforces freshness on the P-256 path (stale timestamp → 401)", async () => {
    const app = makeApp();
    const stale = String(Math.floor(Date.now() / 1000) - 24 * 60 * 60);
    const idem = "idem-p256-stale";
    const canonical = await canonicalForSigner({
      signerId: ids.signerSign,
      timestamp: stale,
      idempotencyKey: idem,
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": stale,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect((await res.json()).error).toContain("stale");
  });

  it("requires an idempotency key on the P-256 path", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const canonical = await canonicalForSigner({
      signerId: ids.signerSign,
      timestamp: ts,
      idempotencyKey: "",
    });
    const sig = await signP256(keypairs.signerSign.privateKey, canonical);

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-signer-id": ids.signerSign,
        "x-steward-request-timestamp": ts,
        "x-steward-signature": `p256=${sig}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(400);
    expect((await res.json()).error).toContain("Idempotency-Key");
  });
});

// ── Nested quorum tests ────────────────────────────────────────────────────

describe("authorizationSignature nested key quorum (P-256)", () => {
  async function quorumHeaders(opts: {
    quorumId: string;
    members: Array<{ id: string; kp: KeyPair }>;
    timestamp: string;
    idempotencyKey: string;
  }) {
    const canonical = await canonicalForQuorum({
      quorumId: opts.quorumId,
      timestamp: opts.timestamp,
      idempotencyKey: opts.idempotencyKey,
    });
    const credentials = await Promise.all(
      opts.members.map(async (m) => ({
        signerId: m.id,
        signature: await signP256(m.kp.privateKey, canonical),
      })),
    );
    return {
      "content-type": "application/json",
      "x-steward-tenant": TENANT_ID,
      "x-steward-key-quorum-id": opts.quorumId,
      "x-steward-key-quorum-credentials": JSON.stringify(credentials),
      "x-steward-request-timestamp": opts.timestamp,
      "idempotency-key": opts.idempotencyKey,
      // The carrier signature header is unused for quorum mode but must parse as p256.
      "x-steward-signature": `p256=${credentials[0].signature}`,
    };
  }

  it("accepts 2-of-3 satisfied by two leaf signers", async () => {
    const app = makeApp();
    const headers = await quorumHeaders({
      quorumId: quorumIds.topLevel,
      members: [
        { id: ids.quorumA, kp: keypairs.quorumA },
        { id: ids.quorumB, kp: keypairs.quorumB },
      ],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-2leaf",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });

  it("accepts 2-of-3 satisfied by one leaf signer + a satisfied 2-of-2 child quorum", async () => {
    const app = makeApp();
    const headers = await quorumHeaders({
      quorumId: quorumIds.topLevel,
      members: [
        { id: ids.quorumA, kp: keypairs.quorumA }, // 1 leaf
        { id: ids.childA, kp: keypairs.childA }, // satisfies child (2-of-2)...
        { id: ids.childB, kp: keypairs.childB },
      ],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-nested-ok",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });

  it("denies when only one member is satisfied (below threshold)", async () => {
    const app = makeApp();
    const headers = await quorumHeaders({
      quorumId: quorumIds.topLevel,
      members: [{ id: ids.quorumA, kp: keypairs.quorumA }],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-below",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("threshold");
  });

  it("denies when a low-permission leaf signer would otherwise satisfy quorum threshold", async () => {
    const app = makeApp();
    const headers = await quorumHeaders({
      quorumId: quorumIds.lowPermissionLeaf,
      members: [
        { id: ids.quorumA, kp: keypairs.quorumA },
        { id: ids.signerNoRole, kp: keypairs.signerNoRole },
      ],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-lowperm-leaf",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("threshold");
  });

  it("denies when the child quorum is only partially satisfied", async () => {
    const app = makeApp();
    // Only childA signs → child (2-of-2) NOT satisfied → only 1 of top-level → deny.
    const headers = await quorumHeaders({
      quorumId: quorumIds.topLevel,
      members: [{ id: ids.childA, kp: keypairs.childA }],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-partialchild",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(403);
  });

  it("denies when one signer is reused through multiple child quorums to fake parent threshold", async () => {
    const app = makeApp();
    const headers = await quorumHeaders({
      quorumId: quorumIds.duplicateParent,
      members: [{ id: ids.childA, kp: keypairs.childA }],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-duplicate-child-union",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toContain("threshold");
  });

  it("denies a credential whose signature is invalid (does not count toward threshold)", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const idem = "idem-q-badsig";
    const canonical = await canonicalForQuorum({
      quorumId: quorumIds.topLevel,
      timestamp: ts,
      idempotencyKey: idem,
    });
    const goodA = await signP256(keypairs.quorumA.privateKey, canonical);
    // quorumB credential signed with the WRONG key.
    const badB = await signP256(keypairs.childA.privateKey, canonical);
    const credentials = [
      { signerId: ids.quorumA, signature: goodA },
      { signerId: ids.quorumB, signature: badB },
    ];

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-key-quorum-id": quorumIds.topLevel,
        "x-steward-key-quorum-credentials": JSON.stringify(credentials),
        "x-steward-request-timestamp": ts,
        "idempotency-key": idem,
        "x-steward-signature": `p256=${goodA}`,
      },
      body: BODY,
    });

    expect(res.status).toBe(403);
  });

  it("denies on a quorum cycle (A → B → A) — fail closed", async () => {
    const app = makeApp();
    // cyclicB references cyclicA which references cyclicB; no leaf signer can
    // ever satisfy it, and cycle detection must short-circuit to deny.
    const headers = await quorumHeaders({
      quorumId: quorumIds.cyclicB,
      members: [{ id: ids.childA, kp: keypairs.childA }],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-cycle",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(403);
  });

  it("denies when nesting exceeds the depth limit — fail closed", async () => {
    const app = makeApp();
    // The deep chain's only real signer (childA) sits at depth 0, far below the
    // root; evaluating from the root exceeds MAX_QUORUM_DEPTH before reaching it.
    const headers = await quorumHeaders({
      quorumId: quorumIds.deep,
      members: [{ id: ids.childA, kp: keypairs.childA }],
      timestamp: FRESH_TS(),
      idempotencyKey: "idem-q-deep",
    });

    const res = await app.request(PATH, { method: "POST", headers, body: BODY });
    expect(res.status).toBe(403);
  });

  it("rejects malformed quorum credentials JSON", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-key-quorum-id": quorumIds.topLevel,
        "x-steward-key-quorum-credentials": "{not-json",
        "x-steward-request-timestamp": ts,
        "idempotency-key": "idem-q-malformed",
        "x-steward-signature": "p256=AAAA",
      },
      body: BODY,
    });

    expect(res.status).toBe(400);
  });
});

// ── HMAC regression: the symmetric path must still work unchanged ──────────

describe("authorizationSignature HMAC regression", () => {
  it("still verifies a valid HMAC-signed request", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: `https://api.test${PATH}`,
        tenantId: TENANT_ID,
        authorization: "Bearer token-a",
        timestamp: ts,
        idempotencyKey: "idem-hmac-ok",
        body: BODY,
      },
      HMAC_SECRET,
    );

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer token-a",
        "x-steward-tenant": TENANT_ID,
        "x-steward-request-timestamp": ts,
        "idempotency-key": "idem-hmac-ok",
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });

  it("still rejects a tampered HMAC-signed body", async () => {
    const app = makeApp();
    const ts = FRESH_TS();
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: `https://api.test${PATH}`,
        tenantId: TENANT_ID,
        timestamp: ts,
        idempotencyKey: "idem-hmac-tamper",
        body: BODY,
      },
      HMAC_SECRET,
    );

    const res = await app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
        "x-steward-request-timestamp": ts,
        "idempotency-key": "idem-hmac-tamper",
        "x-steward-signature": signature,
      },
      body: JSON.stringify({ value: "2000" }),
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });
});

// ── helpers ────────────────────────────────────────────────────────────────

/** Encode a fixed-width r||s P-256 signature as ASN.1 DER for the DER-accept test. */
function p1363ToDer(p1363: Uint8Array): Uint8Array {
  const r = p1363.subarray(0, 32);
  const s = p1363.subarray(32, 64);
  const encodeInt = (bytes: Uint8Array): number[] => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i += 1;
    let trimmed = Array.from(bytes.subarray(i));
    if (trimmed[0] & 0x80) trimmed = [0x00, ...trimmed];
    return [0x02, trimmed.length, ...trimmed];
  };
  const body = [...encodeInt(r), ...encodeInt(s)];
  return Uint8Array.from([0x30, body.length, ...body]);
}
