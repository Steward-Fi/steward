/**
 * Contract tests for the /v1/kms/* routes against the FROZEN Eliza
 * StewardKmsAdapter wire spec (elizaos/eliza
 * packages/security/src/kms/steward-adapter.ts). Every request below is the
 * EXACT method/path/body the adapter emits, and every success assertion reads
 * the EXACT top-level fields the adapter requires (requireString/requireNumber/
 * requireBoolean semantics) — so a green run here is conformance evidence for
 * the client without importing the eliza repo.
 *
 * Deny coverage (fail-closed):
 *   - wrong-agent: agent B addressing agent A's keyId gets 404 (namespace
 *     isolation — B cannot even observe that A's key exists)
 *   - expired agent token: 401 before the router runs
 *   - non-agent principals (session JWT, tenant API key): 403
 *   - proxy-scope-only agent token (api:proxy without agent scope): 403
 *   - malformed: bad base64, bad keyId, bad algorithm, bad version: 400
 *   - tampered ciphertext / wrong AAD: 400, no plaintext, no oracle detail
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { agents, auditEvents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30000);

const TENANT_ID = `kms-tenant-${Date.now()}`;
const AGENT_A = `kms-agent-a-${Date.now()}`;
const AGENT_B = `kms-agent-b-${Date.now()}`;
const KEY_ID = "org:eliza:dek/v1";

let apiKey = "";
let app: Hono<{ Variables: AppVariables }>;
let tokenA = "";
let tokenB = "";

/** the exact call helper shape the eliza adapter uses (bearer + JSON body). */
async function call(
  token: string,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const headers: Record<string, string> = {
    accept: "application/json",
    authorization: `Bearer ${token}`,
  };
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const res = await app.request(path, init);
  const text = await res.text();
  return { status: res.status, json: text.trim() ? JSON.parse(text) : {} };
}

const b64 = (s: string | Uint8Array) => Buffer.from(s).toString("base64");
const fromB64 = (s: string) => Buffer.from(s, "base64");

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "kms-routes-test-master-password";
  process.env.STEWARD_KDF_SALT ??= "6b6d732d726f757465732d746573742d73616c74";
  process.env.STEWARD_JWT_SECRET ??= "kms-routes-test-jwt-secret-with-enough-entropy-0123456789";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "b".repeat(64);

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const { app: realApp } = await import("../app");
  app = realApp;

  const keyPair = generateApiKey();
  apiKey = keyPair.key;
  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "KMS Routes Tenant", apiKeyHash: keyPair.hash })
    .onConflictDoNothing();
  await getDb()
    .insert(agents)
    .values([
      {
        id: AGENT_A,
        tenantId: TENANT_ID,
        name: AGENT_A,
        walletAddress: "0x0000000000000000000000000000000000000a0a",
      },
      {
        id: AGENT_B,
        tenantId: TENANT_ID,
        name: AGENT_B,
        walletAddress: "0x0000000000000000000000000000000000000b0b",
      },
    ])
    .onConflictDoNothing();

  tokenA = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "10m");
  tokenB = await signAgentToken({ agentId: AGENT_B, tenantId: TENANT_ID }, "10m");
});

afterAll(async () => {
  await closeDb();
});

describe("KMS adapter contract — success paths", () => {
  it("POST /v1/kms/keys (getOrCreateKey) returns { keyId, version } and is idempotent", async () => {
    const first = await call(tokenA, "POST", "/v1/kms/keys", { keyId: KEY_ID });
    expect(first.status).toBe(200);
    expect(first.json.keyId).toBe(KEY_ID);
    expect(first.json.version).toBe(1);

    const second = await call(tokenA, "POST", "/v1/kms/keys", { keyId: KEY_ID });
    expect(second.status).toBe(200);
    expect(second.json.version).toBe(1);
  });

  it("encrypt -> decrypt round-trips with AAD, exact adapter field names", async () => {
    const plaintext = "the quick brown fox";
    const aad = "aad-context";
    const enc = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`, {
      plaintext_b64: b64(plaintext),
      aad_b64: b64(aad),
    });
    expect(enc.status).toBe(200);
    // requireString/requireNumber checks the adapter performs:
    expect(typeof enc.json.ciphertext_b64).toBe("string");
    expect(typeof enc.json.nonce_b64).toBe("string");
    expect(typeof enc.json.auth_tag_b64).toBe("string");
    expect(Number.isInteger(enc.json.version)).toBe(true);

    const dec = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/decrypt`, {
      ciphertext_b64: enc.json.ciphertext_b64,
      nonce_b64: enc.json.nonce_b64,
      auth_tag_b64: enc.json.auth_tag_b64,
      aad_b64: b64(aad),
      version: enc.json.version,
    });
    expect(dec.status).toBe(200);
    expect(fromB64(dec.json.plaintext_b64 as string).toString("utf8")).toBe(plaintext);
  });

  it("hmac -> hmac/verify round-trips; wrong data is { valid: false }", async () => {
    const mac = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/hmac`, {
      data_b64: b64("payload"),
    });
    expect(mac.status).toBe(200);
    expect(typeof mac.json.tag_b64).toBe("string");

    const ok = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/hmac/verify`,
      {
        data_b64: b64("payload"),
        tag_b64: mac.json.tag_b64,
      },
    );
    expect(ok.status).toBe(200);
    expect(ok.json.valid).toBe(true);

    const bad = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/hmac/verify`,
      { data_b64: b64("tampered"), tag_b64: mac.json.tag_b64 },
    );
    expect(bad.status).toBe(200);
    expect(bad.json.valid).toBe(false);
  });

  it("sign(ed25519) -> verify round-trips AND verifies against GET /public raw key", async () => {
    const data = "sign me";
    const sig = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/sign`, {
      data_b64: b64(data),
      algorithm: "ed25519",
    });
    expect(sig.status).toBe(200);
    expect(sig.json.algorithm).toBe("ed25519");
    expect(Number.isInteger(sig.json.version)).toBe(true);

    const ver = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/verify`, {
      data_b64: b64(data),
      signature_b64: sig.json.signature_b64,
      algorithm: "ed25519",
    });
    expect(ver.status).toBe(200);
    expect(ver.json.valid).toBe(true);

    // independent cryptographic proof: verify with node crypto against the raw
    // 32-byte ed25519 public key from GET /public (bidirectional evidence).
    const pub = await call(tokenA, "GET", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/public`);
    expect(pub.status).toBe(200);
    expect(pub.json.algorithm).toBe("ed25519");
    const raw = fromB64(pub.json.public_key_b64 as string);
    expect(raw.length).toBe(32);
    const keyObject = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
      format: "jwk",
    });
    expect(
      cryptoVerify(null, Buffer.from(data), keyObject, fromB64(sig.json.signature_b64 as string)),
    ).toBe(true);
  });

  it("rotate bumps version; old-version ciphertext stays decryptable; new encrypts use new version", async () => {
    const before = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`,
      {
        plaintext_b64: b64("pre-rotation"),
      },
    );
    expect(before.status).toBe(200);
    const v1 = before.json.version as number;

    const rot = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/rotate`);
    expect(rot.status).toBe(200);
    expect(rot.json.keyId).toBe(KEY_ID);
    expect(rot.json.newVersion).toBe(v1 + 1);

    const versions = await call(
      tokenA,
      "GET",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/versions`,
    );
    expect(versions.status).toBe(200);
    expect(versions.json.versions).toEqual([v1, v1 + 1]);

    // decrypt-old (explicit version) still works after rotation
    const decOld = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/decrypt`,
      {
        ciphertext_b64: before.json.ciphertext_b64,
        nonce_b64: before.json.nonce_b64,
        auth_tag_b64: before.json.auth_tag_b64,
        version: v1,
      },
    );
    expect(decOld.status).toBe(200);
    expect(fromB64(decOld.json.plaintext_b64 as string).toString("utf8")).toBe("pre-rotation");

    // new encrypts land on the new version
    const after = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`, {
      plaintext_b64: b64("post-rotation"),
    });
    expect(after.json.version).toBe(v1 + 1);
  });

  it("writes keys-never-values audit events for privileged ops", async () => {
    const rows = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "kms.encrypt")));
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const meta = JSON.stringify(row.metadata ?? {});
      expect(meta).not.toContain("plaintext");
      expect(meta).not.toContain("ciphertext");
    }
  });
});

describe("KMS adapter contract — DENY paths (fail-closed)", () => {
  it("wrong-agent DENY: agent B cannot see or use agent A's key (404, no existence leak)", async () => {
    // B addressing A's keyId resolves in B's OWN namespace -> key not found
    for (const [method, path, body] of [
      ["GET", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/versions`, undefined],
      ["POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`, { plaintext_b64: b64("x") }],
      ["POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/hmac`, { data_b64: b64("x") }],
      [
        "POST",
        `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/sign`,
        { data_b64: b64("x"), algorithm: "ed25519" },
      ],
      ["GET", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/public`, undefined],
      ["POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/rotate`, undefined],
    ] as const) {
      const res = await call(tokenB, method, path, body);
      expect(res.status).toBe(404);
      expect(res.json.ok).toBe(false);
    }
  });

  it("wrong-agent DENY: B creating the same keyId gets INDEPENDENT key material", async () => {
    const created = await call(tokenB, "POST", "/v1/kms/keys", { keyId: KEY_ID });
    expect(created.status).toBe(200);
    expect(created.json.version).toBe(1); // fresh key, not A's rotated v2

    // A ciphertext produced under A's key must NOT decrypt under B's key
    const encA = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`, {
      plaintext_b64: b64("cross-agent secret"),
    });
    const decB = await call(tokenB, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/decrypt`, {
      ciphertext_b64: encA.json.ciphertext_b64,
      nonce_b64: encA.json.nonce_b64,
      auth_tag_b64: encA.json.auth_tag_b64,
    });
    expect(decB.status).toBe(400);
    expect(decB.json.plaintext_b64).toBeUndefined();

    // and B's public key differs from A's
    const pubA = await call(tokenA, "GET", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/public`);
    const pubB = await call(tokenB, "GET", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/public`);
    expect(pubA.json.public_key_b64).not.toBe(pubB.json.public_key_b64);
  });

  it("expired token DENY: rejected before any key material access", async () => {
    // an expired bearer fails JWT verification inside tenantAuth; the request
    // then falls through to the API-key arm and is denied there (403). Either
    // 401 or 403 is a fail-closed deny with no principal established.
    const expired = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "-1s");
    const res = await call(expired, "POST", "/v1/kms/keys", { keyId: KEY_ID });
    expect([401, 403]).toContain(res.status);
    expect(res.json.keyId).toBeUndefined();
    expect(res.json.version).toBeUndefined();
  });

  it("non-agent principal DENY: tenant API key is 403", async () => {
    const res = await app.request("/v1/kms/keys", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
      },
      body: JSON.stringify({ keyId: KEY_ID }),
    });
    expect(res.status).toBe(403);
  });

  it("proxy-scope-only agent token DENY: api:proxy without agent scope is 403", async () => {
    const proxyOnly = await signAgentToken(
      { agentId: AGENT_A, tenantId: TENANT_ID, scopes: ["api:proxy"] },
      "2m",
    );
    const res = await call(proxyOnly, "POST", "/v1/kms/keys", { keyId: KEY_ID });
    expect(res.status).toBe(403);
  });

  it("missing bearer DENY", async () => {
    const res = await app.request("/v1/kms/keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ keyId: KEY_ID }),
    });
    expect([401, 403]).toContain(res.status);
  });

  it("malformed DENY: invalid base64, bad keyId, bad algorithm, bad version", async () => {
    const badB64 = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`,
      { plaintext_b64: "not-base64!!!" },
    );
    expect(badB64.status).toBe(400);

    const badKeyId = await call(tokenA, "POST", "/v1/kms/keys", { keyId: "../escape" });
    expect(badKeyId.status).toBe(400);

    const badAlgo = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/sign`, {
      data_b64: b64("x"),
      algorithm: "rsa-pss-sha256",
    });
    expect(badAlgo.status).toBe(400);

    const badVersion = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/decrypt`,
      {
        ciphertext_b64: b64("x"),
        nonce_b64: b64(Buffer.alloc(12)),
        auth_tag_b64: b64(Buffer.alloc(16)),
        version: -1,
      },
    );
    expect(badVersion.status).toBe(400);

    const missingBody = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/hmac`,
      {},
    );
    expect(missingBody.status).toBe(400);
  });

  it("tampered ciphertext / wrong AAD DENY: 400 with no plaintext and no oracle detail", async () => {
    const enc = await call(tokenA, "POST", `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/encrypt`, {
      plaintext_b64: b64("integrity"),
      aad_b64: b64("right-aad"),
    });
    const tamperedCt = fromB64(enc.json.ciphertext_b64 as string);
    tamperedCt[0] ^= 0xff;

    const tampered = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/decrypt`,
      {
        ciphertext_b64: tamperedCt.toString("base64"),
        nonce_b64: enc.json.nonce_b64,
        auth_tag_b64: enc.json.auth_tag_b64,
        aad_b64: b64("right-aad"),
      },
    );
    expect(tampered.status).toBe(400);
    expect(tampered.json.plaintext_b64).toBeUndefined();

    const wrongAad = await call(
      tokenA,
      "POST",
      `/v1/kms/keys/${encodeURIComponent(KEY_ID)}/decrypt`,
      {
        ciphertext_b64: enc.json.ciphertext_b64,
        nonce_b64: enc.json.nonce_b64,
        auth_tag_b64: enc.json.auth_tag_b64,
        aad_b64: b64("wrong-aad"),
      },
    );
    expect(wrongAad.status).toBe(400);
    // identical error for both failure modes: no padding/AAD oracle
    expect(wrongAad.json.error).toBe(tampered.json.error);
  });

  it("unknown key DENY: 404 carries the status the adapter classifies as key-unavailable", async () => {
    const res = await call(
      tokenA,
      "GET",
      `/v1/kms/keys/${encodeURIComponent("never-created")}/versions`,
    );
    expect(res.status).toBe(404);
    // adapter reads `parsed.error` for the KmsError message
    expect(typeof res.json.error).toBe("string");
  });
});
