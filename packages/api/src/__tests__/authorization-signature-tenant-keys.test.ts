import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenantRequestSigningKeys, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { KeyStore } from "@stwd/vault";
import { Hono } from "hono";
import {
  authorizationSignature,
  createAuthorizationSignature,
} from "../middleware/authorization-signature";
import type { AppVariables } from "../services/context";

// SEC-010 re-audit regression: the authorization-signature middleware is mounted
// globally and runs BEFORE route auth. Tenant-key decryption costs a scrypt KDF
// per candidate, so an unauthenticated request bearing signature headers could
// previously force 1+N scrypt evaluations per request (CPU-amplification DoS).
// The middleware must only pay that cost when the request names a specific,
// well-formed, EXISTING X-Steward-Signing-Key-Id.

const TENANT_ID = `sig-keys-tenant-${Date.now()}`;
const KEY_ID = crypto.randomUUID();
const TENANT_KEY_SECRET = "stw_sig_testtenantkeysecret";
const STATIC_SECRET = "request-signing-secret-with-enough-entropy";
const PATH = "/vault/agent-1/sign";
const BODY = JSON.stringify({ value: "1000" });
const FRESH_TS = () => String(Math.floor(Date.now() / 1000));

function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", authorizationSignature({ required: true, secrets: [STATIC_SECRET] }));
  app.post("/vault/:agentId/sign", (c) =>
    c.json({ ok: true, verified: Boolean(c.get("requestSignatureVerified")) }),
  );
  return app;
}

async function signedWith(secret: string, extraHeaders: Record<string, string> = {}) {
  const timestamp = FRESH_TS();
  const signature = await createAuthorizationSignature(
    {
      method: "POST",
      url: `https://api.test${PATH}`,
      tenantId: TENANT_ID,
      timestamp,
      idempotencyKey: "idem-key-123",
      body: BODY,
    },
    secret,
  );
  return {
    "content-type": "application/json",
    "x-steward-tenant": TENANT_ID,
    "x-steward-request-timestamp": timestamp,
    "idempotency-key": "idem-key-123",
    "x-steward-signature": signature,
    ...extraHeaders,
  };
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "sig-keys-master-password";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  await getDb()
    .insert(tenants)
    .values({ id: TENANT_ID, name: "Signature Keys Tenant", apiKeyHash: "h" });

  const encrypted = new KeyStore(
    process.env.STEWARD_MASTER_PASSWORD,
    undefined,
    "secret-vault",
  ).encrypt(TENANT_KEY_SECRET, {
    tenantId: TENANT_ID,
    name: `request-signing-key:${KEY_ID}`,
    version: 1,
  });
  await getDb().insert(tenantRequestSigningKeys).values({
    id: KEY_ID,
    tenantId: TENANT_ID,
    name: "primary",
    secretCiphertext: encrypted.ciphertext,
    secretIv: encrypted.iv,
    secretAuthTag: encrypted.tag,
    secretSalt: encrypted.salt,
    secretPrefix: "stw_sig_test...cret",
    status: "active",
  });
});

afterAll(async () => {
  await closeDb();
});

describe("authorizationSignature tenant signing keys", () => {
  it("verifies a request signed with a named tenant signing key", async () => {
    const app = makeApp();

    const res = await app.request(PATH, {
      method: "POST",
      headers: await signedWith(TENANT_KEY_SECRET, { "x-steward-signing-key-id": KEY_ID }),
      body: BODY,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });

  it("rejects an unknown (well-formed) signing key id without decrypt work", async () => {
    const app = makeApp();

    const res = await app.request(PATH, {
      method: "POST",
      headers: await signedWith(TENANT_KEY_SECRET, {
        "x-steward-signing-key-id": crypto.randomUUID(),
      }),
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid signing key id" });
  });

  it("rejects a malformed signing key id cheaply (no uuid DB error)", async () => {
    const app = makeApp();

    const res = await app.request(PATH, {
      method: "POST",
      headers: await signedWith(TENANT_KEY_SECRET, {
        "x-steward-signing-key-id": "not-a-uuid",
      }),
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid signing key id" });
  });

  it("does not use tenant signing keys when no key id is named", async () => {
    const app = makeApp();

    // Signed with the tenant key but no X-Steward-Signing-Key-Id: the static
    // secret does not match, and the tenant key must NOT be tried (fail closed
    // as "Invalid request signature", not silently verified).
    const res = await app.request(PATH, {
      method: "POST",
      headers: await signedWith(TENANT_KEY_SECRET),
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });

  it("still verifies key-id-less requests signed with a configured static secret", async () => {
    const app = makeApp();

    const res = await app.request(PATH, {
      method: "POST",
      headers: await signedWith(STATIC_SECRET),
      body: BODY,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });
});
