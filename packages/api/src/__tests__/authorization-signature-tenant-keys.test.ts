import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenantRequestSigningKeys, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { KeyStore } from "@stwd/vault";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

// The authorization-signature middleware runs before route authentication.
// Tenant-key decryption must therefore occur only for a named, well-formed,
// existing signing-key ID.

const TENANT_ID = `sig-keys-tenant-${Date.now()}`;
const KEY_ID = crypto.randomUUID();
const TENANT_KEY_SECRET = "stw_sig_testtenantkeysecret";
const STATIC_SECRET = "request-signing-secret-with-enough-entropy";
const PATH = "/vault/agent-1/sign";
const BODY = JSON.stringify({ value: "1000" });
const FRESH_TS = () => String(Math.floor(Date.now() / 1000));
let authorizationSignature: typeof import("../middleware/authorization-signature")["authorizationSignature"];
let createAuthorizationSignature: typeof import("../middleware/authorization-signature")["createAuthorizationSignature"];
let tenantKeyStoreConstructionCount = 0;

function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use(
    "*",
    authorizationSignature({
      required: true,
      secrets: [STATIC_SECRET],
      tenantKeyStoreFactory(masterPassword, masterSalt, domain) {
        tenantKeyStoreConstructionCount += 1;
        return new KeyStore(masterPassword, masterSalt, domain);
      },
    }),
  );
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
  process.env.STEWARD_KDF_SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  ({ authorizationSignature, createAuthorizationSignature } = await import(
    "../middleware/authorization-signature"
  ));

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

beforeEach(() => {
  tenantKeyStoreConstructionCount = 0;
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
    expect(tenantKeyStoreConstructionCount).toBe(1);
  });

  it("never falls back to an isolate-global KDF salt under a request snapshot", async () => {
    const app = makeApp();
    const headers = await signedWith(TENANT_KEY_SECRET, {
      "x-steward-signing-key-id": KEY_ID,
    });
    const response = await withRuntimeEnvironment(
      {
        STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD,
        STEWARD_KDF_SALT: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      },
      () =>
        app.request(PATH, {
          method: "POST",
          headers,
          body: BODY,
        }),
    );

    expect(response.status).toBe(401);
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
    expect(tenantKeyStoreConstructionCount).toBe(0);
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
    expect(tenantKeyStoreConstructionCount).toBe(0);
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
    expect(tenantKeyStoreConstructionCount).toBe(0);
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
    expect(tenantKeyStoreConstructionCount).toBe(0);
  });
});
