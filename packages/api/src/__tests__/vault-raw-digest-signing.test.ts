/**
 * Cross-curve raw digest signing (`POST /:agentId/sign-raw-digest`).
 *
 * The vault generalizes `sign-raw-hash` to sign an exactly-32-byte digest with
 * either the agent's secp256k1 (EVM) key or its ed25519 (Solana) key, while the
 * `stark` curve fails closed (no vetted starknet signing library is installed).
 *
 * This suite drives the real route end-to-end (admin session + recent MFA, the
 * audited env opt-in enabled) and cryptographically verifies BOTH curves:
 *  - secp256k1: the returned signature recovers to the agent's EVM address.
 *  - ed25519:   the returned signature verifies against the agent's Solana pubkey.
 * It also asserts `stark` and unknown curves are rejected (400) and that a
 * non-32-byte payload is rejected (400).
 */

import { afterAll, beforeAll, describe, expect, it, mock } from "bun:test";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { Hono } from "hono";
import { recoverAddress } from "viem";
import type { AppVariables } from "../services/context";

const dispatchWebhookMock = mock(() => {});
mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const TENANT_ID = `raw-digest-tenant-${Date.now()}`;
const AGENT_ID = `raw-digest-agent-${Date.now()}`;
const DENIED_AGENT_ID = `raw-digest-denied-agent-${Date.now()}`;
const DIGEST = "0x2222222222222222222222222222222222222222222222222222222222222222" as const;

/** Decode a base58 (Bitcoin/Solana alphabet) string to bytes — no extra deps. */
function base58ToBytes(s: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const ch of s) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base58 character: ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  let leadingZeros = 0;
  for (let i = 0; i < s.length && s[i] === "1"; i++) leadingZeros++;
  return new Uint8Array([...new Array<number>(leadingZeros).fill(0), ...bytes]);
}

/** Verify a detached Ed25519 signature (hex) over the digest by a base58 pubkey. */
function verifyEd25519(publicKeyBase58: string, digestHex: string, signatureHex: string): boolean {
  const x = Buffer.from(base58ToBytes(publicKeyBase58)).toString("base64url");
  const keyObject = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
  const payload = Buffer.from(digestHex.slice(2), "hex");
  return cryptoVerify(null, payload, keyObject, Buffer.from(signatureHex, "hex"));
}

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("userId", "raw-digest-admin");
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault cross-curve raw digest signing", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let evmAddress = "";
  let solanaAddress = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-raw-digest-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);
    process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING = "true";
    process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Raw Digest Tenant",
      apiKeyHash: "hash",
    });
    const identity = await new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
    }).createAgent(TENANT_ID, AGENT_ID, "Raw Digest Agent");
    await new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
    }).createAgent(TENANT_ID, DENIED_AGENT_ID, "Raw Digest Denied Agent");
    await getDb()
      .insert(policies)
      .values([
        {
          id: `${AGENT_ID}-raw-signing`,
          agentId: AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["tron", "sui"], allowedCurves: ["secp256k1", "ed25519"] },
        },
        {
          id: `${DENIED_AGENT_ID}-raw-signing`,
          agentId: DENIED_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["sui"], allowedCurves: ["ed25519"] },
        },
      ]);
    evmAddress = identity.walletAddress;
    solanaAddress = identity.walletAddresses?.solana ?? "";
    expect(solanaAddress).not.toBe("");
    app = await makeApp();
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING;
    delete process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING;
  });

  it("secp256k1: signs a 32-byte digest and recovers the agent EVM address", async () => {
    dispatchWebhookMock.mockClear();
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chain: "tron",
        curve: "secp256k1",
        payloadHex: DIGEST,
        referenceId: "secp-1",
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        signature: `0x${string}`;
        curve: string;
        payloadHex: typeof DIGEST;
        publicKey: string;
      };
    };

    expect(body.ok).toBe(true);
    expect(body.data.curve).toBe("secp256k1");
    expect(body.data.payloadHex).toBe(DIGEST);
    expect(body.data.publicKey.toLowerCase()).toBe(evmAddress.toLowerCase());

    const recovered = await recoverAddress({ hash: DIGEST, signature: body.data.signature });
    expect(recovered.toLowerCase()).toBe(evmAddress.toLowerCase());
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      AGENT_ID,
      "wallet.raw_signature.created",
      expect.objectContaining({
        kind: "raw_digest",
        chain: "tron",
        curve: "secp256k1",
        payloadHex: DIGEST,
        referenceId: "secp-1",
        publicKey: evmAddress,
      }),
    );
  });

  it("ed25519: signs a 32-byte digest and the signature verifies against the agent Solana pubkey", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chain: "sui",
        curve: "ed25519",
        payloadHex: DIGEST,
        referenceId: "ed-1",
      }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { signature: string; curve: string; payloadHex: typeof DIGEST; publicKey: string };
    };

    expect(body.ok).toBe(true);
    expect(body.data.curve).toBe("ed25519");
    expect(body.data.payloadHex).toBe(DIGEST);
    expect(body.data.publicKey).toBe(solanaAddress);
    expect(body.data.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(verifyEd25519(solanaAddress, DIGEST, body.data.signature)).toBe(true);
  });

  it("fails closed for the stark curve (400, not supported)", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chain: "starknet", curve: "stark", payloadHex: DIGEST }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("starknet raw signing is not supported");
  });

  it("rejects an unknown curve (400)", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chain: "tron", curve: "p256", payloadHex: DIGEST }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("curve must be");
  });

  it("rejects a non-32-byte payload (400)", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chain: "tron", curve: "secp256k1", payloadHex: "0x1234" }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("payloadHex must be a 32-byte hex string");
  });

  it("rejects curve mismatch for the requested chain before signing", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chain: "sui", curve: "secp256k1", payloadHex: DIGEST }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("sui raw signing requires ed25519");
  });

  it("rejects a supported chain when the agent raw-signing policy does not allow it", async () => {
    const response = await app.request(`/vault/${DENIED_AGENT_ID}/sign-raw-digest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chain: "tron", curve: "secp256k1", payloadHex: DIGEST }),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as {
      ok: boolean;
      error?: string;
      data?: { policyResults?: Array<{ type: string; passed: boolean; reason: string }> };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Raw digest signing rejected by policy");
    expect(body.data?.policyResults?.[0]).toMatchObject({
      type: "raw-signing-chain",
      passed: false,
    });
  });
});
