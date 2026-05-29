import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

let vaultRoutes: Awaited<typeof import("../routes/vault")>["vaultRoutes"];

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "vault-message-signing-test-master-password";
  process.env.STEWARD_ALLOW_UNSAFE_TYPED_DATA_SIGNING = "true";
  process.env.STEWARD_ALLOW_VAULT_UNSAFE_TYPED_DATA_SIGNING = "true";
  process.env.STEWARD_ALLOW_VAULT_TYPED_DATA_POLICY_BYPASS = "true";
  process.env.STEWARD_ALLOW_UNSAFE_SOLANA_TRANSACTION_SIGNING = "true";
  process.env.STEWARD_ALLOW_VAULT_UNSAFE_SOLANA_TRANSACTION_SIGNING = "true";
  process.env.STEWARD_ALLOW_VAULT_SOLANA_POLICY_BYPASS = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  ({ vaultRoutes } = await import("../routes/vault"));
});

afterAll(async () => {
  delete process.env.STEWARD_ALLOW_UNSAFE_TYPED_DATA_SIGNING;
  delete process.env.STEWARD_ALLOW_VAULT_UNSAFE_TYPED_DATA_SIGNING;
  delete process.env.STEWARD_ALLOW_VAULT_TYPED_DATA_POLICY_BYPASS;
  delete process.env.STEWARD_ALLOW_UNSAFE_SOLANA_TRANSACTION_SIGNING;
  delete process.env.STEWARD_ALLOW_VAULT_UNSAFE_SOLANA_TRANSACTION_SIGNING;
  delete process.env.STEWARD_ALLOW_VAULT_SOLANA_POLICY_BYPASS;
  await closeDb();
});

describe("vault message signing hardening", () => {
  it("fails closed by default because arbitrary messages bypass transaction policies", async () => {
    const res = await vaultRoutes.request("/agent-1/sign-message", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: "Sign this malicious login challenge" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Message signing is disabled");
  });

  it("ignores typed-data bypass env flags and remains disabled", async () => {
    const res = await vaultRoutes.request("/agent-1/sign-typed-data", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: { name: "Permit2", chainId: 8453 },
        types: {
          PermitSingle: [{ name: "spender", type: "address" }],
        },
        primaryType: "PermitSingle",
        value: { spender: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("EIP-712 typed data signing is disabled");
    expect(body.error).not.toContain("STEWARD_ALLOW_VAULT_TYPED_DATA_POLICY_BYPASS");
  });

  it("ignores Solana bypass env flags and remains disabled", async () => {
    const res = await vaultRoutes.request("/agent-1/sign-solana", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        transaction: "AQIDBA==",
        chainId: 101,
        to: "11111111111111111111111111111111",
        value: "1",
        broadcast: false,
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Serialized Solana transaction signing is disabled");
    expect(body.error).not.toContain("STEWARD_ALLOW_VAULT_SOLANA_POLICY_BYPASS");
  });

  it("fails closed for user-operation signing until calldata policy extraction exists", async () => {
    const res = await vaultRoutes.request("/agent-1/sign-user-operation", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("User operation signing is disabled");
  });

  it("fails closed for raw secp256k1 signing by default", async () => {
    const res = await vaultRoutes.request("/agent-1/sign-raw-hash", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        hash: "0x1111111111111111111111111111111111111111111111111111111111111111",
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Raw secp256k1 signing");
  });

  it("fails closed for EIP-7702 authorization signing by default", async () => {
    const res = await vaultRoutes.request("/agent-1/sign-authorization", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contractAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        chainId: 0,
        nonce: 0,
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("EIP-7702 authorization signing is disabled");
  });
});
