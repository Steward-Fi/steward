import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import {
  createStewardSolanaSigner,
  SOLANA_MAX_TRANSACTION_BYTES,
  StewardSignerError,
} from "../steward-signer";
import {
  legacyTransfer,
  SINK,
  STUB_BLOCKHASH,
  type StubSteward,
  startStubSteward,
  versionedTransfer,
} from "./harness";

const AGENT_ID = "agent-1";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJhZ2VudElkIjoiYWdlbnQtMSJ9.stub-signature";

const vaultKeypair = Keypair.fromSeed(new Uint8Array(32).fill(42));

let stub: StubSteward;

beforeAll(() => {
  stub = startStubSteward(vaultKeypair);
});

afterAll(() => {
  stub.stop();
});

beforeEach(() => {
  stub.setMode("sign");
  stub.requests.length = 0;
});

function newSigner(overrides: Record<string, unknown> = {}) {
  return createStewardSolanaSigner({
    baseUrl: stub.url,
    agentId: AGENT_ID,
    bearerToken: JWT,
    ...overrides,
  });
}

describe("createStewardSolanaSigner", () => {
  it("resolves the agent's Solana address from the vault and sends the bearer JWT", async () => {
    const signer = await newSigner();
    expect(signer.address).toBe(vaultKeypair.publicKey.toBase58());
    expect(signer.publicKey.equals(vaultKeypair.publicKey)).toBe(true);

    expect(stub.requests).toHaveLength(1);
    const req = stub.requests[0];
    expect(req.method).toBe("GET");
    expect(req.path).toBe(`/vault/${AGENT_ID}/addresses`);
    expect(req.headers.authorization).toBe(`Bearer ${JWT}`);
    expect(req.headers["x-steward-key"]).toBeUndefined();
  });

  it("skips the address lookup when the address is supplied", async () => {
    const signer = await newSigner({ address: vaultKeypair.publicKey.toBase58() });
    expect(signer.address).toBe(vaultKeypair.publicKey.toBase58());
    expect(stub.requests).toHaveLength(0);
  });

  it("uses X-Steward-Key when configured with an API key", async () => {
    await createStewardSolanaSigner({ baseUrl: stub.url, agentId: AGENT_ID, apiKey: "sk-test" });
    const req = stub.requests[0];
    expect(req.headers["x-steward-key"]).toBe("sk-test");
    expect(req.headers.authorization).toBeUndefined();
  });

  it("refuses construction without baseUrl or client", async () => {
    await expect(
      createStewardSolanaSigner({ agentId: AGENT_ID, bearerToken: JWT }),
    ).rejects.toThrow(/baseUrl/);
  });

  it("rejects empty agent ids and non-Solana chain ids before any API call", async () => {
    await expect(newSigner({ agentId: " " })).rejects.toThrow(/agentId/);
    await expect(newSigner({ chainId: 1 })).rejects.toThrow(/101.*102/);
    expect(stub.requests).toHaveLength(0);
  });
});

describe("signTransaction", () => {
  it("signs a legacy transaction through the vault with broadcast:false", async () => {
    const signer = await newSigner();
    const tx = legacyTransfer(signer.publicKey);

    const signed = await signer.signTransaction(tx);
    expect(signed).toBe(tx);
    expect(tx.verifySignatures()).toBe(true);

    const req = stub.requests.at(-1);
    expect(req?.method).toBe("POST");
    expect(req?.path).toBe(`/vault/${AGENT_ID}/sign-solana`);
    expect(req?.headers.authorization).toBe(`Bearer ${JWT}`);
    const body = req?.body as { transaction: string; broadcast: boolean; chainId: number };
    expect(body.broadcast).toBe(false);
    expect(body.chainId).toBe(101);
    expect(Buffer.from(body.transaction, "base64").length).toBeGreaterThan(0);
  });

  it("never asks the vault to broadcast, on every request", async () => {
    const signer = await newSigner();
    await signer.signAllTransactions([
      legacyTransfer(signer.publicKey),
      legacyTransfer(signer.publicKey),
    ]);
    const signBodies = stub.requests
      .filter((r) => r.path.endsWith("/sign-solana"))
      .map((r) => r.body as { broadcast?: boolean });
    expect(signBodies).toHaveLength(2);
    for (const body of signBodies) expect(body.broadcast).toBe(false);
  });

  it("preserves partial signatures added by co-signing keypairs", async () => {
    const signer = await newSigner();
    const mintKeypair = Keypair.fromSeed(new Uint8Array(32).fill(5));

    const tx = new Transaction();
    tx.add(
      SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: SINK, lamports: 1_000 }),
    );
    tx.add(
      SystemProgram.transfer({
        fromPubkey: mintKeypair.publicKey,
        toPubkey: SINK,
        lamports: 500,
      }),
    );
    tx.recentBlockhash = STUB_BLOCKHASH;
    tx.feePayer = signer.publicKey;
    tx.partialSign(mintKeypair);

    await signer.signTransaction(tx);
    expect(tx.verifySignatures()).toBe(true);
    const signerSlots = tx.signatures.map((s) => s.publicKey.toBase58());
    expect(signerSlots).toContain(signer.publicKey.toBase58());
    expect(signerSlots).toContain(mintKeypair.publicKey.toBase58());
    for (const slot of tx.signatures) expect(slot.signature).not.toBeNull();
  });

  it("rejects an invalid signature returned by the Steward API", async () => {
    const signer = await newSigner();
    stub.setMode("invalid-signature");
    await expect(signer.signTransaction(legacyTransfer(signer.publicKey))).rejects.toThrow(
      /invalid Solana signature/,
    );
  });

  it("rejects a response that changes an existing co-signer signature", async () => {
    const signer = await newSigner();
    const coSigner = Keypair.fromSeed(new Uint8Array(32).fill(6));
    const tx = new Transaction().add(
      SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: SINK, lamports: 1_000 }),
      SystemProgram.transfer({ fromPubkey: coSigner.publicKey, toPubkey: SINK, lamports: 1 }),
    );
    tx.recentBlockhash = STUB_BLOCKHASH;
    tx.feePayer = signer.publicKey;
    tx.partialSign(coSigner);
    stub.setMode("changed-cosigner");

    await expect(signer.signTransaction(tx)).rejects.toThrow(/changed an existing co-signer/);
  });

  it("rejects a configured Steward address that is not a required signer", async () => {
    const outsider = Keypair.fromSeed(new Uint8Array(32).fill(12)).publicKey;
    const signer = await newSigner({ address: outsider.toBase58() });
    const tx = legacyTransfer(vaultKeypair.publicKey);

    await expect(signer.signTransaction(tx)).rejects.toThrow(/not a required transaction signer/);
  });

  it("rejects malformed and oversized transaction encodings before any vault call", async () => {
    const signer = await newSigner();
    const before = stub.requests.length;
    await expect(signer.signSerializedTransaction("not base64!")).rejects.toThrow(
      /canonical base64/,
    );
    await expect(
      signer.signSerializedTransaction(
        Buffer.alloc(SOLANA_MAX_TRANSACTION_BYTES + 1).toString("base64"),
      ),
    ).rejects.toThrow(/canonical base64/);
    expect(stub.requests.length).toBe(before);
  });

  it("requires explicit non-broadcast and matching-chain proof from Steward", async () => {
    const signer = await newSigner();
    stub.setMode("missing-broadcast-proof");
    await expect(signer.signTransaction(legacyTransfer(signer.publicKey))).rejects.toThrow(
      /broadcast:false was honored/,
    );
    stub.setMode("wrong-chain");
    await expect(signer.signTransaction(legacyTransfer(signer.publicKey))).rejects.toThrow(
      /mismatched Solana chainId/,
    );
  });

  it("signs a v0 versioned transaction", async () => {
    const signer = await newSigner();
    const vtx = versionedTransfer(signer.publicKey);
    const unsignedBytes = vtx.serialize();

    const signed = await signer.signTransaction(vtx);
    expect(signed).toBe(vtx);

    // ed25519 is deterministic: signing the same bytes locally must match.
    const expected = (() => {
      const copy = versionedTransfer(signer.publicKey);
      void unsignedBytes;
      copy.sign([vaultKeypair]);
      return copy.signatures[0];
    })();
    expect(Buffer.from(vtx.signatures[0]).equals(Buffer.from(expected))).toBe(true);
  });

  it("forwards advisory to/value hints for the blind-signing path", async () => {
    const signer = await newSigner({
      hints: () => ({ to: SINK.toBase58(), value: "1000" }),
    });
    await signer.signTransaction(legacyTransfer(signer.publicKey));
    const body = stub.requests.at(-1)?.body as { to?: string; value?: string };
    expect(body.to).toBe(SINK.toBase58());
    expect(body.value).toBe("1000");
  });
});

describe("refusal propagation", () => {
  it("surfaces a policy rejection as StewardSignerError kind policy_rejected", async () => {
    const signer = await newSigner();
    stub.setMode("reject");
    const before = stub.requests.length;

    const err = await signer.signTransaction(legacyTransfer(signer.publicKey)).then(
      () => {
        throw new Error("expected a rejection");
      },
      (e: unknown) => e,
    );

    expect(err).toBeInstanceOf(StewardSignerError);
    const signerErr = err as StewardSignerError;
    expect(signerErr.kind).toBe("policy_rejected");
    expect(signerErr.status).toBe(403);
    expect(signerErr.txId).toBe("tx-reject-1");
    expect(signerErr.policyResults).toHaveLength(1);
    expect(signerErr.message).toContain("daily cap 0.5 SOL exceeded");
    expect(stub.requests.length - before).toBe(1);
  });

  it("surfaces manual-approval queueing as kind pending_approval with the txId", async () => {
    const signer = await newSigner();
    stub.setMode("pending");

    const err = await signer.signTransaction(legacyTransfer(signer.publicKey)).then(
      () => {
        throw new Error("expected a pending refusal");
      },
      (e: unknown) => e,
    );

    const signerErr = err as StewardSignerError;
    expect(signerErr).toBeInstanceOf(StewardSignerError);
    expect(signerErr.kind).toBe("pending_approval");
    expect(signerErr.txId).toBe("tx-pending-1");
    expect(signerErr.message).toMatch(/approval/i);
  });

  it("surfaces a scope refusal as kind auth", async () => {
    const signer = await newSigner();
    stub.setMode("forbidden");

    const err = await signer.signTransaction(legacyTransfer(signer.publicKey)).then(
      () => {
        throw new Error("expected an auth refusal");
      },
      (e: unknown) => e,
    );

    const signerErr = err as StewardSignerError;
    expect(signerErr).toBeInstanceOf(StewardSignerError);
    expect(signerErr.kind).toBe("auth");
    expect(signerErr.status).toBe(403);
    expect(signerErr.message).toContain("token scope");
  });
});
