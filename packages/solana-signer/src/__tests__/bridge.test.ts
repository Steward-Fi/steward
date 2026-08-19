import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { connect } from "node:net";
import { Keypair, Transaction } from "@solana/web3.js";
import {
  BRIDGE_MAX_BODY_BYTES,
  BRIDGE_MAX_TOKEN_BYTES,
  BRIDGE_MIN_TOKEN_BYTES,
  BRIDGE_TOKEN_ENV,
  BRIDGE_TOKEN_HEADER,
  startSignerBridge,
} from "../bridge";
import { createStewardSolanaSigner, type StewardSolanaSigner } from "../steward-signer";
import { legacyTransfer, type StubSteward, startStubSteward } from "./harness";

const vaultKeypair = Keypair.fromSeed(new Uint8Array(32).fill(11));

let stub: StubSteward;
let signer: StewardSolanaSigner;
let bridgeUrl: string;
let bridgeToken: string;
let closeBridge: () => Promise<void>;
let envTokenBefore: string | undefined;

beforeAll(async () => {
  // The suite must see the DEFAULT token path (a random per-session secret),
  // so shield it from any ambient env token; restored in afterAll.
  envTokenBefore = process.env[BRIDGE_TOKEN_ENV];
  delete process.env[BRIDGE_TOKEN_ENV];

  stub = startStubSteward(vaultKeypair);
  signer = await createStewardSolanaSigner({
    baseUrl: stub.url,
    agentId: "agent-bridge",
    bearerToken: "stub.jwt.token",
  });
  const bridge = await startSignerBridge(signer);
  bridgeUrl = bridge.url;
  bridgeToken = bridge.token;
  closeBridge = bridge.close;
});

afterAll(async () => {
  await closeBridge();
  stub.stop();
  if (envTokenBefore !== undefined) process.env[BRIDGE_TOKEN_ENV] = envTokenBefore;
});

beforeEach(() => {
  stub.setMode("sign");
});

/** fetch with this session's shared secret in the bridge token header. */
function authed(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${bridgeUrl}${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), [BRIDGE_TOKEN_HEADER]: bridgeToken },
  });
}

/** Send exact duplicate fields without Fetch/Headers combining them. */
async function rawBridgeStatus(headerLines: string[]): Promise<number> {
  const url = new URL(bridgeUrl);
  return new Promise<number>((resolve, reject) => {
    const socket = connect(Number(url.port), url.hostname);
    let response = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => {
      socket.write(
        [
          `GET /pubkey HTTP/1.1`,
          `Host: ${url.host}`,
          ...headerLines,
          "Connection: close",
          "",
          "",
        ].join("\r\n"),
      );
    });
    socket.on("data", (chunk) => {
      response += chunk;
    });
    socket.on("end", () => {
      const match = /^HTTP\/1\.1 (\d{3}) /.exec(response);
      if (!match) return reject(new Error("bridge returned no HTTP status"));
      resolve(Number(match[1]));
    });
    socket.on("error", reject);
  });
}

describe("signer bridge", () => {
  it("serves the agent address on GET /pubkey", async () => {
    const res = await authed("/pubkey");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ address: vaultKeypair.publicKey.toBase58() });
  });

  it("round-trips a serialized transaction through /sign-transaction", async () => {
    const tx = legacyTransfer(vaultKeypair.publicKey);
    const unsigned = tx.serialize({ requireAllSignatures: false }).toString("base64");

    const res = await authed("/sign-transaction", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transaction: unsigned }),
    });
    expect(res.status).toBe(200);
    const { transaction } = (await res.json()) as { transaction: string };
    const signed = Transaction.from(Buffer.from(transaction, "base64"));
    expect(signed.verifySignatures()).toBe(true);
  });

  it("maps a policy refusal to a clean 403 JSON error", async () => {
    stub.setMode("reject");
    const tx = legacyTransfer(vaultKeypair.publicKey);
    const unsigned = tx.serialize({ requireAllSignatures: false }).toString("base64");

    const res = await authed("/sign-transaction", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transaction: unsigned }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; kind: string; txId?: string };
    expect(body.kind).toBe("policy_rejected");
    expect(body.txId).toBe("tx-reject-1");
    expect(body.error).toContain("daily cap 0.5 SOL exceeded");
  });

  it("fails closed on /sign-message with 501", async () => {
    const res = await authed("/sign-message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: Buffer.from("hello").toString("base64") }),
    });
    expect(res.status).toBe(501);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/not raw messages/);
  });

  it("rejects a missing transaction field with 400 before any vault call", async () => {
    const before = stub.requests.length;
    const res = await authed("/sign-transaction", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    expect(stub.requests.length).toBe(before);
  });

  it("requires JSON content type before reading or signing", async () => {
    const before = stub.requests.length;
    const res = await authed("/sign-transaction", {
      method: "POST",
      body: JSON.stringify({ transaction: "AAAA" }),
    });
    expect(res.status).toBe(415);
    expect(stub.requests.length).toBe(before);
  });

  it("rejects oversized request bodies before any vault call", async () => {
    const before = stub.requests.length;
    const res = await authed("/sign-transaction", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transaction: "A".repeat(BRIDGE_MAX_BODY_BYTES) }),
    });
    expect(res.status).toBe(413);
    expect(stub.requests.length).toBe(before);
  });
});

describe("bridge shared-secret auth", () => {
  it("arms a random per-session token by default", () => {
    expect(bridgeToken).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses a request without the token header, before any vault call", async () => {
    const before = stub.requests.length;
    const tx = legacyTransfer(vaultKeypair.publicKey);
    const unsigned = tx.serialize({ requireAllSignatures: false }).toString("base64");
    const res = await fetch(`${bridgeUrl}/sign-transaction`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transaction: unsigned }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain(BRIDGE_TOKEN_HEADER);
    expect(stub.requests.length).toBe(before);

    const pubkey = await fetch(`${bridgeUrl}/pubkey`);
    expect(pubkey.status).toBe(401);
  });

  it("refuses a wrong token with 401", async () => {
    const res = await fetch(`${bridgeUrl}/pubkey`, {
      headers: { [BRIDGE_TOKEN_HEADER]: `${bridgeToken}x` },
    });
    expect(res.status).toBe(401);
  });

  it("accepts the same secret as Authorization: Bearer (AgentNet's remote-wallet client)", async () => {
    const res = await fetch(`${bridgeUrl}/pubkey`, {
      headers: { authorization: `Bearer ${bridgeToken}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { address: string };
    expect(body.address.length).toBeGreaterThan(30);
  });

  it("treats the bearer scheme case-insensitively", async () => {
    const res = await fetch(`${bridgeUrl}/pubkey`, {
      headers: { authorization: `bearer ${bridgeToken}` },
    });
    expect(res.status).toBe(200);
  });

  it("refuses a wrong bearer token with 401", async () => {
    const res = await fetch(`${bridgeUrl}/pubkey`, {
      headers: { authorization: `Bearer ${bridgeToken}x` },
    });
    expect(res.status).toBe(401);
  });

  it("rejects ambiguous bearer whitespace, folded values, and duplicate fields", async () => {
    for (const authorization of [
      `Bearer  ${bridgeToken}`,
      `Bearer\t${bridgeToken}`,
      `Bearer ${bridgeToken}, Bearer ${bridgeToken}`,
    ]) {
      const res = await fetch(`${bridgeUrl}/pubkey`, { headers: { authorization } });
      expect(res.status).toBe(401);
    }
    expect(
      await rawBridgeStatus([
        `Authorization: Bearer ${bridgeToken}`,
        `Authorization: Bearer ${bridgeToken}`,
      ]),
    ).toBe(401);
    expect(
      await rawBridgeStatus([
        `${BRIDGE_TOKEN_HEADER}: ${bridgeToken}`,
        `${BRIDGE_TOKEN_HEADER}: ${bridgeToken}`,
        `Authorization: Bearer ${bridgeToken}`,
      ]),
    ).toBe(401);
  });

  it("bounds bearer and configured tokens without reflecting them", async () => {
    const canary = "TOKEN_SECRET_CANARY";
    const oversized = `${canary}${"a".repeat(BRIDGE_MAX_TOKEN_BYTES)}`;
    const res = await fetch(`${bridgeUrl}/pubkey`, {
      headers: { authorization: `Bearer ${oversized}` },
    });
    expect(res.status).toBe(401);
    expect(await res.text()).not.toContain(canary);
    await expect(startSignerBridge(signer, { token: oversized })).rejects.toThrow(
      new RegExp(`at most ${BRIDGE_MAX_TOKEN_BYTES} bytes`),
    );
  });

  it("the custom header wins over a bearer header when both are present", async () => {
    const res = await fetch(`${bridgeUrl}/pubkey`, {
      headers: { [BRIDGE_TOKEN_HEADER]: `${bridgeToken}x`, authorization: `Bearer ${bridgeToken}` },
    });
    expect(res.status).toBe(401);
  });

  it(`honors ${BRIDGE_TOKEN_ENV} from the env, the var both sides read`, async () => {
    const envToken = "e".repeat(BRIDGE_MIN_TOKEN_BYTES);
    process.env[BRIDGE_TOKEN_ENV] = envToken;
    try {
      const bridge = await startSignerBridge(signer);
      expect(bridge.token).toBe(envToken);
      const res = await fetch(`${bridge.url}/pubkey`, {
        headers: { [BRIDGE_TOKEN_HEADER]: envToken },
      });
      expect(res.status).toBe(200);
      await bridge.close();
    } finally {
      delete process.env[BRIDGE_TOKEN_ENV];
    }
  });

  it("rejects empty and weak shared secrets", async () => {
    await expect(startSignerBridge(signer, { token: "" })).rejects.toThrow(/at least 32 bytes/);
    await expect(startSignerBridge(signer, { token: "too-short" })).rejects.toThrow(
      /at least 32 bytes/,
    );
  });

  it("rejects non-loopback bind hosts", async () => {
    await expect(startSignerBridge(signer, { host: "0.0.0.0" })).rejects.toThrow(
      /loopback IP literal/,
    );
    await expect(startSignerBridge(signer, { host: "localhost" })).rejects.toThrow(
      /loopback IP literal/,
    );
  });

  it("allows only one signing request in flight", async () => {
    let release!: () => void;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const blockingSigner: StewardSolanaSigner = {
      address: signer.address,
      publicKey: signer.publicKey,
      async signTransaction(tx) {
        return tx;
      },
      async signAllTransactions(txs) {
        return txs;
      },
      async signSerializedTransaction(transaction) {
        entered();
        await blocked;
        return transaction;
      },
    };
    const concurrentBridge = await startSignerBridge(blockingSigner);
    const tx = legacyTransfer(signer.publicKey)
      .serialize({ requireAllSignatures: false })
      .toString("base64");
    const request = () =>
      fetch(`${concurrentBridge.url}/sign-transaction`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [BRIDGE_TOKEN_HEADER]: concurrentBridge.token,
        },
        body: JSON.stringify({ transaction: tx }),
      });
    const first = request();
    await started;
    const second = await request();
    expect(second.status).toBe(429);
    release();
    expect((await first).status).toBe(200);
    await concurrentBridge.close();
  });

  it("returns a bounded 502 when the signer throws a hostile value", async () => {
    const hostile = new Proxy(new Error("secret diagnostic"), {
      get(_target, property) {
        if (property === "message") throw new Error("message trap secret");
        return Reflect.get(_target, property);
      },
      getPrototypeOf() {
        throw new Error("prototype trap secret");
      },
    });
    const hostileSigner: StewardSolanaSigner = {
      address: signer.address,
      publicKey: signer.publicKey,
      async signTransaction(tx) {
        return tx;
      },
      async signAllTransactions(txs) {
        return txs;
      },
      async signSerializedTransaction() {
        throw hostile;
      },
    };
    const hostileBridge = await startSignerBridge(hostileSigner);
    try {
      const transaction = legacyTransfer(signer.publicKey)
        .serialize({ requireAllSignatures: false })
        .toString("base64");
      const response = await fetch(`${hostileBridge.url}/sign-transaction`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [BRIDGE_TOKEN_HEADER]: hostileBridge.token,
        },
        body: JSON.stringify({ transaction }),
      });
      expect(response.status).toBe(502);
      const body = (await response.json()) as { error: string; kind: string };
      expect(body).toEqual({ error: "Steward signing service failed", kind: "api" });
    } finally {
      await hostileBridge.close();
    }
  });
});
