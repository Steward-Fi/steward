/**
 * Monero transfer + balance routes: policy gating (raw-signing-chain presence
 * and allowlists), idempotency, fee caps, referenceId dedupe, signing freeze
 * (423), transactions/audit rows, and the two-phase prepare→relay flow.
 *
 * The monero-wallet-rpc sidecar is simulated by a scripted global fetch so
 * the REAL MoneroWalletRpcBackend code path runs with zero network. Key and
 * address crypto is covered by the vault package's official-vector tests.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, policies, tenants, transactions, vaultSigningFreezes } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  generateMoneroWallet,
  type MoneroBalanceResult,
  type MoneroKeyPayloadV1,
  type MoneroTransferDestination,
  type MoneroWalletBackend,
  type PreparedMoneroTransfer,
  Vault,
} from "@stwd/vault";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `monero-tenant-${Date.now()}`;
const AGENT_ID = `monero-agent-${Date.now()}`;
const NO_POLICY_AGENT_ID = `monero-nopolicy-agent-${Date.now()}`;
const WRONG_CHAIN_AGENT_ID = `monero-wrongchain-agent-${Date.now()}`;
const SPEND_LIMIT_AGENT_ID = `monero-spend-agent-${Date.now()}`;
const FROZEN_AGENT_ID = `monero-frozen-agent-${Date.now()}`;

const SCOPE = "monero:mainnet:0";
const FAKE_WALLET_RPC_URL = "http://monero-wallet-rpc.invalid:18083/json_rpc";
const FAKE_DAEMON_URL = "http://monero-daemon.invalid:18089";
const SCRIPTED_TX_HASH = "ab".repeat(32);
const SCRIPTED_FEE_PICONERO = 25_000_000n;

const allowedRecipient = generateMoneroWallet("mainnet").address;
const deniedRecipient = generateMoneroWallet("mainnet").address;
const stagenetRecipient = generateMoneroWallet("stagenet").address;

/**
 * Backend used only for wallet creation in test setup: approves the
 * dual-derivation check without a sidecar.
 */
class SetupMoneroBackend implements MoneroWalletBackend {
  readonly network = "mainnet" as const;
  async getDaemonHeight(): Promise<number> {
    return 3_400_000;
  }
  async verifyWalletKeys(): Promise<void> {}
  async getBalance(): Promise<MoneroBalanceResult> {
    throw new Error("not used in setup");
  }
  async prepareTransfer(
    _payload: MoneroKeyPayloadV1,
    _context: unknown,
    _request: { destinations: MoneroTransferDestination[] },
  ): Promise<PreparedMoneroTransfer> {
    throw new Error("not used in setup");
  }
  async relayTransfer(): Promise<{ txHash: string }> {
    throw new Error("not used in setup");
  }
  async discardPreparedTransfer(): Promise<void> {}
}

/** Scripted monero-wallet-rpc + daemon: records every JSON-RPC method call. */
function installScriptedMoneroRpc() {
  const realFetch = globalThis.fetch;
  const rpcCalls: Array<{ method: string; params: Record<string, unknown> }> = [];
  const walletFiles = new Map<string, { address: string }>();

  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith(FAKE_DAEMON_URL)) {
      return new Response(JSON.stringify({ status: "OK", height: 3_400_000 }), { status: 200 });
    }
    if (!url.startsWith("http://monero-wallet-rpc.invalid")) {
      return realFetch(input as RequestInfo, init);
    }
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params?: Record<string, unknown>;
    };
    const params = body.params ?? {};
    rpcCalls.push({ method: body.method, params });
    const rpc = (result?: unknown, error?: { code: number; message: string }) =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "0",
          ...(error ? { error } : { result: result ?? {} }),
        }),
        { status: 200 },
      );
    switch (body.method) {
      case "open_wallet": {
        const filename = String(params.filename);
        if (!walletFiles.has(filename)) {
          return rpc(undefined, { code: -1, message: "Failed to open wallet" });
        }
        return rpc({});
      }
      case "generate_from_keys": {
        const filename = String(params.filename);
        const address = String(params.address);
        walletFiles.set(filename, { address });
        return rpc({ address, info: "Wallet has been generated" });
      }
      case "get_address": {
        const [, entry] = [...walletFiles.entries()].at(-1) ?? [];
        return rpc({ address: entry?.address ?? "", addresses: [] });
      }
      case "refresh":
        return rpc({ blocks_fetched: 0, received_money: false });
      case "get_balance":
        return rpc({
          balance: 9_000_000_000_000,
          unlocked_balance: 8_000_000_000_000,
          blocks_to_unlock: 0,
        });
      case "get_height":
        return rpc({ height: 3_400_002 });
      case "transfer": {
        const destinations = (params.destinations ?? []) as Array<{ amount: number }>;
        const amount = destinations.reduce((total, entry) => total + Number(entry.amount), 0);
        return rpc({
          amount,
          fee: Number(SCRIPTED_FEE_PICONERO),
          tx_hash: SCRIPTED_TX_HASH,
          tx_metadata: "scripted-tx-metadata",
        });
      }
      case "relay_tx":
        return rpc({ tx_hash: SCRIPTED_TX_HASH });
      case "rescan_spent":
      case "close_wallet":
        return rpc({});
      default:
        return rpc(undefined, { code: -32601, message: `unexpected method ${body.method}` });
    }
  }) as typeof fetch;

  globalThis.fetch = stub;
  return {
    rpcCalls,
    restore: () => {
      globalThis.fetch = realFetch;
    },
  };
}

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("userId", "monero-admin");
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

function transferRequest(body: unknown, headers: Record<string, string> = {}) {
  return new Request(`http://localhost/vault/${AGENT_ID}/monero/transfer`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("vault Monero transfer + balance routes", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let scripted: ReturnType<typeof installScriptedMoneroRpc>;
  let walletAddress = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-monero-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);
    process.env.STEWARD_MONERO_WALLET_RPC_URL = FAKE_WALLET_RPC_URL;
    process.env.STEWARD_MONERO_DAEMON_URL = FAKE_DAEMON_URL;
    process.env.STEWARD_MONERO_NETWORK = "mainnet";
    scripted = installScriptedMoneroRpc();

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Monero Tenant",
      apiKeyHash: "hash",
    });

    const setupVault = new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
      moneroBackend: new SetupMoneroBackend(),
    });
    for (const agentId of [
      AGENT_ID,
      NO_POLICY_AGENT_ID,
      WRONG_CHAIN_AGENT_ID,
      SPEND_LIMIT_AGENT_ID,
      FROZEN_AGENT_ID,
    ]) {
      await setupVault.createAgent(TENANT_ID, agentId, `Agent ${agentId}`);
      const wallet = await setupVault.createWallet({ agentId, chainType: "monero" });
      if (agentId === AGENT_ID) walletAddress = wallet.address;
    }

    await getDb()
      .insert(policies)
      .values([
        {
          id: `${AGENT_ID}-monero-raw-signing`,
          agentId: AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["monero"], allowedCurves: ["ed25519"] },
        },
        {
          id: `${AGENT_ID}-monero-addresses`,
          agentId: AGENT_ID,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: [allowedRecipient], mode: "whitelist" },
        },
        {
          id: `${WRONG_CHAIN_AGENT_ID}-raw-signing`,
          agentId: WRONG_CHAIN_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["sui"], allowedCurves: ["ed25519"] },
        },
        {
          id: `${SPEND_LIMIT_AGENT_ID}-raw-signing`,
          agentId: SPEND_LIMIT_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["monero"], allowedCurves: ["ed25519"] },
        },
        {
          // 0.000001 XMR per tx: every scripted transfer amount exceeds this.
          id: `${SPEND_LIMIT_AGENT_ID}-spend-limit`,
          agentId: SPEND_LIMIT_AGENT_ID,
          type: "spending-limit",
          enabled: true,
          config: { maxPerTx: "1000000" },
        },
        {
          id: `${FROZEN_AGENT_ID}-raw-signing`,
          agentId: FROZEN_AGENT_ID,
          type: "raw-signing-chain",
          enabled: true,
          config: { allowedChains: ["monero"], allowedCurves: ["ed25519"] },
        },
      ]);
    await getDb().insert(vaultSigningFreezes).values({
      tenantId: TENANT_ID,
      scopeType: "agent",
      agentId: FROZEN_AGENT_ID,
      reason: "test freeze",
      createdByType: "user",
      createdById: "monero-admin",
    });

    app = await makeApp();
  }, 120_000);

  afterAll(async () => {
    scripted.restore();
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_MONERO_WALLET_RPC_URL;
    delete process.env.STEWARD_MONERO_DAEMON_URL;
    delete process.env.STEWARD_MONERO_NETWORK;
  });

  it("returns the wallet balance with piconero string amounts", async () => {
    const res = await app.request(
      `http://localhost/vault/${AGENT_ID}/monero/balance?walletScope=${encodeURIComponent(SCOPE)}`,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { balancePiconero: string; unlockedPiconero: string; walletAddress: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.balancePiconero).toBe("9000000000000");
    expect(body.data.unlockedPiconero).toBe("8000000000000");
    expect(body.data.walletAddress).toBe(walletAddress);
  });

  it("rejects a malformed balance walletScope", async () => {
    const res = await app.request(
      `http://localhost/vault/${AGENT_ID}/monero/balance?walletScope=bitcoin:mainnet:0`,
    );
    expect(res.status).toBe(400);
  });

  it("requires an Idempotency-Key header", async () => {
    const res = await app.request(
      transferRequest({
        walletScope: SCOPE,
        destinations: [{ address: allowedRecipient, amountPiconero: "1000000000" }],
      }),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("Idempotency-Key");
  });

  it("rejects invalid destinations before any policy or RPC work", async () => {
    const badAddress = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: "not-an-address", amountPiconero: "1000000000" }],
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(badAddress.status).toBe(400);

    const wrongNetwork = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: stagenetRecipient, amountPiconero: "1000000000" }],
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(wrongNetwork.status).toBe(400);
    const wrongNetworkBody = (await wrongNetwork.json()) as { error: string };
    expect(wrongNetworkBody.error).toContain("stagenet");

    const zeroAmount = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "0" }],
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(zeroAmount.status).toBe(400);

    const badPriority = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "1000000000" }],
          priority: 9,
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(badPriority.status).toBe(400);
  });

  it("requires an enabled raw-signing-chain policy (403 without one)", async () => {
    const res = await app.request(
      new Request(`http://localhost/vault/${NO_POLICY_AGENT_ID}/monero/transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "1000000000" }],
        }),
      }),
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("raw-signing-chain");
  });

  it("denies transfer when the raw-signing-chain policy does not allow monero", async () => {
    const res = await app.request(
      new Request(`http://localhost/vault/${WRONG_CHAIN_AGENT_ID}/monero/transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "1000000000" }],
        }),
      }),
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("rejected by policy");
  });

  it("denies transfers above a piconero spending limit", async () => {
    const res = await app.request(
      new Request(`http://localhost/vault/${SPEND_LIMIT_AGENT_ID}/monero/transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "1000000000000" }],
        }),
      }),
    );
    expect(res.status).toBe(403);
  });

  it("denies non-whitelisted destinations and never relays", async () => {
    const relayCountBefore = scripted.rpcCalls.filter((call) => call.method === "relay_tx").length;
    const res = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: deniedRecipient, amountPiconero: "1000000000" }],
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(res.status).toBe(403);
    const relayCountAfter = scripted.rpcCalls.filter((call) => call.method === "relay_tx").length;
    expect(relayCountAfter).toBe(relayCountBefore);
  });

  it("blocks transfers for a frozen agent with 423", async () => {
    const res = await app.request(
      new Request(`http://localhost/vault/${FROZEN_AGENT_ID}/monero/transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "1000000000" }],
        }),
      }),
    );
    expect(res.status).toBe(423);
  });

  it("enforces the configured fee ceiling", async () => {
    process.env.STEWARD_MAX_MONERO_FEE_PICONERO = "1000"; // below scripted 25000000
    try {
      const res = await app.request(
        transferRequest(
          {
            walletScope: SCOPE,
            destinations: [{ address: allowedRecipient, amountPiconero: "1000000000" }],
          },
          { "Idempotency-Key": crypto.randomUUID() },
        ),
      );
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string };
      expect(body.error).toContain("fee exceeds");
    } finally {
      delete process.env.STEWARD_MAX_MONERO_FEE_PICONERO;
    }
  });

  it("transfers happy-path: two-phase flow, transactions row, un-prefixed tx hash", async () => {
    const referenceId = `monero-ref-${Date.now()}`;
    const res = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "2000000000000" }],
          priority: 1,
          referenceId,
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        transactionId: string;
        txHash: string;
        feePiconero: string;
        amountPiconero: string;
        totalPiconero: string;
        network: string;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.txHash).toBe(SCRIPTED_TX_HASH);
    expect(body.data.txHash.startsWith("0x")).toBe(false);
    expect(body.data.feePiconero).toBe(SCRIPTED_FEE_PICONERO.toString());
    expect(body.data.amountPiconero).toBe("2000000000000");
    expect(body.data.totalPiconero).toBe((2_000_000_000_000n + SCRIPTED_FEE_PICONERO).toString());
    expect(body.data.network).toBe("mainnet");

    // Two-phase order: transfer (do_not_relay) strictly before relay_tx.
    const methods = scripted.rpcCalls.map((call) => call.method);
    const transferIndex = methods.lastIndexOf("transfer");
    const relayIndex = methods.lastIndexOf("relay_tx");
    expect(transferIndex).toBeGreaterThan(-1);
    expect(relayIndex).toBeGreaterThan(transferIndex);
    const transferCall = scripted.rpcCalls[transferIndex];
    expect(transferCall.params.do_not_relay).toBe(true);

    const [row] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.transactionId));
    expect(row).toBeDefined();
    expect(row.actionType).toBe("monero_transfer");
    expect(row.chainId).toBe(301);
    expect(row.status).toBe("broadcast");
    expect(row.txHash).toBe(SCRIPTED_TX_HASH);
    expect(row.value).toBe(body.data.totalPiconero);

    // referenceId dedupe: identical reference returns the same transaction.
    const dedupe = await app.request(
      transferRequest(
        {
          walletScope: SCOPE,
          destinations: [{ address: allowedRecipient, amountPiconero: "2000000000000" }],
          referenceId,
        },
        { "Idempotency-Key": crypto.randomUUID() },
      ),
    );
    expect(dedupe.status).toBe(200);
    const dedupeBody = (await dedupe.json()) as {
      ok: boolean;
      data: { transactionId: string; deduplicated?: boolean };
    };
    expect(dedupeBody.data.transactionId).toBe(body.data.transactionId);
    expect(dedupeBody.data.deduplicated).toBe(true);
  });

  it("rejects raw-digest signing for monero (transfer-intent capability)", async () => {
    // Opt into the unsafe raw-digest surface so the request reaches the
    // per-chain capability guard — which must still reject monero.
    process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING = "true";
    process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING = "true";
    try {
      const res = await app.request(
        new Request(`http://localhost/vault/${AGENT_ID}/sign-raw-digest`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chain: "monero",
            curve: "ed25519",
            payloadHex: `0x${"11".repeat(32)}`,
          }),
        }),
      );
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toContain("does not support raw-digest signing");
    } finally {
      delete process.env.STEWARD_ALLOW_UNSAFE_RAW_SIGNING;
      delete process.env.STEWARD_ALLOW_VAULT_UNSAFE_RAW_SIGNING;
    }
  });
});
