import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, closeDb, eq, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
  ExternalKeySignTransactionRequest,
  ExternalKeySignTransactionResult,
} from "../external-key-custody";
import { Vault } from "../vault";

const TENANT_ID = "transaction-id-hardening";
const TX_ID = "shared-transaction-id";
let vault: Vault;

class SigningProvider implements ExternalKeyCustodyProvider {
  readonly id = "transaction-id-test-provider";
  readonly contractVersion = 1 as const;

  async registerKeyHandle(
    request: ExternalKeyHandleImportRequest,
  ): Promise<ExternalKeyHandleRegistration> {
    return {
      custody: "external",
      tenantId: request.tenantId,
      agentId: request.agentId,
      chainFamily: request.chainFamily,
      address: request.address,
      handle: request.handle,
      venue: request.venue ?? null,
      purpose: request.purpose ?? null,
      metadata: request.metadata ?? {},
      registeredAt: new Date(),
      exportablePrivateKey: false,
      signingAvailability: "provider-signing",
    };
  }

  async signTransaction(
    request: ExternalKeySignTransactionRequest,
  ): Promise<ExternalKeySignTransactionResult> {
    return { result: `0xsigned-${request.agentId}`, broadcast: false };
  }
}

setDefaultTimeout(120_000);

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Transaction ID Hardening",
    apiKeyHash: "test-hash",
  });
  await getDb()
    .insert(agents)
    .values([
      {
        id: "agent-a",
        tenantId: TENANT_ID,
        name: "Agent A",
        walletAddress: "0x1111111111111111111111111111111111111111",
      },
      {
        id: "agent-b",
        tenantId: TENANT_ID,
        name: "Agent B",
        walletAddress: "0x2222222222222222222222222222222222222222",
      },
    ]);
  vault = new Vault({
    masterPassword: "transaction-id-hardening-test-password",
    externalKeyCustodyProvider: new SigningProvider(),
  });
  for (const [agentId, address] of [
    ["agent-a", "0x1111111111111111111111111111111111111111"],
    ["agent-b", "0x2222222222222222222222222222222222222222"],
  ] as const) {
    await vault.importExternalKeyHandle({
      tenantId: TENANT_ID,
      agentId,
      chainFamily: "evm",
      address,
      venue: "transaction-id-test",
      handle: { providerId: "test-hsm", keyId: `key-${agentId}` },
    });
  }
});

afterAll(async () => {
  await closeDb();
});

async function record(
  agentId: string,
  options: { txId?: string; to?: string; value?: string } = {},
): Promise<void> {
  const target = await vault.resolveExecutionTarget({
    tenantId: TENANT_ID,
    agentId,
    chainId: 8453,
    venue: "transaction-id-test",
  });
  await vault.signTransaction(
    {
      tenantId: TENANT_ID,
      agentId,
      to: options.to ?? "0x3333333333333333333333333333333333333333",
      value: options.value ?? "1",
      chainId: 8453,
      venue: "transaction-id-test",
      broadcast: false,
    },
    {
      txId: options.txId ?? TX_ID,
      expectedBackend: target.backend,
      expectedBackendIdentityDigest: target.backendIdentityDigest,
    },
  );
}

describe("transaction id hardening", () => {
  it("rejects reusing a transaction id across agents without modifying the original row", async () => {
    await record("agent-a");
    await expect(record("agent-b")).rejects.toThrow(
      "Transaction id already belongs to a different agent",
    );

    const [stored] = await getDb().select().from(transactions).where(eq(transactions.id, TX_ID));
    expect(stored).toMatchObject({
      id: TX_ID,
      agentId: "agent-a",
      toAddress: "0x3333333333333333333333333333333333333333",
      value: "1",
      status: "signed",
    });
  });

  it("rejects same-agent reuse with different immutable transaction fields", async () => {
    const txId = "same-agent-immutable-id";
    await record("agent-a", { txId, value: "1" });
    await expect(record("agent-a", { txId, value: "2" })).rejects.toThrow(
      "Transaction id conflicts with an existing immutable transaction",
    );

    const [stored] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
    expect(stored.value).toBe("1");
    expect(stored.toAddress).toBe("0x3333333333333333333333333333333333333333");
  });

  it("atomically admits only one of two concurrent bodies for the same id", async () => {
    const txId = "concurrent-immutable-id";
    const results = await Promise.allSettled([
      record("agent-a", { txId, value: "10" }),
      record("agent-a", { txId, value: "20" }),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const [stored] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
    expect(["10", "20"]).toContain(stored.value);
  });
});
