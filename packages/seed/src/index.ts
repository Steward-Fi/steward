import { createHash } from "node:crypto";

import {
  agents,
  approvalQueue,
  closeDb,
  encryptedKeys,
  getDb,
  getSql,
  policies,
  tenants,
  transactions,
} from "../../db/src/index.ts";
import { KeyStore } from "../../vault/src/index.ts";
import {
  encodeFunctionData,
  parseAbi,
  parseEther,
  parseUnits,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const TENANT_ID = "waifu.fun";
const TENANT_NAME = "waifu.fun";
const DEMO_API_KEY = "stw_demo_waifu_fun_dashboard";
const ERC20_ABI = parseAbi(["function transfer(address to, uint256 amount)"]);

type SeedAgent = {
  id: string;
  name: string;
  platformId: string;
  erc8004TokenId?: string;
};

type PolicySeed = {
  id: string;
  agentId: string;
  type:
    | "spending-limit"
    | "approved-addresses"
    | "auto-approve-threshold"
    | "time-window"
    | "rate-limit";
  enabled: boolean;
  config: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
};

type PolicyResultSeed = {
  policyId: string;
  type: PolicySeed["type"];
  passed: boolean;
  reason?: string;
};

type TransactionSeed = {
  id: string;
  agentId: string;
  status: "pending" | "approved" | "rejected" | "signed" | "broadcast" | "confirmed" | "failed";
  toAddress: `0x${string}`;
  value: string;
  data?: `0x${string}`;
  chainId: number;
  txHash?: `0x${string}`;
  policyResults: PolicyResultSeed[];
  createdAt: Date;
  signedAt?: Date;
  confirmedAt?: Date;
};

type ApprovalSeed = {
  id: string;
  txId: string;
  agentId: string;
  status: "pending" | "approved" | "rejected";
  requestedAt: Date;
  resolvedAt?: Date;
  resolvedBy?: string;
};

function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function makeHex(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

function makeTxHash(seed: string): `0x${string}` {
  return `0x${makeHex(seed)}`;
}

function createWallet() {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  return { privateKey, address: account.address };
}

function hoursAgo(hours: number): Date {
  return new Date(Date.now() - hours * 60 * 60 * 1000);
}

function usdcTransfer(to: `0x${string}`, amount: string): `0x${string}` {
  return encodeFunctionData({
    abi: ERC20_ABI,
    functionName: "transfer",
    args: [to, parseUnits(amount, 6)],
  });
}

async function cleanDatabase() {
  await getSql().unsafe(
    "TRUNCATE TABLE approval_queue, transactions, policies, encrypted_keys, agents, tenants RESTART IDENTITY CASCADE"
  );
}

async function seed() {
  if (!process.env.STEWARD_MASTER_PASSWORD) {
    throw new Error("STEWARD_MASTER_PASSWORD is required");
  }

  const clean = process.argv.includes("--clean");
  const db = getDb();

  if (clean) {
    console.log("Cleaning existing demo data...");
    await cleanDatabase();
  }

  const createdAt = hoursAgo(72);
  const updatedAt = hoursAgo(1);
  const keyStore = new KeyStore(process.env.STEWARD_MASTER_PASSWORD);

  const agentSeeds: SeedAgent[] = [
    {
      id: "agent-milady-trader",
      name: "milady-trader",
      platformId: "waifu-agent-mlady-01",
      erc8004TokenId: "8004-101",
    },
    {
      id: "agent-aethernet-0x",
      name: "aethernet-0x",
      platformId: "waifu-agent-aether-02",
      erc8004TokenId: "8004-102",
    },
    {
      id: "agent-token-launcher",
      name: "token-launcher",
      platformId: "waifu-agent-launch-03",
    },
    {
      id: "agent-yield-farmer",
      name: "yield-farmer",
      platformId: "waifu-agent-yield-04",
    },
    {
      id: "agent-treasury-ops",
      name: "treasury-ops",
      platformId: "waifu-agent-treasury-05",
      erc8004TokenId: "8004-105",
    },
  ];

  const recipients = {
    marketMaker: createWallet().address,
    coinbasePrime: createWallet().address,
    launchpadTreasury: createWallet().address,
    miladyMultisig: createWallet().address,
    farmingVault: createWallet().address,
    opsHotWallet: createWallet().address,
    strategist: createWallet().address,
    creatorPayouts: createWallet().address,
  };

  const policySeeds: PolicySeed[] = [
    {
      id: "policy-milady-spend",
      agentId: "agent-milady-trader",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("6").toString(),
        maxPerDay: parseEther("18").toString(),
        maxPerWeek: parseEther("72").toString(),
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-milady-approved",
      agentId: "agent-milady-trader",
      type: "approved-addresses",
      enabled: true,
      config: {
        addresses: [recipients.marketMaker, recipients.miladyMultisig],
        mode: "whitelist",
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-milady-auto",
      agentId: "agent-milady-trader",
      type: "auto-approve-threshold",
      enabled: true,
      config: {
        threshold: parseEther("1.2").toString(),
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-aether-approved",
      agentId: "agent-aethernet-0x",
      type: "approved-addresses",
      enabled: true,
      config: {
        addresses: [recipients.coinbasePrime, recipients.strategist],
        mode: "whitelist",
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-aether-rate",
      agentId: "agent-aethernet-0x",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 4,
        maxTxPerDay: 18,
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-aether-window",
      agentId: "agent-aethernet-0x",
      type: "time-window",
      enabled: true,
      config: {
        allowedHours: [{ start: 8, end: 23 }],
        allowedDays: [1, 2, 3, 4, 5],
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-launch-spend",
      agentId: "agent-token-launcher",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("10").toString(),
        maxPerDay: parseEther("30").toString(),
        maxPerWeek: parseEther("120").toString(),
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-launch-approved",
      agentId: "agent-token-launcher",
      type: "approved-addresses",
      enabled: true,
      config: {
        addresses: [recipients.launchpadTreasury, recipients.creatorPayouts],
        mode: "whitelist",
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-launch-rate",
      agentId: "agent-token-launcher",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 3,
        maxTxPerDay: 10,
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-yield-spend",
      agentId: "agent-yield-farmer",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("4").toString(),
        maxPerDay: parseEther("16").toString(),
        maxPerWeek: parseEther("48").toString(),
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-yield-auto",
      agentId: "agent-yield-farmer",
      type: "auto-approve-threshold",
      enabled: true,
      config: {
        threshold: parseEther("0.75").toString(),
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-yield-window",
      agentId: "agent-yield-farmer",
      type: "time-window",
      enabled: true,
      config: {
        allowedHours: [{ start: 6, end: 22 }],
        allowedDays: [1, 2, 3, 4, 5, 6],
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-treasury-spend",
      agentId: "agent-treasury-ops",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("25").toString(),
        maxPerDay: parseEther("80").toString(),
        maxPerWeek: parseEther("240").toString(),
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-treasury-approved",
      agentId: "agent-treasury-ops",
      type: "approved-addresses",
      enabled: true,
      config: {
        addresses: [recipients.opsHotWallet, recipients.coinbasePrime, recipients.miladyMultisig],
        mode: "whitelist",
      },
      createdAt,
      updatedAt,
    },
    {
      id: "policy-treasury-rate",
      agentId: "agent-treasury-ops",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 2,
        maxTxPerDay: 8,
      },
      createdAt,
      updatedAt,
    },
  ];

  const txSeeds: TransactionSeed[] = [
    {
      id: "demo-tx-001",
      agentId: "agent-milady-trader",
      status: "confirmed",
      toAddress: recipients.marketMaker,
      value: parseEther("1.82").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-001"),
      policyResults: [
        { policyId: "policy-milady-spend", type: "spending-limit", passed: true },
        { policyId: "policy-milady-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-milady-auto", type: "auto-approve-threshold", passed: false, reason: "above 1.2 ETH threshold" },
      ],
      createdAt: hoursAgo(44),
      signedAt: hoursAgo(44),
      confirmedAt: hoursAgo(43.6),
    },
    {
      id: "demo-tx-002",
      agentId: "agent-milady-trader",
      status: "signed",
      toAddress: recipients.miladyMultisig,
      value: parseEther("0.68").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-002"),
      policyResults: [
        { policyId: "policy-milady-spend", type: "spending-limit", passed: true },
        { policyId: "policy-milady-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-milady-auto", type: "auto-approve-threshold", passed: true },
      ],
      createdAt: hoursAgo(31),
      signedAt: hoursAgo(30.9),
    },
    {
      id: "demo-tx-003",
      agentId: "agent-milady-trader",
      status: "pending",
      toAddress: recipients.coinbasePrime,
      value: parseEther("4.6").toString(),
      chainId: 8453,
      policyResults: [
        { policyId: "policy-milady-spend", type: "spending-limit", passed: true },
        { policyId: "policy-milady-approved", type: "approved-addresses", passed: false, reason: "destination not on whitelist" },
        { policyId: "policy-milady-auto", type: "auto-approve-threshold", passed: false, reason: "manual review required" },
      ],
      createdAt: hoursAgo(2.8),
    },
    {
      id: "demo-tx-004",
      agentId: "agent-aethernet-0x",
      status: "confirmed",
      toAddress: recipients.coinbasePrime,
      value: parseEther("2.15").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-004"),
      policyResults: [
        { policyId: "policy-aether-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-aether-rate", type: "rate-limit", passed: true },
        { policyId: "policy-aether-window", type: "time-window", passed: true },
      ],
      createdAt: hoursAgo(38),
      signedAt: hoursAgo(37.95),
      confirmedAt: hoursAgo(37.4),
    },
    {
      id: "demo-tx-005",
      agentId: "agent-aethernet-0x",
      status: "failed",
      toAddress: recipients.strategist,
      value: parseEther("3.8").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-005"),
      policyResults: [
        { policyId: "policy-aether-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-aether-rate", type: "rate-limit", passed: true },
        { policyId: "policy-aether-window", type: "time-window", passed: true },
      ],
      createdAt: hoursAgo(26),
      signedAt: hoursAgo(25.9),
    },
    {
      id: "demo-tx-006",
      agentId: "agent-aethernet-0x",
      status: "broadcast",
      toAddress: recipients.coinbasePrime,
      value: parseEther("1.1").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-006"),
      policyResults: [
        { policyId: "policy-aether-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-aether-rate", type: "rate-limit", passed: true },
        { policyId: "policy-aether-window", type: "time-window", passed: true },
      ],
      createdAt: hoursAgo(7.2),
      signedAt: hoursAgo(7.1),
    },
    {
      id: "demo-tx-007",
      agentId: "agent-token-launcher",
      status: "confirmed",
      toAddress: recipients.launchpadTreasury,
      value: parseEther("8.4").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-007"),
      policyResults: [
        { policyId: "policy-launch-spend", type: "spending-limit", passed: true },
        { policyId: "policy-launch-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-launch-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(52),
      signedAt: hoursAgo(51.8),
      confirmedAt: hoursAgo(51.2),
    },
    {
      id: "demo-tx-008",
      agentId: "agent-token-launcher",
      status: "rejected",
      toAddress: recipients.marketMaker,
      value: parseEther("12.0").toString(),
      chainId: 8453,
      policyResults: [
        { policyId: "policy-launch-spend", type: "spending-limit", passed: false, reason: "exceeds 10 ETH max per tx" },
        { policyId: "policy-launch-approved", type: "approved-addresses", passed: false, reason: "destination not on whitelist" },
        { policyId: "policy-launch-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(18),
    },
    {
      id: "demo-tx-009",
      agentId: "agent-token-launcher",
      status: "signed",
      toAddress: recipients.creatorPayouts,
      value: "0",
      data: usdcTransfer(recipients.creatorPayouts, "12500"),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-009"),
      policyResults: [
        { policyId: "policy-launch-spend", type: "spending-limit", passed: true },
        { policyId: "policy-launch-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-launch-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(10),
      signedAt: hoursAgo(9.95),
    },
    {
      id: "demo-tx-010",
      agentId: "agent-token-launcher",
      status: "pending",
      toAddress: recipients.marketMaker,
      value: parseEther("9.8").toString(),
      chainId: 8453,
      policyResults: [
        { policyId: "policy-launch-spend", type: "spending-limit", passed: true },
        { policyId: "policy-launch-approved", type: "approved-addresses", passed: false, reason: "launch pool address pending review" },
        { policyId: "policy-launch-rate", type: "rate-limit", passed: false, reason: "hourly burst cap reached" },
      ],
      createdAt: hoursAgo(1.4),
    },
    {
      id: "demo-tx-011",
      agentId: "agent-yield-farmer",
      status: "confirmed",
      toAddress: recipients.farmingVault,
      value: parseEther("3.2").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-011"),
      policyResults: [
        { policyId: "policy-yield-spend", type: "spending-limit", passed: true },
        { policyId: "policy-yield-auto", type: "auto-approve-threshold", passed: false, reason: "above 0.75 ETH threshold" },
        { policyId: "policy-yield-window", type: "time-window", passed: true },
      ],
      createdAt: hoursAgo(29),
      signedAt: hoursAgo(28.9),
      confirmedAt: hoursAgo(28.3),
    },
    {
      id: "demo-tx-012",
      agentId: "agent-yield-farmer",
      status: "signed",
      toAddress: recipients.farmingVault,
      value: parseEther("0.42").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-012"),
      policyResults: [
        { policyId: "policy-yield-spend", type: "spending-limit", passed: true },
        { policyId: "policy-yield-auto", type: "auto-approve-threshold", passed: true },
        { policyId: "policy-yield-window", type: "time-window", passed: true },
      ],
      createdAt: hoursAgo(15),
      signedAt: hoursAgo(14.9),
    },
    {
      id: "demo-tx-013",
      agentId: "agent-yield-farmer",
      status: "failed",
      toAddress: recipients.strategist,
      value: parseEther("2.7").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-013"),
      policyResults: [
        { policyId: "policy-yield-spend", type: "spending-limit", passed: true },
        { policyId: "policy-yield-auto", type: "auto-approve-threshold", passed: false, reason: "manual approval bypassed by operator" },
        { policyId: "policy-yield-window", type: "time-window", passed: true },
      ],
      createdAt: hoursAgo(12),
      signedAt: hoursAgo(11.8),
    },
    {
      id: "demo-tx-014",
      agentId: "agent-treasury-ops",
      status: "confirmed",
      toAddress: recipients.opsHotWallet,
      value: parseEther("14.25").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-014"),
      policyResults: [
        { policyId: "policy-treasury-spend", type: "spending-limit", passed: true },
        { policyId: "policy-treasury-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-treasury-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(60),
      signedAt: hoursAgo(59.8),
      confirmedAt: hoursAgo(59.2),
    },
    {
      id: "demo-tx-015",
      agentId: "agent-treasury-ops",
      status: "signed",
      toAddress: recipients.coinbasePrime,
      value: parseEther("18.75").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-015"),
      policyResults: [
        { policyId: "policy-treasury-spend", type: "spending-limit", passed: true },
        { policyId: "policy-treasury-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-treasury-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(22),
      signedAt: hoursAgo(21.85),
    },
    {
      id: "demo-tx-016",
      agentId: "agent-treasury-ops",
      status: "rejected",
      toAddress: recipients.marketMaker,
      value: parseEther("28").toString(),
      chainId: 8453,
      policyResults: [
        { policyId: "policy-treasury-spend", type: "spending-limit", passed: false, reason: "exceeds treasury transfer cap" },
        { policyId: "policy-treasury-approved", type: "approved-addresses", passed: false, reason: "destination not on treasury whitelist" },
        { policyId: "policy-treasury-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(9),
    },
    {
      id: "demo-tx-017",
      agentId: "agent-treasury-ops",
      status: "confirmed",
      toAddress: recipients.miladyMultisig,
      value: "0",
      data: usdcTransfer(recipients.miladyMultisig, "85000"),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-017"),
      policyResults: [
        { policyId: "policy-treasury-spend", type: "spending-limit", passed: true },
        { policyId: "policy-treasury-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-treasury-rate", type: "rate-limit", passed: true },
      ],
      createdAt: hoursAgo(6),
      signedAt: hoursAgo(5.9),
      confirmedAt: hoursAgo(5.2),
    },
    {
      id: "demo-tx-018",
      agentId: "agent-milady-trader",
      status: "confirmed",
      toAddress: recipients.marketMaker,
      value: parseEther("0.18").toString(),
      chainId: 8453,
      txHash: makeTxHash("demo-tx-018"),
      policyResults: [
        { policyId: "policy-milady-spend", type: "spending-limit", passed: true },
        { policyId: "policy-milady-approved", type: "approved-addresses", passed: true },
        { policyId: "policy-milady-auto", type: "auto-approve-threshold", passed: true },
      ],
      createdAt: hoursAgo(4.5),
      signedAt: hoursAgo(4.45),
      confirmedAt: hoursAgo(4.1),
    },
  ];

  const approvalSeeds: ApprovalSeed[] = [
    {
      id: "approval-demo-001",
      txId: "demo-tx-003",
      agentId: "agent-milady-trader",
      status: "pending",
      requestedAt: hoursAgo(2.75),
    },
    {
      id: "approval-demo-002",
      txId: "demo-tx-010",
      agentId: "agent-token-launcher",
      status: "pending",
      requestedAt: hoursAgo(1.35),
    },
    {
      id: "approval-demo-003",
      txId: "demo-tx-011",
      agentId: "agent-yield-farmer",
      status: "approved",
      requestedAt: hoursAgo(28.95),
      resolvedAt: hoursAgo(28.92),
      resolvedBy: TENANT_ID,
    },
    {
      id: "approval-demo-004",
      txId: "demo-tx-016",
      agentId: "agent-treasury-ops",
      status: "rejected",
      requestedAt: hoursAgo(8.95),
      resolvedAt: hoursAgo(8.85),
      resolvedBy: TENANT_ID,
    },
  ];

  await db
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: TENANT_NAME,
      apiKeyHash: hashApiKey(DEMO_API_KEY),
      createdAt,
      updatedAt,
    })
    .onConflictDoUpdate({
      target: tenants.id,
      set: {
        name: TENANT_NAME,
        apiKeyHash: hashApiKey(DEMO_API_KEY),
        updatedAt,
      },
    });

  const agentRows = [];
  const encryptedKeyRows = [];

  for (const agent of agentSeeds) {
    const wallet = createWallet();
    const encrypted = keyStore.encrypt(wallet.privateKey);

    agentRows.push({
      id: agent.id,
      tenantId: TENANT_ID,
      name: agent.name,
      walletAddress: wallet.address,
      platformId: agent.platformId,
      erc8004TokenId: agent.erc8004TokenId,
      createdAt,
      updatedAt,
    });

    encryptedKeyRows.push({
      agentId: agent.id,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
      salt: encrypted.salt,
    });
  }

  await db.insert(agents).values(agentRows).onConflictDoNothing({ target: agents.id });
  await db
    .insert(encryptedKeys)
    .values(encryptedKeyRows)
    .onConflictDoNothing({ target: encryptedKeys.agentId });
  await db.insert(policies).values(policySeeds).onConflictDoNothing({ target: policies.id });
  await db.insert(transactions).values(txSeeds).onConflictDoNothing({ target: transactions.id });
  await db.insert(approvalQueue).values(approvalSeeds).onConflictDoNothing({ target: approvalQueue.id });

  console.log(`Seeded tenant ${TENANT_ID}`);
  console.log(`Demo API key: ${DEMO_API_KEY}`);
  console.log(`Agents: ${agentSeeds.length}, policies: ${policySeeds.length}, transactions: ${txSeeds.length}, approvals: ${approvalSeeds.length}`);
}

try {
  await seed();
} finally {
  await closeDb();
}
