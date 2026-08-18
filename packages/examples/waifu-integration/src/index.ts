import {
  type PolicyRule,
  StewardApiError,
  StewardClient,
  type TxRecord,
  verifyWebhookSignature,
} from "@stwd/sdk";
import type { ApiResponse, WebhookEvent } from "@stwd/shared";

const BASE_CHAIN_ID = 8453;
const USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const UNISWAP_UNIVERSAL_ROUTER = "0x6fF5693B99212Da76ad316178A184AB56D299b43";

const config = {
  apiUrl: process.env.STEWARD_API_URL ?? "http://127.0.0.1:3200",
  tenantId: process.env.STEWARD_TENANT_ID ?? "waifu-fun",
  apiKey: process.env.STEWARD_API_KEY ?? "waifu-demo-secret",
  tenantName: process.env.STEWARD_TENANT_NAME ?? "waifu.fun",
  sessionToken: process.env.STEWARD_TOKEN,
  webhookPort: Number(process.env.WAIFU_WEBHOOK_PORT ?? "4210"),
  webhookPath: process.env.WAIFU_WEBHOOK_PATH ?? "/steward-events",
  webhookUrl: process.env.WAIFU_WEBHOOK_URL,
  agentId: process.env.WAIFU_AGENT_ID ?? "milady-trader",
  agentName: process.env.WAIFU_AGENT_NAME ?? "Milady Trader",
  platformId: process.env.WAIFU_PLATFORM_ID ?? "waifu.fun:milady-trader",
};

type TenantPayload = {
  id: string;
  name: string;
  apiKeyHash: string;
  defaultPolicies?: PolicyRule[];
};

export type ReceivedWebhook = {
  event: string;
  deliveryId: string;
  signature: string;
  payload: WebhookEvent;
};

const localWebhookUrl = `http://127.0.0.1:${config.webhookPort}${config.webhookPath}`;

export function parseEther(value: string): bigint {
  const [wholePart, fractionalPart = ""] = value.split(".");
  const normalizedFraction = `${fractionalPart}000000000000000000`.slice(0, 18);
  return BigInt(wholePart || "0") * 10n ** 18n + BigInt(normalizedFraction);
}

export function formatEther(value: bigint): string {
  const whole = value / 10n ** 18n;
  const fraction = value % 10n ** 18n;
  if (fraction === 0n) {
    return whole.toString();
  }

  const fractionText = fraction.toString().padStart(18, "0").replace(/0+$/, "");
  return `${whole}.${fractionText}`;
}

function section(title: string) {
  console.log(`\n=== ${title} ===`);
}

function detail(label: string, value: unknown) {
  console.log(`- ${label}:`, value);
}

function weiToEthLabel(value: string): string {
  return `${formatEther(BigInt(value))} ETH`;
}

export async function verifyIncomingWebhook(
  body: string,
  secret: string,
  headers: Headers,
): Promise<ReceivedWebhook | null> {
  const event = headers.get("X-Steward-Event");
  const signature = headers.get("X-Steward-Signature");
  const timestamp = headers.get("X-Steward-Timestamp");
  const deliveryId = headers.get("X-Steward-Delivery-Id");
  const verification = await verifyWebhookSignature(body, signature, secret, timestamp, {
    eventType: event,
    deliveryId,
  });
  if (!verification.valid || !event || !deliveryId || !signature) return null;

  const payload = JSON.parse(body) as WebhookEvent;
  if (payload.type !== event) return null;
  return { event, deliveryId, signature, payload };
}

function authHeaders(): HeadersInit {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    "X-Steward-Tenant": config.tenantId,
    "X-Steward-Key": config.apiKey,
  };
}

async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(authHeaders());
  const extraHeaders = new Headers(init.headers);

  extraHeaders.forEach((value, key) => {
    headers.set(key, value);
  });

  const response = await fetch(`${config.apiUrl}${path}`, {
    ...init,
    headers,
  });

  const payload = (await response.json()) as ApiResponse<T>;
  if (!response.ok || !payload.ok) {
    throw new Error(payload.error ?? `Request failed: ${response.status}`);
  }

  if (typeof payload.data === "undefined") {
    throw new Error(`Missing response data from ${path}`);
  }

  return payload.data;
}

async function registerOrUpdateTenant(defaultPolicies: PolicyRule[]) {
  section("Tenant Registration");

  const payload: TenantPayload = {
    id: config.tenantId,
    name: config.tenantName,
    apiKeyHash: config.apiKey,
    defaultPolicies,
  };

  const createResponse = await fetch(`${config.apiUrl}/tenants`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  const body = (await createResponse.json()) as ApiResponse<TenantPayload>;
  if (createResponse.ok && body.ok && body.data) {
    detail("tenant", body.data.id);
    return;
  }

  if (createResponse.status !== 400 || body.error !== "Tenant already exists") {
    throw new Error(body.error ?? `Failed to register tenant: ${createResponse.status}`);
  }

  const tenant = await requestJson<TenantPayload>(
    `/tenants/${encodeURIComponent(config.tenantId)}`,
  );
  detail("tenant", `${tenant.id} (reused)`);
}

async function approvePending(agentId: string, txId: string) {
  return requestJson<{ txId: string; txHash: string }>(
    `/vault/${encodeURIComponent(agentId)}/approve/${encodeURIComponent(txId)}`,
    { method: "POST" },
  );
}

async function fetchHistory(agentId: string) {
  return requestJson<TxRecord[]>(`/vault/${encodeURIComponent(agentId)}/history`);
}

export function createWebhookHandler(options: {
  path: string;
  getSecret: () => string | undefined;
  onWebhook: (webhook: ReceivedWebhook) => void;
}) {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== options.path) {
      return Response.json({ ok: false, error: "Not found" }, { status: 404 });
    }
    const secret = options.getSecret();
    if (!secret) {
      return Response.json({ ok: false, error: "Webhook is not configured" }, { status: 503 });
    }
    const rawBody = await request.text();
    const webhook = await verifyIncomingWebhook(rawBody, secret, request.headers).catch(() => null);
    if (!webhook) {
      return Response.json({ ok: false, error: "Invalid webhook signature" }, { status: 401 });
    }
    options.onWebhook(webhook);
    return Response.json({ ok: true });
  };
}

export async function waitForWebhook(
  received: ReceivedWebhook[],
  predicate: (webhook: ReceivedWebhook) => boolean,
  timeoutMs = 15_000,
): Promise<ReceivedWebhook> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const match = received.find(predicate);
    if (match) return match;
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for Steward webhook delivery`);
}

async function configureWebhook(client: StewardClient): Promise<string> {
  if (!config.webhookUrl) {
    throw new Error("WAIFU_WEBHOOK_URL must be a public HTTPS URL routed to the webhook receiver");
  }
  const existing = (await client.listWebhooks()).find(
    (webhook) => webhook.url === config.webhookUrl,
  );
  if (existing) await client.deleteWebhook(existing.id);
  const created = await client.createWebhook({
    url: config.webhookUrl,
    events: ["approval_required"],
    description: "waifu.fun integration example",
  });
  if (!created.secret)
    throw new Error("Steward did not return the one-time webhook signing secret");
  return created.secret;
}

async function startWebhookServer(
  received: ReceivedWebhook[],
  getSecret: () => string | undefined,
) {
  section("Webhook Receiver");

  const server = Bun.serve({
    port: config.webhookPort,
    fetch: createWebhookHandler({
      path: config.webhookPath,
      getSecret,
      onWebhook: (webhook) => {
        received.push(webhook);
        console.log(`[webhook] ${webhook.event} for ${webhook.payload.agentId}`);
        detail("webhook txId", webhook.payload.data.txId ?? "n/a");
      },
    }),
  });

  detail("listening", localWebhookUrl);
  return server;
}

export function buildDefaultPolicies(agentWalletAddress: string): PolicyRule[] {
  return [
    {
      id: "waifu-spending-limit",
      type: "spending-limit",
      enabled: true,
      // Current API requires a weekly ceiling in addition to the per-tx and daily limits.
      config: {
        maxPerTx: parseEther("0.1").toString(),
        maxPerDay: parseEther("1").toString(),
        maxPerWeek: parseEther("3").toString(),
      },
    },
    {
      id: "waifu-approved-addresses",
      type: "approved-addresses",
      enabled: true,
      // The demo keeps the required Uniswap + USDC allowlist and adds the wallet itself
      // so the reference flow can execute against a funded test wallet without swap calldata.
      config: {
        mode: "whitelist",
        addresses: [UNISWAP_UNIVERSAL_ROUTER, USDC_ADDRESS, agentWalletAddress],
      },
    },
    {
      id: "waifu-auto-approve-threshold",
      type: "auto-approve-threshold",
      enabled: true,
      config: {
        threshold: parseEther("0.01").toString(),
      },
    },
  ];
}

function printPolicySummary(policies: PolicyRule[]) {
  for (const policy of policies) {
    detail(`policy ${policy.type}`, policy.config);
  }
}

function printPolicyResults(
  label: string,
  results: Array<{ type: string; passed: boolean; reason?: string }>,
) {
  console.log(label);
  for (const result of results) {
    console.log(
      `  ${result.passed ? "PASS" : "FAIL"} ${result.type}${result.reason ? ` - ${result.reason}` : ""}`,
    );
  }
}

async function main() {
  const receivedWebhooks: ReceivedWebhook[] = [];
  let webhookSecret: string | undefined;
  const server = await startWebhookServer(receivedWebhooks, () => webhookSecret);

  try {
    const client = new StewardClient({
      baseUrl: config.apiUrl,
      apiKey: config.apiKey,
      tenantId: config.tenantId,
    });

    const bootstrapPolicies = buildDefaultPolicies("0x0000000000000000000000000000000000000000");
    await registerOrUpdateTenant(bootstrapPolicies);

    if (!config.sessionToken) {
      throw new Error(
        "STEWARD_TOKEN must contain a tenant owner/admin session with recent MFA to configure the webhook",
      );
    }
    const webhookAdmin = new StewardClient({
      baseUrl: config.apiUrl,
      bearerToken: config.sessionToken,
      tenantId: config.tenantId,
    });
    webhookSecret = await configureWebhook(webhookAdmin);
    detail("configured webhook", config.webhookUrl);

    section("Agent Wallet");

    let agent;
    try {
      agent = await client.createWallet(config.agentId, config.agentName, config.platformId);
      detail("created", `${agent.id} -> ${agent.walletAddress}`);
    } catch (error) {
      if (!(error instanceof StewardApiError) || error.status !== 400) {
        throw error;
      }

      agent = await client.getAgent(config.agentId);
      detail("reused", `${agent.id} -> ${agent.walletAddress}`);
    }

    detail("tenant", agent.tenantId);
    detail("platform id", agent.platformId ?? "not set");

    section("Policy Setup");
    const policies = buildDefaultPolicies(agent.walletAddress);
    await client.setPolicies(agent.id, policies);
    const storedPolicies = await client.getPolicies(agent.id);
    printPolicySummary(storedPolicies);

    section("Tenant View");
    const listedAgents = await client.listAgents();
    detail("tenant agent count", listedAgents.length);
    detail("agent ids", listedAgents.map((entry) => entry.id).join(", "));

    section("Message Signing");
    const message = `waifu.fun custody proof for ${agent.id} on Base`;
    const signature = await client.signMessage(agent.id, message);
    detail("message", message);
    detail("signature", signature.signature);

    section("Transaction Flow");
    console.log(
      "Steward enforces policy at the wallet backend. waifu.fun decides when to auto-approve or escalate.",
    );

    const smallTxValue = parseEther("0.005").toString();
    try {
      const smallTx = await client.signTransaction(agent.id, {
        to: agent.walletAddress,
        value: smallTxValue,
        chainId: BASE_CHAIN_ID,
      });

      if ("txHash" in smallTx) {
        detail("small tx", `auto-approved and signed (${smallTx.txHash})`);
      }
    } catch (error) {
      console.log("Small tx passed policy but could not be broadcast.");
      detail("likely cause", "fund the demo wallet with ETH on Base so the signer can pay gas");
      detail("error", error instanceof Error ? error.message : "Unknown error");
    }

    const mediumTxValue = parseEther("0.05").toString();
    const mediumTx = await client.signTransaction(agent.id, {
      to: agent.walletAddress,
      value: mediumTxValue,
      chainId: BASE_CHAIN_ID,
    });

    if (!("status" in mediumTx) || mediumTx.status !== "pending_approval") {
      throw new Error("Expected medium transaction to require manual approval");
    }

    printPolicyResults(
      `Medium tx (${weiToEthLabel(mediumTxValue)}) requested manual approval:`,
      mediumTx.results,
    );

    const approvalWebhook = await waitForWebhook(
      receivedWebhooks,
      (webhook) =>
        webhook.event === "approval_required" &&
        webhook.payload.agentId === agent.id &&
        typeof webhook.payload.data.txId === "string",
    );
    const approvalTxId = approvalWebhook.payload.data.txId as string;
    detail("approval webhook delivery", approvalWebhook.deliveryId);

    const mediumApproval = await approvePending(agent.id, approvalTxId);
    detail("medium tx", `approved and signed (${mediumApproval.txHash})`);

    const largeTxValue = parseEther("0.2").toString();
    try {
      await client.signTransaction(agent.id, {
        to: agent.walletAddress,
        value: largeTxValue,
        chainId: BASE_CHAIN_ID,
      });
      throw new Error("Expected large transaction to be rejected by the spending limit");
    } catch (error) {
      if (!(error instanceof StewardApiError)) {
        throw error;
      }

      console.log(`Large tx (${weiToEthLabel(largeTxValue)}) was rejected before signing.`);
      printPolicyResults(
        "Policy engine result:",
        (error.data?.results as
          | Array<{ type: string; passed: boolean; reason?: string }>
          | undefined) ?? [],
      );
    }

    section("Lifecycle Summary");
    const history = await fetchHistory(agent.id);
    for (const entry of history) {
      detail(
        "history",
        `${entry.status} ${weiToEthLabel(entry.request.value)} -> ${entry.request.to} @ ${new Date(entry.createdAt).toISOString()}`,
      );
      if (entry.txHash) {
        detail("tx hash", entry.txHash);
      }
    }
    detail("webhook deliveries", receivedWebhooks.length);
    detail("received events", receivedWebhooks.map((entry) => entry.event).join(", ") || "none");
  } finally {
    server.stop();
  }
}

if (import.meta.main) {
  await main().catch((error) => {
    console.error("\nWaifu integration example failed.");
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  });
}
