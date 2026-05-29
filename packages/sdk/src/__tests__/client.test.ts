import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  type SignTransactionInput,
  type SignUserOperationInput,
  StewardApiError,
  StewardClient,
  type StewardClientConfig,
} from "../client";
import type { PolicyRule } from "../types";

// ─── Fetch Mocking Helpers ────────────────────────────────────────────────

type FetchFn = typeof fetch;

let originalFetch: FetchFn;

interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  rawBody: string | undefined;
  body: unknown;
}

let lastCapture: CapturedRequest | null = null;

function installMockFetch(responseBody: object, status = 200): void {
  global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;
    const headers: Record<string, string> = {};
    if (init?.headers) {
      const h = new Headers(init.headers);
      h.forEach((v, k) => {
        headers[k] = v;
      });
    }
    lastCapture = {
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers,
      rawBody: init?.body as string | undefined,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    };
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
}

function installNetworkErrorFetch(): void {
  global.fetch = async () => {
    throw new Error("Network error: connection refused");
  };
}

function installBadJsonFetch(status = 200): void {
  global.fetch = async () =>
    new Response("this is not json", {
      status,
      headers: { "Content-Type": "text/plain" },
    });
}

beforeEach(() => {
  originalFetch = global.fetch;
  lastCapture = null;
});

afterEach(() => {
  global.fetch = originalFetch;
  delete (globalThis as unknown as { window?: unknown }).window;
  delete (globalThis as unknown as { document?: unknown }).document;
});

// ─── Helper factories ─────────────────────────────────────────────────────

function makeClient(overrides: Partial<StewardClientConfig> = {}): StewardClient {
  return new StewardClient({
    baseUrl: "https://api.steward.example",
    ...overrides,
  });
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret: string, canonical: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function expectedServerSignature(capture: CapturedRequest, secret: string): Promise<string> {
  const url = new URL(capture.url);
  const headers = capture.headers;
  const canonical = [
    "steward-request-signature-v1",
    capture.method,
    `${url.pathname}${url.search}`,
    headers["x-steward-tenant"] ?? "",
    await sha256Hex(headers.authorization ?? ""),
    await sha256Hex(headers["x-steward-key"] ?? ""),
    await sha256Hex(headers["x-steward-platform-key"] ?? ""),
    await sha256Hex(headers["x-steward-signer-id"] ?? ""),
    await sha256Hex(headers["x-steward-signer-secret"] ?? ""),
    await sha256Hex(headers["x-steward-key-quorum-id"] ?? ""),
    await sha256Hex(headers["x-steward-key-quorum-credentials"] ?? ""),
    headers["x-steward-request-timestamp"] ?? "",
    headers["x-steward-request-expires-at"] ?? "",
    headers["idempotency-key"] ?? "",
    await sha256Hex(capture.rawBody ?? ""),
  ].join("\n");
  return `v1=${await hmacSha256Hex(secret, canonical)}`;
}

const mockAgent = {
  id: "agent-1",
  tenantId: "tenant-1",
  name: "Test Agent",
  walletAddress: "0xabcdef0123456789abcdef0123456789abcdef01",
  createdAt: new Date("2024-01-01T00:00:00Z").toISOString(),
};

const mockPolicy: PolicyRule = {
  id: "rule-1",
  type: "spending-limit",
  enabled: true,
  config: { maxPerTx: "1000000000000000000" },
};

// ─── Construction Tests ───────────────────────────────────────────────────

describe("StewardClient construction", () => {
  it("creates a client with minimal config (baseUrl only)", () => {
    const client = new StewardClient({ baseUrl: "https://api.example.com" });
    expect(client).toBeInstanceOf(StewardClient);
  });

  it("strips trailing slash from baseUrl", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = new StewardClient({ baseUrl: "https://api.example.com///" });
    await client.listAgents();
    expect(lastCapture?.url).not.toContain("///agents");
    expect(lastCapture?.url).toMatch(/\/agents$/);
  });

  it("creates a client with all config options", () => {
    const client = new StewardClient({
      baseUrl: "https://api.example.com",
      apiKey: "test-api-key",
      platformKey: "test-platform-key",
      bearerToken: "test-bearer-token",
      tenantId: "test-tenant",
    });
    expect(client).toBeInstanceOf(StewardClient);
  });

  it("creates a client with apiKey only", () => {
    const client = new StewardClient({
      baseUrl: "https://api.example.com",
      apiKey: "my-api-key",
    });
    expect(client).toBeInstanceOf(StewardClient);
  });

  it("rejects server-grade secrets in browser runtimes by default", () => {
    (globalThis as unknown as { window: unknown }).window = {};
    (globalThis as unknown as { document: unknown }).document = {};

    expect(
      () =>
        new StewardClient({
          baseUrl: "https://api.example.com",
          appId: "tenant/web-prod",
          appSecret: "stw_app_secret",
        }),
    ).toThrow(/must not be used in browser runtimes/);
  });

  it("allows browser bearer tokens without enabling unsafe secrets", () => {
    (globalThis as unknown as { window: unknown }).window = {};
    (globalThis as unknown as { document: unknown }).document = {};

    const client = new StewardClient({
      baseUrl: "https://api.example.com",
      bearerToken: "short-lived-token",
    });

    expect(client).toBeInstanceOf(StewardClient);
  });

  it("allows explicit audited browser secret usage", () => {
    (globalThis as unknown as { window: unknown }).window = {};
    (globalThis as unknown as { document: unknown }).document = {};

    const client = new StewardClient({
      baseUrl: "https://api.example.com",
      apiKey: "my-api-key",
      allowUnsafeBrowserSecrets: true,
    });

    expect(client).toBeInstanceOf(StewardClient);
  });
});

describe("StewardClient webhooks", () => {
  it("lists webhook deliveries with pagination and retries delivery ids", async () => {
    installMockFetch({
      ok: true,
      data: [
        {
          id: "delivery-1",
          eventType: "user.created",
          status: "failed",
          attempts: 2,
          maxAttempts: 6,
          nextRetryAt: "2026-05-28T12:00:00.000Z",
          hasError: true,
          createdAt: "2026-05-28T11:00:00.000Z",
          deliveredAt: null,
        },
      ],
    });
    const deliveries = await makeClient().getWebhookDeliveries("webhook-1", {
      limit: 25,
      offset: 50,
    });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/webhooks/webhook-1/deliveries?limit=25&offset=50",
    );
    expect(deliveries[0].eventType).toBe("user.created");
    expect(deliveries[0].hasError).toBe(true);

    installMockFetch({
      ok: true,
      data: {
        id: "delivery-1",
        eventType: "user.created",
        status: "pending",
        attempts: 2,
        maxAttempts: 6,
        nextRetryAt: "2026-05-28T12:05:00.000Z",
        hasError: false,
        createdAt: "2026-05-28T11:00:00.000Z",
        deliveredAt: null,
      },
    });
    const retried = await makeClient().retryDelivery("delivery-1");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/webhooks/deliveries/delivery-1/retry",
    );
    expect(retried.status).toBe("pending");
  });
});

// ─── Header Tests ─────────────────────────────────────────────────────────

describe("Request headers", () => {
  it("always sends Content-Type: application/json", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    await makeClient().listAgents();
    expect(lastCapture?.headers["content-type"]).toBe("application/json");
  });

  it("always sends Accept: application/json", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    await makeClient().listAgents();
    expect(lastCapture?.headers.accept).toBe("application/json");
  });

  it("sends X-Steward-Key header when apiKey is set", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = makeClient({ apiKey: "my-secret-key" });
    await client.listAgents();
    expect(lastCapture?.headers["x-steward-key"]).toBe("my-secret-key");
  });

  it("sends Privy-style app secret Basic auth when app credentials are set", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = makeClient({ appId: "tenant-1/web-prod", appSecret: "stw_app_secret" });
    await client.listAgents();
    expect(lastCapture?.headers["x-steward-app-id"]).toBe("tenant-1/web-prod");
    expect(lastCapture?.headers.authorization).toBe(
      `Basic ${btoa("tenant-1/web-prod:stw_app_secret")}`,
    );
  });

  it("sends Authorization: Bearer header when bearerToken is set", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = makeClient({ bearerToken: "my-jwt-token" });
    await client.listAgents();
    expect(lastCapture?.headers.authorization).toBe("Bearer my-jwt-token");
  });

  it("bearerToken takes priority over apiKey when both are set", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = makeClient({
      apiKey: "my-api-key",
      bearerToken: "my-bearer",
    });
    await client.listAgents();
    expect(lastCapture?.headers.authorization).toBe("Bearer my-bearer");
    // apiKey should not be sent when bearerToken is present
    expect(lastCapture?.headers["x-steward-key"]).toBeUndefined();
  });

  it("sends X-Steward-Tenant header when tenantId is set", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = makeClient({ tenantId: "my-tenant-123" });
    await client.listAgents();
    expect(lastCapture?.headers["x-steward-tenant"]).toBe("my-tenant-123");
  });

  it("sends X-Steward-Platform-Key header when platformKey is set", async () => {
    installMockFetch({ ok: true, data: { users: [], limit: 50, offset: 0 } });
    const client = makeClient({ platformKey: "platform-secret" });
    await client.platformUsers.search("tenant-1");
    expect(lastCapture?.headers["x-steward-platform-key"]).toBe("platform-secret");
    expect(lastCapture?.headers.authorization).toBeUndefined();
    expect(lastCapture?.headers["x-steward-key"]).toBeUndefined();
  });

  it("does not send auth header when neither apiKey nor bearerToken is set", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    await makeClient().listAgents();
    expect(lastCapture?.headers.authorization).toBeUndefined();
    expect(lastCapture?.headers["x-steward-key"]).toBeUndefined();
  });

  it("signs sensitive mutating requests when requestSigningSecret is configured", async () => {
    installMockFetch({ ok: true, data: { txHash: "0xdeadbeef" } });
    const requestSigningSecret = "request-signing-secret-with-enough-entropy";
    const client = makeClient({
      tenantId: "tenant-1",
      requestSigningSecret,
    });

    await client.signTransaction("agent-1", {
      to: "0x1234567890123456789012345678901234567890",
      value: "1000000000000000000",
    });

    expect(lastCapture?.headers["x-steward-request-timestamp"]).toMatch(/^\d+$/);
    expect(lastCapture?.headers["idempotency-key"]).toMatch(/^[\x21-\x7e]{8,255}$/);
    expect(lastCapture?.headers["x-steward-signature"]).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(lastCapture?.headers["x-steward-signature"]).toBe(
      await expectedServerSignature(lastCapture!, requestSigningSecret),
    );
  });

  it("signs delegated sensitive requests with the server canonical signer headers", async () => {
    installMockFetch({ ok: true, data: { txHash: "0xdeadbeef" } });
    const requestSigningSecret = "request-signing-secret-with-enough-entropy";
    const client = makeClient({
      tenantId: "tenant-1",
      apiKey: "tenant-api-key",
      requestSigningSecret,
    });

    await client.signTransaction(
      "agent-1",
      {
        to: "0x1234567890123456789012345678901234567890",
        value: "1000000000000000000",
      },
      {
        signerId: "signer-a",
        signerSecret: "delegated-secret-a",
        keyQuorumId: "quorum-a",
        keyQuorumCredentials: [{ signerId: "signer-b", signerSecret: "delegated-secret-b" }],
      },
    );

    expect(lastCapture?.headers["x-steward-signature"]).toBe(
      await expectedServerSignature(lastCapture!, requestSigningSecret),
    );
  });

  it("does not sign non-sensitive requests", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const client = makeClient({
      requestSigningSecret: "request-signing-secret",
    });

    await client.listAgents();

    expect(lastCapture?.headers["x-steward-request-timestamp"]).toBeUndefined();
    expect(lastCapture?.headers["x-steward-signature"]).toBeUndefined();
  });
});

// ─── HTTP Request Building Tests ──────────────────────────────────────────

describe("HTTP request building", () => {
  it("listAgents → GET /agents", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    await makeClient().listAgents();
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents");
  });

  it("getAgent → GET /agents/:id", async () => {
    installMockFetch({ ok: true, data: mockAgent });
    await makeClient().getAgent("agent-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1");
  });

  it("getAgent encodes special characters in agentId", async () => {
    installMockFetch({ ok: true, data: mockAgent });
    await makeClient().getAgent("agent/with spaces");
    expect(lastCapture?.url).toContain(encodeURIComponent("agent/with spaces"));
  });

  it("createWallet → POST /agents with correct body", async () => {
    installMockFetch({ ok: true, data: mockAgent });
    await makeClient().createWallet("agent-1", "Test Agent", "platform-xyz");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents");
    expect(lastCapture?.body).toEqual({
      id: "agent-1",
      name: "Test Agent",
      platformId: "platform-xyz",
    });
  });

  it("createWallet without platformId sends undefined/omitted field", async () => {
    installMockFetch({ ok: true, data: mockAgent });
    await makeClient().createWallet("agent-1", "Test Agent");
    expect(lastCapture?.body).toEqual({
      id: "agent-1",
      name: "Test Agent",
      platformId: undefined,
    });
  });

  it("signTransaction → POST /vault/:agentId/sign", async () => {
    installMockFetch({ ok: true, data: { txHash: "0xdeadbeef" } });
    const tx: SignTransactionInput = {
      to: "0x1234567890123456789012345678901234567890",
      value: "1000000000000000000",
      chainId: 8453,
    };
    await makeClient().signTransaction("agent-1", tx, {
      signerId: "signer-tx-1",
      signerSecret: "secret-tx-1",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-tx-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-tx-1");
    expect(lastCapture?.body).toEqual(tx);
  });

  it("signTransaction can send key quorum credentials in headers", async () => {
    installMockFetch({ ok: true, data: { txHash: "0xdeadbeef" } });
    const tx: SignTransactionInput = {
      to: "0x1234567890123456789012345678901234567890",
      value: "1000000000000000000",
      chainId: 8453,
    };
    await makeClient().signTransaction("agent-1", tx, {
      keyQuorumId: "quorum-1",
      keyQuorumCredentials: [
        { signerId: "signer-1", signerSecret: "secret-1" },
        { signerId: "signer-2", signerSecret: "secret-2" },
      ],
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign");
    expect(lastCapture?.headers["x-steward-key-quorum-id"]).toBe("quorum-1");
    expect(JSON.parse(lastCapture?.headers["x-steward-key-quorum-credentials"] ?? "[]")).toEqual([
      { signerId: "signer-1", signerSecret: "secret-1" },
      { signerId: "signer-2", signerSecret: "secret-2" },
    ]);
    expect(lastCapture?.body).toEqual(tx);
  });

  it("signUserOperation → POST /vault/:agentId/sign-user-operation", async () => {
    installMockFetch({
      ok: true,
      data: {
        signature: "0xsig",
        userOperationHash: "0xhash",
        entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
        chainId: 8453,
        txId: "tx-1",
      },
    });
    const input: SignUserOperationInput = {
      userOperation: {
        sender: "0x1234567890123456789012345678901234567890",
        nonce: "0",
        callData: "0x",
        verificationGasLimit: "100000",
        callGasLimit: "100000",
        preVerificationGas: "21000",
        maxPriorityFeePerGas: "1000000",
        maxFeePerGas: "2000000",
      },
      chainId: 8453,
      to: "0x1234567890123456789012345678901234567890",
      value: "0",
      referenceId: "userop-ref-1",
    };

    const result = await makeClient().signUserOperation("agent-1", input, {
      signerId: "signer-userop-1",
      signerSecret: "secret-userop-1",
    });

    expect(result.txId).toBe("tx-1");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign-user-operation");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-userop-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-userop-1");
    expect(lastCapture?.body).toEqual(input);
  });

  it("signAuthorization → POST /vault/:agentId/sign-authorization", async () => {
    installMockFetch({
      ok: true,
      data: {
        authorization: {
          contractAddress: "0x1234567890123456789012345678901234567890",
          chainId: 8453,
          nonce: 7,
          r: "0x01",
          s: "0x02",
          yParity: 1,
        },
        txId: "tx-auth-1",
      },
    });
    const input = {
      contractAddress: "0x1234567890123456789012345678901234567890",
      chainId: 8453,
      nonce: 7,
      referenceId: "auth-ref-1",
    };

    const result = await makeClient().signAuthorization("agent-1", input, {
      signerId: "signer-auth-1",
      signerSecret: "secret-auth-1",
    });

    expect(result.txId).toBe("tx-auth-1");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign-authorization");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-auth-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-auth-1");
    expect(lastCapture?.body).toEqual(input);
  });

  it("signTypedData → POST /vault/:agentId/sign-typed-data", async () => {
    installMockFetch({ ok: true, data: { signature: "0xsig", txId: "typed-1" } });
    const input = {
      domain: { name: "Permit2", chainId: 8453 },
      types: { PermitSingle: [{ name: "spender", type: "address" }] },
      primaryType: "PermitSingle",
      value: { spender: "0x1234567890123456789012345678901234567890" },
    };

    const result = await makeClient().signTypedData("agent-1", input, {
      signerId: "signer-typed-1",
      signerSecret: "secret-typed-1",
    });

    expect(result.signature).toBe("0xsig");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign-typed-data");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-typed-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-typed-1");
    expect(lastCapture?.body).toEqual(input);
  });

  it("quoteTransfer → POST /vault/:agentId/actions/transfer/quote", async () => {
    installMockFetch({
      ok: true,
      data: {
        quoteId: "quote-1",
        type: "transfer",
        chainId: 8453,
        from: "0x0000000000000000000000000000000000000000",
        to: "0x1234567890123456789012345678901234567890",
        value: "1000",
        token: "native",
        expiresAt: "2026-05-25T00:00:00.000Z",
        request: {
          to: "0x1234567890123456789012345678901234567890",
          token: "native",
          value: "1000",
          chainId: 8453,
          broadcast: false,
          sponsor: true,
        },
      },
    });

    const quote = await makeClient().quoteTransfer("agent-1", {
      to: "0x1234567890123456789012345678901234567890",
      value: "1000",
      chainId: 8453,
      broadcast: false,
      sponsor: true,
    });

    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/vault/agent-1/actions/transfer/quote",
    );
    expect(lastCapture?.body).toMatchObject({ sponsor: true });
    expect(quote.request.sponsor).toBe(true);
  });

  it("createTransferAction → POST /vault/:agentId/actions/transfer", async () => {
    installMockFetch({
      ok: true,
      data: {
        id: "action-1",
        type: "transfer",
        status: "signed",
        chainId: 8453,
        to: "0x1234567890123456789012345678901234567890",
        value: "1000",
        signedTx: "0xsigned",
      },
    });

    const result = await makeClient().createTransferAction(
      "agent-1",
      {
        to: "0x1234567890123456789012345678901234567890",
        token: "0x4200000000000000000000000000000000000006",
        value: "1000",
        broadcast: false,
        referenceId: "transfer-ref-1",
        sponsor: true,
      },
      { signerId: "signer-transfer-1", signerSecret: "secret-transfer-1" },
    );

    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/actions/transfer");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-transfer-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-transfer-1");
    expect(lastCapture?.body).toMatchObject({
      token: "0x4200000000000000000000000000000000000006",
      referenceId: "transfer-ref-1",
      sponsor: true,
    });
    expect(result.status).toBe("signed");
  });

  it("createSendCallsAction → POST /vault/:agentId/actions/send-calls", async () => {
    installMockFetch({
      ok: true,
      data: {
        id: "send-calls-1",
        type: "send_calls",
        status: "pending_approval",
        chainId: 8453,
        calls: [{ to: "0x1234567890123456789012345678901234567890", value: "1000" }],
        totalValue: "1000",
      },
    });

    const input = {
      calls: [{ to: "0x1234567890123456789012345678901234567890", value: "1000" }],
      chainId: 8453,
      broadcast: false,
      referenceId: "send-calls-ref-1",
      sponsor: true,
    };
    const result = await makeClient().createSendCallsAction("agent-1", input, {
      signerId: "signer-send-calls-1",
      signerSecret: "secret-send-calls-1",
    });

    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/actions/send-calls");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-send-calls-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-send-calls-1");
    expect(lastCapture?.body).toEqual(input);
    expect(result.status).toBe("pending_approval");
    expect(result.totalValue).toBe("1000");
  });

  it("getTransferAction → GET /vault/:agentId/actions/:actionId", async () => {
    installMockFetch({
      ok: true,
      data: {
        id: "action-1",
        type: "transfer",
        status: "rejected",
        chainId: 8453,
        to: "0x1234567890123456789012345678901234567890",
        value: "1000",
      },
    });

    await makeClient().getTransferAction("agent-1", "action-1");

    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/actions/action-1");
  });

  it("user linked account helpers use /user/me/accounts", async () => {
    installMockFetch({
      ok: true,
      data: {
        accounts: [
          {
            id: "account-1",
            provider: "google",
            providerAccountId: "google-1",
            expiresAt: null,
          },
        ],
        primaryLoginMethods: [{ provider: "email", providerAccountId: "user@example.test" }],
      },
    });
    const accounts = await makeClient({ bearerToken: "user-token" }).listUserAccounts();
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts");
    expect(accounts.accounts[0].provider).toBe("google");

    installMockFetch({ ok: true, data: { deleted: true, issuedBefore: 123 } });
    await makeClient({ bearerToken: "user-token" }).unlinkUserAccount("google", "google-1");
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/google/google-1");
  });

  it("getUserAccount → GET /user/me/account", async () => {
    installMockFetch({
      ok: true,
      data: {
        id: "user-1",
        type: "user",
        userId: "user-1",
        tenantId: "personal-user-1",
        email: "user@example.test",
        emailVerified: true,
        name: null,
        image: null,
        walletAddress: "0x1234567890123456789012345678901234567890",
        walletChain: "ethereum",
        customMetadata: {},
        linkedAccounts: [],
        primaryLoginMethods: [{ provider: "email", providerAccountId: "user@example.test" }],
        wallet: {
          id: "user-wallet-user-1",
          agentId: "user-wallet-user-1",
          walletAddress: "0x1234567890123456789012345678901234567890",
          walletAddresses: { evm: "0x1234567890123456789012345678901234567890" },
          createdAt: new Date().toISOString(),
        },
        walletAddresses: { evm: "0x1234567890123456789012345678901234567890" },
        wallets: [],
        balances: { evm: null, unavailableReason: "mocked" },
        portfolio: {
          chainId: 8453,
          walletAddress: "0x1234567890123456789012345678901234567890",
          native: null,
          tokens: [],
          totalUsd: null,
          totalUsdText: null,
          unavailableReason: "mocked",
        },
        spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
        capabilities: ["sign_transaction"],
        sponsorship: { enabled: false, provider: null },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    });

    const account = await makeClient({ bearerToken: "user-token" }).getUserAccount({
      chainId: 8453,
      tokens: ["0x1111111111111111111111111111111111111111"],
    });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/account?chainId=8453&tokens=0x1111111111111111111111111111111111111111",
    );
    expect(account.type).toBe("user");
    expect(account.wallet?.agentId).toBe("user-wallet-user-1");
  });

  it("user Ethereum wallet link helpers use proof endpoints", async () => {
    installMockFetch({
      ok: true,
      data: {
        nonce: "nonce-1",
        message: "message-to-sign",
        expiresIn: 300,
        address: "0x1234567890123456789012345678901234567890",
      },
    });
    const nonce = await makeClient({
      bearerToken: "user-token",
    }).createUserEthereumWalletLinkNonce("0x1234567890123456789012345678901234567890");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/accounts/wallet/ethereum/nonce",
    );
    expect(lastCapture?.body).toEqual({
      address: "0x1234567890123456789012345678901234567890",
    });
    expect(nonce.message).toBe("message-to-sign");

    installMockFetch({
      ok: true,
      data: {
        account: {
          id: "account-1",
          provider: "wallet:ethereum",
          providerAccountId: "0x1234567890123456789012345678901234567890",
          expiresAt: null,
        },
        isNew: true,
      },
    });
    const linked = await makeClient({ bearerToken: "user-token" }).linkUserEthereumWallet({
      address: "0x1234567890123456789012345678901234567890",
      message: "message-to-sign",
      signature: "0xsig",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/wallet/ethereum");
    expect(linked.account.provider).toBe("wallet:ethereum");
  });

  it("user Solana wallet link helpers use proof endpoints", async () => {
    installMockFetch({
      ok: true,
      data: {
        nonce: "nonce-1",
        message: "message-to-sign",
        expiresIn: 300,
        publicKey: "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct",
      },
    });
    const nonce = await makeClient({
      bearerToken: "user-token",
    }).createUserSolanaWalletLinkNonce("zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/accounts/wallet/solana/nonce",
    );
    expect(lastCapture?.body).toEqual({
      publicKey: "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct",
    });
    expect(nonce.message).toBe("message-to-sign");

    installMockFetch({
      ok: true,
      data: {
        account: {
          id: "account-1",
          provider: "wallet:solana",
          providerAccountId: "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct",
          expiresAt: null,
        },
        isNew: true,
      },
    });
    const linked = await makeClient({ bearerToken: "user-token" }).linkUserSolanaWallet({
      publicKey: "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct",
      message: "message-to-sign",
      signature: "solana-sig",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/wallet/solana");
    expect(linked.account.provider).toBe("wallet:solana");
  });

  it("user OAuth account link helpers use state challenge and provider token endpoints", async () => {
    installMockFetch({
      ok: true,
      data: {
        state: "oauth-state",
        redirectUri: "https://app.example.test/auth/callback",
        expiresIn: 300,
      },
    });
    const challenge = await makeClient({
      bearerToken: "user-token",
    }).createUserOAuthAccountLinkChallenge("github", {
      redirectUri: "https://app.example.test/auth/callback",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/accounts/oauth/github/challenge",
    );
    expect(lastCapture?.body).toEqual({
      redirectUri: "https://app.example.test/auth/callback",
    });
    expect(challenge.state).toBe("oauth-state");

    installMockFetch({
      ok: true,
      data: {
        account: {
          id: "account-1",
          provider: "github",
          providerAccountId: "gh-1",
          expiresAt: null,
        },
        isNew: true,
      },
    });
    const linked = await makeClient({ bearerToken: "user-token" }).linkUserOAuthAccount("github", {
      code: "oauth-code",
      redirectUri: "https://app.example.test/auth/callback",
      state: "oauth-state",
      codeVerifier: "verifier",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/accounts/oauth/github/token",
    );
    expect(lastCapture?.body).toEqual({
      code: "oauth-code",
      redirectUri: "https://app.example.test/auth/callback",
      state: "oauth-state",
      codeVerifier: "verifier",
    });
    expect(linked.account.provider).toBe("github");
  });

  it("user phone account link helpers use OTP endpoints", async () => {
    installMockFetch({
      ok: true,
      data: { phone: "***0123", expiresAt: "2026-05-27T12:00:00.000Z" },
    });
    const send = await makeClient({ bearerToken: "user-token" }).sendUserPhoneAccountLinkOtp(
      "+14155550123",
    );
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/phone/sms/send");
    expect(lastCapture?.body).toEqual({ phone: "+14155550123" });
    expect(send.phone).toBe("***0123");

    installMockFetch({
      ok: true,
      data: {
        account: {
          id: "account-1",
          provider: "phone",
          providerAccountId: "phone:hash",
          expiresAt: null,
        },
        isNew: true,
      },
    });
    const linked = await makeClient({ bearerToken: "user-token" }).verifyUserPhoneAccountLinkOtp({
      phone: "+14155550123",
      code: "123456",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/phone/sms/verify");
    expect(lastCapture?.body).toEqual({ phone: "+14155550123", code: "123456" });
    expect(linked.account.provider).toBe("phone");
  });

  it("user Telegram and Farcaster account link helpers use social proof endpoints", async () => {
    installMockFetch({
      ok: true,
      data: { challengeId: "telegram-challenge", expiresIn: 300 },
    });
    const telegramChallenge = await makeClient({
      bearerToken: "user-token",
    }).createUserTelegramAccountLinkChallenge();
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/accounts/telegram/challenge",
    );
    expect(telegramChallenge.challengeId).toBe("telegram-challenge");

    installMockFetch({
      ok: true,
      data: {
        account: {
          id: "account-1",
          provider: "telegram",
          providerAccountId: "424242",
          expiresAt: null,
        },
        isNew: true,
      },
    });
    const telegram = await makeClient({ bearerToken: "user-token" }).linkUserTelegramAccount({
      id: "424242",
      auth_date: 1_778_200_000,
      hash: "a".repeat(64),
      challengeId: "telegram-challenge",
    });
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/telegram");
    expect(telegram.account.provider).toBe("telegram");

    installMockFetch({ ok: true, data: { nonce: "farcaster-nonce", expiresIn: 300 } });
    const farcasterNonce = await makeClient({
      bearerToken: "user-token",
    }).createUserFarcasterAccountLinkNonce();
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/farcaster/nonce");
    expect(farcasterNonce.nonce).toBe("farcaster-nonce");

    installMockFetch({
      ok: true,
      data: {
        account: {
          id: "account-2",
          provider: "farcaster",
          providerAccountId: "address:0x0000000000000000000000000000000000000001",
          expiresAt: null,
        },
        isNew: true,
      },
    });
    const farcaster = await makeClient({ bearerToken: "user-token" }).linkUserFarcasterAccount({
      message: "siwf-message",
      signature: `0x${"a".repeat(130)}`,
      custodyAddress: "0x0000000000000000000000000000000000000001",
      fid: "4242",
    });
    expect(lastCapture?.url).toBe("https://api.steward.example/user/me/accounts/farcaster");
    expect(farcaster.account.provider).toBe("farcaster");
  });

  it("getPolicies → GET /agents/:id/policies", async () => {
    installMockFetch({ ok: true, data: [mockPolicy] });
    await makeClient().getPolicies("agent-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/policies");
  });

  it("tenant config helpers preserve allowedOrigins", async () => {
    installMockFetch({
      ok: true,
      data: {
        tenantId: "tenant-1",
        policyExposure: {},
        policyTemplates: [],
        secretRoutePresets: [],
        approvalConfig: {},
        featureFlags: {},
        allowedOrigins: ["https://app.example.test", "http://localhost:3000"],
      },
    });

    const config = await makeClient({ bearerToken: "user-token" }).getTenantConfig("tenant-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/tenants/tenant-1/config");
    expect(config.allowedOrigins).toEqual(["https://app.example.test", "http://localhost:3000"]);

    installMockFetch({
      ok: true,
      data: {
        tenantId: "tenant-1",
        policyExposure: {},
        policyTemplates: [],
        secretRoutePresets: [],
        approvalConfig: {},
        featureFlags: {},
        allowedOrigins: ["https://dashboard.example.test"],
      },
    });

    await makeClient({ bearerToken: "user-token" }).updateTenantConfig("tenant-1", {
      allowedOrigins: ["https://dashboard.example.test"],
    });
    expect(lastCapture?.method).toBe("PUT");
    expect(lastCapture?.body).toEqual({ allowedOrigins: ["https://dashboard.example.test"] });
  });

  it("app origin helpers use tenant app-origin aliases", async () => {
    installMockFetch({ ok: true, data: { entries: ["https://app.example.test"] } });
    const entries = await makeClient({ bearerToken: "user-token" }).listAppOrigins("tenant/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/app-origins`,
    );
    expect(entries).toEqual(["https://app.example.test"]);

    installMockFetch({
      ok: true,
      data: { entries: ["https://app.example.test", "https://dashboard.example.test"] },
    });
    await makeClient({ bearerToken: "user-token" }).addAppOrigin(
      "tenant/one",
      "https://dashboard.example.test",
    );
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.body).toEqual({ origins: ["https://dashboard.example.test"] });

    installMockFetch({ ok: true, data: { entries: ["https://app.example.test"] } });
    await makeClient({ bearerToken: "user-token" }).removeAppOrigins("tenant/one", [
      "https://dashboard.example.test",
    ]);
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.body).toEqual({ origins: ["https://dashboard.example.test"] });
  });

  it("redirect URL helpers use tenant redirect-url aliases", async () => {
    installMockFetch({ ok: true, data: { entries: ["https://app.example.test/callback"] } });
    const entries = await makeClient({ bearerToken: "user-token" }).listRedirectUrls("tenant/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/redirect-urls`,
    );
    expect(entries).toEqual(["https://app.example.test/callback"]);

    installMockFetch({
      ok: true,
      data: {
        entries: ["https://app.example.test/callback", "https://dashboard.example.test/auth"],
      },
    });
    await makeClient({ bearerToken: "user-token" }).addRedirectUrl(
      "tenant/one",
      "https://dashboard.example.test/auth",
    );
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.body).toEqual({ urls: ["https://dashboard.example.test/auth"] });

    installMockFetch({ ok: true, data: { entries: ["https://app.example.test/callback"] } });
    await makeClient({ bearerToken: "user-token" }).removeRedirectUrls("tenant/one", [
      "https://dashboard.example.test/auth",
    ]);
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.body).toEqual({ urls: ["https://dashboard.example.test/auth"] });
  });

  it("app client helpers use tenant app-client aliases", async () => {
    const clients = [
      {
        id: "web-prod",
        name: "Production Web",
        environment: "production" as const,
        enabled: true,
        isDefault: true,
        allowedOrigins: ["https://app.example.test"],
        allowedRedirectUrls: ["https://app.example.test/auth/callback"],
      },
    ];

    installMockFetch({ ok: true, data: { clients } });
    const listed = await makeClient({ bearerToken: "user-token" }).listTenantAppClients(
      "tenant/one",
    );
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/app-clients`,
    );
    expect(listed).toEqual(clients);

    installMockFetch({ ok: true, data: { clients } });
    await makeClient({ bearerToken: "user-token" }).replaceTenantAppClients("tenant/one", clients);
    expect(lastCapture?.method).toBe("PUT");
    expect(lastCapture?.body).toEqual({ clients });

    installMockFetch({ ok: true, data: { client: clients[0] } });
    await makeClient({ bearerToken: "user-token" }).createTenantAppClient("tenant/one", clients[0]);
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.body).toEqual({ client: clients[0] });

    installMockFetch({ ok: true, data: { clients: [] } });
    await makeClient({ bearerToken: "user-token" }).deleteTenantAppClient("tenant/one", "web/prod");
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/app-clients/${encodeURIComponent("web/prod")}`,
    );

    installMockFetch({
      ok: true,
      data: {
        appId: "tenant/one/web-prod",
        secrets: [
          {
            id: "secret-1",
            tenantId: "tenant/one",
            clientId: "web-prod",
            appId: "tenant/one/web-prod",
            secretPrefix: "stw_app_1234...abcd",
            status: "active",
            createdAt: "2026-05-28T12:00:00.000Z",
            updatedAt: "2026-05-28T12:00:00.000Z",
            expiresAt: null,
            revokedAt: null,
          },
        ],
      },
    });
    const secretList = await makeClient({ bearerToken: "user-token" }).listTenantAppClientSecrets(
      "tenant/one",
      "web-prod",
    );
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/app-clients/web-prod/secrets`,
    );
    expect(secretList.secrets[0].secretPrefix).toBe("stw_app_1234...abcd");

    installMockFetch({
      ok: true,
      data: {
        appId: "tenant/one/web-prod",
        appSecret: "stw_app_new",
        secret: {
          id: "secret-2",
          tenantId: "tenant/one",
          clientId: "web-prod",
          appId: "tenant/one/web-prod",
          secretPrefix: "stw_app_new...wxyz",
          status: "active",
          createdAt: "2026-05-28T12:05:00.000Z",
          updatedAt: "2026-05-28T12:05:00.000Z",
          expiresAt: null,
          revokedAt: null,
        },
      },
    });
    const rotated = await makeClient({ bearerToken: "user-token" }).rotateTenantAppClientSecret(
      "tenant/one",
      "web-prod",
    );
    expect(lastCapture?.method).toBe("POST");
    expect(rotated.appSecret).toBe("stw_app_new");

    installMockFetch({
      ok: true,
      data: {
        secret: {
          id: "secret-2",
          tenantId: "tenant/one",
          clientId: "web-prod",
          appId: "tenant/one/web-prod",
          secretPrefix: "stw_app_new...wxyz",
          status: "revoked",
          createdAt: "2026-05-28T12:05:00.000Z",
          updatedAt: "2026-05-28T12:06:00.000Z",
          expiresAt: null,
          revokedAt: "2026-05-28T12:06:00.000Z",
        },
      },
    });
    const revoked = await makeClient({ bearerToken: "user-token" }).revokeTenantAppClientSecret(
      "tenant/one",
      "web-prod",
      "secret-2",
    );
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/app-clients/web-prod/secrets/secret-2`,
    );
    expect(revoked.status).toBe("revoked");
  });

  it("access allowlist helpers use tenant access-allowlist aliases", async () => {
    const allowlist = [
      {
        id: "email_123",
        tenantId: "tenant/one",
        type: "email" as const,
        value: "person@example.com",
        acceptedAt: null,
      },
    ];
    installMockFetch({ ok: true, data: { entries: allowlist } });
    const entries = await makeClient({ bearerToken: "user-token" }).listAccessAllowlistEntries(
      "tenant/one",
    );
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/access-allowlist`,
    );
    expect(entries).toEqual(allowlist);

    installMockFetch({ ok: true, data: { entries: allowlist } });
    await makeClient({ bearerToken: "user-token" }).addAccessAllowlistEntry("tenant/one", {
      type: "email_domain",
      value: "example.com",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.body).toEqual({
      entries: [{ type: "email_domain", value: "example.com" }],
    });

    installMockFetch({ ok: true, data: { entries: [] } });
    await makeClient({ bearerToken: "user-token" }).removeAccessAllowlistEntry("tenant/one", {
      id: "email_123",
    });
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.body).toEqual({ ids: ["email_123"] });
  });

  it("policy rule helpers use nested /agents/:id/policies/rules endpoints", async () => {
    installMockFetch({ ok: true, data: { rules: [mockPolicy] } });
    const rules = await makeClient().listPolicyRules("agent-1");
    expect(rules[0].id).toBe("rule-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/policies/rules");

    installMockFetch({ ok: true, data: mockPolicy });
    await makeClient().createPolicyRule("agent-1", {
      type: "spending-limit",
      config: { maxPerTx: "1000" },
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/policies/rules");
    expect(lastCapture?.body).toEqual({
      type: "spending-limit",
      config: { maxPerTx: "1000" },
    });

    installMockFetch({ ok: true, data: mockPolicy });
    await makeClient().getPolicyRule("agent-1", "rule/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/agents/agent-1/policies/rules/${encodeURIComponent("rule/one")}`,
    );

    installMockFetch({ ok: true, data: { ...mockPolicy, enabled: false } });
    await makeClient().updatePolicyRule("agent-1", "rule-1", { enabled: false });
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/policies/rules/rule-1",
    );
    expect(lastCapture?.body).toEqual({ enabled: false });

    installMockFetch({ ok: true, data: mockPolicy });
    await makeClient().deletePolicyRule("agent-1", "rule-1");
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/policies/rules/rule-1",
    );
  });

  it("platformUsers.search → GET /platform/tenants/:id/users with query params", async () => {
    installMockFetch({ ok: true, data: { users: [], limit: 10, offset: 5 } });
    await makeClient({ platformKey: "platform-key" }).platformUsers.search("tenant/one", {
      q: "alice",
      limit: 10,
      offset: 5,
    });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/platform/tenants/${encodeURIComponent("tenant/one")}/users?q=alice&limit=10&offset=5`,
    );
  });

  it("platformUsers.updateMetadata → PATCH metadata endpoint", async () => {
    const user = {
      userId: "user-1",
      tenantId: "tenant-1",
      role: "member",
      joinedAt: "2024-01-01T00:00:00Z",
      email: "alice@example.com",
      emailVerified: true,
      name: "Alice",
      tenantCustomMetadata: { externalId: "crm-1" },
      createdAt: "2024-01-01T00:00:00Z",
      updatedAt: "2024-01-02T00:00:00Z",
    };
    installMockFetch({ ok: true, data: user });
    const result = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.updateMetadata("tenant-1", "user-1", {
      tenantCustomMetadata: { externalId: "crm-1" },
    });
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/tenants/tenant-1/users/user-1/metadata",
    );
    expect(lastCapture?.body).toEqual({
      tenantCustomMetadata: { externalId: "crm-1" },
    });
    expect(result.createdAt).toBeInstanceOf(Date);
    expect(result.joinedAt).toBeInstanceOf(Date);
  });

  it("platformUsers.get returns the tenant-scoped user shape", async () => {
    installMockFetch({
      ok: true,
      data: {
        userId: "user-1",
        tenantId: "tenant-1",
        role: "member",
        joinedAt: "2024-01-01T00:00:00Z",
        email: "alice@example.com",
        emailVerified: true,
        name: "Alice",
        tenantCustomMetadata: { externalId: "crm-1" },
        createdAt: "2024-01-01T00:00:00Z",
        updatedAt: "2024-01-02T00:00:00Z",
      },
    });

    const result = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.get("tenant-1", "user-1");

    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/tenants/tenant-1/users/user-1",
    );
    expect(result.createdAt).toBeInstanceOf(Date);
    expect("linkedAccounts" in result).toBe(false);
  });

  it("tenant user helpers use user-authenticated team directory routes", async () => {
    const user = {
      userId: "user-1",
      tenantId: "tenant-1",
      role: "viewer",
      joinedAt: "2024-01-01T00:00:00Z",
      email: "alice@example.com",
      emailVerified: true,
      name: "Alice",
      tenantCustomMetadata: { team: "eng" },
      createdAt: "2024-01-01T00:00:00Z",
      updatedAt: "2024-01-02T00:00:00Z",
    };
    const client = makeClient({ bearerToken: "user-token" });

    installMockFetch({ ok: true, data: { users: [user], limit: 10, offset: 5 } });
    const listed = await client.listTenantUsers("tenant/one", { q: "alice", limit: 10, offset: 5 });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/user/me/tenants/${encodeURIComponent("tenant/one")}/users?q=alice&limit=10&offset=5`,
    );
    expect(listed.users[0].joinedAt).toBeInstanceOf(Date);

    installMockFetch({ ok: true, data: user });
    await client.getTenantUser("tenant-1", "user-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/tenants/tenant-1/users/user-1",
    );

    installMockFetch({ ok: true, data: { ...user, role: "developer" } });
    const updated = await client.updateTenantUserRole("tenant-1", "user-1", "developer");
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/user/me/tenants/tenant-1/users/user-1/role",
    );
    expect(lastCapture?.body).toEqual({ role: "developer" });
    expect(updated.role).toBe("developer");
    expect(updated.updatedAt).toBeInstanceOf(Date);
  });

  it("platformUsers.linkAccount and unlinkAccount use linked account endpoints", async () => {
    installMockFetch({
      ok: true,
      data: {
        id: "account-1",
        provider: "google",
        providerAccountId: "google-1",
        expiresAt: null,
        isNew: true,
      },
    });
    await makeClient({ platformKey: "platform-key" }).platformUsers.linkAccount("user-1", {
      provider: "google",
      providerAccountId: "google-1",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/platform/users/user-1/accounts");
    expect(lastCapture?.body).toEqual({
      provider: "google",
      providerAccountId: "google-1",
    });

    installMockFetch({ ok: true });
    await makeClient({
      platformKey: "platform-key",
    }).platformUsers.unlinkAccount("user-1", "google", "google-1", {
      force: true,
    });
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/user-1/accounts/google/google-1?force=true",
    );

    installMockFetch({
      ok: true,
      data: {
        id: "account-1",
        provider: "google",
        providerAccountId: "google-1",
        expiresAt: null,
        fromUserId: "user-1",
        toUserId: "user-2",
      },
    });
    const transfer = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.transferAccount("user-1", "google", "google-1", {
      toUserId: "user-2",
      force: true,
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/user-1/accounts/google/google-1/transfer",
    );
    expect(lastCapture?.body).toEqual({ toUserId: "user-2", force: true });
    expect(transfer.toUserId).toBe("user-2");
  });

  it("platformUsers.getIdentity and lookup use global identity endpoints", async () => {
    const identity = {
      userId: "user-1",
      email: "alice@example.com",
      emailVerified: true,
      name: "Alice",
      image: null,
      walletAddress: "0xabc",
      walletChain: "ethereum",
      customMetadata: { plan: "pro" },
      createdAt: "2024-01-01T00:00:00Z",
      updatedAt: "2024-01-02T00:00:00Z",
      tenantIds: ["tenant-1"],
      linkedAccounts: [
        {
          id: "acct-1",
          provider: "google",
          providerAccountId: "google-1",
          expiresAt: null,
        },
      ],
    };

    installMockFetch({ ok: true, data: identity });
    const result = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.getIdentity("user-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/platform/users/user-1");
    expect(result.createdAt).toBeInstanceOf(Date);

    installMockFetch({ ok: true, data: { user: identity } });
    const lookup = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.lookup({
      provider: "google",
      providerAccountId: "google-1",
      tenantId: "tenant-1",
    });
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/lookup?provider=google&providerAccountId=google-1&tenantId=tenant-1",
    );
    expect(lookup.user?.updatedAt).toBeInstanceOf(Date);

    installMockFetch({
      ok: true,
      data: { ...identity, customMetadata: { plan: "enterprise" } },
    });
    const updated = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.updateCustomMetadata("user-1", { plan: "enterprise" });
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe("https://api.steward.example/platform/users/user-1/metadata");
    expect(lastCapture?.body).toEqual({
      customMetadata: { plan: "enterprise" },
    });
    expect(updated.customMetadata).toEqual({ plan: "enterprise" });
    expect(updated.createdAt).toBeInstanceOf(Date);

    installMockFetch({ ok: true, data: { user: null } });
    await makeClient({ platformKey: "platform-key" }).platformUsers.lookup({
      phone: "+14155550101",
      smartWalletId: "smart-wallet-1",
      customAuthId: "custom-auth-1",
    });
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/lookup?phone=%2B14155550101&smartWalletId=smart-wallet-1&customAuthId=custom-auth-1",
    );
  });

  it("platformUsers lookup aliases delegate to provider-specific lookup params", async () => {
    installMockFetch({ ok: true, data: { user: null } });
    await makeClient({ platformKey: "platform-key" }).platformUsers.getUserByEmailAddress(
      "alice@example.test",
      { tenantId: "tenant-1" },
    );
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/lookup?email=alice%40example.test&tenantId=tenant-1",
    );

    installMockFetch({ ok: true, data: { user: null } });
    await makeClient({ platformKey: "platform-key" }).platformUsers.getUserByWalletAddress(
      "0x1111111111111111111111111111111111111111",
    );
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/lookup?walletAddress=0x1111111111111111111111111111111111111111",
    );

    installMockFetch({ ok: true, data: { user: null } });
    await makeClient({ platformKey: "platform-key" }).platformUsers.getUserByGithubUsername(
      "octocat",
    );
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/users/lookup?provider=github&providerAccountId=octocat",
    );
  });

  it("platformUsers.deactivate and delete use global user lifecycle endpoints", async () => {
    installMockFetch({
      ok: true,
      data: { userId: "user-1", deactivatedAt: "2024-01-03T00:00:00Z" },
    });
    const deactivated = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.deactivate("user-1");
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe("https://api.steward.example/platform/users/user-1/deactivate");
    expect(lastCapture?.body).toEqual({ deactivated: true });
    expect(deactivated.deactivatedAt).toBeInstanceOf(Date);

    installMockFetch({ ok: true, data: { userId: "user-1", deleted: true } });
    const deleted = await makeClient({
      platformKey: "platform-key",
    }).platformUsers.delete("user-1");
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe("https://api.steward.example/platform/users/user-1");
    expect(deleted).toEqual({ userId: "user-1", deleted: true });
  });

  it("platformTestAccounts manage tenant test credentials", async () => {
    installMockFetch({
      ok: true,
      data: {
        testAccount: {
          enabled: true,
          email: "test-123456@steward.test",
          phone: "+15555551234",
          otp: "123456",
        },
      },
    });
    const enabled = await makeClient({
      platformKey: "platform-key",
    }).platformTestAccounts.enable("tenant-1");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/tenants/tenant-1/test-account",
    );
    expect(enabled.otp).toBe("123456");

    installMockFetch({ ok: true, data: { testAccount: { enabled: false } } });
    await makeClient({
      platformKey: "platform-key",
    }).platformTestAccounts.disable("tenant-1");
    expect(lastCapture?.method).toBe("DELETE");
  });

  it("tenant OIDC provider helpers use tenant config endpoints", async () => {
    const provider = {
      id: "auth0-prod",
      enabled: true,
      issuer: "https://tenant.example.com",
      audience: ["steward-api"],
      jwksUri: "https://tenant.example.com/.well-known/jwks.json",
      allowedAlgs: ["RS256" as const],
    };

    installMockFetch({ ok: true, data: { providers: [provider] } });
    const providers = await makeClient({
      bearerToken: "session-token",
    }).getTenantOidcProviders("tenant/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/oidc-providers`,
    );
    expect(providers).toEqual([provider]);

    installMockFetch({ ok: true, data: { providers: [provider] } });
    await makeClient({
      bearerToken: "session-token",
    }).updateTenantOidcProviders("tenant/one", [provider]);
    expect(lastCapture?.method).toBe("PUT");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/oidc-providers`,
    );
    expect(lastCapture?.body).toEqual({ providers: [provider] });
  });

  it("tenant SSO domain helpers use discovery and tenant config endpoints", async () => {
    const domain = {
      id: "domain-1",
      tenantId: "tenant-1",
      domain: "example.com",
      verificationToken: "steward-sso-token",
      status: "pending",
      ssoRequired: true,
      verifiedAt: null,
      createdAt: "2026-05-28T12:00:00.000Z",
      updatedAt: "2026-05-28T12:00:00.000Z",
    };

    installMockFetch({
      ok: true,
      data: { domain: "example.com", tenantId: "tenant-1", ssoRequired: true, available: true },
    });
    const discovered = await makeClient().discoverSso("admin@example.com");
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/auth/sso/discover");
    expect(lastCapture?.body).toEqual({ email: "admin@example.com" });
    expect(discovered.available).toBe(true);

    installMockFetch({ ok: true, data: { domains: [domain] } });
    await makeClient({ bearerToken: "session-token" }).listTenantSsoDomains("tenant/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/sso-domains`,
    );

    installMockFetch({ ok: true, data: { domain } });
    await makeClient({ bearerToken: "session-token" }).createTenantSsoDomain("tenant/one", {
      domain: "example.com",
      ssoRequired: true,
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.body).toEqual({ domain: "example.com", ssoRequired: true });

    installMockFetch({ ok: true, data: { domain: { ...domain, status: "verified" } } });
    await makeClient({ bearerToken: "session-token" }).verifyTenantSsoDomain(
      "tenant/one",
      "example.com",
    );
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/sso-domains/example.com/verify`,
    );

    installMockFetch({ ok: true, data: { deleted: true } });
    await makeClient({ bearerToken: "session-token" }).deleteTenantSsoDomain(
      "tenant/one",
      "example.com",
    );
    expect(lastCapture?.method).toBe("DELETE");
  });

  it("tenant auth abuse helpers use tenant config endpoints", async () => {
    const authAbuseConfig = {
      loginMethods: {
        email: false,
        sms: true,
        oauth: { google: false },
      },
      captcha: {
        enabled: true,
        provider: "turnstile" as const,
        siteKey: "site-key",
        requiredFor: ["email_otp" as const],
      },
    };

    installMockFetch({ ok: true, data: { authAbuseConfig } });
    const loaded = await makeClient({
      bearerToken: "session-token",
    }).getTenantAuthAbuseConfig("tenant/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/auth-abuse-config`,
    );
    expect(loaded).toEqual(authAbuseConfig);

    installMockFetch({ ok: true, data: { authAbuseConfig } });
    await makeClient({
      bearerToken: "session-token",
    }).updateTenantAuthAbuseConfig("tenant/one", authAbuseConfig);
    expect(lastCapture?.method).toBe("PUT");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/auth-abuse-config`,
    );
    expect(lastCapture?.body).toEqual({ authAbuseConfig });
  });

  it("tenant gas sponsorship helpers use tenant config endpoints", async () => {
    const gasSponsorshipConfig = {
      enabled: true,
      provider: "mock" as const,
      mode: "erc4337" as const,
      allowedChainIds: [8453],
      maxPerTxUsd: 1,
      requireSimulation: true,
    };

    installMockFetch({ ok: true, data: { gasSponsorshipConfig } });
    const loaded = await makeClient({
      bearerToken: "session-token",
    }).getTenantGasSponsorshipConfig("tenant/one");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/gas-sponsorship`,
    );
    expect(loaded).toEqual(gasSponsorshipConfig);

    installMockFetch({ ok: true, data: { gasSponsorshipConfig } });
    await makeClient({
      bearerToken: "session-token",
    }).updateTenantGasSponsorshipConfig("tenant/one", gasSponsorshipConfig);
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe(
      `https://api.steward.example/tenants/${encodeURIComponent("tenant/one")}/gas-sponsorship`,
    );
    expect(lastCapture?.body).toEqual({ gasSponsorshipConfig });
  });

  it("platform gas spend helper uses Privy-compatible query params", async () => {
    installMockFetch({
      ok: true,
      data: {
        currency: "USD",
        reservedUsd: "1.25",
        actualUsd: "1.00",
        count: 1,
        entries: [
          {
            id: "event-1",
            tenantId: "tenant/one",
            agentId: "agent-1",
            chainFamily: "evm",
            chainId: 8453,
            provider: "mock",
            mode: "erc4337",
            status: "submitted",
            reservedUsd: "1.25",
            actualUsd: "1.00",
            createdAt: "2026-05-28T00:00:00.000Z",
            updatedAt: "2026-05-28T00:00:00.000Z",
          },
        ],
      },
    });

    const spend = await makeClient({
      platformKey: "platform-key",
    }).platformApps.getGasSpend({
      tenantId: "tenant/one",
      walletIds: ["agent-1", "agent-2"],
      startTimestamp: 1_764_195_200,
      endTimestamp: 1_764_281_600,
    });

    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.headers["x-steward-platform-key"]).toBe("platform-key");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/platform/apps/gas_spend?tenant_id=tenant%2Fone&wallet_ids=agent-1%2Cagent-2&start_timestamp=1764195200&end_timestamp=1764281600",
    );
    expect(spend.reservedUsd).toBe("1.25");
    expect(spend.entries[0]?.agentId).toBe("agent-1");
  });

  it("setPolicies → PUT /agents/:id/policies", async () => {
    installMockFetch({ ok: true, data: null });
    await makeClient().setPolicies("agent-1", [mockPolicy]);
    expect(lastCapture?.method).toBe("PUT");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/policies");
    expect(lastCapture?.body).toEqual([mockPolicy]);
  });

  it("getHistory → GET /vault/:id/history", async () => {
    installMockFetch({ ok: true, data: [] });
    await makeClient().getHistory("agent-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/history");
  });

  it("listTransactions and getTransaction use first-class transaction endpoints", async () => {
    const tx = {
      id: "tx-1",
      agentId: "agent-1",
      status: "broadcast",
      request: {
        agentId: "agent-1",
        tenantId: "",
        to: "0x1234567890123456789012345678901234567890",
        value: "42",
        chainId: 8453,
      },
      actionType: "transfer",
      actionPayload: { type: "transfer" },
      txHash: "0xfeedface",
      policyResults: [],
      createdAt: "2026-05-25T00:00:00.000Z",
    };

    installMockFetch({
      ok: true,
      data: { transactions: [tx], limit: 5, offset: 2 },
    });
    const list = await makeClient().listTransactions("agent-1", {
      status: "broadcast",
      actionType: "transfer",
      limit: 5,
      offset: 2,
    });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/vault/agent-1/transactions?status=broadcast&actionType=transfer&limit=5&offset=2",
    );
    expect(list.transactions[0].createdAt).toBeInstanceOf(Date);
    expect(list.transactions[0].actionType).toBe("transfer");

    installMockFetch({ ok: true, data: tx });
    const fetched = await makeClient().getTransaction("agent-1", "tx-1");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/transactions/tx-1");
    expect(fetched.createdAt).toBeInstanceOf(Date);
    expect(fetched.txHash).toBe("0xfeedface");

    installMockFetch({
      ok: true,
      data: {
        ...tx,
        status: "confirmed",
        confirmedAt: "2026-05-25T00:01:00.000Z",
      },
    });
    const updated = await makeClient().updateTransactionLifecycle("agent-1", "tx-1", {
      type: "transaction.confirmed",
      txHash: "0xfeedface",
      blockNumber: 123,
      confirmations: 2,
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/vault/agent-1/transactions/tx-1/lifecycle",
    );
    expect(lastCapture?.body).toEqual({
      type: "transaction.confirmed",
      txHash: "0xfeedface",
      blockNumber: 123,
      confirmations: 2,
    });
    expect(updated.status).toBe("confirmed");
    expect(updated.confirmedAt).toBeInstanceOf(Date);

    installMockFetch({
      ok: true,
      data: {
        ...tx,
        status: "broadcast",
        txHash: "0xreplacement",
      },
    });
    const replaced = await makeClient().replaceTransaction("agent-1", "tx-1", {
      replacementTxHash: "0xreplacement",
      reason: "speed-up",
      provider: "alchemy",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/vault/agent-1/transactions/tx-1/replace",
    );
    expect(lastCapture?.body).toEqual({
      replacementTxHash: "0xreplacement",
      reason: "speed-up",
      provider: "alchemy",
    });
    expect(replaced.status).toBe("broadcast");
    expect(replaced.txHash).toBe("0xreplacement");
  });

  it("signMessage → POST /vault/:id/sign-message", async () => {
    installMockFetch({ ok: true, data: { signature: "0xsig" } });
    await makeClient().signMessage("agent-1", "hello world", {
      signerId: "signer-1",
      signerSecret: "secret-message-1",
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign-message");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-message-1");
    expect(lastCapture?.body).toEqual({ message: "hello world" });
  });

  it("signRawHash → POST /vault/:id/sign-raw-hash", async () => {
    installMockFetch({
      ok: true,
      data: {
        signature: "0xsig",
        hash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        walletAddress: "0xabc",
      },
    });
    const result = await makeClient().signRawHash("agent-1", {
      hash: "0x1111111111111111111111111111111111111111111111111111111111111111",
      referenceId: "raw-ref-1",
      signerId: "signer-raw-1",
      signerSecret: "secret-raw-1",
      keyQuorumId: "quorum-raw-1",
      keyQuorumCredentials: [{ signerId: "signer-raw-2", signerSecret: "secret-raw-2" }],
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/vault/agent-1/sign-raw-hash");
    expect(lastCapture?.headers["x-steward-signer-id"]).toBe("signer-raw-1");
    expect(lastCapture?.headers["x-steward-signer-secret"]).toBe("secret-raw-1");
    expect(lastCapture?.headers["x-steward-key-quorum-id"]).toBe("quorum-raw-1");
    expect(lastCapture?.headers["x-steward-key-quorum-credentials"]).toContain("signer-raw-2");
    expect(lastCapture?.body).toEqual({
      hash: "0x1111111111111111111111111111111111111111111111111111111111111111",
      referenceId: "raw-ref-1",
    });
    expect(result.signature).toBe("0xsig");
  });

  it("getBalance without chainId → GET /agents/:id/balance (no query param)", async () => {
    installMockFetch({
      ok: true,
      data: {
        agentId: "agent-1",
        walletAddress: "0xabc",
        balances: {
          native: "0",
          nativeFormatted: "0",
          chainId: 8453,
          symbol: "ETH",
        },
      },
    });
    await makeClient().getBalance("agent-1");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/balance");
  });

  it("getBalance with chainId → GET /agents/:id/balance?chainId=1", async () => {
    installMockFetch({
      ok: true,
      data: {
        agentId: "agent-1",
        walletAddress: "0xabc",
        balances: {
          native: "0",
          nativeFormatted: "0",
          chainId: 1,
          symbol: "ETH",
        },
      },
    });
    await makeClient().getBalance("agent-1", 1);
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/balance?chainId=1");
  });

  it("getAgentSpend → GET /agents/:id/spend", async () => {
    installMockFetch({
      ok: true,
      data: {
        agentId: "agent-1",
        walletAddress: "0xabc",
        onchain: { todayWei: "1", weekWei: "2", monthWei: "3" },
        realtime: {
          enabled: false,
          periods: [
            { period: "day", spentUsd: null, byHost: {} },
            { period: "week", spentUsd: null, byHost: {} },
            { period: "month", spentUsd: null, byHost: {} },
          ],
        },
        sponsorship: { enabled: false, provider: null },
      },
    });
    const spend = await makeClient().getAgentSpend("agent-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/spend");
    expect(spend.onchain.todayWei).toBe("1");
    expect(spend.realtime.enabled).toBe(false);
  });

  it("getAgentAccount → GET /agents/:id/account", async () => {
    installMockFetch({
      ok: true,
      data: {
        id: "agent-1",
        type: "agent",
        agentId: "agent-1",
        tenantId: "tenant-1",
        name: "Test Agent",
        walletAddress: "0xabc",
        walletAddresses: { evm: "0xabc", solana: "sol" },
        wallets: [
          {
            id: "wallet-1",
            chainFamily: "evm",
            address: "0xabc",
            venue: null,
            purpose: "primary",
            createdAt: "2024-01-01T00:00:00.000Z",
          },
        ],
        balances: { evm: null, unavailableReason: "provider unavailable" },
        portfolio: {
          chainId: 8453,
          walletAddress: "0xabc",
          native: null,
          tokens: [
            {
              token: "0x1111111111111111111111111111111111111111",
              symbol: "USDC",
              balance: "1000000",
              formatted: "1",
              decimals: 6,
              usdPrice: 1,
              usdValue: 1,
              usdPriceText: "1",
              usdValueText: "1",
            },
          ],
          totalUsd: 1,
          totalUsdText: "1",
        },
        spend: { todayWei: "1", weekWei: "2", monthWei: "3" },
        capabilities: ["sign_transaction", "transfer"],
        sponsorship: { enabled: false, provider: null },
        createdAt: "2024-01-01T00:00:00.000Z",
      },
    });
    const account = await makeClient().getAgentAccount("agent-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/account");
    expect(account.walletAddresses.evm).toBe("0xabc");
    expect(account.portfolio.tokens[0].symbol).toBe("USDC");
    expect(account.capabilities).toContain("transfer");

    await makeClient().getAgentAccount("agent-1", {
      chainId: 8453,
      tokens: ["0x1111111111111111111111111111111111111111"],
    });
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/account?chainId=8453&tokens=0x1111111111111111111111111111111111111111",
    );
  });

  it("agent signer helpers use /agents/:id/signers", async () => {
    const signer = {
      id: "signer-1",
      tenantId: "tenant-1",
      agentId: "agent-1",
      signerType: "delegated",
      subjectType: "wallet",
      subjectId: "0xabc",
      address: "0xabc",
      chainFamily: "evm",
      label: "Ops signer",
      permissions: ["sign_transaction"],
      metadata: {},
      hasCredential: true,
      status: "active",
      createdBy: "user-1",
      createdAt: "2024-01-01T00:00:00.000Z",
      updatedAt: "2024-01-01T00:00:00.000Z",
    };

    installMockFetch({ ok: true, data: { signers: [signer] } });
    const signers = await makeClient().listAgentSigners("agent-1", { status: "active" });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/signers?status=active",
    );
    expect(signers[0].id).toBe("signer-1");

    installMockFetch({ ok: true, data: { ...signer, credentialSecret: "stwd_signer_secret" } });
    const createdSigner = await makeClient().createAgentSigner("agent-1", {
      signerType: "delegated",
      subjectType: "wallet",
      subjectId: "0xabc",
      address: "0xabc",
      chainFamily: "evm",
      permissions: ["sign_transaction"],
      issueCredential: true,
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/signers");
    expect(lastCapture?.body).toMatchObject({ issueCredential: true });
    expect(createdSigner.credentialSecret).toBe("stwd_signer_secret");

    installMockFetch({ ok: true, data: { ...signer, status: "paused" } });
    await makeClient().updateAgentSigner("agent-1", "signer-1", { status: "paused" });
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/signers/signer-1");

    installMockFetch({ ok: true, data: { ...signer, status: "revoked" } });
    const revoked = await makeClient().revokeAgentSigner("agent-1", "signer-1");
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/signers/signer-1");
    expect(revoked.status).toBe("revoked");
  });

  it("agent key quorum helpers use /agents/:id/key-quorums", async () => {
    const quorum = {
      id: "quorum-1",
      tenantId: "tenant-1",
      agentId: "agent-1",
      name: "Treasury quorum",
      threshold: 2,
      memberSignerIds: ["signer-1", "signer-2"],
      permissions: ["sign_transaction"],
      metadata: { scope: "treasury" },
      status: "active",
      createdBy: "user-1",
      createdAt: "2024-01-01T00:00:00.000Z",
      updatedAt: "2024-01-01T00:00:00.000Z",
    };

    installMockFetch({ ok: true, data: { quorums: [quorum] } });
    const quorums = await makeClient().listAgentKeyQuorums("agent-1", { status: "active" });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/key-quorums?status=active",
    );
    expect(quorums[0].id).toBe("quorum-1");

    installMockFetch({ ok: true, data: quorum });
    await makeClient().createAgentKeyQuorum("agent-1", {
      name: "Treasury quorum",
      threshold: 2,
      memberSignerIds: ["signer-1", "signer-2"],
      permissions: ["sign_transaction"],
      metadata: { scope: "treasury" },
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/agent-1/key-quorums");
    expect(lastCapture?.body).toMatchObject({
      threshold: 2,
      memberSignerIds: ["signer-1", "signer-2"],
    });

    installMockFetch({ ok: true, data: { ...quorum, threshold: 1, status: "paused" } });
    const updated = await makeClient().updateAgentKeyQuorum("agent-1", "quorum-1", {
      threshold: 1,
      status: "paused",
    });
    expect(lastCapture?.method).toBe("PATCH");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/key-quorums/quorum-1",
    );
    expect(updated.threshold).toBe(1);

    installMockFetch({ ok: true, data: { ...quorum, status: "revoked" } });
    const revoked = await makeClient().revokeAgentKeyQuorum("agent-1", "quorum-1");
    expect(lastCapture?.method).toBe("DELETE");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/agents/agent-1/key-quorums/quorum-1",
    );
    expect(revoked.status).toBe("revoked");
  });

  it("intent helpers use /intents lifecycle endpoints", async () => {
    const intent = {
      id: "intent-1",
      intent_id: "intent-1",
      tenantId: "tenant-1",
      agentId: "agent-1",
      wallet_id: "agent-1",
      intentType: "wallet_update",
      intent_type: "wallet_update",
      status: "pending",
      resourceType: "agent_wallet",
      resourceId: "agent-1",
      resource_id: "agent-1",
      createdByType: "api-key",
      createdById: "api-key:tenant-1",
      created_by_id: "api-key:tenant-1",
      createdByDisplayName: "ops@example.com",
      created_by_display_name: "ops@example.com",
      authorizationDetails: [],
      authorization_details: [],
      payload: { displayName: "Treasury" },
      executionResult: null,
      execution_result: null,
      expiresAt: "2024-01-01T01:00:00.000Z",
      expires_at: 1704070800000,
      authorizedBy: null,
      authorized_by: null,
      canceledAt: null,
      canceledBy: null,
      canceled_by: null,
      cancellationReason: null,
      cancellation_reason: null,
      expiredAt: null,
      expiredBy: null,
      expired_by: null,
      rejectedAt: null,
      rejectedBy: null,
      rejected_by: null,
      rejectionReason: null,
      rejection_reason: null,
      executedBy: null,
      executed_by: null,
      failedAt: null,
      failedBy: null,
      failed_by: null,
      failureReason: null,
      failure_reason: null,
      createdAt: "2024-01-01T00:00:00.000Z",
      created_at: 1704067200000,
      updatedAt: "2024-01-01T00:00:00.000Z",
      authorizedAt: null,
      executedAt: null,
    };

    installMockFetch({ ok: true, data: { intents: [intent], limit: 10, offset: 0 } });
    const listed = await makeClient().listIntents({
      status: "pending",
      intentType: "wallet_update",
      agentId: "agent-1",
      limit: 10,
    });
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe(
      "https://api.steward.example/intents?status=pending&intentType=wallet_update&agentId=agent-1&limit=10",
    );
    expect(listed.intents[0].id).toBe("intent-1");

    installMockFetch({ ok: true, data: intent });
    await makeClient().createIntent({
      intentType: "wallet_update",
      agentId: "agent-1",
      resourceType: "agent_wallet",
      resourceId: "agent-1",
      ttlSeconds: 300,
      payload: { displayName: "Treasury" },
    });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/intents");
    expect(lastCapture?.body).toMatchObject({ intentType: "wallet_update" });

    installMockFetch({ ok: true, data: intent });
    await makeClient().getIntent("intent-1");
    expect(lastCapture?.method).toBe("GET");
    expect(lastCapture?.url).toBe("https://api.steward.example/intents/intent-1");

    installMockFetch({ ok: true, data: { ...intent, status: "authorized" } });
    await makeClient().authorizeIntent("intent-1", { reason: "reviewed" });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/intents/intent-1/authorize");
    expect(lastCapture?.body).toEqual({ reason: "reviewed" });

    installMockFetch({ ok: true, data: { ...intent, status: "executed" } });
    await makeClient().executeIntent("intent-1", { executionResult: { ok: true } });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/intents/intent-1/execute");
    expect(lastCapture?.body).toEqual({ executionResult: { ok: true } });

    installMockFetch({ ok: true, data: { ...intent, status: "canceled" } });
    await makeClient().cancelIntent("intent-1", { reason: "withdrawn" });
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/intents/intent-1/cancel");
    expect(lastCapture?.body).toEqual({ reason: "withdrawn" });
  });

  it("createWalletBatch → POST /agents/batch", async () => {
    installMockFetch({ ok: true, data: { created: [mockAgent], errors: [] } });
    await makeClient().createWalletBatch([{ id: "a1", name: "Agent 1" }]);
    expect(lastCapture?.method).toBe("POST");
    expect(lastCapture?.url).toBe("https://api.steward.example/agents/batch");
    expect((lastCapture?.body as Record<string, unknown>)?.agents).toEqual([
      { id: "a1", name: "Agent 1" },
    ]);
  });
});

// ─── Error Handling Tests ─────────────────────────────────────────────────

describe("Error handling", () => {
  it("throws StewardApiError on non-ok API response", async () => {
    installMockFetch({ ok: false, error: "Agent not found" }, 404);
    const client = makeClient();
    await expect(client.getAgent("missing-agent")).rejects.toThrow(StewardApiError);
  });

  it("StewardApiError carries correct status code", async () => {
    installMockFetch({ ok: false, error: "Unauthorized" }, 401);
    const client = makeClient();
    let caught: StewardApiError | null = null;
    try {
      await client.getAgent("agent-1");
    } catch (e) {
      caught = e as StewardApiError;
    }
    expect(caught).not.toBeNull();
    expect(caught?.status).toBe(401);
    expect(caught?.message).toBe("Unauthorized");
    expect(caught?.name).toBe("StewardApiError");
  });

  it("StewardApiError carries response data payload", async () => {
    const errorData = {
      results: [{ policyId: "p1", type: "spending-limit", passed: false }],
    };
    installMockFetch({ ok: false, error: "Policy rejected", data: errorData }, 403);
    const client = makeClient();
    let caught: StewardApiError | null = null;
    try {
      await client.signTransaction("agent-1", {
        to: "0x1234567890123456789012345678901234567890",
        value: "1000000000000000000",
      });
    } catch (e) {
      caught = e as StewardApiError;
    }
    expect(caught).not.toBeNull();
    expect(caught?.data).toEqual(errorData);
  });

  it("throws StewardApiError on network failure (fetch throws)", async () => {
    installNetworkErrorFetch();
    const client = makeClient();
    let caught: StewardApiError | null = null;
    try {
      await client.listAgents();
    } catch (e) {
      caught = e as StewardApiError;
    }
    expect(caught).not.toBeNull();
    expect(caught?.name).toBe("StewardApiError");
    expect(caught?.status).toBe(0);
    expect(caught?.message).toContain("Network error");
  });

  it("throws StewardApiError on invalid JSON response", async () => {
    installBadJsonFetch(200);
    const client = makeClient();
    await expect(client.listAgents()).rejects.toThrow(StewardApiError);
  });

  it("createWallet rethrows StewardApiError on 409 Conflict", async () => {
    installMockFetch({ ok: false, error: "Agent already exists" }, 409);
    const client = makeClient();
    let caught: StewardApiError | null = null;
    try {
      await client.createWallet("agent-1", "Duplicate");
    } catch (e) {
      caught = e as StewardApiError;
    }
    expect(caught?.status).toBe(409);
    expect(caught?.message).toContain("already exists");
  });

  it("setPolicies throws on error without returning data", async () => {
    installMockFetch({ ok: false, error: "Forbidden" }, 403);
    const client = makeClient();
    await expect(client.setPolicies("agent-1", [])).rejects.toThrow(StewardApiError);
  });
});

// ─── Response Parsing Tests ───────────────────────────────────────────────

describe("Response parsing", () => {
  it("listAgents returns parsed agent array", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const agents = await makeClient().listAgents();
    expect(agents).toHaveLength(1);
    expect(agents[0].id).toBe("agent-1");
    expect(agents[0].name).toBe("Test Agent");
  });

  it("listAgents parses createdAt as Date object", async () => {
    installMockFetch({ ok: true, data: [mockAgent] });
    const agents = await makeClient().listAgents();
    // parseAgentIdentity converts createdAt string to Date
    expect(agents[0].createdAt).toBeInstanceOf(Date);
  });

  it("getAgent returns single agent", async () => {
    installMockFetch({ ok: true, data: mockAgent });
    const agent = await makeClient().getAgent("agent-1");
    expect(agent.id).toBe("agent-1");
    expect(agent.walletAddress).toBe("0xabcdef0123456789abcdef0123456789abcdef01");
  });

  it("getPolicies returns array of PolicyRule", async () => {
    installMockFetch({ ok: true, data: [mockPolicy] });
    const policies = await makeClient().getPolicies("agent-1");
    expect(policies).toHaveLength(1);
    expect(policies[0].id).toBe("rule-1");
    expect(policies[0].type).toBe("spending-limit");
  });

  it("signTransaction returns txHash on success", async () => {
    installMockFetch({ ok: true, data: { txHash: "0xdeadbeef123" } });
    const result = await makeClient().signTransaction("agent-1", {
      to: "0x1234567890123456789012345678901234567890",
      value: "1000000000000000000",
    });
    expect(result).toEqual({ txHash: "0xdeadbeef123" });
  });

  it("signTransaction returns pending_approval when status 202", async () => {
    // The client treats 202 + pending_approval data as a valid result (not an error)
    installMockFetch(
      {
        ok: false,
        error: "Approval required",
        data: {
          status: "pending_approval",
          results: [{ policyId: "p1", type: "auto-approve-threshold", passed: false }],
        },
      },
      202,
    );
    const result = await makeClient().signTransaction("agent-1", {
      to: "0x1234567890123456789012345678901234567890",
      value: "5000000000000000000",
    });
    expect((result as { status: string }).status).toBe("pending_approval");
  });

  it("signMessage returns signature string", async () => {
    const sig =
      "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    installMockFetch({ ok: true, data: { signature: sig } });
    const result = await makeClient().signMessage("agent-1", "test");
    expect(result.signature).toBe(sig);
  });

  it("createWalletBatch returns created and errors arrays", async () => {
    installMockFetch({
      ok: true,
      data: {
        created: [mockAgent],
        errors: [{ id: "agent-bad", error: "Already exists" }],
      },
    });
    const result = await makeClient().createWalletBatch([
      { id: "agent-1", name: "Agent 1" },
      { id: "agent-bad", name: "Bad Agent" },
    ]);
    expect(result.created).toHaveLength(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].id).toBe("agent-bad");
  });
});

// ─── StewardApiError Class Tests ──────────────────────────────────────────

describe("StewardApiError", () => {
  it("constructs with message, status, and optional data", () => {
    const err = new StewardApiError("Something went wrong", 500, {
      detail: "internal",
    });
    expect(err.message).toBe("Something went wrong");
    expect(err.status).toBe(500);
    expect(err.data).toEqual({ detail: "internal" });
    expect(err.name).toBe("StewardApiError");
  });

  it("constructs without data (undefined)", () => {
    const err = new StewardApiError("Not found", 404);
    expect(err.status).toBe(404);
    expect(err.data).toBeUndefined();
  });

  it("is an instance of Error", () => {
    const err = new StewardApiError("test", 500);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(StewardApiError);
  });

  it("status 0 indicates a network-level failure (no HTTP response)", () => {
    const err = new StewardApiError("Network request failed", 0);
    expect(err.status).toBe(0);
  });
});
