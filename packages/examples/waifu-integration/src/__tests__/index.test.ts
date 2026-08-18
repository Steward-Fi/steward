import { describe, expect, it } from "bun:test";
import { signWebhookPayload } from "@stwd/sdk";
import {
  buildDefaultPolicies,
  createWebhookHandler,
  formatEther,
  parseEther,
  type ReceivedWebhook,
  verifyIncomingWebhook,
  waitForWebhook,
} from "../index";

describe("waifu integration helpers", () => {
  it("converts decimal ETH values without floating-point rounding", () => {
    expect(parseEther("0.005")).toBe(5_000_000_000_000_000n);
    expect(parseEther("1.000000000000000001")).toBe(1_000_000_000_000_000_001n);
    expect(formatEther(parseEther("12.3405"))).toBe("12.3405");
  });

  it("authenticates Steward v2 webhook headers and rejects tampering", async () => {
    const secret = "integration-webhook-secret";
    const eventType = "approval_required";
    const deliveryId = "delivery-1";
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = JSON.stringify({
      type: eventType,
      tenantId: "waifu-fun",
      agentId: "milady-trader",
      timestamp: new Date().toISOString(),
      data: { txId: "tx-1" },
    });
    const canonical = `v2:${timestamp}.${deliveryId.length}:${deliveryId}.${eventType.length}:${eventType}.${payload}`;
    const signature = `v2=${await signWebhookPayload(canonical, secret)}`;
    const headers = new Headers({
      "X-Steward-Delivery-Id": deliveryId,
      "X-Steward-Event": eventType,
      "X-Steward-Signature": signature,
      "X-Steward-Timestamp": timestamp,
    });

    expect((await verifyIncomingWebhook(payload, secret, headers))?.deliveryId).toBe(deliveryId);
    expect(await verifyIncomingWebhook(`${payload} `, secret, headers)).toBeNull();

    const received: ReceivedWebhook[] = [];
    const handler = createWebhookHandler({
      path: "/steward-events",
      getSecret: () => secret,
      onWebhook: (webhook) => received.push(webhook),
    });
    const response = await handler(
      new Request("https://example.test/steward-events", {
        method: "POST",
        headers,
        body: payload,
      }),
    );
    expect(response.status).toBe(200);
    expect(
      (await waitForWebhook(received, (webhook) => webhook.event === eventType, 100)).payload.data
        .txId,
    ).toBe("tx-1");
  });

  it("builds executable typed guardrails for the agent wallet", () => {
    const wallet = "0x1111111111111111111111111111111111111111";
    const policies = buildDefaultPolicies(wallet);

    expect(policies.map((policy) => policy.type)).toEqual([
      "spending-limit",
      "approved-addresses",
      "auto-approve-threshold",
    ]);
    expect(policies[0]?.config).toEqual({
      maxPerTx: parseEther("0.1").toString(),
      maxPerDay: parseEther("1").toString(),
      maxPerWeek: parseEther("3").toString(),
    });
    expect(policies[1]?.config).toMatchObject({
      mode: "whitelist",
      addresses: expect.arrayContaining([wallet]),
    });
    expect(policies[2]?.config).toEqual({ threshold: parseEther("0.01").toString() });
  });
});
