/**
 * plugin-webhook-events.test.ts — proves the trading plugin DECLARES its webhook
 * event names via the Phase 2a contribution point, and that registering it
 * through the host makes those events valid in the runtime event registry (core
 * ∪ plugin-declared) without the plugin's `register` having to run.
 *
 * This is the end-to-end demonstration of the `webhookEvents` contribution
 * point: a plugin declares events, the host merges them, and the registry then
 * accepts them as configurable webhook event types.
 */

import { describe, expect, it } from "bun:test";
import { WebhookEventRegistry } from "@stwd/shared";
import { TRADING_WEBHOOK_EVENTS, tradingPlugin } from "../index";

describe("trading plugin — webhookEvents declaration", () => {
  it("declares its webhookEvents on the plugin contract", () => {
    expect(tradingPlugin.webhookEvents).toBeDefined();
    expect(tradingPlugin.webhookEvents).toEqual(TRADING_WEBHOOK_EVENTS);
    // the declared names follow the plugin's trade.* vocabulary.
    for (const event of tradingPlugin.webhookEvents ?? []) {
      expect(event.startsWith("trade.")).toBe(true);
    }
  });

  it("declares a version", () => {
    expect(tradingPlugin.version).toBe("0.1.0");
  });

  it("merging the declared events into a registry makes them valid", () => {
    // a registry seeded with a single core event — the trading events are NOT in
    // the core union, so they are invalid until the plugin contributes them.
    const registry = new WebhookEventRegistry(["tx.pending"]);
    for (const event of TRADING_WEBHOOK_EVENTS) {
      expect(registry.has(event)).toBe(false);
    }

    registry.registerPluginEvents(tradingPlugin.name, tradingPlugin.webhookEvents ?? []);

    // core event still valid; every trading event now valid.
    expect(registry.has("tx.pending")).toBe(true);
    for (const event of TRADING_WEBHOOK_EVENTS) {
      expect(registry.has(event)).toBe(true);
    }
    // diagnostics attribute the events to the trading plugin.
    expect(registry.describeContributions().trading).toEqual([...TRADING_WEBHOOK_EVENTS].sort());
  });
});
