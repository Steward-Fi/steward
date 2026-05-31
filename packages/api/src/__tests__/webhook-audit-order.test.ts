import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "webhooks.ts"), "utf8");

function expectBefore(first: string, second: string) {
  const firstIndex = routeSource.indexOf(first);
  const secondIndex = routeSource.indexOf(second, firstIndex);
  expect(firstIndex).toBeGreaterThanOrEqual(0);
  expect(secondIndex).toBeGreaterThanOrEqual(0);
  expect(firstIndex).toBeLessThan(secondIndex);
}

describe("webhook audit ordering", () => {
  it("marks webhook control-plane and delivery responses as non-cacheable", () => {
    expect(routeSource).toContain("setNoStoreHeaders");
    expect(routeSource).toContain('webhookRoutes.use("*"');
    expect(routeSource).toContain("setNoStoreHeaders(c)");
    expect(routeSource).toContain('"Cache-Control": "no-store, max-age=0"');
    expect(routeSource).toContain('Pragma: "no-cache"');
    expect(routeSource).toContain('Expires: "0"');
  });

  it("requires recent owner/admin MFA for webhook control-plane routes", () => {
    for (const [marker, reason] of [
      ['webhookRoutes.post("/",', "Webhook creation"],
      ['webhookRoutes.get("/",', "Webhook configuration access"],
      ['webhookRoutes.put("/:id",', "Webhook updates"],
      ['webhookRoutes.delete("/:id",', "Webhook deletion"],
      ['webhookRoutes.get("/:id/deliveries",', "Webhook delivery history"],
      ['webhookRoutes.post("/deliveries/:id/retry",', "Webhook delivery retry"],
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      expect(routeSource.indexOf("requireTenantAdminSession(c)", start)).toBeGreaterThan(start);
      expect(routeSource.indexOf("requireRecentTenantAdminMfa", start)).toBeGreaterThan(start);
      expect(routeSource.indexOf(reason, start)).toBeGreaterThan(start);
    }
  });

  it("writes authorization audit events before sensitive webhook mutations", () => {
    expectBefore('action: "webhook.update.authorized"', ".update(webhookConfigs)");
    expectBefore('action: "webhook.delete.authorized"', ".delete(webhookConfigs)");
    expectBefore('action: "webhook_delivery.retry.authorized"', ".update(webhookDeliveries)");
  });

  it("rolls back webhook mutations when final audit writes fail", () => {
    const updateStart = routeSource.indexOf('webhookRoutes.put("/:id"');
    expect(updateStart).toBeGreaterThanOrEqual(0);
    const updateRoute = routeSource.slice(
      updateStart,
      routeSource.indexOf('webhookRoutes.delete("/:id"', updateStart),
    );
    expect(updateRoute).toContain('action: "webhook.update"');
    expect(updateRoute).toContain("} catch (err) {");
    expect(updateRoute).toContain(".update(webhookConfigs)");
    expect(updateRoute).toContain("url: existing.url");
    expect(updateRoute).toContain("secret: existing.secret");
    expect(updateRoute).toContain("updatedAt: existing.updatedAt");

    const deleteStart = routeSource.indexOf('webhookRoutes.delete("/:id"');
    expect(deleteStart).toBeGreaterThanOrEqual(0);
    const deleteRoute = routeSource.slice(
      deleteStart,
      routeSource.indexOf('webhookRoutes.get("/:id/deliveries"', deleteStart),
    );
    expect(deleteRoute).toContain('action: "webhook.delete"');
    expect(deleteRoute).toContain("} catch (err) {");
    expect(deleteRoute).toContain("db.insert(webhookConfigs).values");
    expect(deleteRoute).toContain("id: deleted.id");
    expect(deleteRoute).toContain("secret: deleted.secret");
    expect(deleteRoute).toContain("updatedAt: deleted.updatedAt");

    const retryStart = routeSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryStart).toBeGreaterThanOrEqual(0);
    const retryRoute = routeSource.slice(retryStart);
    const mutation = retryRoute.indexOf(".update(webhookDeliveries)");
    const finalAudit = retryRoute.indexOf('action: "webhook_delivery.retry"', mutation);
    const rollback = retryRoute.indexOf("status: delivery.status", finalAudit);
    expect(mutation).toBeGreaterThanOrEqual(0);
    expect(finalAudit).toBeGreaterThan(mutation);
    expect(rollback).toBeGreaterThan(finalAudit);
    expect(retryRoute).toContain("nextRetryAt: delivery.nextRetryAt");
    expect(retryRoute).toContain("lastError: delivery.lastError");
  });

  it("does not report test or replay dispatch success when final audit fails", () => {
    for (const [marker, error] of [
      [
        'webhookRoutes.post("/:id/test"',
        "Webhook test was dispatched but audit record failed to persist",
      ],
      [
        'webhookRoutes.post("/deliveries/:id/replay"',
        "Webhook replay was dispatched but audit record failed to persist",
      ],
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const route = routeSource.slice(start, routeSource.indexOf("\nwebhookRoutes.", start + 1));
      const dispatch = route.indexOf(marker.includes("/:id/test") ? "dispatchTestWebhook" : "dispatchReplayWebhook");
      const finalAudit = route.indexOf(
        marker.includes("/:id/test") ? 'action: "webhook.test_send"' : 'action: "webhook_delivery.replay"',
        dispatch,
      );
      const failure = route.indexOf(error, finalAudit);
      expect(dispatch).toBeGreaterThanOrEqual(0);
      expect(finalAudit).toBeGreaterThan(dispatch);
      expect(failure).toBeGreaterThan(finalAudit);
    }
  });

  it("requires a current enabled webhook before manual delivery retry", () => {
    const activeCheckIndex = routeSource.indexOf("const [activeWebhook]");
    expect(activeCheckIndex).toBeGreaterThanOrEqual(0);
    expect(
      routeSource.indexOf("eq(webhookConfigs.id, delivery.webhookConfigId)", activeCheckIndex),
    ).toBeGreaterThan(activeCheckIndex);
    expect(
      routeSource.indexOf("eq(webhookConfigs.enabled, true)", activeCheckIndex),
    ).toBeGreaterThan(activeCheckIndex);
    expect(routeSource.indexOf("Delivery cannot be retried", activeCheckIndex)).toBeGreaterThan(
      activeCheckIndex,
    );
    expect(
      routeSource.indexOf('action: "webhook_delivery.retry.authorized"', activeCheckIndex),
    ).toBeGreaterThan(activeCheckIndex);
  });

  it("redacts stored webhook delivery payloads from history responses", () => {
    expect(routeSource).toContain("function redactDelivery");
    expect(routeSource).toContain("deliveries.map(redactDelivery)");
    expect(routeSource).toContain("hasError: Boolean(row.lastError)");
    expect(routeSource).not.toContain(
      "return c.json<ApiResponse>({ ok: true, data: deliveries });",
    );
  });

  it("keeps delivery history reachable after webhook config deletion", () => {
    // The delivery-history filter now lives in the shared buildDeliveryHistoryQuery
    // helper. It must filter by the payload-embedded webhookConfigId (so history
    // survives config deletion) and only 404 when there are genuinely zero matching
    // deliveries — not merely because the config row is gone.
    const builderIndex = routeSource.indexOf("async function buildDeliveryHistoryQuery");
    expect(builderIndex).toBeGreaterThanOrEqual(0);
    const builder = routeSource.slice(
      builderIndex,
      routeSource.indexOf("\nwebhookRoutes.", builderIndex),
    );
    expect(builder).toContain("webhookDeliveryFilter");
    expect(builder).toContain("payload}->>'webhookConfigId' = ${webhookId}");
    expect(builder).toContain("deliveryCount.count === 0");
    // The missing-config branch must count deliveries, not short-circuit to a 404.
    expect(builder).not.toContain("if (!webhook) {\n    return c.json<ApiResponse>");

    const historyRouteIndex = routeSource.indexOf('webhookRoutes.get("/:id/deliveries"');
    expect(historyRouteIndex).toBeGreaterThanOrEqual(0);
    const historyRoute = routeSource.slice(
      historyRouteIndex,
      routeSource.indexOf('webhookRoutes.get("/:id/deliveries/export"', historyRouteIndex),
    );
    // The route delegates filtering to the builder and never independently 404s
    // on a missing config row.
    expect(historyRoute).toContain("buildDeliveryHistoryQuery(c)");
    expect(historyRoute).toContain("deliveryQuery.deliveryWhere");
    expect(historyRoute).not.toContain("if (!webhook)");
  });

  it("redacts stored webhook delivery payloads from manual retry responses", () => {
    const retryRouteIndex = routeSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryRouteIndex).toBeGreaterThanOrEqual(0);
    const retryRoute = routeSource.slice(retryRouteIndex);

    expect(retryRoute).toContain("data: redactDelivery(updated)");
    expect(retryRoute).not.toContain("data: updated");
  });

  it("does not reset the delivery attempt budget during manual retry", () => {
    const retryRouteIndex = routeSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryRouteIndex).toBeGreaterThanOrEqual(0);
    const retryRoute = routeSource.slice(retryRouteIndex);

    expect(retryRoute).toContain("attempt budget");
    expect(retryRoute).not.toContain("attempts: 0");
  });

  it("rechecks terminal status and retry budget during manual retry update", () => {
    const retryRouteIndex = routeSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryRouteIndex).toBeGreaterThanOrEqual(0);
    const retryRoute = routeSource.slice(retryRouteIndex);
    const updateIndex = retryRoute.indexOf(".update(webhookDeliveries)");
    expect(updateIndex).toBeGreaterThanOrEqual(0);
    const updateWhere = retryRoute.slice(updateIndex);

    expect(updateWhere).toContain("${webhookDeliveries.status} <> 'delivered'");
    expect(updateWhere).toContain(
      "${webhookDeliveries.attempts} < ${webhookDeliveries.maxAttempts}",
    );
    expect(updateWhere).toContain("Delivery is no longer retryable");
  });
});
