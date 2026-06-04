import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const tradeRouteSource = readFileSync(join(apiRoot, "routes", "trade.ts"), "utf8");
const tradeSessionSource = readFileSync(
  join(apiRoot, "..", "..", "trade-sessions", "src", "index.ts"),
  "utf8",
);
const hyperliquidSource = readFileSync(
  join(apiRoot, "..", "..", "venue-hyperliquid", "src", "index.ts"),
  "utf8",
);

describe("trade session revocation fence", () => {
  it("marks trade responses as non-cacheable", () => {
    expect(tradeRouteSource).toContain("setNoStoreHeaders");
    expect(tradeRouteSource).toContain('tradeRoutes.use("*"');
    expect(tradeRouteSource).toContain("setNoStoreHeaders(c)");
  });

  it("serializes revocation with the final order sign and submit phase", () => {
    expect(tradeSessionSource).toContain("function sessionFenceKey");
    expect(tradeSessionSource).toContain("pg_advisory_xact_lock");
    expect(tradeSessionSource).toContain("withActiveSubmissionFence");

    const submitStart = tradeRouteSource.indexOf('tradeRoutes.post("/hyperliquid/order"');
    expect(submitStart).toBeGreaterThanOrEqual(0);
    const fenceStart = tradeRouteSource.indexOf("withActiveSubmissionFence", submitStart);
    const signStart = tradeRouteSource.indexOf("adapter.signOrder(order)", submitStart);
    const activeAfterSign = tradeRouteSource.indexOf(
      "getSessionManager().getActive(tenantId, session.id)",
      signStart,
    );
    const submitOrderStart = tradeRouteSource.indexOf("adapter.submitOrder(signed)", submitStart);
    expect(fenceStart).toBeGreaterThan(submitStart);
    expect(signStart).toBeGreaterThan(fenceStart);
    expect(activeAfterSign).toBeGreaterThan(signStart);
    expect(activeAfterSign).toBeLessThan(submitOrderStart);
    expect(submitOrderStart).toBeGreaterThan(signStart);
    expect(tradeRouteSource).toContain("Trade session was revoked before order submission");
  });

  it("serializes revocation with the submission fence", () => {
    const revokeStart = tradeSessionSource.indexOf("async revokeSession");
    expect(revokeStart).toBeGreaterThanOrEqual(0);
    const revokeBody = tradeSessionSource.slice(
      revokeStart,
      tradeSessionSource.indexOf("async revoke(", revokeStart),
    );
    expect(revokeBody).toContain("pg_advisory_xact_lock");
    expect(revokeBody).toContain("sessionFenceKey(input.tenantId, input.id)");
  });

  it("bounds Hyperliquid network calls while a submission fence is held", () => {
    expect(hyperliquidSource).toContain("HYPERLIQUID_FETCH_TIMEOUT_MS");
    expect(hyperliquidSource).toContain("AbortSignal.timeout(DEFAULT_FETCH_TIMEOUT_MS)");
    expect(hyperliquidSource).toContain("withTimeoutSignal({");
  });

  it("does not mutate venue leverage during order submission", () => {
    const submitStart = tradeRouteSource.indexOf('tradeRoutes.post("/hyperliquid/order"');
    const routeEnd = tradeRouteSource.indexOf(
      'tradeRoutes.post("/hyperliquid/session',
      submitStart + 1,
    );
    const orderRoute = tradeRouteSource.slice(submitStart, routeEnd === -1 ? undefined : routeEnd);

    expect(orderRoute).not.toContain("adapter.updateLeverage");
    expect(tradeRouteSource).toContain("hyperliquidOrderSchema.safeParse(order)");
    expect(tradeRouteSource).toContain("leverage: z.number().int().positive().default(1)");
    expect(hyperliquidSource).toContain('type: "updateLeverage"');
    expect(hyperliquidSource).toContain("export function toUpdateLeverageAction");
    expect(hyperliquidSource).toContain("async updateLeverage");
  });

  it("does not return clean venue results when final trade audits fail", () => {
    const submitStart = tradeRouteSource.indexOf('tradeRoutes.post("/hyperliquid/order"');
    expect(submitStart).toBeGreaterThanOrEqual(0);
    const route = tradeRouteSource.slice(submitStart);
    const submitOrder = route.indexOf("adapter.submitOrder(signed)");
    const response = route.indexOf("const response = {", submitOrder);
    const envelope = route.indexOf("const envelope: TradeIdempotencyResponse", response);
    const auditTry = route.indexOf("try {", envelope);
    const auditFailureEnvelope = route.indexOf(
      "Trade order submitted but audit record failed to persist",
      auditTry,
    );
    const completeBestEffort = route.indexOf(
      "completeTradeIdempotencyBestEffort(idempotency, auditFailureEnvelope)",
      auditFailureEnvelope,
    );
    const returnFailure = route.indexOf(
      "return c.json<ApiResponse>(auditFailureEnvelope.body as ApiResponse, 500)",
      completeBestEffort,
    );
    const cleanSuccess = route.indexOf("return c.json(responseData(response))", returnFailure);

    expect(tradeRouteSource).toContain("async function completeTradeIdempotencyBestEffort");
    expect(submitOrder).toBeGreaterThanOrEqual(0);
    expect(response).toBeGreaterThan(submitOrder);
    expect(envelope).toBeGreaterThan(response);
    expect(auditTry).toBeGreaterThan(envelope);
    expect(auditFailureEnvelope).toBeGreaterThan(auditTry);
    expect(completeBestEffort).toBeGreaterThan(auditFailureEnvelope);
    expect(returnFailure).toBeGreaterThan(completeBestEffort);
    expect(cleanSuccess).toBeGreaterThan(returnFailure);

    expect(route).toContain("Trade order rejected by venue but audit record failed to persist");
  });

  it("does not let idempotency completion failures mask unknown venue-submit outcomes", () => {
    const submitStart = tradeRouteSource.indexOf('tradeRoutes.post("/hyperliquid/order"');
    expect(submitStart).toBeGreaterThanOrEqual(0);
    const route = tradeRouteSource.slice(submitStart);
    const unknownResponse = route.indexOf('status: "submit_unknown"');
    const completeBestEffort = route.indexOf(
      "completeTradeIdempotencyBestEffort(idempotency, envelope)",
      unknownResponse,
    );
    const returnUnknown = route.indexOf(
      "return c.json<ApiResponse>(envelope.body as ApiResponse, 502)",
      completeBestEffort,
    );

    expect(unknownResponse).toBeGreaterThanOrEqual(0);
    expect(completeBestEffort).toBeGreaterThan(unknownResponse);
    expect(returnUnknown).toBeGreaterThan(completeBestEffort);
    expect(route).not.toContain("await idempotency.complete(envelope)");
  });
});
