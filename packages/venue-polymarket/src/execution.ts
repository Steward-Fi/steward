import {
  createPolymarketBuilderConfig,
  type ResolvedBuilderConfig,
  resolveBuilderConfig,
} from "./builder";
import {
  DEFAULT_POLYGON_RPC_URL,
  POLY_GNOSIS_SAFE_SIGNATURE_TYPE,
  POLYGON_CHAIN_ID,
  POLYMARKET_CLOB_API_BASE,
} from "./constants";
import {
  assertPolymarketAccount,
  isPolymarketUnauthorized,
  type PolymarketAccount,
  toClobCompatibleSigner,
} from "./credentials";
import { resolveCreateOrderOptions } from "./marketdata";
import {
  type OrderSide,
  openOrderSchema,
  orderRequestSchema,
  type PolymarketCancelResult,
  type PolymarketCreateOrderOptions,
  type PolymarketOpenOrder,
  type PolymarketOrderRequest,
  type PolymarketPostOrderResult,
  postOrderResultSchema,
} from "./types";

// ---------------------------------------------------------------------------
// Execution — sigType-2 order build with tickSize/negRisk resolution, precision
// rounding (BUY 2dp / SELL 5dp), marketable-limit (NOT createMarketOrder),
// postOrder / cancelOrder / getOpenOrders. Lifted from matchr's polymarket.ts.
// ---------------------------------------------------------------------------

export { isPolymarketUnauthorized };

export interface PolymarketAdapterOptions {
  rpcUrl?: string;
  clobUrl?: string;
  builder?: ResolvedBuilderConfig;
  /** Injected fetch for marketdata (tickSize/negRisk resolution) in tests. */
  fetch?: typeof fetch;
}

// ---------------------------------------------------------------------------
// Precision rounding — the maker/taker decimal asymmetry.
//   BUY:  amount is USD; size = USD/price, round DOWN to 2 decimals (taker).
//   SELL: amount is shares; size rounded to 5 decimals (maker).
// "Market" orders never use createMarketOrder — caller passes best ask/bid as
// price and we build a properly-rounded limit.
//
// NB the clob-client itself floors `UserOrder.size` to 2 decimals for ALL tick
// sizes (its ROUNDING_CONFIG.size === 2). So a SELL size like 0.005 shares would
// be silently floored to 0.00 by the SDK and produce a zero/rejected order. We
// keep the 5dp SELL rounding (harmless — the SDK re-floors), but guard against
// sizes that the SDK's 2dp floor would zero out (see assertSizeSurvivesSdk).
// ---------------------------------------------------------------------------

// The clob-client floors UserOrder.size to this many decimals when building the
// signed order, regardless of tick size.
export const CLOB_SIZE_DECIMALS = 2;

export function roundOrderSize(side: OrderSide, amount: number, price: number): number {
  if (side === "buy") {
    if (!(price > 0)) throw new Error("buy price must be > 0 to size from USD amount");
    // USD -> shares, round DOWN to 2 decimals.
    return Math.floor((amount / price) * 100) / 100;
  }
  // SELL: amount is already shares; round to 5 decimals.
  return Math.floor(amount * 100000) / 100000;
}

/**
 * The size the clob-client will ACTUALLY sign after its internal 2dp floor.
 * Use this to reject orders that look positive but the SDK would truncate to 0.
 */
export function sdkEffectiveSize(size: number): number {
  const scale = 10 ** CLOB_SIZE_DECIMALS;
  return Math.floor(size * scale) / scale;
}

interface RawPostOrderResult {
  error?: string;
  errorMsg?: string;
  success?: boolean;
  status?: string | number;
  orderID?: string;
  orderId?: string;
  makingAmount?: string;
  takingAmount?: string;
}

/**
 * Did the venue REJECT the order? CLOB returns HTTP 200 with success=false
 * and/or an error message (and no orderID) on rejection. Treat any of those as
 * rejected so we never report a fabricated fill for a non-accepted order.
 */
export function isRejectedPostOrder(raw: RawPostOrderResult): boolean {
  if (raw.success === false) return true;
  if (raw.error || raw.errorMsg) return true;
  const status = typeof raw.status === "string" ? raw.status.toLowerCase() : raw.status;
  if (status === "rejected" || status === "error" || status === "unmatched") return true;
  // No order id AND no fill amounts -> nothing was accepted.
  if (!raw.orderID && !raw.orderId && !raw.makingAmount && !raw.takingAmount) return true;
  return false;
}

// USDC + outcome-token base-unit scale (6 decimals). The CLOB can report the
// post-order making/taking amounts either as human-readable units (what matchr
// observed live and consumed directly) or as 6-decimal base-unit strings
// (matching the signed makerAmount/takerAmount). We detect + normalize so a
// filled 20-share order is never reported as 20_000_000.
const BASE_UNIT_SCALE = 1e6;
// Above this magnitude an "amount of shares/USD" is implausibly large for a
// human unit and is almost certainly a 6-decimal base-unit value.
const BASE_UNIT_DETECT_THRESHOLD = 1e6;

function normalizeFillUnit(value: number): number {
  // The price ratio is unit-invariant; only absolute amounts need scaling. If a
  // value is in base-unit magnitude, scale it down to human units.
  return value >= BASE_UNIT_DETECT_THRESHOLD ? value / BASE_UNIT_SCALE : value;
}

/**
 * Derive the actual fill amount/price from a post-order response's
 * making/taking amounts (the protocol's source of truth), mirroring matchr.
 *
 * actualPrice = making/taking is unit-invariant (the 1e6 scale cancels), so it
 * is computed on the RAW amounts. actualAmount is normalized to human units
 * (shares) so callers never record base-unit-inflated sizes.
 *
 * Cases:
 *  - amounts MISSING/unparsable -> use fallback (accepted-no-amounts case).
 *  - amounts PRESENT but ZERO   -> actualAmount 0, no price (accepted GTC limit
 *    resting on the book — NOT a fill; never report the requested size here).
 *  - amounts PRESENT and > 0    -> real fill.
 */
export function deriveActualFill(
  side: OrderSide,
  result: { makingAmount?: string; takingAmount?: string },
  fallback: { amount: number; price: number },
): { actualAmount: number; actualPrice?: number } {
  if (result.makingAmount === undefined || result.takingAmount === undefined) {
    return { actualAmount: fallback.amount, actualPrice: fallback.price };
  }
  const makingAmount = Number.parseFloat(result.makingAmount);
  const takingAmount = Number.parseFloat(result.takingAmount);
  if (!Number.isFinite(makingAmount) || !Number.isFinite(takingAmount)) {
    return { actualAmount: fallback.amount, actualPrice: fallback.price };
  }
  // Present but zero -> accepted/resting, not filled. Report 0, no price.
  if (makingAmount === 0 || takingAmount === 0) {
    return { actualAmount: 0, actualPrice: undefined };
  }
  if (side === "buy") {
    // BUY: taking = shares acquired, making = USD spent. price = making/taking.
    return {
      actualAmount: normalizeFillUnit(takingAmount),
      actualPrice: makingAmount / takingAmount,
    };
  }
  // SELL: making = shares sold, taking = USD received. price = taking/making.
  // (Zero amounts already handled above as the resting/unfilled case.)
  return {
    actualAmount: normalizeFillUnit(makingAmount),
    actualPrice: takingAmount / makingAmount,
  };
}

// ---------------------------------------------------------------------------
// clob-client construction — sigType 2 + funder Safe + builder attribution.
// The clob-client is typed against ethers v5 Wallet; we cast the injected
// (v6-shaped) signer. Known wart — see KNOWLEDGE-DUMP §5/§8.
// ---------------------------------------------------------------------------

export class PolymarketExecutionAdapter {
  readonly venue = "polymarket" as const;
  private readonly clobUrl: string;
  private readonly rpcUrl: string;
  private readonly builderConfig: ResolvedBuilderConfig;
  private readonly injectedFetch?: typeof fetch;

  constructor(
    private readonly account: PolymarketAccount,
    options: PolymarketAdapterOptions = {},
  ) {
    assertPolymarketAccount(account);
    this.clobUrl = options.clobUrl ?? POLYMARKET_CLOB_API_BASE;
    this.rpcUrl = options.rpcUrl ?? DEFAULT_POLYGON_RPC_URL;
    this.builderConfig = options.builder ?? resolveBuilderConfig();
    this.injectedFetch = options.fetch;
  }

  private signatureType(): number {
    return this.account.signatureType ?? POLY_GNOSIS_SAFE_SIGNATURE_TYPE;
  }

  /**
   * Build a ClobClient bound to the injected delegate signer + funder Safe +
   * (optional) builder config. Lazy imports so nothing network-touches at import.
   */
  private async createClobClient(): Promise<{
    client: ClobClientLike;
    OrderType: ClobOrderTypeEnum;
    Side: ClobSideEnum;
  }> {
    const { ClobClient, OrderType, Side } = await import("@polymarket/clob-client");
    const builder = await createPolymarketBuilderConfig(this.builderConfig);

    const client = new ClobClient(
      this.clobUrl,
      POLYGON_CHAIN_ID,
      // @polymarket/clob-client is typed against ethers v5 Wallet; the injected
      // signer is an ethers-v6-shaped delegate. toClobCompatibleSigner bridges
      // the v6 `signTypedData` to the v5 `_signTypedData` that order-utils calls.
      toClobCompatibleSigner(this.account.signer) as unknown as ConstructorParameters<
        typeof ClobClient
      >[2],
      this.account.apiCredentials,
      this.signatureType(),
      this.account.funderAddress,
      undefined,
      false,
      // builder is null when attribution is disabled (default) — client then
      // constructs without builder attribution. Cast: the SDK's BuilderConfig
      // type isn't in our type graph (lazy import); the runtime object is valid.
      (builder ?? undefined) as unknown as ConstructorParameters<typeof ClobClient>[8],
    );

    return {
      client: client as unknown as ClobClientLike,
      OrderType: OrderType as unknown as ClobOrderTypeEnum,
      Side: Side as unknown as ClobSideEnum,
    };
  }

  /** Resolve { tickSize, negRisk } from the CLOB book unless caller supplied both. */
  async resolveOrderOptions(req: PolymarketOrderRequest): Promise<PolymarketCreateOrderOptions> {
    if (req.tickSize && typeof req.negRisk === "boolean") {
      return { tickSize: req.tickSize, negRisk: req.negRisk };
    }
    // STRICT: when the caller hasn't supplied both, the book MUST yield real
    // tickSize + negRisk. We do NOT guess — a wrong value breaks the order hash.
    const resolved = await resolveCreateOrderOptions(req.tokenId, {
      strict: true,
      ...(this.injectedFetch ? { fetch: this.injectedFetch } : {}),
    });
    return {
      tickSize: req.tickSize ?? resolved.tickSize,
      negRisk: typeof req.negRisk === "boolean" ? req.negRisk : resolved.negRisk,
    };
  }

  /**
   * Build a SIGNED order: resolve tickSize/negRisk, round size per side, and
   * sign with the delegate signer via the clob-client. ALWAYS passes
   * { tickSize, negRisk } to createOrder (omitting = broken hash).
   */
  async buildSignedOrder(input: PolymarketOrderRequest): Promise<unknown> {
    const req = orderRequestSchema.parse(input);
    const amount = Number.parseFloat(String(req.amount));
    const price = Number.parseFloat(String(req.price));
    if (!Number.isFinite(amount) || amount <= 0) throw new Error("invalid order amount");
    if (!Number.isFinite(price) || price <= 0 || price >= 1) {
      throw new Error("invalid order price (must be in (0,1))");
    }

    const size = roundOrderSize(req.side, amount, price);
    if (!(size > 0)) throw new Error("computed order size is not positive after rounding");
    // The clob-client floors size to 2dp internally; reject sizes it would zero out
    // (e.g. a sub-0.01 SELL) so we never sign a doomed/zero order.
    if (!(sdkEffectiveSize(size) > 0)) {
      throw new Error(
        `order size ${size} is below the clob-client's ${CLOB_SIZE_DECIMALS}-decimal minimum (would be floored to 0)`,
      );
    }

    const options = await this.resolveOrderOptions(req);
    const { client, Side } = await this.createClobClient();

    // Only include feeRateBps when the caller explicitly supplied it; otherwise
    // leave it off so the clob-client resolves the market's actual fee (passing
    // 0 on a non-zero-fee market makes the SDK reject the order).
    const order: {
      tokenID: string;
      price: number;
      side: unknown;
      size: number;
      nonce: number;
      feeRateBps?: number;
    } = {
      tokenID: req.tokenId,
      price,
      side: req.side === "buy" ? Side.BUY : Side.SELL,
      size,
      nonce: req.nonce ?? 0,
    };
    if (req.feeRateBps !== undefined) order.feeRateBps = req.feeRateBps;

    return client.createOrder(order, options);
  }

  /**
   * Build + post an order. market/FOK -> FOK (marketable limit at supplied
   * price), otherwise GTC. Returns the venue-neutral result with actual fill.
   *
   * For callers that need to separate the BUILD/sign phase (no network reaches
   * the venue) from the POST phase (the order may land), call buildSignedOrder()
   * then submitSignedOrder() instead — a build failure then never gets confused
   * with a post failure (e.g. for spend-accounting fail-safety).
   */
  async submitOrder(input: PolymarketOrderRequest): Promise<PolymarketPostOrderResult> {
    const req = orderRequestSchema.parse(input);
    const signed = await this.buildSignedOrder(req);
    return this.submitSignedOrder(signed, req);
  }

  /**
   * POST-ONLY phase: post an ALREADY-built signed order to the venue. Splitting
   * this from buildSignedOrder lets a caller attribute failures precisely — a
   * throw from THIS method means the post was attempted (the order may have
   * landed), whereas a throw from buildSignedOrder means nothing was submitted.
   * Does NOT rebuild/re-sign, so it never re-touches CLOB metadata or the signer.
   */
  async submitSignedOrder(
    signed: unknown,
    input: PolymarketOrderRequest,
  ): Promise<PolymarketPostOrderResult> {
    const req = orderRequestSchema.parse(input);
    const { client, OrderType } = await this.createClobClient();

    const isMarketable = req.orderType === "market" || req.orderType === "FOK";
    const raw = (await client.postOrder(
      signed,
      isMarketable ? OrderType.FOK : OrderType.GTC,
    )) as RawPostOrderResult;

    const reqAmount = Number.parseFloat(String(req.amount));
    const reqPrice = Number.parseFloat(String(req.price));
    // The size the SDK actually signs (shares). roundOrderSize applies the
    // per-side precision (BUY 2dp / SELL 5dp), but the clob-client re-rounds the
    // signed maker amount to sdkEffectiveSize (2dp). Report what is ACTUALLY
    // signed so the no-amounts ACCEPTED fallback matches the on-chain order.
    const signedSize = sdkEffectiveSize(roundOrderSize(req.side, reqAmount, reqPrice));

    let actualAmount: number | undefined;
    let actualPrice: number | undefined;
    if (isRejectedPostOrder(raw)) {
      // Venue REJECTED the order: do NOT fabricate a fill. Report 0 filled so
      // downstream accounting doesn't record a phantom position.
      actualAmount = 0;
      actualPrice = undefined;
    } else {
      // Accepted: use protocol amounts when present, else the rounded/signed size
      // (shares) as the fallback — NOT the raw USD/unrounded requested amount.
      const fill = deriveActualFill(req.side, raw, { amount: signedSize, price: reqPrice });
      actualAmount = fill.actualAmount;
      actualPrice = fill.actualPrice;
    }

    return postOrderResultSchema.parse({
      venue: "polymarket",
      orderId: raw.orderID ?? raw.orderId,
      status: typeof raw.status === "string" ? raw.status : undefined,
      success: raw.success,
      errorMsg: raw.error ?? raw.errorMsg,
      makingAmount: raw.makingAmount,
      takingAmount: raw.takingAmount,
      actualAmount,
      actualPrice,
      raw,
    });
  }

  /** List open orders, optionally scoped to a market (condition id). */
  async listOrders(params: { market?: string } = {}): Promise<PolymarketOpenOrder[]> {
    const { client } = await this.createClobClient();
    const raw = (await client.getOpenOrders(
      params.market ? { market: params.market } : undefined,
    )) as unknown[];
    return (Array.isArray(raw) ? raw : []).map((o) => openOrderSchema.parse(o));
  }

  /** Cancel an order by id. */
  async cancelOrder(params: { orderId: string }): Promise<PolymarketCancelResult> {
    const { client } = await this.createClobClient();
    const raw = await client.cancelOrder({ orderID: params.orderId });
    return { venue: "polymarket", orderId: params.orderId, raw };
  }
}

export function createPolymarketExecutionAdapter(
  account: PolymarketAccount,
  options?: PolymarketAdapterOptions,
): PolymarketExecutionAdapter {
  return new PolymarketExecutionAdapter(account, options);
}

// ---------------------------------------------------------------------------
// Minimal structural types for the clob-client surface we use. We don't import
// the SDK's types at module scope (lazy import only), so these describe the
// shape we depend on without pulling the dependency into the type graph.
// ---------------------------------------------------------------------------

interface ClobClientLike {
  createOrder(
    order: {
      tokenID: string;
      price: number;
      side: unknown;
      size: number;
      feeRateBps?: number;
      nonce: number;
    },
    options: PolymarketCreateOrderOptions,
  ): Promise<unknown>;
  postOrder(signedOrder: unknown, orderType?: unknown): Promise<unknown>;
  getOpenOrders(params?: { market?: string }): Promise<unknown>;
  cancelOrder(params: { orderID: string }): Promise<unknown>;
}
interface ClobOrderTypeEnum {
  FOK: unknown;
  GTC: unknown;
}
interface ClobSideEnum {
  BUY: unknown;
  SELL: unknown;
}
