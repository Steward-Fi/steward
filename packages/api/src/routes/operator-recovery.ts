/**
 * operator-recovery.ts — Operator fund-recovery endpoints.
 *
 * These routes implement the core promise of Steward: a HUMAN OPERATOR must
 * ALWAYS be able to close an agent's positions and withdraw its funds, even
 * when the agent's RS256 trade token is expired or the eliza-cloud control
 * plane is down. The Hyperliquid incident proved this capability was missing.
 *
 * ── Auth (deliberate) ────────────────────────────────────────────────────────
 * These are OPERATOR endpoints, NOT agent endpoints. They are gated by
 * `operatorAuth` (see app.ts), which accepts EITHER:
 *   - a platform key (header `X-Steward-Platform-Key`, validated by
 *     `isValidPlatformKey`), OR
 *   - a tenant-admin credential (tenant API key `X-Steward-Key` +
 *     `X-Steward-Tenant`, or a user session JWT) via `tenantAuth`.
 *
 * They MUST NOT be gated behind `requireAgentJwt`. That is exactly the broken
 * path that stranded funds when the agent token expired. A human recovering
 * funds has no valid agent JWT — that's the whole point.
 *
 * ── Signing (unchanged invariant) ──────────────────────────────────────────────
 * The raw signing key NEVER touches this route. We build the same
 * `vaultClient` shim used by POST /hyperliquid/order and hand it to the
 * `HyperliquidAdapter`; the vault decrypts in-memory, signs, and zeroes the
 * key internally. We reuse the Wave-1 adapter methods (closeAllPositions,
 * signWithdraw, submitWithdraw) — no signing is reimplemented here.
 */

import { proxyAuditLog } from "@stwd/db";
import {
  HyperliquidAdapter,
  hyperliquidAssetSchema,
  isBuilderPerpSymbol,
} from "@stwd/venue-hyperliquid";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  ensureAgentForTenant,
  getPolicySet,
  isValidAnyAddress,
  policyEngine,
  priceOracle,
  safeJsonParse,
  vault,
} from "../services/context";

export const operatorRecoveryRoutes = new Hono<{ Variables: AppVariables }>();

// ── Idempotency (mirrors trade.ts in-memory helper) ───────────────────────────
const operatorIdempotency = new Map<
  string,
  { bodyHash: string; response: unknown; expiresAt: number }
>();

function getOperatorIdempotency(
  scope: string,
  key: string | undefined,
  body: unknown,
): { conflict?: boolean; response?: unknown; store?: (response: unknown) => void } {
  if (!key) return {};
  const now = Date.now();
  const mapKey = `${scope}:${key}`;
  const bodyHash = JSON.stringify(body);
  const existing = operatorIdempotency.get(mapKey);
  if (existing && existing.expiresAt > now) {
    if (existing.bodyHash !== bodyHash) return { conflict: true };
    return { response: existing.response };
  }
  return {
    store(response: unknown) {
      operatorIdempotency.set(mapKey, {
        bodyHash,
        response,
        expiresAt: now + 24 * 60 * 60 * 1000,
      });
    },
  };
}

function operatorActor(c: Context<{ Variables: AppVariables }>): {
  actorType: "platform" | "user" | "agent";
  actorId: string;
} {
  // operatorAuth sets authType to "platform" when authenticated via platform key.
  if (c.get("authType") === "platform") {
    return { actorType: "platform", actorId: "platform-operator" };
  }
  const userId = c.get("userId");
  if (userId) return { actorType: "user", actorId: userId };
  return { actorType: "user", actorId: c.get("tenantId") ?? "operator" };
}

async function auditRecoveryEvent(
  c: Context<{ Variables: AppVariables }>,
  tenantId: string,
  agentId: string,
  action: string,
  metadata: Record<string, unknown>,
): Promise<void> {
  const actor = operatorActor(c);
  await writeAuditEvent({
    tenantId,
    actorType: actor.actorType,
    actorId: actor.actorId,
    action,
    resourceType: "trade",
    resourceId: agentId,
    metadata,
  });
  await db
    .insert(proxyAuditLog)
    .values({
      tenantId,
      agentId,
      targetHost: action,
      targetPath: JSON.stringify(metadata),
      method: "AUDIT",
      statusCode: 200,
      latencyMs: 0,
      reason: action,
    })
    .catch(() => undefined);
}

/**
 * Resolve the agent's Hyperliquid venue wallet address. Prefers the explicit
 * venue-scoped wallet (vault.getWallet) and falls back to the agent's EVM
 * wallet — same resolution priority as POST /sessions in trade.ts.
 */
async function resolveVenueWallet(
  tenantId: string,
  agentId: string,
  venue: string,
): Promise<string | null> {
  try {
    const wallet = await vault.getWallet({ agentId, venue });
    if (wallet?.address) return wallet.address;
  } catch {
    // fall through to agent EVM wallet
  }
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return null;
  const evm = agent.walletAddresses?.evm;
  if (evm) return evm;
  return agent.walletAddress?.startsWith("0x") ? agent.walletAddress : null;
}

function buildAdapter(tenantId: string, agentId: string, walletAddress: string) {
  const vaultClient = {
    signTypedData: (input: Omit<Parameters<typeof vault.signTypedData>[0], "tenantId">) =>
      vault.signTypedData({ ...input, tenantId, venue: "hyperliquid" as const }),
  };
  return new HyperliquidAdapter(vaultClient, agentId, walletAddress);
}

const closeAllSchema = z.object({
  agentId: z.string().min(1),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const withdrawSchema = z.object({
  agentId: z.string().min(1),
  amount: z.union([z.string(), z.number()]).optional(),
  destination: z.string().min(1),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const transferSchema = z
  .object({
    agentId: z.string().min(1),
    sourceDex: z.string(),
    destinationDex: z.string(),
    amountUsdc: z.union([z.string(), z.number()]),
    token: z.string().min(1).optional(),
    idempotencyKey: z.string().min(1).max(256).optional(),
  })
  .refine((v) => v.sourceDex !== v.destinationDex, "sourceDex and destinationDex must differ");

const leverageSchema = z.object({
  agentId: z.string().min(1),
  coin: hyperliquidAssetSchema,
  leverage: z.number().int().positive().max(100),
  isCross: z.boolean().optional(),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const addMarginSchema = z.object({
  agentId: z.string().min(1),
  coin: hyperliquidAssetSchema,
  amountUsdc: z.union([z.string(), z.number()]),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const approveBuilderSchema = z.object({
  agentId: z.string().min(1),
  builder: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  maxFeeRate: z.string().min(1),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const usdSendSchema = z.object({
  agentId: z.string().min(1),
  destination: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  amount: z
    .string()
    .regex(/^\d+(?:\.\d+)?$/)
    .refine((v) => Number(v) > 0, "amount must be positive"),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

// ── Deposit constants (Hyperliquid on Arbitrum) ────────────────────────────────
// HL credits the SENDING address, so the deposit MUST originate from the agent's
// own venue wallet. We sign an ERC-20 transfer(bridge, amount) from that wallet.
const ARBITRUM_CHAIN_ID = 42161;
// Native USDC on Arbitrum One (6 decimals).
const ARBITRUM_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
// Hyperliquid mainnet deposit bridge on Arbitrum.
const HYPERLIQUID_ARBITRUM_BRIDGE = "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7";
// HL enforces a 5 USDC minimum deposit. Below this, funds are lost.
const HL_MIN_DEPOSIT_USDC = 5;
// Sane upper bound: a single deposit call may not exceed this. Defends against
// a fat-finger/typo moving the whole reserve in one tx. Larger deposits must be
// split into multiple deliberate calls. (Override per-tenant later if needed.)
const HL_MAX_DEPOSIT_USDC = 2000;
// Sane upper bound for a single OPERATOR withdraw. Mirrors HL_MAX_DEPOSIT_USDC:
// defends against a fat-finger/typo (or a compromised operator client) draining
// the whole venue balance in one call. Larger withdraws must be split into
// multiple deliberate calls. (Override per-tenant later if needed.)
const HL_MAX_WITHDRAW_USDC = 2000;
const USDC_DECIMALS = 6;
const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
const USDC_AMOUNT_RE = /^\d+(?:\.(\d+))?$/;

function parseUsdcBaseUnits(amount: string | number): bigint | null {
  const raw = typeof amount === "number" ? String(amount) : amount.trim();
  if (!USDC_AMOUNT_RE.test(raw)) return null;
  const [, fractional = ""] = raw.match(USDC_AMOUNT_RE) ?? [];
  if (fractional.length > USDC_DECIMALS) return null;
  const [whole, fraction = ""] = raw.split(".");
  return BigInt(whole) * 10n ** BigInt(USDC_DECIMALS) + BigInt(fraction.padEnd(USDC_DECIMALS, "0"));
}

function hasTooManyUsdcDecimals(amount: string | number): boolean {
  const raw = typeof amount === "number" ? String(amount) : amount.trim();
  const [, fractional = ""] = raw.match(USDC_AMOUNT_RE) ?? [];
  return fractional.length > USDC_DECIMALS;
}

/**
 * Encode an ERC-20 `transfer(address,uint256)` call as calldata.
 * selector (4 bytes) + padded address (32) + padded amount (32).
 */
function encodeErc20Transfer(to: string, amountBaseUnits: bigint): string {
  const addr = to.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  const amt = amountBaseUnits.toString(16).padStart(64, "0");
  return `${ERC20_TRANSFER_SELECTOR}${addr}${amt}`;
}

const depositSchema = z.object({
  agentId: z.string().min(1),
  // USDC amount as a decimal string or number (e.g. "10" or 10). Converted to
  // 6-decimal base units. Must be >= HL_MIN_DEPOSIT_USDC.
  amount: z.union([z.string(), z.number()]),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

// ── POST /v1/trade/:venue/deposit ──────────────────────────────────────────────
// Fund an agent's Hyperliquid account by signing an ERC-20 USDC transfer from
// the agent's OWN venue wallet to the HL Arbitrum bridge. HL credits the sender,
// so this correctly credits the policy-scoped venue wallet (NOT the operator).
// The agent's wallet must already hold USDC + a little ETH for gas on Arbitrum.
operatorRecoveryRoutes.post("/:venue/deposit", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }

  const raw = await safeJsonParse(c);
  const parsed = depositSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId } = body;

  // Parse + validate the USDC amount.
  const amountNum = Number(body.amount);
  if (!Number.isFinite(amountNum) || amountNum <= 0) {
    return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
  }
  if (amountNum < HL_MIN_DEPOSIT_USDC) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `amount below Hyperliquid minimum deposit of ${HL_MIN_DEPOSIT_USDC} USDC`,
      },
      400,
    );
  }
  if (amountNum > HL_MAX_DEPOSIT_USDC) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `amount exceeds the per-deposit maximum of ${HL_MAX_DEPOSIT_USDC} USDC; split into smaller deposits`,
      },
      400,
    );
  }
  // Reject sub-cent precision the 6-decimal conversion can't represent exactly,
  // so the on-chain amount always matches the requested amount.
  const scaled = amountNum * 10 ** USDC_DECIMALS;
  if (!Number.isInteger(scaled)) {
    return c.json<ApiResponse>({ ok: false, error: "amount has more than 6 decimal places" }, 400);
  }
  // Convert to 6-decimal base units (exact: `scaled` is an integer here).
  const amountBaseUnits = BigInt(scaled);

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  // Idempotency keyed on (agent, amount). Computed BEFORE broadcast so a retried
  // deposit with the same key returns the original result instead of double-sending.
  const idempotency = getOperatorIdempotency(`${tenantId}:deposit`, body.idempotencyKey, {
    agentId,
    venue,
    amount: amountBaseUnits.toString(),
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  // Build the ERC-20 transfer(bridge, amount) calldata and have the vault sign +
  // broadcast it FROM the agent's venue wallet on Arbitrum. The raw key never
  // leaves the vault. venue is set so the vault selects the hyperliquid-scoped key.
  const data = encodeErc20Transfer(HYPERLIQUID_ARBITRUM_BRIDGE, amountBaseUnits);
  let txHash: string;
  try {
    txHash = await vault.signTransaction({
      agentId,
      tenantId,
      to: ARBITRUM_USDC,
      value: "0",
      data,
      chainId: ARBITRUM_CHAIN_ID,
      venue: "hyperliquid",
      broadcast: true,
    });
  } catch (err) {
    // TEMP DEBUG (deposit-cause): drizzle wraps the REAL error in DrizzleQueryError;
    // walk the .cause chain to surface the underlying failure. Remove after.
    const chain: string[] = [];
    let cur: unknown = err;
    for (let i = 0; i < 6 && cur; i++) {
      const e = cur as { message?: string; cause?: unknown; code?: string };
      chain.push(`[${i}] ${e?.code ? e.code + ": " : ""}${e?.message ?? String(cur)}`);
      cur = e?.cause;
    }
    console.error("[deposit-cause] chain:", JSON.stringify(chain, null, 2));
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.deposit.failed", {
      venue,
      walletAddress,
      bridge: HYPERLIQUID_ARBITRUM_BRIDGE,
      amount: amountBaseUnits.toString(),
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to submit deposit" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.deposit.submitted", {
    venue,
    walletAddress,
    bridge: HYPERLIQUID_ARBITRUM_BRIDGE,
    amount: amountBaseUnits.toString(),
    txHash,
  });

  const response = {
    venue,
    walletAddress,
    bridge: HYPERLIQUID_ARBITRUM_BRIDGE,
    amountUsdc: amountNum,
    amountBaseUnits: amountBaseUnits.toString(),
    txHash,
  };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

// ── POST /v1/trade/:venue/leverage ─────────────────────────────────────────────
// Platform-key recovery lever for already-open Hyperliquid positions. Builder
// perps are isolated-only and capped at 3x here, matching the order path.
operatorRecoveryRoutes.post("/:venue/leverage", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }
  if (c.get("authType") !== "platform") {
    return c.json<ApiResponse>(
      { ok: false, error: "Platform key required for leverage update" },
      403,
    );
  }

  const raw = await safeJsonParse(c);
  const parsed = leverageSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId, coin } = body;
  const builderPerp = isBuilderPerpSymbol(coin);
  const effectiveLeverage = builderPerp ? Math.min(body.leverage, 3) : body.leverage;
  const isCross = builderPerp ? false : (body.isCross ?? false);

  const idempotency = getOperatorIdempotency(`${tenantId}:leverage`, body.idempotencyKey, {
    agentId,
    venue,
    coin,
    leverage: effectiveLeverage,
    requestedLeverage: body.leverage,
    isCross,
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.leverage.requested", {
    venue,
    walletAddress,
    coin,
    leverage: effectiveLeverage,
    requestedLeverage: body.leverage,
    isCross,
    builderPerp,
  });

  let result: unknown;
  try {
    result = await adapter.updateLeverage({ coin, leverage: effectiveLeverage, isCross });
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.leverage.failed", {
      venue,
      walletAddress,
      coin,
      leverage: effectiveLeverage,
      requestedLeverage: body.leverage,
      isCross,
      builderPerp,
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to update leverage" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.leverage.submitted", {
    venue,
    walletAddress,
    coin,
    leverage: effectiveLeverage,
    requestedLeverage: body.leverage,
    isCross,
    builderPerp,
  });

  const response = {
    venue,
    walletAddress,
    coin,
    leverage: effectiveLeverage,
    requestedLeverage: body.leverage,
    isCross,
    builderPerp,
    result,
  };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

// ── POST /v1/trade/:venue/add-margin ───────────────────────────────────────────
// Platform-key recovery lever for adding USDC margin to an existing isolated
// Hyperliquid position before lowering isolated leverage.
operatorRecoveryRoutes.post("/:venue/add-margin", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }
  if (c.get("authType") !== "platform") {
    return c.json<ApiResponse>(
      { ok: false, error: "Platform key required for margin update" },
      403,
    );
  }

  const raw = await safeJsonParse(c);
  const parsed = addMarginSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId, coin } = body;

  if (hasTooManyUsdcDecimals(body.amountUsdc)) {
    return c.json<ApiResponse>(
      { ok: false, error: "amountUsdc has more than 6 decimal places" },
      400,
    );
  }
  const amountBaseUnits = parseUsdcBaseUnits(body.amountUsdc);
  if (amountBaseUnits === null || amountBaseUnits <= 0n) {
    return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
  }
  const amountNum = Number(body.amountUsdc);
  if (!Number.isFinite(amountNum) || amountNum <= 0) {
    return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
  }
  if (amountNum > HL_MAX_WITHDRAW_USDC) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `amountUsdc exceeds the per-margin-update maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller updates`,
      },
      400,
    );
  }

  const idempotency = getOperatorIdempotency(`${tenantId}:add-margin`, body.idempotencyKey, {
    agentId,
    venue,
    coin,
    amount: amountBaseUnits.toString(),
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.add-margin.requested", {
    venue,
    walletAddress,
    coin,
    amountUsdc: String(body.amountUsdc),
    amountBaseUnits: amountBaseUnits.toString(),
  });

  let result: unknown;
  try {
    result = await adapter.addIsolatedMargin({ coin, amountUsdc: body.amountUsdc });
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.add-margin.failed", {
      venue,
      walletAddress,
      coin,
      amountUsdc: String(body.amountUsdc),
      amountBaseUnits: amountBaseUnits.toString(),
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to add isolated margin" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.add-margin.submitted", {
    venue,
    walletAddress,
    coin,
    amountUsdc: String(body.amountUsdc),
    amountBaseUnits: amountBaseUnits.toString(),
  });

  const response = {
    venue,
    walletAddress,
    coin,
    amountUsdc: String(body.amountUsdc),
    amountBaseUnits: amountBaseUnits.toString(),
    result,
  };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

// ── POST /v1/trade/:venue/usd-send ───────────────────────────────────────────
// Platform-key only internal USDC transfer between Hyperliquid accounts. This is
// a user-signed action and must be signed by the sending agent/vault master HL wallet.
operatorRecoveryRoutes.post("/:venue/usd-send", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }
  if (c.get("authType") !== "platform") {
    return c.json<ApiResponse>({ ok: false, error: "Platform key required for usdSend" }, 403);
  }

  const raw = await safeJsonParse(c);
  const parsed = usdSendSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    destination: parsed.data.destination.toLowerCase(),
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId, destination, amount } = body;

  const idempotency = getOperatorIdempotency(`${tenantId}:usd-send`, body.idempotencyKey, {
    agentId,
    venue,
    destination,
    amount,
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.requested", {
    venue,
    walletAddress,
    destination,
    amount,
  });

  let result: unknown;
  try {
    result = await adapter.usdSend({ destination, amount });
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.failed", {
      venue,
      walletAddress,
      destination,
      amount,
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to submit usdSend" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.completed", {
    venue,
    walletAddress,
    destination,
    amount,
  });

  const response = { venue, walletAddress, destination, amount, result };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

// ── POST /v1/trade/:venue/approve-builder ─────────────────────────────────────
// Platform-key only approval for Hyperliquid builder-code fees. This is a
// user-signed action and must be signed by the agent/vault master HL wallet.
operatorRecoveryRoutes.post("/:venue/approve-builder", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }
  if (c.get("authType") !== "platform") {
    return c.json<ApiResponse>(
      { ok: false, error: "Platform key required for builder fee approval" },
      403,
    );
  }

  const raw = await safeJsonParse(c);
  const parsed = approveBuilderSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    builder: parsed.data.builder.toLowerCase(),
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId, builder, maxFeeRate } = body;

  const idempotency = getOperatorIdempotency(`${tenantId}:approve-builder`, body.idempotencyKey, {
    agentId,
    venue,
    builder,
    maxFeeRate,
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  await auditRecoveryEvent(c, tenantId, agentId, "trade.builder.approve.requested", {
    venue,
    walletAddress,
    builder,
    maxFeeRate,
  });

  let result: unknown;
  try {
    result = await adapter.approveBuilderFee({ builder, maxFeeRate });
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.builder.approve.failed", {
      venue,
      walletAddress,
      builder,
      maxFeeRate,
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to approve builder fee" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.builder.approved", {
    venue,
    walletAddress,
    builder,
    maxFeeRate,
  });

  const response = { venue, walletAddress, builder, maxFeeRate, result };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

// ── POST /v1/trade/:venue/transfer ─────────────────────────────────────────────
// Platform-key only capital movement between Hyperliquid collateral buckets. This
// does NOT withdraw funds, but it can strand core withdrawable USDC on an
// isolated HIP-3 builder dex, so it is gated like operator recovery and audited
// before/after signing. Exit story: close any builder-dex position first, call
// transferFromBuilderDex (sourceDex "xyz" → destinationDex "") to pull USDC back
// to core, then use the existing core-only withdraw route.
operatorRecoveryRoutes.post("/:venue/transfer", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }
  if (c.get("authType") !== "platform") {
    return c.json<ApiResponse>(
      { ok: false, error: "Platform key required for collateral transfer" },
      403,
    );
  }

  const raw = await safeJsonParse(c);
  const parsed = transferSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId, sourceDex, destinationDex } = body;

  if (hasTooManyUsdcDecimals(body.amountUsdc)) {
    return c.json<ApiResponse>(
      { ok: false, error: "amountUsdc has more than 6 decimal places" },
      400,
    );
  }
  const amountBaseUnits = parseUsdcBaseUnits(body.amountUsdc);
  if (amountBaseUnits === null || amountBaseUnits <= 0n) {
    return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
  }
  const amountNum = Number(body.amountUsdc);
  if (!Number.isFinite(amountNum) || amountNum <= 0) {
    return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
  }
  if (amountNum > HL_MAX_WITHDRAW_USDC) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: `amountUsdc exceeds the per-transfer maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller transfers`,
      },
      400,
    );
  }

  const idempotency = getOperatorIdempotency(`${tenantId}:transfer`, body.idempotencyKey, {
    agentId,
    venue,
    sourceDex,
    destinationDex,
    amount: amountBaseUnits.toString(),
    token: body.token ?? null,
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.transfer.requested", {
    venue,
    walletAddress,
    sourceDex,
    destinationDex,
    amountUsdc: String(body.amountUsdc),
    amountBaseUnits: amountBaseUnits.toString(),
  });

  let result: unknown;
  let action: unknown;
  try {
    const signed = await adapter.signSendAsset({
      destination: walletAddress,
      sourceDex,
      destinationDex,
      token: body.token,
      amount: body.amountUsdc,
    });
    action = signed.action;
    result = await adapter.submitSendAsset(signed);
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.transfer.failed", {
      venue,
      walletAddress,
      sourceDex,
      destinationDex,
      amountUsdc: String(body.amountUsdc),
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to submit collateral transfer" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.transfer.submitted", {
    venue,
    walletAddress,
    sourceDex,
    destinationDex,
    amountUsdc: String(body.amountUsdc),
    amountBaseUnits: amountBaseUnits.toString(),
    action,
  });

  const response = {
    venue,
    walletAddress,
    sourceDex,
    destinationDex,
    amountUsdc: String(body.amountUsdc),
    result,
  };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

// ── POST /v1/trade/:venue/close-all ────────────────────────────────────────────
operatorRecoveryRoutes.post("/:venue/close-all", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }

  const raw = await safeJsonParse(c);
  const parsed = closeAllSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId } = body;

  const idempotency = getOperatorIdempotency(`${tenantId}:close-all`, body.idempotencyKey, {
    agentId,
    venue,
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  let results: Awaited<ReturnType<HyperliquidAdapter["closeAllPositions"]>>;
  try {
    results = await adapter.closeAllPositions();
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.close-all.failed", {
      venue,
      walletAddress,
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to close positions" }, 502);
  }

  // Audit every per-coin close so the recovery action is fully traceable.
  for (const r of results) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.position-closed", {
      venue,
      walletAddress,
      coin: r.coin,
      status: r.result.status,
      orderId: r.result.orderId ?? null,
    });
  }

  const response = { venue, walletAddress, closed: results };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});

/**
 * Read the agent's withdrawable USDC balance from the Hyperliquid
 * clearinghouseState. HL exposes a top-level `withdrawable` string. We reach
 * it via the same /info endpoint the adapter uses; if the shape is unexpected
 * we return null so the caller must supply an explicit amount.
 */
async function fetchWithdrawable(walletAddress: string): Promise<string | null> {
  try {
    const r = await fetch("https://api.hyperliquid.xyz/info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "clearinghouseState", user: walletAddress }),
    });
    if (!r.ok) return null;
    const j = (await r.json()) as { withdrawable?: unknown };
    const w = j?.withdrawable;
    if (typeof w === "string" && w.length > 0) return w;
    if (typeof w === "number") return String(w);
    return null;
  } catch {
    return null;
  }
}

// ── POST /v1/trade/:venue/withdraw ─────────────────────────────────────────────
operatorRecoveryRoutes.post("/:venue/withdraw", async (c) => {
  const tenantId = c.get("tenantId");
  const venue = c.req.param("venue");
  if (venue !== "hyperliquid") {
    return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
  }

  const raw = await safeJsonParse(c);
  const parsed = withdrawSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }
  const body = {
    ...parsed.data,
    idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
  };
  const { agentId, destination } = body;

  if (!isValidAnyAddress(destination)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid destination address" }, 400);
  }

  // Validate the EXPLICIT withdraw amount the same way /deposit validates its
  // amount: reject non-finite/NaN/<=0, enforce a per-call max cap, and reject
  // sub-cent/over-precision values the 6-decimal conversion can't represent.
  // (The no-amount path resolves the full withdrawable balance below.)
  let explicitAmountBaseUnits: bigint | null = null;
  if (body.amount !== undefined) {
    if (hasTooManyUsdcDecimals(body.amount)) {
      return c.json<ApiResponse>(
        { ok: false, error: "amount has more than 6 decimal places" },
        400,
      );
    }
    explicitAmountBaseUnits = parseUsdcBaseUnits(body.amount);
    if (explicitAmountBaseUnits === null || explicitAmountBaseUnits <= 0n) {
      return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
    }
    const amountNum = Number(body.amount);
    if (amountNum > HL_MAX_WITHDRAW_USDC) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amount exceeds the per-withdraw maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller withdraws`,
        },
        400,
      );
    }
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  const explicitIdempotencyAmount =
    explicitAmountBaseUnits !== null ? explicitAmountBaseUnits.toString() : null;
  const idempotency = getOperatorIdempotency(`${tenantId}:withdraw`, body.idempotencyKey, {
    agentId,
    venue,
    destination,
    amount: explicitIdempotencyAmount,
  });
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json<ApiResponse>({ ok: true, data: idempotency.response });
  }

  // Resolve amount after the idempotency cache lookup, so a retry for a
  // previous full-balance withdraw returns the cached success before reading a
  // changed live balance.
  // `amount` stays human-readable for signing; `amountBaseUnits` (USDC 6-decimal
  // base units, a uint256 integer string) is what the policy spend-cap sees.
  let amount = body.amount;
  let amountBaseUnits = explicitAmountBaseUnits;
  if (amount === undefined) {
    const withdrawable = await fetchWithdrawable(walletAddress);
    amountBaseUnits = withdrawable ? parseUsdcBaseUnits(withdrawable) : null;
    if (!withdrawable || amountBaseUnits === null || amountBaseUnits <= 0n) {
      return c.json<ApiResponse>(
        { ok: false, error: "No withdrawable balance and no amount specified" },
        400,
      );
    }
    amount = withdrawable;
  }
  if (amountBaseUnits === null) {
    return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
  }

  // ── Policy gate (BEFORE signing) ─────────────────────────────────────────────
  // The withdraw destination must be on the agent's approved list AND the amount
  // must satisfy the spend-cap. We evaluate the full policy set the same way POST
  // /vault/sign does; the approved-addresses evaluator reads `request.to`, and the
  // spending-limit evaluator reads `request.value` (the real USDC base-unit
  // notional, NOT the previous hardcoded "0" which bypassed the spend-cap).
  const policySet = await getPolicySet(tenantId, agentId);
  const evaluation = await policyEngine.evaluate(policySet, {
    request: {
      agentId,
      tenantId,
      to: destination,
      value: amountBaseUnits.toString(),
      chainId: 42161, // Arbitrum HL withdraw destination chain
    },
    // `venue` must be top-level on the evaluation context: the engine reads
    // `ctx.venue` (engine.ts) for the venue-allowlist evaluator. Nesting it
    // inside `request` leaves ctx.venue undefined → venue-allowlist fails closed.
    venue: "hyperliquid" as const,
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    priceOracle,
  });
  if (!evaluation.approved) {
    const failed = evaluation.results.find((r) => !r.passed);
    const reason = failed?.reason ?? "withdraw destination violates policy";
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.policy-rejected", {
      venue,
      walletAddress,
      destination,
      reason,
    });
    return c.json({ code: "policy-violation", reason }, 400);
  }

  const adapter = buildAdapter(tenantId, agentId, walletAddress);

  let result: unknown;
  try {
    const signed = await adapter.signWithdraw({ amount, destination });
    result = await adapter.submitWithdraw(signed);
  } catch (err) {
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.failed", {
      venue,
      walletAddress,
      destination,
      amount,
      error: err instanceof Error ? err.message : String(err),
    });
    return c.json<ApiResponse>({ ok: false, error: "Failed to submit withdraw" }, 502);
  }

  await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.submitted", {
    venue,
    walletAddress,
    destination,
    amount,
  });

  const response = { venue, walletAddress, destination, amount, result };
  idempotency.store?.(response);
  return c.json<ApiResponse>({ ok: true, data: response });
});
