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
import { HyperliquidAdapter } from "@stwd/venue-hyperliquid";
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

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      { ok: false, error: "Hyperliquid venue wallet not found for agent" },
      404,
    );
  }

  // ── Approved-addresses policy gate (BEFORE signing) ──────────────────────────
  // The withdraw destination must be on the agent's approved list. We evaluate
  // the full policy set the same way POST /vault/sign does; the policy engine's
  // approved-addresses evaluator reads `request.to`.
  const policySet = await getPolicySet(tenantId, agentId);
  const evaluation = await policyEngine.evaluate(policySet, {
    request: {
      agentId,
      tenantId,
      to: destination,
      value: "0",
      chainId: 42161, // Arbitrum — HL withdraw destination chain
      venue: "hyperliquid" as const,
    },
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

  // Idempotency keyed on (agent, destination, amount). Computed after the policy
  // gate so a rejected withdraw is never cached as a success.
  const idempotency = getOperatorIdempotency(`${tenantId}:withdraw`, body.idempotencyKey, {
    agentId,
    venue,
    destination,
    amount: body.amount ?? null,
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

  // Resolve amount: explicit, or full withdrawable balance.
  let amount = body.amount;
  if (amount === undefined) {
    const withdrawable = await fetchWithdrawable(walletAddress);
    if (!withdrawable || Number(withdrawable) <= 0) {
      return c.json<ApiResponse>(
        { ok: false, error: "No withdrawable balance and no amount specified" },
        400,
      );
    }
    amount = withdrawable;
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
