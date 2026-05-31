/**
 * Vault routes — transaction signing, approval/rejection, history, key import,
 * multi-wallet addresses, RPC passthrough, Solana signing, EIP-712 typed data.
 *
 * Mount: app.route("/vault", vaultRoutes)
 */

import { verifyToken } from "@stwd/auth";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { enforceRateLimit, recordVaultSpend } from "../middleware/redis-enforcement";
import { trackAuditEvent, writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  agentKeyQuorums,
  agentSigners,
  approvalQueue,
  db,
  ensureAgentForTenant,
  extractRpcErrorMessage,
  formatAuthenticatedPrincipal,
  getAuthenticatedPrincipal,
  getPolicySet,
  getTransactionStats,
  isNonEmptyString,
  isRpcError,
  isSameAuthenticatedPrincipal,
  isValidAddress,
  isValidAgentId,
  isValidAnyAddress,
  isValidSolanaAddress,
  policyEngine,
  priceOracle,
  type RpcRequest,
  type RpcResponse,
  requireAgentAccess,
  requireTenantLevel,
  type SignRequest,
  type SignTypedDataRequest,
  safeJsonParse,
  sanitizeErrorMessage,
  toSignRequest,
  toTxRecord,
  transactions,
  vault,
} from "../services/context";
import { verifySignerCredential } from "../services/signer-credentials";
import { dispatchWebhook } from "../services/webhook-dispatch";

export const vaultRoutes = new Hono<{ Variables: AppVariables }>();

const MAX_QUORUM_CREDENTIALS = 16;

function hasRecentSessionMfa(c: Parameters<typeof requireTenantLevel>[0], maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function hasTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function signerHasPermission(permissions: readonly string[], required: string): boolean {
  const family = required.includes("_") ? `${required.split("_")[0]}:*` : `${required}:*`;
  const aliases =
    required === "wallet_action_transfer"
      ? ["transfer"]
      : required === "wallet_action_send_calls"
        ? ["send_calls"]
        : [];
  return (
    permissions.includes("*") ||
    (required.startsWith("sign_") && permissions.includes("sign:*")) ||
    permissions.includes(required) ||
    aliases.some((permission) => permissions.includes(permission)) ||
    permissions.includes(family)
  );
}

type SignerAuthorization =
  | { authMode: "admin"; signerId: string | null }
  | { authMode: "signer"; signerId: string }
  | { authMode: "quorum"; quorumId: string; memberSignerIds: string[] };

function signerAuthAuditMetadata(auth: SignerAuthorization): Record<string, unknown> {
  if (auth.authMode === "quorum") {
    return {
      authMode: "quorum",
      quorumId: auth.quorumId,
      memberSignerIds: auth.memberSignerIds,
    };
  }
  return {
    authMode: auth.authMode,
    signerId: auth.signerId,
  };
}

async function requireSignerPermission(
  c: Parameters<typeof requireTenantLevel>[0],
  tenantId: string,
  agentId: string,
  requiredPermission: string,
): Promise<{ ok: true; auth: SignerAuthorization } | { ok: false; response: Response }> {
  const genericError =
    "Signing requires owner/admin MFA; owner/admin session; owner or admin session with recent MFA or valid signer-bound credentials";
  if (hasTenantAdminSession(c)) {
    if (hasRecentSessionMfa(c)) {
      return { ok: true, auth: { authMode: "admin", signerId: c.get("userId") ?? null } };
    }
    return {
      ok: false,
      response: c.json<ApiResponse>(
        { ok: false, error: "Signing requires recent MFA verification" },
        403,
      ),
    };
  }

  const signerId = c.req.header("x-steward-signer-id")?.trim();
  const signerSecret = c.req.header("x-steward-signer-secret");
  const quorumId = c.req.header("x-steward-key-quorum-id")?.trim();
  if (quorumId) {
    const credentialsHeader = c.req.header("x-steward-key-quorum-credentials");
    if (!credentialsHeader) {
      return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
    }

    let credentials: Array<{ signerId: string; signerSecret: string }>;
    try {
      const parsed = JSON.parse(credentialsHeader) as unknown;
      if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > MAX_QUORUM_CREDENTIALS) {
        throw new Error("invalid quorum credential count");
      }
      credentials = parsed.map((credential) => {
        if (!credential || typeof credential !== "object")
          throw new Error("invalid quorum credential");
        const value = credential as Record<string, unknown>;
        if (typeof value.signerId !== "string" || !value.signerId.trim()) {
          throw new Error("invalid quorum signer id");
        }
        if (typeof value.signerSecret !== "string" || !value.signerSecret) {
          throw new Error("invalid quorum signer secret");
        }
        return { signerId: value.signerId.trim(), signerSecret: value.signerSecret };
      });
    } catch {
      return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
    }

    const uniqueSignerIds = [...new Set(credentials.map((credential) => credential.signerId))];
    if (uniqueSignerIds.length !== credentials.length) {
      return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
    }

    const [quorum] = await db
      .select()
      .from(agentKeyQuorums)
      .where(
        and(
          eq(agentKeyQuorums.id, quorumId),
          eq(agentKeyQuorums.tenantId, tenantId),
          eq(agentKeyQuorums.agentId, agentId),
        ),
      );
    if (
      !quorum ||
      quorum.status !== "active" ||
      !signerHasPermission(quorum.permissions, requiredPermission)
    ) {
      return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
    }
    const memberSet = new Set(quorum.memberSignerIds);
    if (
      uniqueSignerIds.some((id) => !memberSet.has(id)) ||
      uniqueSignerIds.length < quorum.threshold
    ) {
      return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
    }

    const rows = await db
      .select()
      .from(agentSigners)
      .where(and(eq(agentSigners.tenantId, tenantId), eq(agentSigners.agentId, agentId)));
    const signersById = new Map(rows.map((row) => [row.id, row]));
    const now = new Date();
    for (const credential of credentials) {
      const signer = signersById.get(credential.signerId);
      const credentialHash =
        signer?.metadata && typeof signer.metadata.credentialHash === "string"
          ? signer.metadata.credentialHash
          : null;
      if (
        !signer ||
        signer.status !== "active" ||
        !credentialHash ||
        !(await verifySignerCredential(credential.signerSecret, credentialHash)) ||
        !signerHasPermission(signer.permissions, requiredPermission)
      ) {
        return {
          ok: false,
          response: c.json<ApiResponse>({ ok: false, error: genericError }, 403),
        };
      }
      await db
        .update(agentSigners)
        .set({
          metadata: { ...signer.metadata, credentialLastUsedAt: now.toISOString() },
          updatedAt: now,
        })
        .where(eq(agentSigners.id, signer.id));
    }
    return {
      ok: true,
      auth: { authMode: "quorum", quorumId: quorum.id, memberSignerIds: uniqueSignerIds },
    };
  }

  if (!signerId || !signerSecret) {
    return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
  }

  const [signer] = await db
    .select()
    .from(agentSigners)
    .where(
      and(
        eq(agentSigners.id, signerId),
        eq(agentSigners.tenantId, tenantId),
        eq(agentSigners.agentId, agentId),
      ),
    );
  const credentialHash =
    signer?.metadata && typeof signer.metadata.credentialHash === "string"
      ? signer.metadata.credentialHash
      : null;
  if (
    !signer ||
    signer.status !== "active" ||
    !credentialHash ||
    !(await verifySignerCredential(signerSecret, credentialHash)) ||
    !signerHasPermission(signer.permissions, requiredPermission)
  ) {
    return { ok: false, response: c.json<ApiResponse>({ ok: false, error: genericError }, 403) };
  }
  const now = new Date();
  await db
    .update(agentSigners)
    .set({
      metadata: { ...signer.metadata, credentialLastUsedAt: now.toISOString() },
      updatedAt: now,
    })
    .where(eq(agentSigners.id, signer.id));
  return { ok: true, auth: { authMode: "signer", signerId: signer.id } };
}

// ─── Sign transaction (EVM) ───────────────────────────────────────────────────

vaultRoutes.post("/:agentId/sign", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const request = await safeJsonParse<Omit<SignRequest, "agentId" | "tenantId">>(c);
  if (!request) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(request.to)) {
    return c.json<ApiResponse>({ ok: false, error: "'to' address is required" }, 400);
  }
  if (!isValidAnyAddress(request.to)) {
    const errMsg = request.to.startsWith("0x")
      ? "'to' must be a valid Ethereum address (0x + 40 hex chars)"
      : "'to' must be a valid Ethereum address (0x + 40 hex chars) or a valid Solana address (base58, 32–44 chars)";
    return c.json<ApiResponse>({ ok: false, error: errMsg }, 400);
  }
  if (request.value === undefined || request.value === null) {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required (wei amount as string)" },
      400,
    );
  }

  const resolvedChainId = request.chainId || parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = {
    ...request,
    tenantId,
    agentId,
    chainId: resolvedChainId,
  };
  const requester = getAuthenticatedPrincipal(c);
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    "sign_transaction",
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;
  const signerAuditMetadata = signerAuthAuditMetadata(signerAuthorization.auth);
  if (signerAuthorization.auth.authMode !== "admin") {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Signing requires owner/admin MFA; owner/admin session; owner or admin session with recent MFA or valid signer-bound credentials",
      },
      403,
    );
  }
  void signerAuditMetadata;
  const policySet = await getPolicySet(tenantId, agentId);

  // ── Redis rate-limit check (before policy evaluation) ──────────────────────
  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  // Set rate limit headers on success too
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) {
      c.header(key, value);
    }
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress: signRequest.to,
          value: signRequest.value,
          data: signRequest.data,
          chainId: signRequest.chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
          requestedByType: requester.type,
          requestedById: requester.id,
        });
      });

      trackAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          to: signRequest.to,
          value: signRequest.value,
          venue: signRequest.venue,
          walletAddress: signRequest.walletAddress,
          policyResults: evaluation.results,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress: signRequest.to,
      value: signRequest.value,
      data: signRequest.data,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        to: signRequest.to,
        value: signRequest.value,
        policyResults: evaluation.results,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  try {
    const txId = crypto.randomUUID();
    const shouldBroadcast = signRequest.broadcast !== false;
    const result = await vault.signTransaction(signRequest, {
      txId,
      policyResults: evaluation.results,
      status: "signed",
    });

    await db
      .update(transactions)
      .set({
        status: "signed",
        txHash: shouldBroadcast ? result : undefined,
        policyResults: evaluation.results,
        signedAt: new Date(),
      })
      .where(eq(transactions.id, txId));

    // ── Record spend in Redis (fire-and-forget) ──────────────────────────────
    recordVaultSpend(agentId, tenantId, signRequest.value, resolvedChainId).catch((err) =>
      console.error("[vault] Failed to record spend:", err),
    );

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: shouldBroadcast ? "vault.sign.broadcast" : "vault.sign",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: resolvedChainId,
        to: signRequest.to,
        value: signRequest.value,
        venue: signRequest.venue,
        walletAddress: signRequest.walletAddress,
        broadcast: shouldBroadcast,
        txHash: shouldBroadcast ? result : undefined,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", {
      txId,
      txHash: shouldBroadcast ? result : undefined,
    });

    if (shouldBroadcast) {
      return c.json<ApiResponse<{ txId: string; txHash: string }>>({
        ok: true,
        data: { txId, txHash: result },
      });
    }

    return c.json<ApiResponse<{ txId: string; signedTx: string }>>({
      ok: true,
      data: { txId, signedTx: result },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Sign transaction failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      error: rawMessage,
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Approve transaction ──────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/approve/:txId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction approval requires tenant-level authentication",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const [transaction] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
  if (!transaction) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const approver = getAuthenticatedPrincipal(c);
  const [approvalEntry] = await db
    .select({
      id: approvalQueue.id,
      status: approvalQueue.status,
      requestedByType: approvalQueue.requestedByType,
      requestedById: approvalQueue.requestedById,
    })
    .from(approvalQueue)
    .where(and(eq(approvalQueue.txId, txId), eq(approvalQueue.agentId, agentId)));

  if (!approvalEntry || approvalEntry.status !== "pending") {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  if (
    approvalEntry.requestedByType &&
    approvalEntry.requestedById &&
    isSameAuthenticatedPrincipal(
      { type: approvalEntry.requestedByType, id: approvalEntry.requestedById },
      approver,
    )
  ) {
    return c.json<ApiResponse>({ ok: false, error: "Approval requires separation of duties" }, 403);
  }

  const resolvedAt = new Date();
  const claimResult = await db
    .update(approvalQueue)
    .set({
      status: "approved",
      resolvedAt,
      resolvedBy: formatAuthenticatedPrincipal(approver),
      resolvedByType: approver.type,
      resolvedById: approver.id,
    })
    .where(and(eq(approvalQueue.id, approvalEntry.id), eq(approvalQueue.status, "pending")))
    .returning();

  if (claimResult.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  try {
    const isSolana = transaction.chainId === 101 || transaction.chainId === 102;
    let txHash: string;

    if (isSolana) {
      if (!transaction.data) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: "Solana transaction blob not found — cannot replay approval",
          },
          500,
        );
      }
      const result = await vault.signSolanaTransaction({
        agentId,
        tenantId,
        transaction: transaction.data,
        chainId: transaction.chainId,
        broadcast: true,
      });
      txHash = result.signature;
    } else {
      txHash = await vault.signTransaction(
        { ...toSignRequest(transaction), tenantId },
        { txId, policyResults: transaction.policyResults, status: "signed" },
      );
    }

    await db
      .update(transactions)
      .set({ status: "signed", txHash, signedAt: resolvedAt })
      .where(eq(transactions.id, txId));

    trackAuditEvent({
      tenantId,
      actorType: approver.type === "agent" ? "agent" : "user",
      actorId: approver.id,
      action: "vault.approve",
      resourceType: "transaction",
      resourceId: txId,
      metadata: { agentId, chainId: transaction.chainId, txHash },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", { txId, txHash });

    return c.json<ApiResponse<{ txId: string; txHash: string }>>({
      ok: true,
      data: { txId, txHash },
    });
  } catch (e: unknown) {
    // Revert the atomic claim so the approval can be retried
    await db
      .update(approvalQueue)
      .set({
        status: "pending",
        resolvedAt: null,
        resolvedBy: null,
        resolvedByType: null,
        resolvedById: null,
      })
      .where(and(eq(approvalQueue.txId, txId), eq(approvalQueue.agentId, agentId)));

    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Approve transaction failed for agent ${agentId}, tx ${txId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      error: rawMessage,
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Reject transaction ───────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/reject/:txId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction approval requires tenant-level authentication",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const rejectResult = await db
    .update(approvalQueue)
    .set({ status: "rejected", resolvedAt: new Date(), resolvedBy: tenantId })
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
      ),
    )
    .returning();

  if (rejectResult.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  await db
    .update(transactions)
    .set({ status: "rejected" })
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));

  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: tenantId,
    action: "vault.reject",
    resourceType: "transaction",
    resourceId: txId,
    metadata: { agentId },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  return c.json<ApiResponse>({ ok: true });
});

// ─── Pending approvals ────────────────────────────────────────────────────────

vaultRoutes.get("/:agentId/pending", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const pendingTransactions = await db
    .select({
      queueId: approvalQueue.id,
      status: approvalQueue.status,
      requestedAt: approvalQueue.requestedAt,
      transaction: transactions,
    })
    .from(approvalQueue)
    .innerJoin(transactions, eq(transactions.id, approvalQueue.txId))
    .where(
      and(
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
        eq(transactions.agentId, agentId),
      ),
    );

  return c.json<ApiResponse>({
    ok: true,
    data: pendingTransactions.map((entry) => ({
      queueId: entry.queueId,
      status: entry.status,
      requestedAt: entry.requestedAt,
      transaction: toTxRecord(entry.transaction),
    })),
  });
});

// ─── Transaction history ──────────────────────────────────────────────────────

vaultRoutes.get("/:agentId/history", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const history = await db.select().from(transactions).where(eq(transactions.agentId, agentId));

  return c.json<ApiResponse>({
    ok: true,
    data: history.map(toTxRecord),
  });
});

// ─── EIP-712 Typed Data Signing ───────────────────────────────────────────────

// ─── Sign arbitrary message (personal_sign / eth_sign) ───────────────────────────────
//
// Used by server-to-server flows that need an off-chain signature from an
// agent (e.g. four.meme SIWE login). EVM uses viem's personal_sign over the
// UTF-8 bytes of the message. Solana uses Ed25519 over the message bytes.
//
// POST /vault/:agentId/sign-message
// body: { "message": "<string>" }
// resp: { ok: true, data: { signature: "0x..." } }
vaultRoutes.post("/:agentId/sign-message", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{ message: string }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isNonEmptyString(body.message)) {
    return c.json<ApiResponse>({ ok: false, error: "'message' is required" }, 400);
  }

  const signerAuthorization = await requireSignerPermission(c, tenantId, agentId, "sign_message");
  if (!signerAuthorization.ok) return signerAuthorization.response;

  try {
    const signature = await vault.signMessage(tenantId, agentId, body.message);
    return c.json<ApiResponse>({ ok: true, data: { signature } });
  } catch (e) {
    console.error(`[Vault] sign-message failed for ${tenantId}/${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

vaultRoutes.post("/:agentId/sign-typed-data", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    domain: SignTypedDataRequest["domain"];
    types: SignTypedDataRequest["types"];
    primaryType: string;
    value: Record<string, unknown>;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!body.domain || typeof body.domain !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'domain' is required and must be an object" },
      400,
    );
  }
  if (!body.types || typeof body.types !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'types' is required and must be an object" },
      400,
    );
  }
  if (!isNonEmptyString(body.primaryType)) {
    return c.json<ApiResponse>({ ok: false, error: "'primaryType' is required" }, 400);
  }
  if (!body.value || typeof body.value !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required and must be an object" },
      400,
    );
  }

  const resolvedChainId =
    (typeof body.domain.chainId === "number" ? body.domain.chainId : 0) ||
    parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: "0x0000000000000000000000000000000000000000",
    value: "0",
    chainId: resolvedChainId,
  };
  const requester = getAuthenticatedPrincipal(c);

  const policySet = await getPolicySet(tenantId, agentId);

  // ── Redis rate-limit check (typed data) ────────────────────────────────────
  const rlResult = await enforceRateLimit(agentId, policySet);
  if (!rlResult.allowed) {
    if (rlResult.headers) {
      for (const [key, value] of Object.entries(rlResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>({ ok: false, error: rlResult.reason || "Rate limit exceeded" }, 429);
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress: signRequest.to,
          value: signRequest.value,
          chainId: signRequest.chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
          requestedByType: requester.type,
          requestedById: requester.id,
        });
      });

      trackAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.typed_data.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          primaryType: body.primaryType,
          policyResults: evaluation.results,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress: signRequest.to,
      value: signRequest.value,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.typed_data.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        primaryType: body.primaryType,
        policyResults: evaluation.results,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  const txId = crypto.randomUUID();

  try {
    const signature = await vault.signTypedData({
      agentId,
      tenantId,
      domain: body.domain,
      types: body.types,
      primaryType: body.primaryType,
      value: body.value,
    });

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "signed",
      toAddress: signRequest.to,
      value: signRequest.value,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
      signedAt: new Date(),
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.typed_data",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        primaryType: body.primaryType,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", { txId });

    return c.json<ApiResponse<{ signature: string; txId: string }>>({
      ok: true,
      data: { signature, txId },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Sign typed data failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      error: rawMessage,
      requestId,
    });

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Solana Transaction Signing ───────────────────────────────────────────────

vaultRoutes.post("/:agentId/sign-solana", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    transaction: string;
    chainId?: number;
    broadcast?: boolean;
    to?: string;
    value?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.transaction)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'transaction' is required (base64-encoded serialized Solana transaction)",
      },
      400,
    );
  }

  if (body.to !== undefined && body.to !== "") {
    if (!isValidSolanaAddress(body.to) && !isValidAddress(body.to)) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "'to' must be a valid Solana address (base58, 32–44 chars) or Ethereum address",
        },
        400,
      );
    }
  }

  if (!body.to || !body.value) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Solana signing requires 'to' (recipient address) and 'value' (lamports as string) for policy evaluation",
      },
      400,
    );
  }

  const chainId = body.chainId ?? 101;
  const toAddress = body.to;
  const txValue = body.value;

  const signRequest = {
    agentId,
    tenantId,
    to: toAddress,
    value: txValue,
    chainId,
  };
  const requester = getAuthenticatedPrincipal(c);

  const policySet = await getPolicySet(tenantId, agentId);

  // ── Redis rate-limit check (Solana) ────────────────────────────────────────
  const solRlResult = await enforceRateLimit(agentId, policySet);
  if (!solRlResult.allowed) {
    if (solRlResult.headers) {
      for (const [key, value] of Object.entries(solRlResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: solRlResult.reason || "Rate limit exceeded" },
      429,
    );
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress,
          value: txValue,
          data: body.transaction,
          chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
          requestedByType: requester.type,
          requestedById: requester.id,
        });
      });

      trackAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.solana.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId,
          to: toAddress,
          value: txValue,
          policyResults: evaluation.results,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress,
      value: txValue,
      chainId,
      policyResults: evaluation.results,
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.solana.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId,
        to: toAddress,
        value: txValue,
        policyResults: evaluation.results,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  try {
    const txId = crypto.randomUUID();

    const result = await vault.signSolanaTransaction({
      agentId,
      tenantId,
      transaction: body.transaction,
      chainId,
      broadcast: body.broadcast,
    });

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "signed",
      toAddress,
      value: txValue,
      chainId,
      txHash: result.broadcast ? result.signature : undefined,
      policyResults: evaluation.results,
      signedAt: new Date(),
    });

    // ── Record spend in Redis (fire-and-forget) ──────────────────────────────
    recordVaultSpend(agentId, tenantId, txValue, chainId).catch((err) =>
      console.error("[vault] Failed to record Solana spend:", err),
    );

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.solana",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId,
        to: toAddress,
        value: txValue,
        broadcast: result.broadcast,
        signature: result.broadcast ? result.signature : undefined,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", {
      txId,
      txHash: result.broadcast ? result.signature : undefined,
    });

    return c.json<
      ApiResponse<{
        txId: string;
        signature: string;
        broadcast: boolean;
        chainId: number;
        caip2?: string;
      }>
    >({
      ok: true,
      data: { txId, ...result },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Solana sign failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      error: e instanceof Error ? e.message : "Unknown error",
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Delegated wallet action signing placeholders ────────────────────────────

async function rejectWithoutSignerAuth(
  c: Parameters<typeof requireTenantLevel>[0],
  requiredPermission: string,
) {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId") ?? "";
  const signerAuthorization = await requireSignerPermission(
    c,
    tenantId,
    agentId,
    requiredPermission,
  );
  if (!signerAuthorization.ok) return signerAuthorization.response;
  return c.json<ApiResponse>(
    { ok: false, error: "Delegated wallet action signing is not enabled on this branch" },
    501,
  );
}

vaultRoutes.post("/:agentId/actions/transfer", async (c) => {
  return rejectWithoutSignerAuth(c, "wallet_action_transfer");
});

vaultRoutes.post("/:agentId/actions/send-calls", async (c) => {
  return rejectWithoutSignerAuth(c, "wallet_action_send_calls");
});

vaultRoutes.post("/:agentId/sign-user-operation", async (c) => {
  return rejectWithoutSignerAuth(c, "sign_user_operation");
});

vaultRoutes.post("/:agentId/sign-authorization", async (c) => {
  return rejectWithoutSignerAuth(c, "sign_authorization");
});

// ─── Generic RPC Passthrough ──────────────────────────────────────────────────

vaultRoutes.post("/:agentId/rpc", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<RpcRequest>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.method)) {
    return c.json<ApiResponse>({ ok: false, error: "'method' is required" }, 400);
  }

  if (!body.chainId || typeof body.chainId !== "number") {
    return c.json<ApiResponse>(
      { ok: false, error: "'chainId' is required and must be a number" },
      400,
    );
  }

  try {
    const result = await vault.rpcPassthrough(body);
    return c.json<ApiResponse<RpcResponse>>({
      ok: true,
      data: result,
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const message = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] RPC passthrough failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Multi-Wallet Address List ────────────────────────────────────────────────

vaultRoutes.get("/:agentId/addresses", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const addresses = await vault.getAddresses(tenantId, agentId);
    return c.json<
      ApiResponse<{
        agentId: string;
        addresses: Array<{ chainFamily: "evm" | "solana"; address: string }>;
      }>
    >({
      ok: true,
      data: { agentId, addresses },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] getAddresses failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Import ───────────────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/import", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key import requires tenant-level authentication" },
      403,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!isValidAgentId(agentId)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)",
      },
      400,
    );
  }

  const body = await safeJsonParse<{
    privateKey: string;
    chain: "evm" | "solana";
  }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.privateKey)) {
    return c.json<ApiResponse>({ ok: false, error: "privateKey is required" }, 400);
  }

  if (body.chain !== "evm" && body.chain !== "solana") {
    return c.json<ApiResponse>({ ok: false, error: "chain must be 'evm' or 'solana'" }, 400);
  }

  try {
    const result = await vault.importKey(tenantId, agentId, body.privateKey, body.chain);
    return c.json<ApiResponse<{ agentId: string; walletAddress: string; chain: string }>>({
      ok: true,
      data: { agentId, walletAddress: result.walletAddress, chain: body.chain },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Key import failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Export ──────────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/export", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires tenant-level authentication" },
      403,
    );
  }

  const allowExport =
    process.env.STEWARD_ALLOW_KEY_EXPORT !== undefined
      ? process.env.STEWARD_ALLOW_KEY_EXPORT === "true"
      : process.env.NODE_ENV !== "production";
  if (!allowExport) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export is disabled by STEWARD_ALLOW_KEY_EXPORT" },
      403,
    );
  }

  const authHeader = c.req.header("Authorization");
  let actorId = c.get("userId") ?? null;
  let hasRecentMfa = false;
  if (authHeader?.startsWith("Bearer ")) {
    try {
      const payload = await verifyToken(authHeader.slice(7));
      actorId = typeof payload.userId === "string" ? payload.userId : actorId;
      const verifiedAt = payload.sessionMfaVerifiedAt ?? payload.mfaVerifiedAt;
      const verifiedAtMs =
        typeof verifiedAt === "number"
          ? verifiedAt < 10_000_000_000
            ? verifiedAt * 1000
            : verifiedAt
          : typeof verifiedAt === "string"
            ? Date.parse(verifiedAt)
            : Number.NaN;
      hasRecentMfa = Number.isFinite(verifiedAtMs) && Date.now() - verifiedAtMs <= 5 * 60 * 1000;
    } catch {
      hasRecentMfa = false;
    }
  }
  if (!hasRecentMfa) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires recent MFA or passkey step-up" },
      403,
    );
  }

  const body = await safeJsonParse<{ reason: string }>(c);
  if (!body || !isNonEmptyString(body.reason)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires a non-empty audited reason" },
      400,
    );
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const requestId = c.get("requestId") || null;
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId,
      action: "vault.key_export",
      resourceType: "agent",
      resourceId: agentId,
      metadata: {
        sensitivity: "HIGH",
        reason: body.reason.trim(),
        authType: c.get("authType"),
      },
      ipAddress: c.req.header("x-forwarded-for") ?? c.req.header("cf-connecting-ip") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId,
    });

    const keys = await vault.exportPrivateKey(tenantId, agentId);

    return c.json<
      ApiResponse<{
        evm?: { privateKey: string; address: string };
        solana?: { privateKey: string; address: string };
        warning: string;
      }>
    >({
      ok: true,
      data: {
        ...keys,
        warning: "This key controls real funds. Store securely.",
      },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Key export failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});
