/**
 * provider-execution.ts — PR4 execution authorization v2 minting (spec §2.3,
 * §3, §4.1 step 1, §7.1).
 *
 * This module owns the API-side MINT of a v2 execution authorization. It runs
 * INSIDE the PR3 `resume()` transaction (spec §2.3 preferred: one atomic step
 * from approved→execution_ready→authorization minted, removing an extra crash
 * window). It:
 *
 *   1. reads the persisted PR3 approval commitment (source of every bound fact)
 *      + the persisted PR2 canonical action bytes (source of the pinned target +
 *      header profile),
 *   2. reconstructs the exact v2 commitment document (@stwd/shared pure builder),
 *   3. signs it with the domain-separated HKDF(STEWARD_EXECUTION_AUTH_SECRET)
 *      v2 key (fail-closed if the secret is absent — X7, P49/F06),
 *   4. inserts the v2 `execution_authorization_nonces` row `active/none`,
 *   5. appends `provider.execution.authorized` in the SAME audited transaction.
 *
 * It NEVER decrypts a credential, calls the proxy, or claims — the claim happens
 * at the proxy signing boundary in the separate proxy process (see
 * `@stwd/proxy` governed-execution handler). Mint idempotency is enforced by the
 * DB unique index `exec_auth_nonces_intent_uniq` (one v2 authorization per
 * intent, K22/F01): a duplicate resume returns the existing authorization with
 * no second row and no second `authorized` event.
 *
 * Correlation contract (PR5 C1): the audit event sets top-level
 * `resource_type='provider_action'`, `resource_id=intents.id`.
 * Data minimization (PR5 C3): audit metadata records
 * `providerIdempotencyKeyHash` (sha256), NEVER the raw provider idempotency key.
 */

import { createHash, randomUUID } from "node:crypto";
import { executionAuthorizationNonces } from "@stwd/db";
import {
  activeExecutionAuthV2Key,
  buildProviderExecutionCommitmentV2,
  computeActionDigest,
  computeApprovalCommitmentHash,
  computeProviderExecutionCommitmentHash,
  decodeUtf8Strict,
  type GithubCanonicalActionV1,
  isExecutionAuthV2SecretConfigured,
  type ProviderApprovalCommitmentV1,
  signProviderExecutionCommitmentV2,
  strictParseJson,
} from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";

// ─── Error codes (spec §6.1) ───────────────────────────────────────────────────

export type ProviderExecutionErrorCode =
  | "EXEC_AUTH_NOT_READY"
  | "EXEC_AUTH_KEY_UNAVAILABLE"
  | "EXEC_AUTH_MINT_FAILED"
  | "EXEC_AUDIT_UNAVAILABLE";

export class ProviderExecutionMintError extends Error {
  constructor(
    readonly code: ProviderExecutionErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ProviderExecutionMintError";
  }
}

// v2 authorization TTL from mint. The DB `expires_at > now()` is the sole
// expiry authority at claim (X4); this is the mint-time window.
const V2_AUTHORIZATION_TTL_MS = 300_000; // 5 minutes

/** sha256: hex of the provider idempotency key (audit records the HASH, never raw). */
export function hashProviderIdempotencyKey(key: string): string {
  return `sha256:${createHash("sha256").update(key, "utf8").digest("hex")}`;
}

// A `tx`/`append` pair from `withTenantAuditedTransaction`. The service is
// transaction-agnostic (it is handed the running tx by the PR3 resume path).
type TxLike = {
  insert: (...args: unknown[]) => {
    values: (row: Record<string, unknown>) => {
      onConflictDoNothing: (arg: { target: unknown; where?: unknown }) => {
        returning: (cols: Record<string, unknown>) => Promise<Array<{ id: string }>>;
      };
    };
  };
  select: (...args: unknown[]) => unknown;
};

type AppendAudit = (ev: { tenantId: string } & Record<string, unknown>) => Promise<void>;

/** The subset of the PR3 binding + persisted approval a mint needs. */
export interface MintBindingInput {
  intentId: string;
  tenantId: string;
  workspaceId: string;
  actorAgentId: string;
  providerAccountId: string;
  operationId: string;
  operationRevision: number;
  requestHash: string;
  actionDigest: string;
  /** PR3 approval_queue row id. */
  approvalId: string;
  /** The exact hash the binding recorded. */
  approvalCommitmentHash: string;
  /** The persisted PR3 approval commitment (approval_queue.approval_commitment). */
  approvalCommitment: ProviderApprovalCommitmentV1;
  /** The persisted PR2 canonical action bytes (provider_action_bindings.canonical_action_bytes). */
  canonicalActionBytes: Uint8Array;
  /** PR3 request envelope requestId (defaults to intentId). */
  requestId?: string | null;
}

export interface MintResult {
  authorizationId: string;
  executionId: string;
  nonce: string;
  commitmentHash: string;
  keyId: string;
  providerIdempotencyKey: string;
  /** True when a prior mint already existed for this intent (idempotent no-op). */
  replayed: boolean;
}

/**
 * Parse the persisted PR2 canonical action bytes back into the canonical action
 * object. The bytes are the strict JCS serialization PR2 stored; we parse them
 * with the same strict JSON parser so a corrupted/truncated blob fails closed.
 */
function parseCanonicalAction(bytes: Uint8Array): GithubCanonicalActionV1 {
  const text = decodeUtf8Strict(bytes);
  const parsed = strictParseJson(text) as unknown as GithubCanonicalActionV1;
  return parsed;
}

/**
 * Mint the v2 execution authorization for an `execution_ready` provider action,
 * INSIDE the caller's audited transaction. Idempotent by intent.
 *
 * @throws ProviderExecutionMintError (EXEC_AUTH_KEY_UNAVAILABLE) if the v2 secret
 * is absent — the caller must map this to a fail-closed denial (503, P49). The
 * caller's audit-failure handling maps AuditUnavailableError to
 * EXEC_AUDIT_UNAVAILABLE.
 */
export async function mintProviderExecutionAuthorizationWithinTx(
  tx: TxLike,
  append: AppendAudit,
  binding: MintBindingInput,
  opts?: {
    now?: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
    requestId?: string | null;
    /** Test-only fault hooks; production no-ops. */
    hooks?: { beforeInsert?: () => Promise<void>; beforeAudit?: () => Promise<void> };
  },
): Promise<MintResult> {
  // Fail closed at MINT if the v2 secret is absent (X7, P49). We never fall back
  // to STEWARD_JWT_SECRET.
  if (!isExecutionAuthV2SecretConfigured()) {
    throw new ProviderExecutionMintError(
      "EXEC_AUTH_KEY_UNAVAILABLE",
      "STEWARD_EXECUTION_AUTH_SECRET is not configured; cannot mint v2 authorization",
    );
  }

  const now = opts?.now ?? new Date();
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + V2_AUTHORIZATION_TTL_MS).toISOString();

  const authorizationId = randomUUID();
  const executionId = randomUUID();
  const nonce = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "").slice(0, 16);
  const providerIdempotencyKey = randomUUID();

  const active = activeExecutionAuthV2Key();
  const action = parseCanonicalAction(binding.canonicalActionBytes);

  // The approval JSON, its stored hash, and the denormalized binding tuple must
  // all describe the same approved action before we mint a signature. Otherwise
  // a storage-level substitution could be blessed with a fresh v2 authorization.
  const approval = binding.approvalCommitment;
  if (
    computeApprovalCommitmentHash(approval) !== binding.approvalCommitmentHash ||
    approval.intentId !== binding.intentId ||
    approval.tenantId !== binding.tenantId ||
    approval.workspaceId !== binding.workspaceId ||
    approval.requestActor.id !== binding.actorAgentId ||
    approval.providerAccount.id !== binding.providerAccountId ||
    approval.operation.id !== binding.operationId ||
    approval.operation.revision !== binding.operationRevision ||
    approval.requestHash !== binding.requestHash ||
    approval.actionDigest !== binding.actionDigest ||
    computeActionDigest(action) !== binding.actionDigest
  ) {
    throw new ProviderExecutionMintError(
      "EXEC_AUTH_MINT_FAILED",
      "approval commitment, binding, and canonical action are inconsistent",
    );
  }

  const commitment = buildProviderExecutionCommitmentV2({
    approval: binding.approvalCommitment,
    action,
    approvalCommitmentHash: binding.approvalCommitmentHash,
    approvalId: binding.approvalId,
    authorizationId,
    executionId,
    requestId: binding.requestId ?? binding.intentId,
    providerIdempotencyKey,
    nonce,
    issuedAt,
    expiresAt,
    keyId: active.keyId,
  });

  const commitmentHash = computeProviderExecutionCommitmentHash(commitment);
  const signature = signProviderExecutionCommitmentV2(commitment);
  const grantDependencyHash = commitment.grantDependencyHash;

  // The v1-reused columns `payload_digest` + `policy_revision_hash` are
  // varchar(64) and hold a BARE 64-hex digest (no `sha256:` prefix); the v2
  // arm columns (`action_digest`, `request_hash`, ...) are varchar(71) and hold
  // the prefixed form. Strip the prefix for the v1 columns only.
  const bareDigest = (h: string): string => (h.startsWith("sha256:") ? h.slice(7) : h);

  await opts?.hooks?.beforeInsert?.();

  // Insert the v2 nonce row. `onConflictDoNothing` on the intent unique index
  // makes the mint idempotent (K22/F01): a duplicate resume inserts nothing.
  const inserted = await tx
    .insert(executionAuthorizationNonces)
    .values({
      authorizationId,
      requestId: binding.requestId ?? binding.intentId,
      tenantId: binding.tenantId,
      agentId: binding.actorAgentId,
      capability: "credential.inject_http",
      backend: "credential-proxy",
      payloadDigest: bareDigest(binding.actionDigest),
      policyRevisionHash: bareDigest(binding.approvalCommitment.policyDecision.policyRevisionHash),
      approvalId: binding.approvalId,
      nonce,
      signature,
      idempotencyKey: providerIdempotencyKey,
      status: "active",
      issuedAt: now,
      expiresAt: new Date(expiresAt),
      // v2 arm
      version: 2,
      executionId,
      intentId: binding.intentId,
      workspaceId: binding.workspaceId,
      providerAccountId: binding.providerAccountId,
      operationId: binding.operationId,
      operationRevision: binding.operationRevision,
      requestHash: binding.requestHash,
      actionDigest: binding.actionDigest,
      grantDependencyHash,
      routeId: commitment.routeId,
      routeRevision: commitment.routeRevision,
      secretId: commitment.secretId,
      secretVersion: commitment.secretVersion,
      providerIdempotencyKey,
      commitmentHash,
      keyId: active.keyId,
      dispatchState: "none",
    })
    // The intent-uniq index is PARTIAL (WHERE version = 2), so the ON CONFLICT
    // arbiter must repeat the predicate to be inferred.
    .onConflictDoNothing({
      target: executionAuthorizationNonces.intentId,
      where: sql`${executionAuthorizationNonces.version} = 2`,
    })
    .returning({ id: executionAuthorizationNonces.id });

  if (inserted.length === 0) {
    // Idempotent replay: a prior mint already owns this intent. Load and return
    // it without a second `authorized` event.
    const existing = await loadExistingV2AuthorizationForIntent(tx, binding.intentId);
    if (!existing) {
      throw new ProviderExecutionMintError(
        "EXEC_AUTH_MINT_FAILED",
        "mint conflict on intent but no existing v2 authorization found",
      );
    }
    return {
      authorizationId: existing.authorizationId,
      executionId: existing.executionId,
      nonce: existing.nonce,
      commitmentHash: existing.commitmentHash,
      keyId: existing.keyId,
      providerIdempotencyKey: existing.providerIdempotencyKey,
      replayed: true,
    };
  }

  await opts?.hooks?.beforeAudit?.();

  // `provider.execution.authorized` in the SAME audited transaction (§4.1 step 1,
  // §7.1). Audit metadata carries the idempotency key HASH, never the raw key.
  await append({
    tenantId: binding.tenantId,
    actorType: "system",
    actorId: "steward-system",
    action: "provider.execution.authorized",
    resourceType: "provider_action",
    resourceId: binding.intentId,
    metadata: {
      schemaVersion: "steward.provider-execution-audit.v1",
      intentId: binding.intentId,
      executionId,
      authorizationId,
      dispatchState: "none",
      operationId: binding.operationId,
      operationRevision: binding.operationRevision,
      routeId: commitment.routeId,
      routeRevision: commitment.routeRevision,
      secretVersion: commitment.secretVersion,
      requestHash: binding.requestHash,
      actionDigest: binding.actionDigest,
      commitmentHash,
      keyId: active.keyId,
      providerIdempotencyKeyHash: hashProviderIdempotencyKey(providerIdempotencyKey),
      approvalCommitmentHash: binding.approvalCommitmentHash,
    },
    ipAddress: opts?.ipAddress ?? null,
    userAgent: opts?.userAgent ?? null,
    requestId: opts?.requestId ?? null,
  });

  return {
    authorizationId,
    executionId,
    nonce,
    commitmentHash,
    keyId: active.keyId,
    providerIdempotencyKey,
    replayed: false,
  };
}

interface ExistingV2Authorization {
  authorizationId: string;
  executionId: string;
  nonce: string;
  commitmentHash: string;
  keyId: string;
  providerIdempotencyKey: string;
}

async function loadExistingV2AuthorizationForIntent(
  tx: TxLike,
  intentId: string,
): Promise<ExistingV2Authorization | null> {
  const rows = (await (
    tx.select as unknown as (cols: Record<string, unknown>) => {
      from: (t: unknown) => {
        where: (w: unknown) => { limit: (n: number) => Promise<Array<Record<string, string>>> };
      };
    }
  )({
    authorizationId: executionAuthorizationNonces.authorizationId,
    executionId: executionAuthorizationNonces.executionId,
    nonce: executionAuthorizationNonces.nonce,
    commitmentHash: executionAuthorizationNonces.commitmentHash,
    keyId: executionAuthorizationNonces.keyId,
    providerIdempotencyKey: executionAuthorizationNonces.providerIdempotencyKey,
  })
    .from(executionAuthorizationNonces)
    .where(
      and(
        eq(executionAuthorizationNonces.intentId, intentId),
        eq(executionAuthorizationNonces.version, 2),
      ),
    )
    .limit(1)) as Array<Record<string, string>>;
  const row = rows[0];
  if (!row) return null;
  return {
    authorizationId: row.authorizationId,
    executionId: row.executionId,
    nonce: row.nonce,
    commitmentHash: row.commitmentHash,
    keyId: row.keyId,
    providerIdempotencyKey: row.providerIdempotencyKey,
  };
}
