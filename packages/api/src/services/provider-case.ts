import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
/**
 * provider-case.ts — correlated provider-case evidence assembler (pure read).
 *
 * Builds a deterministic, offline-verifiable case manifest for one governed
 * provider action and, on demand, packages it alongside the EXISTING signed
 * audit bundle. It adds no ledger, mints no case id (the case IS `intents.id`),
 * and carries no independent trust: every manifest fact is checkable against a
 * signed audit event (spec E1–E8, §2.3).
 *
 * Correlation (spec §1.3, C1 RATIFIED): every provider-lifecycle audit event
 * sets top-level `resource_type='provider_action'` + `resource_id=intents.id`
 * AND `metadata.intentId=intents.id`. Online correlation queries the indexed
 * `resource_id`; the assembler additionally asserts `metadata.intentId` agrees
 * (defense-in-depth against event-theft, N23).
 *
 * Snapshot (spec §4.1): all reads (binding/queue/nonce/events/chain-verify/
 * bundle) run inside ONE read-only transaction so the manifest and bundle are
 * observed at one coherent snapshot (KC06). On Postgres we request REPEATABLE
 * READ READ ONLY; PGLite serializes writers, so a plain read is consistent.
 */

import {
  approvalQueue,
  executionAuthorizationNonces,
  getDb,
  hasTenantTransactionDatabase,
  providerAccounts,
  providerActionBindings,
  providerOperations,
  redactWebhookSecrets,
} from "@stwd/db";
import {
  assertRegisteredProfile,
  chainSegmentBrokenReason,
  describeThrown,
  missingRoleReason,
  PROVIDER_CASE_MANIFEST_SCHEMA_VERSION,
  PROVIDER_CASE_REASON,
  type ProviderCaseDispatchState,
  type ProviderCaseEventRole,
  type ProviderCaseEvidenceV1,
  type ProviderCaseManifestEvent,
  type ProviderCaseManifestV1,
  type ProviderCaseTerminalState,
  requiredRoles,
  roleForAction,
  sha256HexPrefixed,
} from "@stwd/shared";
import { and, asc, eq, sql } from "drizzle-orm";
import {
  type AuditBundleData,
  type AuditReadExecutor,
  readAuditBundleData,
  type SignedAuditBundle,
  signAuditBundle,
  verifyAuditChain,
} from "./audit";

/**
 * The snapshot read surface: the Drizzle db OR a Drizzle transaction. Both
 * support `.select()` and `.execute()`. CRITICAL for PGLite (single connection):
 * every read inside `runInSnapshot` MUST use the SAME `tx` object, never a fresh
 * `getDb()`, or the open transaction deadlocks the single connection.
 */
type SnapshotDb = ReturnType<typeof getDb>;

/** Per-event serialized metadata cap (spec §3.6). */
const MAX_EVENT_METADATA_BYTES = 16 * 1024;
/** Whole-manifest cap (spec §3.6). */
const MAX_MANIFEST_BYTES = 256 * 1024;
/** Defensive segment cap; mirrors MAX_AUDIT_BUNDLE_EVENTS (spec §5.5/KC15). */
const MAX_CASE_SEGMENT_EVENTS = 10_000;

/**
 * Thrown by `getProviderCaseEvidence` when a case's contiguous chain segment
 * exceeds `MAX_CASE_SEGMENT_EVENTS`. The route maps it to 400
 * `CASE_RANGE_TOO_LARGE` (spec §5.4/KC15) so a pathological interleave cannot
 * materialize/sign an unbounded audit range. `/case` (manifest-only) still works.
 */
export class CaseRangeTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CaseRangeTooLargeError";
  }
}

/**
 * PGLite runtime detection (mirrors the private helper in @stwd/db
 * audit-chain.ts, which is not exported). On PGLite the per-tenant writer queue
 * serializes appends so a plain tx read is coherent; on real Postgres we
 * escalate to REPEATABLE READ READ ONLY for a true snapshot.
 */
function isPGLiteRuntime(): boolean {
  return (
    runtimeEnvironmentValue("STEWARD_DB_MODE") === "pglite" ||
    runtimeEnvironmentValue("STEWARD_PGLITE_MEMORY") === "true"
  );
}

/** Sensitive-key set for the safe-summary re-validation (spec §3.3). Mirrors the
 * @stwd/db redaction denylist; if any survives, we OMIT the summary. */
const SAFE_SUMMARY_SENSITIVE_SUFFIXES = [
  "accesstoken",
  "apikey",
  "bearertoken",
  "claimtoken",
  "clientsecret",
  "credentialsecret",
  "idtoken",
  "jwt",
  "mnemonic",
  "password",
  "privatekey",
  "recoveryphrase",
  "refreshtoken",
  "secret",
  "seedphrase",
  "sessiontoken",
  "signersecret",
  "tokenhash",
];

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function summaryHasSensitiveKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(summaryHasSensitiveKey);
  if (!value || typeof value !== "object") return false;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const n = normalizeKey(k);
    if (
      n === "secret" ||
      n === "password" ||
      n === "jwt" ||
      n === "authorization" ||
      SAFE_SUMMARY_SENSITIVE_SUFFIXES.some((s) => n.endsWith(s))
    ) {
      return true;
    }
    if (summaryHasSensitiveKey(v)) return true;
  }
  return false;
}

/** A correlated audit-event row as read from `audit_events`. */
interface CorrelatedEvent {
  seq: number;
  action: string;
  hmac: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

type BindingRow = typeof providerActionBindings.$inferSelect;
type NonceRow = typeof executionAuthorizationNonces.$inferSelect;
type QueueRow = typeof approvalQueue.$inferSelect;
type OperationRow = typeof providerOperations.$inferSelect;
type AccountRow = typeof providerAccounts.$inferSelect;

/** Raw executor row helper (postgres-js / neon both expose rows differently). */
function rows<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  const r = (result as { rows?: unknown[] }).rows;
  return (r ?? []) as T[];
}

/**
 * Correlate every signed audit event for a case by `resource_id=caseId` (fast
 * indexed path, §1.3) AND assert `metadata.intentId===caseId` on each (§3.5,
 * N23 event-theft guard). Returns events sorted by seq ascending.
 */
async function correlateCaseEvents(
  executor: AuditReadExecutor,
  tenantId: string,
  caseId: string,
): Promise<CorrelatedEvent[]> {
  const result: unknown = await executor.execute(
    sql`SELECT seq, action, hmac, metadata, created_at
        FROM audit_events
        WHERE tenant_id = ${tenantId}
          AND resource_type = 'provider_action'
          AND resource_id = ${caseId}
        ORDER BY seq ASC`,
  );
  const out: CorrelatedEvent[] = [];
  for (const row of rows<{
    seq: number | string;
    action: string;
    hmac: unknown;
    metadata: Record<string, unknown> | null;
    created_at: Date | string;
  }>(result)) {
    const metadata = row.metadata ?? {};
    // Defense-in-depth agreement check (§1.3): the online correlation column
    // (resource_id) MUST agree with the offline-authoritative signed
    // metadata.intentId. A mismatch means a forged/misfiled event; drop it so it
    // can never be smuggled into a foreign case (N23).
    if (metadata.intentId !== caseId) continue;
    const created = row.created_at instanceof Date ? row.created_at : new Date(row.created_at);
    out.push({
      seq: Number(row.seq),
      action: row.action,
      hmac: toHex(row.hmac),
      metadata,
      createdAt: created.toISOString(),
    });
  }
  return out;
}

function toHex(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) {
    let hex = "";
    for (let i = 0; i < value.length; i++) hex += value[i].toString(16).padStart(2, "0");
    return hex;
  }
  // Buffer-like {type:'Buffer',data:[...]} or array
  if (value && typeof value === "object" && "data" in (value as Record<string, unknown>)) {
    const data = (value as { data: number[] }).data;
    return data.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  return String(value);
}

/**
 * Resolve the authoritative terminal state from the binding + nonce columns
 * (spec §4.4). This is the source of truth; the required-event function is
 * computed from it and cross-checked against present events.
 */
function resolveTerminalState(
  binding: BindingRow,
  nonce: NonceRow | null,
): ProviderCaseTerminalState {
  // Binding.status is the authoritative provider-action state. Values per the
  // 0082 status_chk allowlist: denied | pending_approval | allowed_stub |
  // stub_succeeded | stub_failed | approved | execution_ready | approval_denied
  // | approval_expired | approval_stale | executing | succeeded | failed |
  // outcome_unknown.
  switch (binding.status) {
    case "denied":
      // Distinguish access vs policy deny from the persisted effects.
      if (binding.accessEffect === "deny") return "denied_access";
      return "denied_policy";
    case "pending_approval":
      return "pending_approval";
    // The non-approval allowed path can execute via the in-process stub. These
    // states are terminal for that fake-transport path; map to succeeded/failed
    // so completeness is honest against the stub outcome. (Full governed
    // execution uses the execution_ready→executing→terminal arm below.)
    case "allowed_stub":
      return "executing";
    case "stub_succeeded":
      return "succeeded";
    case "stub_failed":
      return "failed";
    case "approved":
      // Approved but not yet resumed to execution_ready.
      return "execution_ready";
    case "approval_denied":
      return "approval_denied";
    case "approval_expired":
      return "approval_expired";
    case "approval_stale":
      return "approval_staled";
    case "execution_ready":
      return "execution_ready";
    case "executing":
      if (nonce?.dispatchState === "outcome_unknown") return "outcome_unknown";
      return "executing";
    case "succeeded":
      return "succeeded";
    case "failed":
      return "failed";
    case "outcome_unknown":
      return "outcome_unknown";
    default:
      return "unknown";
  }
}

/** Map the raw nonce dispatch_state to the manifest enum, defaulting to none. */
function dispatchStateOf(nonce: NonceRow | null): ProviderCaseDispatchState {
  const s = nonce?.dispatchState;
  switch (s) {
    case "claimed":
    case "dispatched":
    case "succeeded":
    case "failed":
    case "outcome_unknown":
      return s;
    default:
      return "none";
  }
}

/**
 * The assembled manifest plus the internal seq bounds + correlated events the
 * evidence packager needs (so it does not re-read).
 */
export interface ProviderCaseAssembly {
  manifest: ProviderCaseManifestV1;
  correlated: CorrelatedEvent[];
  segmentFrom: number | null;
  segmentTo: number | null;
}

/**
 * Assemble the case manifest for `caseId` within the caller's tenant + one of
 * the authorized workspaces. Returns `null` for a case that does not exist in
 * the caller's tenant/authorized-workspace set (uniform not-found, §5.4 —
 * caller maps to 404 CASE_NOT_FOUND, non-enumerating). NEVER throws for a
 * data-corruption/absent-row case: it returns an honest `unknown`/`incomplete`
 * manifest (N46/KC14).
 */
export async function getProviderCase(
  tenantId: string,
  caseId: string,
  authorizedWorkspaceIds: string[],
): Promise<ProviderCaseAssembly | null> {
  return runInSnapshot(tenantId, (sdb) =>
    assembleWithinSnapshot(sdb, tenantId, caseId, authorizedWorkspaceIds),
  );
}

export interface ProviderCaseEvidenceSnapshot {
  tenantId: string;
  caseId: string;
  assembly: ProviderCaseAssembly;
  bundleData: AuditBundleData;
  segmentFrom: number;
  segmentTo: number;
}

/**
 * Assemble the full evidence envelope (manifest + signed bundle). Uses ONE
 * snapshot so the manifest and bundle cannot diverge (KC06). Returns `null` for
 * a not-found/foreign case (§5.4). Throws only on a signing-key-unavailable
 * (caller maps to 503) or a genuine chain-read failure (caller maps to 500).
 */
export async function getProviderCaseEvidence(
  tenantId: string,
  caseId: string,
  authorizedWorkspaceIds: string[],
): Promise<ProviderCaseEvidenceV1 | null> {
  const snapshot = await readProviderCaseEvidenceSnapshot(tenantId, caseId, authorizedWorkspaceIds);
  return snapshot ? signProviderCaseEvidenceSnapshot(snapshot) : null;
}

/**
 * Read every manifest and bundle input in one snapshot. Route callers end the
 * read-only transaction before passing this immutable material to the signer,
 * whose best-effort checkpoint persistence is intentionally a separate write.
 */
export async function readProviderCaseEvidenceSnapshot(
  tenantId: string,
  caseId: string,
  authorizedWorkspaceIds: string[],
): Promise<ProviderCaseEvidenceSnapshot | null> {
  return runInSnapshot(tenantId, async (sdb) => {
    const assembly = await assembleWithinSnapshot(sdb, tenantId, caseId, authorizedWorkspaceIds);
    if (!assembly) return null;
    const { segmentFrom, segmentTo } = assembly;
    if (
      segmentFrom != null &&
      segmentTo != null &&
      segmentTo - segmentFrom + 1 > MAX_CASE_SEGMENT_EVENTS
    ) {
      throw new CaseRangeTooLargeError(
        `case segment [${segmentFrom},${segmentTo}] exceeds ${MAX_CASE_SEGMENT_EVENTS} events`,
      );
    }
    const from = segmentFrom ?? 0;
    const to = segmentTo ?? 0;
    const bundleData =
      segmentFrom == null || segmentTo == null
        ? { head: null, events: [], bundleHeadHmac: null, bundleHeadSeq: null }
        : await readAuditBundleData(tenantId, segmentFrom, segmentTo, sdb);
    return { tenantId, caseId, assembly, bundleData, segmentFrom: from, segmentTo: to };
  });
}

export async function signProviderCaseEvidenceSnapshot(
  snapshot: ProviderCaseEvidenceSnapshot,
): Promise<ProviderCaseEvidenceV1> {
  const { tenantId, caseId, assembly, bundleData, segmentFrom, segmentTo } = snapshot;
  const { manifest } = assembly;
  const bundle: SignedAuditBundle = await signAuditBundle(
    tenantId,
    segmentFrom,
    segmentTo,
    bundleData,
  );

  return {
    version: 1,
    tenantId,
    caseId,
    manifest,
    bundle: {
      version: 1,
      tenantId: bundle.tenantId,
      range: bundle.range,
      canonicalizationSpec: bundle.canonicalizationSpec,
      events: bundle.events as unknown[],
      checkpoint: bundle.checkpoint,
      generatedAt: bundle.generatedAt,
    },
    completeness: manifest.completeness,
    generatedAt: new Date().toISOString(),
  };
}

/** Shared snapshot-scoped assembly used by both /case and /evidence. */
async function assembleWithinSnapshot(
  sdb: SnapshotDb,
  tenantId: string,
  caseId: string,
  authorizedWorkspaceIds: string[],
): Promise<ProviderCaseAssembly | null> {
  const binding = await loadBinding(sdb, tenantId, caseId);
  if (!binding) return null;
  if (!authorizedWorkspaceIds.includes(binding.workspaceId)) return null;

  // Sequential (NOT Promise.all): PGLite is a single connection and cannot run
  // concurrent statements on the same snapshot tx (they would serialize/deadlock).
  const nonce = await loadNonce(sdb, tenantId, caseId);
  const queue = binding.approvalQueueId
    ? await loadQueue(sdb, tenantId, binding.approvalQueueId)
    : null;
  const operation = await loadOperation(sdb, tenantId, binding.operationId);
  const account = await loadAccount(sdb, tenantId, binding.providerAccountId);
  const correlated = await correlateCaseEvents(sdb, tenantId, caseId);

  const assembly = buildManifest({
    tenantId,
    caseId,
    binding,
    nonce,
    queue,
    operation,
    account,
    correlated,
  });

  if (assembly.segmentFrom != null && assembly.segmentTo != null) {
    const span = assembly.segmentTo - assembly.segmentFrom + 1;
    if (span > MAX_CASE_SEGMENT_EVENTS) {
      pushReason(assembly.manifest, PROVIDER_CASE_REASON.MANIFEST_SIZE_EXCEEDED);
      assembly.manifest.completeness = "unknown";
    } else {
      const verify = await verifyAuditChain(tenantId, {
        fromSeq: assembly.segmentFrom,
        toSeq: assembly.segmentTo,
        requireHead: false,
        executor: sdb,
      });
      if (!verify.valid) {
        pushReason(assembly.manifest, chainSegmentBrokenReason(verify.brokenAt));
        assembly.manifest.completeness = "unknown";
      }
    }
  }

  finalizeCompleteness(assembly.manifest);
  enforceManifestSizeCap(assembly.manifest);
  return assembly;
}

// ─── Manifest construction ────────────────────────────────────────────────────

interface BuildManifestArgs {
  tenantId: string;
  caseId: string;
  binding: BindingRow;
  nonce: NonceRow | null;
  queue: QueueRow | null;
  operation: OperationRow | null;
  account: AccountRow | null;
  correlated: CorrelatedEvent[];
}

function buildManifest(args: BuildManifestArgs): ProviderCaseAssembly {
  const { tenantId, caseId, binding, nonce, queue, operation, account, correlated } = args;
  const reasons: string[] = [];

  const terminalState = resolveTerminalState(binding, nonce);

  // Event index (sorted by seq; roles derived from action).
  const events: ProviderCaseManifestEvent[] = correlated.map((ev) => ({
    seq: ev.seq,
    action: ev.action,
    // Unknown/drifted actions map to `unclassified`, NEVER `genesis`, so a
    // corrupted or taxonomy-drifted event can never mis-satisfy a required role
    // and falsely upgrade a case to `complete`. Linkage is still
    // proven (the seq+hmac stays in the index).
    role: roleForAction(ev.action) ?? "unclassified",
    hmac: ev.hmac,
  }));

  // Per-event metadata size cap (§3.6): if any event's metadata is over-cap the
  // manifest is flagged; the event index still carries seq+hmac+role (linkage
  // proof is never dropped).
  for (const ev of correlated) {
    if (byteLength(JSON.stringify(ev.metadata)) > MAX_EVENT_METADATA_BYTES) {
      pushReasonList(reasons, PROVIDER_CASE_REASON.MANIFEST_SIZE_EXCEEDED);
      break;
    }
  }

  const segmentFrom = correlated.length > 0 ? correlated[0].seq : null;
  const segmentTo = correlated.length > 0 ? correlated[correlated.length - 1].seq : null;

  // Dependency revisions from the persisted access decision (JSONB on binding).
  const depRev = (binding.dependencyRevisions ?? {}) as {
    actor?: number;
    workspace?: number;
    providerAccount?: number;
    operation?: number;
    bindings?: Array<{ id: string; revision: number }>;
    grants?: Array<{ id: string; revision: number }>;
  };

  // Safe-summary re-validation (§3.3): redact then assert no sensitive key
  // survives; omit and flag any row that lacks one.
  let safeSummary: Record<string, unknown> | null = null;
  const rawSummary = binding.safeSummary ?? null;
  if (rawSummary && typeof rawSummary === "object") {
    const redacted = redactWebhookSecrets(rawSummary) as Record<string, unknown>;
    if (summaryHasSensitiveKey(redacted)) {
      pushReasonList(reasons, PROVIDER_CASE_REASON.SAFE_SUMMARY_REDACTION_FAILED);
    } else {
      safeSummary = redacted;
    }
  }

  // Execution facts. providerIdempotencyKeyHash is derived from the raw
  // nonce key by HASHING it here — the raw key NEVER enters the manifest (§3.4).
  let execution: ProviderCaseManifestV1["execution"] = null;
  if (nonce && nonce.version === 2) {
    const dispatchState = dispatchStateOf(nonce);
    execution = {
      authorizationId: nonce.authorizationId ?? null,
      dispatchState,
      providerIdempotencyKeyHash: nonce.providerIdempotencyKey
        ? sha256HexPrefixed(nonce.providerIdempotencyKey)
        : null,
      upstreamStatusCode: extractUpstreamStatusCode(correlated),
      reconciled: correlated.some((e) => e.action === "provider.execution.reconciled"),
    };
  }

  // Row-absence honesty (§4.6, N47/N48).
  // A case that WENT THROUGH approval has a non-null approvalQueueId. If that
  // referenced queue row failed to load (deleted / corrupted), flag it — do NOT
  // gate on `approvalQueueId == null`, which is the OPPOSITE (a case that never
  // had a queue, such as the allowed-stub direct path.
  if (binding.approvalQueueId != null && !queue) {
    pushReasonList(reasons, PROVIDER_CASE_REASON.QUEUE_ROW_ABSENT_FOR_APPROVAL_PATH);
  }
  if (isExecutionPath(terminalState) && !nonce) {
    pushReasonList(reasons, PROVIDER_CASE_REASON.AUTHORIZATION_ROW_ABSENT_FOR_EXECUTION_PATH);
  }

  const genesisAt = correlated.length > 0 ? correlated[0].createdAt : null;
  const terminalAt = resolveTerminalAt(correlated, terminalState);

  const manifest: ProviderCaseManifestV1 = {
    schemaVersion: PROVIDER_CASE_MANIFEST_SCHEMA_VERSION,
    caseId,
    tenantId,
    workspaceId: binding.workspaceId,
    requestActor: {
      type: "agent",
      id: binding.actorAgentId,
      revision: depRev.actor ?? 0,
    },
    approvalActor: binding.approvalActorUserId
      ? { type: "user", id: binding.approvalActorUserId }
      : null,
    resumeActor: binding.resumeActor === "steward-system" ? "steward-system" : null,
    providerAccount: {
      id: binding.providerAccountId,
      revision: account?.revision ?? depRev.providerAccount ?? 0,
    },
    operation: {
      id: binding.operationId,
      key: operation?.operationKey ?? "",
      revision: binding.operationRevision,
      canonicalProfile: assertRegisteredProfile(binding.canonicalProfile),
      riskClass: operation?.riskClass ?? "",
    },
    actionDigest: binding.actionDigest,
    requestHash: binding.requestHash,
    idempotencyKeyHash: binding.idempotencyKeyHash,
    accessDecision: {
      id: binding.accessDecisionId,
      hash: binding.accessDecisionHash,
      effect: binding.accessEffect === "allow" ? "allow" : "deny",
    },
    policyDecision: {
      id: binding.policyDecisionId ?? null,
      hash: binding.policyDecisionHash ?? null,
      effect: binding.policyEffect,
    },
    approvalCommitmentHash: binding.approvalCommitmentHash ?? null,
    execution,
    dependencyRevisions: {
      actor: depRev.actor ?? 0,
      workspace: depRev.workspace ?? 0,
      providerAccount: depRev.providerAccount ?? 0,
      operation: depRev.operation ?? 0,
      matchedGrants: sortById(depRev.grants ?? []),
      matchedBindings: sortById(depRev.bindings ?? []),
      route:
        nonce?.routeId != null && nonce?.routeRevision != null
          ? { id: nonce.routeId, revision: nonce.routeRevision }
          : null,
      secret:
        nonce?.secretId != null && nonce?.secretVersion != null
          ? { id: nonce.secretId, version: nonce.secretVersion }
          : null,
      policyRevisionHash: binding.policyRevisionHash ?? null,
    },
    events,
    eventSeqRange:
      segmentFrom != null && segmentTo != null ? { from: segmentFrom, to: segmentTo } : null,
    terminalState,
    completeness: "incomplete",
    missingRequiredRoles: [],
    incompletenessReasons: reasons,
    safeSummary,
    genesisAt,
    terminalAt,
    assembledAt: new Date().toISOString(),
  };

  return { manifest, correlated, segmentFrom, segmentTo };
}

/**
 * Mechanical completeness (spec §4.4). `complete` iff every required role for
 * the resolved terminal state is present in the event index AND no reason code
 * downgrades it. `outcome_unknown` without a reconciled event is `incomplete`;
 * an in-flight dispatch is `incomplete` (awaiting terminal). A chain-break or
 * unresolved state already set `unknown` upstream and is never upgraded here.
 */
function finalizeCompleteness(manifest: ProviderCaseManifestV1): void {
  // A prior chain-break/size step may have set `unknown`; never upgrade it.
  const forcedUnknown = manifest.completeness === "unknown";

  const present = new Set<ProviderCaseEventRole>(manifest.events.map((e) => e.role));
  const required = requiredRoles(manifest.terminalState);
  const missing = required.filter((r) => !present.has(r));
  manifest.missingRequiredRoles = missing;
  for (const r of missing) pushReason(manifest, missingRoleReason(r));

  // Duplicate-dispatch / duplicate-terminal detection (§4.6, N33/KC12).
  const terminalCount = manifest.events.filter((e) => e.role === "exec_terminal").length;
  const dispatchedCount = manifest.events.filter((e) => e.role === "exec_dispatched").length;
  if (terminalCount > 1 || dispatchedCount > 1) {
    pushReason(manifest, PROVIDER_CASE_REASON.TERMINAL_STATE_UNRESOLVED);
  }

  // Honest in-flight / unknown reasons.
  if (manifest.terminalState === "outcome_unknown" && !manifest.execution?.reconciled) {
    pushReason(manifest, PROVIDER_CASE_REASON.OUTCOME_UNKNOWN_UNRECONCILED);
  }
  if (
    (manifest.terminalState === "executing" || manifest.terminalState === "execution_ready") &&
    manifest.execution?.dispatchState !== "succeeded" &&
    manifest.execution?.dispatchState !== "failed"
  ) {
    // A dispatched-but-no-terminal or claimed state is awaiting the terminal.
    if (
      manifest.execution?.dispatchState === "dispatched" ||
      manifest.execution?.dispatchState === "claimed" ||
      manifest.terminalState === "executing"
    ) {
      pushReason(manifest, PROVIDER_CASE_REASON.AWAITING_TERMINAL_EVENT);
    }
  }

  if (forcedUnknown || manifest.terminalState === "unknown") {
    manifest.completeness = "unknown";
    return;
  }
  const hasBlockingReason = manifest.incompletenessReasons.length > 0;
  manifest.completeness = hasBlockingReason ? "incomplete" : "complete";
}

/** Enforce the whole-manifest size cap (§3.6): if over, drop optional
 * descriptive fields (safeSummary) but KEEP the seq+hmac+role linkage index. */
function enforceManifestSizeCap(manifest: ProviderCaseManifestV1): void {
  if (byteLength(JSON.stringify(manifest)) <= MAX_MANIFEST_BYTES) return;
  manifest.safeSummary = null;
  pushReason(manifest, PROVIDER_CASE_REASON.MANIFEST_SIZE_EXCEEDED);
  if (manifest.completeness === "complete") manifest.completeness = "incomplete";
  // Still over? The event index (seq+hmac+role) is the irreducible linkage
  // proof and is never dropped; mark unknown so no false `complete` survives.
  if (byteLength(JSON.stringify(manifest)) > MAX_MANIFEST_BYTES) {
    manifest.completeness = "unknown";
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pushReason(manifest: ProviderCaseManifestV1, reason: string): void {
  if (!manifest.incompletenessReasons.includes(reason)) {
    manifest.incompletenessReasons.push(reason);
  }
}
function pushReasonList(reasons: string[], reason: string): void {
  if (!reasons.includes(reason)) reasons.push(reason);
}

function sortById(
  arr: Array<{ id: string; revision: number }>,
): Array<{ id: string; revision: number }> {
  return [...arr].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

function isExecutionPath(t: ProviderCaseTerminalState): boolean {
  return t === "executing" || t === "succeeded" || t === "failed" || t === "outcome_unknown";
}

function extractUpstreamStatusCode(correlated: CorrelatedEvent[]): number | null {
  // The terminal (succeeded/failed/outcome_unknown) event carries the integer
  // upstreamStatusCode in its metadata when present (never a body).
  for (let i = correlated.length - 1; i >= 0; i--) {
    const ev = correlated[i];
    if (
      ev.action === "provider.execution.succeeded" ||
      ev.action === "provider.execution.failed" ||
      ev.action === "provider.execution.outcome_unknown"
    ) {
      const code = ev.metadata.upstreamStatusCode;
      return typeof code === "number" ? code : null;
    }
  }
  return null;
}

function resolveTerminalAt(
  correlated: CorrelatedEvent[],
  terminalState: ProviderCaseTerminalState,
): string | null {
  const terminalActions = new Set<string>([
    "provider.action.denied",
    "provider.approval.decided",
    "provider.approval.expired",
    "provider.approval.staled",
    "provider.execution.succeeded",
    "provider.execution.failed",
    "provider.execution.outcome_unknown",
  ]);
  // For a still-open case, terminalAt is null.
  if (
    terminalState === "pending_approval" ||
    terminalState === "execution_ready" ||
    terminalState === "executing"
  ) {
    return null;
  }
  for (let i = correlated.length - 1; i >= 0; i--) {
    if (terminalActions.has(correlated[i].action)) return correlated[i].createdAt;
  }
  return null;
}

// ─── DB reads ─────────────────────────────────────────────────────────────────

async function loadBinding(
  sdb: SnapshotDb,
  tenantId: string,
  caseId: string,
): Promise<BindingRow | null> {
  const [row] = await sdb
    .select()
    .from(providerActionBindings)
    .where(
      and(
        eq(providerActionBindings.tenantId, tenantId),
        eq(providerActionBindings.intentId, caseId),
      ),
    )
    .limit(1);
  return row ?? null;
}

async function loadNonce(
  sdb: SnapshotDb,
  tenantId: string,
  caseId: string,
): Promise<NonceRow | null> {
  const [row] = await sdb
    .select()
    .from(executionAuthorizationNonces)
    .where(
      and(
        eq(executionAuthorizationNonces.tenantId, tenantId),
        eq(executionAuthorizationNonces.intentId, caseId),
        eq(executionAuthorizationNonces.version, 2),
      ),
    )
    .orderBy(asc(executionAuthorizationNonces.createdAt))
    .limit(1);
  return row ?? null;
}

async function loadQueue(
  sdb: SnapshotDb,
  tenantId: string,
  queueId: string,
): Promise<QueueRow | null> {
  const [row] = await sdb
    .select()
    .from(approvalQueue)
    .where(and(eq(approvalQueue.tenantId, tenantId), eq(approvalQueue.id, queueId)))
    .limit(1);
  return row ?? null;
}

async function loadOperation(
  sdb: SnapshotDb,
  tenantId: string,
  operationId: string,
): Promise<OperationRow | null> {
  const [row] = await sdb
    .select()
    .from(providerOperations)
    .where(and(eq(providerOperations.tenantId, tenantId), eq(providerOperations.id, operationId)))
    .limit(1);
  return row ?? null;
}

async function loadAccount(
  sdb: SnapshotDb,
  tenantId: string,
  accountId: string,
): Promise<AccountRow | null> {
  const [row] = await sdb
    .select()
    .from(providerAccounts)
    .where(and(eq(providerAccounts.tenantId, tenantId), eq(providerAccounts.id, accountId)))
    .limit(1);
  return row ?? null;
}

/**
 * Run `fn` inside a single read-only snapshot transaction (spec §4.1). On
 * Postgres we escalate to REPEATABLE READ READ ONLY so all reads observe one
 * snapshot even under concurrent appends; on PGLite the writer queue already
 * serializes, so a plain tx read is consistent. We do NOT take the tenant
 * advisory write lock (that would block appends); a snapshot read is enough and
 * non-blocking (§4.1). The audit chain-verify + bundle read are threaded the tx
 * executor so they share this snapshot (KC06).
 */
async function runInSnapshot<T>(tenantId: string, fn: (sdb: SnapshotDb) => Promise<T>): Promise<T> {
  const db = getDb();
  // Mounted case routes deliberately establish this tenant-bound snapshot
  // before entering the service. A nested Drizzle transaction would only be a
  // savepoint, so reuse is permitted only when the tenant and transaction
  // characteristics match exactly; ordinary READ COMMITTED reuse fails closed.
  if (
    hasTenantTransactionDatabase({
      tenantId,
      isolationLevel: "repeatable read",
      readOnly: true,
    })
  ) {
    return fn(db as SnapshotDb);
  }
  try {
    return await db.transaction(async (tx) => {
      if (!isPGLiteRuntime()) {
        await (tx as unknown as AuditReadExecutor).execute(
          sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`,
        );
      }
      return await fn(tx as unknown as SnapshotDb);
    });
  } catch (err) {
    // A genuine transaction failure surfaces to the caller (mapped to 500). We
    // never fabricate a manifest on a DB error (E8).
    throw new Error(`provider-case snapshot read failed: ${describeThrown(err)}`);
  }
}

export type { CorrelatedEvent };
export { correlateCaseEvents, dispatchStateOf, finalizeCompleteness, resolveTerminalState };
